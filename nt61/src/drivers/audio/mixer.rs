//! Audio Mixer
//
//! Combines multiple audio streams into a single output stream with
//! per-stream volume, per-stream mute, master volume and master mute.
//! All mixing is done in 32-bit integer samples (Q8.8 fixed-point
//! gains) with proper clamping, matching the AC'97 / Intel HDA
//! 16-bit PCM output formats.
//
//! Clean-room implementation. Spec source: AC'97 Component
//! Specification Rev 2.3 (mixer register semantics) and the Intel
//! High Definition Audio Specification 1.0a (output conversion
//! rules). No code is copied from any Microsoft or ReactOS source
//! file.

use crate::drivers::audio::stream_buffer::StreamBuffer;
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

/// Gain is represented as a Q8.8 fixed-point value where 256 == 0 dB
/// (unity gain), matching the AC'97 0x00..0x1F attenuation encoding
/// mapped onto a linear percentage scale.
pub const GAIN_UNITY: i32 = 256;
/// Fixed-point shift used when converting volume percentages to gains.
pub const GAIN_SHIFT: i32 = 8;

/// Convert a 0-100 percentage volume into a Q8.8 gain.
pub const fn volume_percent_to_gain(percent: u8) -> i32 {
    let p = if percent as i32 > 100 {
        100
    } else {
        percent as i32
    };
    (p * GAIN_UNITY) / 100
}

/// Apply a Q8.8 gain to a 16-bit sample, returning the scaled
/// 32-bit result without clamping (caller sums then clamps).
#[inline]
pub const fn apply_gain_i16(sample: i16, gain: i32) -> i32 {
    (sample as i32 * gain) >> GAIN_SHIFT
}

/// Clamp a 32-bit accumulated sample to the 16-bit PCM range.
#[inline]
pub const fn clamp_i16(sample: i32) -> i16 {
    if sample > i16::MAX as i32 {
        i16::MAX as i16
    } else if sample < i16::MIN as i32 {
        i16::MIN as i16
    } else {
        sample as i16
    }
}

/// One mixing input: a producer pushes interleaved 16-bit PCM frames
/// into its stream buffer; the mixer consumes them each pump cycle.
pub struct MixerInput {
    /// Caller-chosen identifier for this input.
    pub id: u32,
    /// Stream buffer holding interleaved 16-bit frames.
    buffer: StreamBuffer,
    /// Per-stream Q8.8 gain.
    gain: i32,
    /// Per-stream mute.
    muted: bool,
}

impl MixerInput {
    /// Create a new mixer input with the given capacity (in frames)
    /// and format.
    pub fn new(id: u32, capacity_frames: usize, channels: u8, sample_rate: u32) -> Self {
        Self {
            id,
            buffer: StreamBuffer::new(capacity_frames, channels, sample_rate),
            gain: GAIN_UNITY,
            muted: false,
        }
    }

    /// Set the per-stream volume (0-100 percentage).
    pub fn set_volume(&mut self, percent: u8) {
        self.gain = volume_percent_to_gain(percent);
    }

    /// Set the per-stream mute flag.
    pub fn set_mute(&mut self, muted: bool) {
        self.muted = muted;
    }

    /// Access the input's stream buffer for pushing samples.
    pub fn buffer(&mut self) -> &mut StreamBuffer {
        &mut self.buffer
    }

    /// Number of frames still buffered for this input.
    pub fn frames_available(&self) -> usize {
        self.buffer.available_frames()
    }
}

/// Master mixer: combines all non-muted inputs, applies the master
/// gain, and clamps the summed output to 16-bit PCM.
pub struct Mixer {
    inputs: Vec<MixerInput>,
    /// Master Q8.8 gain.
    master_gain: i32,
    /// Master mute.
    master_muted: bool,
    /// Output channel count (all inputs are down/up-mixed to this).
    output_channels: u8,
    /// Output sample rate; inputs with a different rate are resampled
    /// by the playback format-conversion layer, not here.
    output_sample_rate: u32,
}

impl Mixer {
    /// Create a mixer with the given output format.
    pub fn new(output_channels: u8, output_sample_rate: u32) -> Self {
        Self {
            inputs: Vec::new(),
            master_gain: GAIN_UNITY,
            master_muted: false,
            output_channels,
            output_sample_rate,
        }
    }

    /// Add a new input stream and return its index.
    pub fn add_input(
        &mut self,
        id: u32,
        capacity_frames: usize,
        channels: u8,
        sample_rate: u32,
    ) -> usize {
        self.inputs
            .push(MixerInput::new(id, capacity_frames, channels, sample_rate));
        self.inputs.len() - 1
    }

    /// Get a mutable reference to an input by index.
    pub fn input_mut(&mut self, index: usize) -> Option<&mut MixerInput> {
        self.inputs.get_mut(index)
    }

    /// Get an input by index.
    pub fn input(&self, index: usize) -> Option<&MixerInput> {
        self.inputs.get(index)
    }

    /// Set the master volume (0-100 percentage).
    pub fn set_master_volume(&mut self, percent: u8) {
        self.master_gain = volume_percent_to_gain(percent);
    }

    /// Set the master mute flag.
    pub fn set_master_mute(&mut self, muted: bool) {
        self.master_muted = muted;
    }

    /// Set the volume of one input by index.
    pub fn set_input_volume(&mut self, index: usize, percent: u8) -> bool {
        match self.inputs.get_mut(index) {
            Some(input) => {
                input.set_volume(percent);
                true
            }
            None => false,
        }
    }

    /// Set the mute flag of one input by index.
    pub fn set_input_mute(&mut self, index: usize, muted: bool) -> bool {
        match self.inputs.get_mut(index) {
            Some(input) => {
                input.set_mute(muted);
                true
            }
            None => false,
        }
    }

    /// Mix up to `out_frames` frames from every input into `out`
    /// (interleaved 16-bit samples, `out` must hold
    /// `out_frames * output_channels` samples).
    ///
    /// Returns the number of frames actually written. When every
    /// input is muted or the master is muted, no frames are produced
    /// (the playback engine treats that as a silent period rather
    /// than emitting zero-filled DMA frames). Unmuted inputs with
    /// fewer frames contribute silence for the remainder, matching
    /// the "mix on top of silence" behaviour of the Windows audio
    /// engine mixer described in the Microsoft WDK audio
    /// documentation.
    pub fn mix(&mut self, out: &mut [i16], out_frames: usize) -> usize {
        let has_active_input = self.inputs.iter().any(|input| !input.muted);
        if self.master_muted || !has_active_input || out_frames == 0 {
            return 0;
        }

        let channels = self.output_channels as usize;
        let frames_to_mix = out_frames.min(out.len() / channels.max(1));
        if frames_to_mix == 0 {
            return 0;
        }

        // Accumulator: one i32 sample slot per output frame/channel.
        let mut acc = alloc::vec![0i32; frames_to_mix * channels];

        for input in self.inputs.iter_mut() {
            if input.muted {
                continue;
            }
            let gain = input.gain;
            let in_channels = input.buffer.channels as usize;
            let mut scratch = alloc::vec![0i16; frames_to_mix * in_channels];
            let got = input.buffer.read_frames(&mut scratch, frames_to_mix);
            if got == 0 {
                continue;
            }

            for frame in 0..got {
                for ch in 0..channels {
                    let src_ch = if in_channels == channels {
                        ch
                    } else {
                        ch % in_channels
                    };
                    let sample = scratch[frame * in_channels + src_ch];
                    acc[frame * channels + ch] += apply_gain_i16(sample, gain);
                }
            }
        }

        let master = self.master_gain;
        let mut written = 0usize;
        for slot in acc.iter_mut().take(frames_to_mix * channels) {
            *slot = (*slot * master) >> GAIN_SHIFT;
            out[written] = clamp_i16(*slot);
            written += 1;
        }
        frames_to_mix
    }

    /// Number of inputs currently registered.
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Output channel count.
    pub fn output_channels(&self) -> u8 {
        self.output_channels
    }

    /// Output sample rate in Hz.
    pub fn output_sample_rate(&self) -> u32 {
        self.output_sample_rate
    }
}

/// Locked mixer wrapper: the playback engine owns a `Mixer` that is
/// touched from both the submit path (producer threads) and the pump
/// path (playback engine), so the raw `Mixer` sits behind a spinlock.
pub struct LockedMixer {
    inner: Spinlock<Mixer>,
}

impl LockedMixer {
    /// Create a new locked mixer with the given output format.
    pub fn new(output_channels: u8, output_sample_rate: u32) -> Self {
        Self {
            inner: Spinlock::new(Mixer::new(output_channels, output_sample_rate)),
        }
    }

    /// Run a closure with the mixer locked.
    pub fn with<R>(&self, f: impl FnOnce(&mut Mixer) -> R) -> R {
        let mut guard = self.inner.lock();
        f(&mut guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_percent_to_gain_bounds() {
        assert_eq!(volume_percent_to_gain(0), 0);
        assert_eq!(volume_percent_to_gain(100), GAIN_UNITY);
        assert_eq!(volume_percent_to_gain(50), GAIN_UNITY / 2);
    }

    #[test]
    fn clamp_i16_limits_sum() {
        assert_eq!(clamp_i16(40000), i16::MAX);
        assert_eq!(clamp_i16(-40000), i16::MIN);
        assert_eq!(clamp_i16(0), 0);
    }

    #[test]
    fn mixer_sums_two_streams_with_clamping() {
        let mut mixer = Mixer::new(2, 48000);
        let idx_a = mixer.add_input(1, 64, 2, 48000);
        let idx_b = mixer.add_input(2, 64, 2, 48000);

        let loud = [i16::MAX; 2];
        mixer
            .input_mut(idx_a)
            .unwrap()
            .buffer()
            .write_frames(&loud, 1);
        mixer
            .input_mut(idx_b)
            .unwrap()
            .buffer()
            .write_frames(&loud, 1);

        let mut out = [0i16; 2];
        let frames = mixer.mix(&mut out, 1);
        assert_eq!(frames, 1);
        assert_eq!(out[0], i16::MAX);
    }

    #[test]
    fn mixer_mute_and_master_volume() {
        let mut mixer = Mixer::new(1, 48000);
        let idx = mixer.add_input(1, 8, 1, 48000);
        mixer.set_master_volume(50);
        mixer.set_input_mute(idx, true);

        let samples = [1000i16];
        mixer
            .input_mut(idx)
            .unwrap()
            .buffer()
            .write_frames(&samples, 1);
        let mut out = [0i16];
        assert_eq!(mixer.mix(&mut out, 1), 0);

        mixer.set_input_mute(idx, false);
        mixer
            .input_mut(idx)
            .unwrap()
            .buffer()
            .write_frames(&samples, 1);
        let frames = mixer.mix(&mut out, 1);
        assert_eq!(frames, 1);
        assert_eq!(out[0], 500);
    }

    #[test]
    fn mixer_passes_stereo_through_to_stereo() {
        let mut mixer = Mixer::new(2, 48000);
        let idx = mixer.add_input(1, 8, 2, 48000);
        let samples = [100i16, 200];
        mixer
            .input_mut(idx)
            .unwrap()
            .buffer()
            .write_frames(&samples, 1);
        let mut out = [0i16; 2];
        let frames = mixer.mix(&mut out, 1);
        assert_eq!(frames, 1);
        assert_eq!(out[0], 100);
        assert_eq!(out[1], 200);
    }

    #[test]
    fn locked_mixer_allows_nested_access() {
        let mixer = LockedMixer::new(2, 48000);
        let result = mixer.with(|m| {
            let idx = m.add_input(1, 4, 2, 48000);
            m.set_input_volume(idx, 100);
            m.input_count()
        });
        assert_eq!(result, 1);
    }
}
