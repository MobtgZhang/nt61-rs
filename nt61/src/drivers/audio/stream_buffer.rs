//! Audio Stream Ring Buffer
//
//! A single-producer / single-consumer lock-free ring buffer for
//! interleaved 16-bit PCM frames. Tracks a read cursor and a write
//! cursor, detects underruns (consumer attempted to read past what
//! the producer has written), and records the stream format
//! (sample rate, channels, bit depth) so the format-conversion
//! layer can query it without extra state.
//
//! The ring uses power-of-two sizing and masked index arithmetic,
//! the same lock-free pattern the Linux kernel uses for
//! `kfifo` (Documentation/ring-buffer.txt) and that the NDIS
//! circular-buffer model in the Windows WDK audio samples uses.
//! Memory ordering: the producer publishes frames with a Release
//! store on the write cursor; the consumer reads the write cursor
//! with Acquire so it never observes data before it is written.

use crate::ke::sync::Spinlock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Default ring capacity in frames when the caller does not care.
pub const DEFAULT_CAPACITY_FRAMES: usize = 1024;
/// Maximum ring capacity in frames (4 MiB of 16-bit stereo).
pub const MAX_CAPACITY_FRAMES: usize = 1 << 20;

/// Lock-free SPSC ring buffer for interleaved 16-bit PCM frames.
pub struct StreamBuffer {
    /// Interleaved 16-bit sample storage, `capacity * channels` long.
    data: Spinlock<Vec<i16>>,
    /// Mask for wrapping a raw cursor index into the ring.
    mask: usize,
    /// Number of frames the ring holds (power of two).
    capacity_frames: usize,
    /// Number of interleaved channels per frame.
    pub channels: u8,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Bits per sample (always 16 for this buffer type).
    pub bits_per_sample: u8,
    /// Producer cursor: total frames ever written (never wraps).
    write_cursor: AtomicUsize,
    /// Consumer cursor: total frames ever read (never wraps).
    read_cursor: AtomicUsize,
    /// Number of underrun events (consumer starved).
    underruns: AtomicUsize,
    /// Number of overrun events (producer dropped frames).
    overruns: AtomicUsize,
}

impl StreamBuffer {
    /// Create a new ring buffer. `capacity_frames` is rounded down to
    /// the nearest power of two and clamped to `MAX_CAPACITY_FRAMES`.
    pub fn new(capacity_frames: usize, channels: u8, sample_rate: u32) -> Self {
        let requested = capacity_frames.clamp(1, MAX_CAPACITY_FRAMES);
        let capacity = requested.next_power_of_two();
        let channels_usize = (channels as usize).max(1);
        Self {
            data: Spinlock::new(alloc::vec![0i16; capacity * channels_usize]),
            mask: capacity - 1,
            capacity_frames: capacity,
            channels,
            sample_rate,
            bits_per_sample: 16,
            write_cursor: AtomicUsize::new(0),
            read_cursor: AtomicUsize::new(0),
            underruns: AtomicUsize::new(0),
            overruns: AtomicUsize::new(0),
        }
    }

    /// Ring capacity in frames (power of two).
    pub fn capacity_frames(&self) -> usize {
        self.capacity_frames
    }

    /// Frames currently available for the consumer to read.
    pub fn available_frames(&self) -> usize {
        let w = self.write_cursor.load(Ordering::Acquire);
        let r = self.read_cursor.load(Ordering::Acquire);
        w.saturating_sub(r)
    }

    /// Frames of free space the producer can still write into.
    pub fn free_frames(&self) -> usize {
        self.capacity_frames - self.available_frames()
    }

    /// Total underrun events since creation.
    pub fn underrun_count(&self) -> usize {
        self.underruns.load(Ordering::Relaxed)
    }

    /// Total overrun events since creation.
    pub fn overrun_count(&self) -> usize {
        self.overruns.load(Ordering::Relaxed)
    }

    /// Write `frames` interleaved frames from `samples` into the ring.
    /// Returns the number of frames actually written; if the ring is
    /// full the excess frames are dropped and an overrun is recorded.
    pub fn write_frames(&self, samples: &[i16], frames: usize) -> usize {
        let channels = (self.channels as usize).max(1);
        let free = self.free_frames();
        if free == 0 || frames == 0 {
            if frames > free {
                self.overruns.fetch_add(frames - free, Ordering::Relaxed);
            }
            return 0;
        }
        let to_write = frames.min(free);
        if frames > to_write {
            self.overruns
                .fetch_add(frames - to_write, Ordering::Relaxed);
        }

        let w = self.write_cursor.load(Ordering::Relaxed);
        for i in 0..to_write {
            let frame_index = (w + i) & self.mask;
            for ch in 0..channels {
                let slot = frame_index * channels + ch;
                let src = i * channels + ch;
                if src < samples.len() {
                    self.data.lock()[slot] = samples[src];
                }
            }
        }
        // Publish the new frames to the consumer.
        self.write_cursor.store(w + to_write, Ordering::Release);
        to_write
    }

    /// Read up to `frames` interleaved frames into `samples`.
    /// Returns the number of frames actually read; if fewer frames
    /// are available the shortfall is counted as an underrun.
    pub fn read_frames(&self, samples: &mut [i16], frames: usize) -> usize {
        let available = self.available_frames();
        if available < frames {
            self.underruns
                .fetch_add(frames - available, Ordering::Relaxed);
        }
        if frames == 0 || available == 0 {
            return 0;
        }

        let channels = (self.channels as usize).max(1);
        let to_read = frames.min(available);
        let r = self.read_cursor.load(Ordering::Relaxed);
        for i in 0..to_read {
            let frame_index = (r + i) & self.mask;
            for ch in 0..channels {
                let slot = frame_index * channels + ch;
                let dst = i * channels + ch;
                if dst < samples.len() {
                    samples[dst] = self.data.lock()[slot];
                }
            }
        }
        // Publish the consumed frames to the producer.
        self.read_cursor.store(r + to_read, Ordering::Release);
        to_read
    }

    /// Reset both cursors and clear the ring contents.
    pub fn reset(&self) {
        self.write_cursor.store(0, Ordering::Release);
        self.read_cursor.store(0, Ordering::Release);
        self.data.lock().fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_round_trip() {
        let buf = StreamBuffer::new(4, 1, 48000);
        let samples = [1i16, 2, 3, 4];
        assert_eq!(buf.write_frames(&samples, 4), 4);
        let mut out = [0i16; 4];
        assert_eq!(buf.read_frames(&mut out, 4), 4);
        assert_eq!(out, samples);
    }

    #[test]
    fn wrap_around_preserves_order() {
        let buf = StreamBuffer::new(4, 1, 48000);
        // Write and read enough times to wrap the ring several times.
        for round in 0..12u16 {
            let v = [(round as i16) + 1];
            assert_eq!(buf.write_frames(&v, 1), 1);
            let mut out = [0i16; 1];
            assert_eq!(buf.read_frames(&mut out, 1), 1);
            assert_eq!(out[0], v[0]);
        }
    }

    #[test]
    fn underrun_is_detected() {
        let buf = StreamBuffer::new(4, 1, 48000);
        let mut out = [0i16; 4];
        assert_eq!(buf.read_frames(&mut out, 3), 0);
        assert_eq!(buf.underrun_count(), 3);
    }

    #[test]
    fn overrun_is_detected() {
        let buf = StreamBuffer::new(4, 1, 48000);
        let samples = [1i16, 2, 3, 4, 5];
        let written = buf.write_frames(&samples, 5);
        assert_eq!(written, 4);
        assert_eq!(buf.overrun_count(), 1);
    }

    #[test]
    fn stereo_channels_preserved() {
        let buf = StreamBuffer::new(4, 2, 44100);
        let samples = [10i16, 20, 30, 40];
        assert_eq!(buf.write_frames(&samples, 2), 2);
        let mut out = [0i16; 4];
        assert_eq!(buf.read_frames(&mut out, 2), 2);
        assert_eq!(out, samples);
        assert_eq!(buf.sample_rate, 44100);
        assert_eq!(buf.channels, 2);
        assert_eq!(buf.bits_per_sample, 16);
    }

    #[test]
    fn reset_clears_all_state() {
        let buf = StreamBuffer::new(4, 1, 48000);
        let samples = [1i16, 2, 3, 4];
        buf.write_frames(&samples, 4);
        buf.reset();
        assert_eq!(buf.available_frames(), 0);
        assert_eq!(buf.free_frames(), 4);
    }

    #[test]
    fn capacity_is_power_of_two() {
        let buf = StreamBuffer::new(3, 1, 48000);
        assert_eq!(buf.capacity_frames(), 4);
        let big = StreamBuffer::new(MAX_CAPACITY_FRAMES * 2, 1, 48000);
        assert_eq!(big.capacity_frames(), MAX_CAPACITY_FRAMES);
    }
}
