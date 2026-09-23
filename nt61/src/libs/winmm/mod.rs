//! Windows Multimedia API (WinMM)
//!
//! This module implements the Windows Multimedia APIs for audio and MIDI:
//! - Wave Audio (waveOut/waveIn)
//! - MIDI
//! - Mixer
//! - Auxiliary Audio
//! - Joystick

pub mod wave;

pub use wave::{
    WaveFormatEx, WaveHdr, WaveOutCaps, WaveInCaps,
    wave_out_get_num_devs, wave_out_get_dev_caps, wave_out_open, wave_out_close,
    wave_out_prepare_header, wave_out_unprepare_header, wave_out_write,
    wave_out_restart, wave_out_pause, wave_out_reset, wave_out_get_position,
    wave_out_set_volume, wave_out_get_volume,
    wave_in_get_num_devs, wave_in_get_dev_caps, wave_in_open, wave_in_close,
    wave_in_start, wave_in_stop, wave_in_reset,
    MMSYSERR_NOERROR, MMSYSERR_ERROR, MMSYSERR_BADDEVICEID, MMSYSERR_INVALHANDLE,
    WAVE_FORMAT_PCM, WAVE_FORMAT_IEEE_FLOAT,
};

/// Initialize WinMM subsystem
pub fn init() {
    wave::init();
}

/// Smoke test for WinMM
pub fn smoke_test() -> bool {
    let num_out = wave_out_get_num_devs();
    let num_in = wave_in_get_num_devs();

    // Basic validation
    num_out > 0 || num_in > 0
}
