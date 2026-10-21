//! Audio Driver Stack
//
//! Wraps the two PC audio interfaces we care about: Intel HDA
//! (PCI class 0x0403) and AC'97 (PCI class 0x0401, plus the
//! native MC'97 at 0xFEC00000). For the bootstrap we only need
//! to enumerate the controllers and verify the HDA / AC'97
//! register layouts are present.
//
//! Clean-room implementation. Spec source: Intel High
//! Definition Audio specification 1.0a, and the AC'97
//! specification revision 2.3. No code is copied from any
//! Microsoft or ReactOS source file.

extern crate alloc;

pub mod ac97;
pub mod capture;
pub mod intel_hda;
pub mod mixer;
pub mod playback;
pub mod portcls;
pub mod stream_buffer;

pub mod smoke;

pub fn init() {
    // kprintln!("    Audio drivers: Intel HDA, AC'97, PortCls");
    intel_hda::init();
    ac97::init();
    portcls::init();
    // kprintln!("    Audio stack ready");
}

pub fn smoke_test() -> bool {
    smoke::smoke_test()
}

pub use ac97::{
    get_playback_position, set_master_volume, set_mute, set_pcm_volume, start_playback,
    stop_playback, write_pcm_samples,
};
/// Re-export audio functions for public API
pub use intel_hda::{get_codecs, get_info as get_hda_info, send_codec_cmd};
pub use portcls::{
    create_hda_audio_device, create_wavert_port, get_device_state, start_device, stop_device,
};

pub mod audio_core;

/// Initialise the full audio stack: hardware drivers plus the real
/// mixer / playback / capture paths.
pub fn init_full_audio_paths() {
    // Default mixer format: 48 kHz stereo, matching the AC'97
    // front DAC baseline and the HDA default output stream.
    playback::init(2, 48000);
    capture::init(2, 48000);
    // Attach whichever hardware backend was found first.
    if crate::drivers::audio::ac97::count() > 0 {
        playback::attach_ac97();
        capture::attach_ac97();
    } else if crate::drivers::audio::intel_hda::count() > 0 {
        playback::attach_hda();
        capture::attach_hda();
    }
}
