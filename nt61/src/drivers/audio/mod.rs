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

pub mod intel_hda;
pub mod ac97;
pub mod portcls;

pub mod smoke;

use crate::kprintln;

pub fn init() {
    // kprintln!("    Audio drivers: Intel HDA, AC'97, PortCls")  // kprintln disabled (memcpy crash workaround);
    intel_hda::init();
    ac97::init();
    portcls::init();
    // kprintln!("    Audio stack ready")  // kprintln disabled (memcpy crash workaround);
}

pub fn smoke_test() -> bool { smoke::smoke_test() }

/// Re-export audio functions for public API
pub use intel_hda::{send_codec_cmd, get_codecs, get_info as get_hda_info};
pub use ac97::{
    start_playback, stop_playback, write_pcm_samples,
    set_master_volume, set_pcm_volume, set_mute, get_playback_position
};
pub use portcls::{
    create_wavert_port, start_device, stop_device,
    get_device_state, create_hda_audio_device,
};
