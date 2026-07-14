//! Driver PE-Image Emitter
//!
//! Driver `.sys` files are normal PE32+ images, just with the
//! `IMAGE_SUBSYSTEM_NATIVE` (1) subsystem value.
//!
//! **As of the winload-to-disk-ntoskrnl handoff refactor**, this
//! module is no longer compiled into the kernel. The host kernel
//! does not synthesise `.sys` files in memory any longer — every
//! driver PE is produced by `tools/src/fs/build.rs` and baked
//! into the on-disk system image (see `boot_drivers_pe` in that
//! crate). The winload side reads those files back via
//! `winload::load_boot_drivers` and resolves their imports
//! against the on-disk `ntoskrnl.exe` export table.
//!
//! The original implementation depended on `crate::pegen` which
//! was removed when the in-binary PE pipeline was retired.
//! Nothing live below depends on it any more; the legacy
//! implementation is preserved in git history.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// One driver .sys image in the on-disk system tree.
pub struct DriverImage {
    /// Path relative to `C:\` (e.g. `Windows\System32\drivers\iastor.sys`).
    pub path: String,
    /// Raw PE bytes.
    pub bytes: Vec<u8>,
    /// Driver name.
    pub name: &'static str,
}

/// Stub kept for source compatibility.
///
/// In the live system, drivers are baked into the disk image by
/// `tools/src/fs/build.rs`. The host kernel MUST NOT try to build
/// driver PEs at runtime any more — there is no `pegen` module
/// to back this function. Returning an empty list is the safe
/// placeholder so any leftover caller surfaces immediately at the
/// I/O manager when its `DriverEntry` list is unexpectedly empty.
pub fn build_all(_machine: u16) -> Vec<DriverImage> {
    Vec::new()
}
