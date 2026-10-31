//! Guest memory model for BTL.
//!
//! Models how the BTL sees the user-mode VA space and the
//! kernel-mode page mappings behind it. Reads / writes from the
//! translated guest go through `read_virt` / `write_virt` so the
//! runtime can intercept `MOV` operations that hit
//! `IMAGE_DIRECTORY_ENTRY_RESOURCE`-style structures or set up
//! aligned accesses on demand.
//!
//! Phase 4 ships a thin wrapper around the kernel VM. Phase 5
//! extends it with watchpoints for self-modifying code detection
//! and a guest-side FS/GS base for TIB modelling.

#![cfg(any(feature = "btl", test))]

use super::decoder::DecMode;
use crate::arch::common::btl::memory::{ArchLeafPaging, GuestAddressSpace, GuestMemory};

/// Maximum user-VA we model. Phase 4 matches USER_STACK_BASE + 1
/// page; Phase 5 will widen to USER_STACK_TOP.
pub const BTL_USER_VA_LIMIT: u64 = 0x00008000_0000_0000;

/// Decode mode for the current guest (32- vs 64-bit).
static DEC_MODE: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(1 /*Mode64 by default*/);

/// Guest memory surface shared with the common BTL bridge.
pub type BtlGuestMemory = GuestAddressSpace<ArchLeafPaging>;

/// Construct a memory view for the active guest address space.
pub fn guest_memory() -> BtlGuestMemory {
    GuestAddressSpace::new(ArchLeafPaging)
}

/// Reject kernel VAs before handing the range to the shared page-walk.
fn valid_user_range(va: u64, len: usize) -> bool {
    let end = match va.checked_add(len as u64) {
        Some(end) => end,
        None => return false,
    };
    va < BTL_USER_VA_LIMIT && end <= BTL_USER_VA_LIMIT
}

/// Set the decoder mode for the current guest.
pub fn set_decoder_mode(m: DecMode) {
    DEC_MODE.store(m as u8, core::sync::atomic::Ordering::Release);
}

/// read the current decoder mode.
pub fn decoder_mode() -> DecMode {
    if DEC_MODE.load(core::sync::atomic::Ordering::Acquire) == 0 {
        DecMode::Mode32
    } else {
        DecMode::Mode64
    }
}

/// Kernel-mode proxy: translate a guest read into a kernel-side
/// byte buffer. Returns the number of bytes actually copied.
pub fn read_virt(va: u64, buf: &mut [u8]) -> usize {
    if !valid_user_range(va, buf.len()) {
        return 0;
    }
    guest_memory().read_virt(va, buf)
}

/// Kernel-mode proxy: write into guest memory. Returns true on
/// success.
pub fn write_virt(va: u64, data: &[u8]) -> bool {
    if !valid_user_range(va, data.len()) {
        return false;
    }
    guest_memory().write_virt(va, data)
}

pub fn init() {}

pub fn smoke_test() -> bool {
    let mut b = [0u8; 4];
    let n = read_virt(0x1000, &mut b);
    // A clean, unmapped guest VA must fail closed rather than expose
    // kernel scratch memory or fill bytes.
    n == 0 && !write_virt(0x1000, &[0x00; 4])
}
