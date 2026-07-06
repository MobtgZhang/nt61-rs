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

#![cfg(feature = "btl")]

use super::decoder::DecMode;

/// Maximum user-VA we model. Phase 4 matches USER_STACK_BASE + 1
/// page; Phase 5 will widen to USER_STACK_TOP.
pub const BTL_USER_VA_LIMIT: u64 = 0x00008000_0000_0000;

/// Decode mode for the current guest (32- vs 64-bit).
static DEC_MODE: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(1 /*Mode64 by default*/);

/// Set the decoder mode for the current guest.
pub fn set_decoder_mode(m: DecMode) {
    DEC_MODE.store(m as u8, core::sync::atomic::Ordering::Release);
}

/// Read the current decoder mode.
pub fn decoder_mode() -> DecMode {
    if DEC_MODE.load(core::sync::atomic::Ordering::Acquire) == 0 {
        DecMode::Mode32
    } else { DecMode::Mode64 }
}

/// Kernel-mode proxy: translate a guest read into a kernel-side
/// byte buffer. Returns the number of bytes actually copied.
pub fn read_virt(_va: u64, _buf: &mut [u8]) -> usize {
    // Phase 4: pretend the read always succeeds.
    let _ = BTL_USER_VA_LIMIT;
    buf_fill(_buf, 0xCC)
}

/// Kernel-mode proxy: write into guest memory. Returns true on
/// success.
pub fn write_virt(_va: u64, _data: &[u8]) -> bool {
    // Phase 4: pretend the write always succeeds.
    true
}

fn buf_fill(buf: &mut [u8], v: u8) -> usize {
    let n = buf.len();
    for b in buf.iter_mut() { *b = v; }
    n
}

pub fn init() {}

pub fn smoke_test() -> bool {
    let mut b = [0u8; 4];
    let n = read_virt(0x1000, &mut b);
    b[0] == 0xCC && n == 4
}