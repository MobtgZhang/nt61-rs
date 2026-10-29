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

/// Validate that every page in `va..va+len` is mapped, user-owned, and
/// has the access right required by the copy direction.
fn validate_virt(va: u64, len: usize, writable: bool) -> bool {
    if len == 0 {
        return true;
    }
    let end = match va.checked_add(len as u64) {
        Some(end) => end,
        None => return false,
    };
    if va >= BTL_USER_VA_LIMIT || end > BTL_USER_VA_LIMIT {
        return false;
    }

    let mut page = va & !0xFFF;
    while page < end {
        let Some(pte) = crate::arch::leaf_entry(page) else {
            return false;
        };
        if !crate::arch::page_user_accessible(pte, writable) {
            return false;
        }
        page += 0x1000;
    }
    true
}

/// Copy through the active Sv39 root a page at a time. The full range
/// is validated first, so a failed translation can only mean a racing
/// unmap and results in a partial count for the caller.
fn copy_virt(
    va: u64,
    len: usize,
    guest_src: bool,
    mut kernel_buf: *mut u8,
    writable: bool,
) -> usize {
    if !validate_virt(va, len, writable) {
        return 0;
    }

    let mut copied = 0;
    let mut guest_va = va;
    while copied < len {
        let bytes_in_page = (0x1000 - (guest_va & 0xFFF)) as usize;
        let chunk = (len - copied).min(bytes_in_page);
        let Some(pa) = crate::arch::riscv64::paging::translate_virt(guest_va) else {
            break;
        };
        unsafe {
            let (src, dst) = if guest_src {
                (pa as *const u8, kernel_buf)
            } else {
                (kernel_buf as *const u8, pa as *mut u8)
            };
            core::ptr::copy(src, dst, chunk);
        }
        copied += chunk;
        guest_va = guest_va.wrapping_add(chunk as u64);
        kernel_buf = kernel_buf.wrapping_add(chunk);
    }
    copied
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
    copy_virt(va, buf.len(), true, buf.as_mut_ptr(), false)
}

/// Kernel-mode proxy: write into guest memory. Returns true on
/// success.
pub fn write_virt(va: u64, data: &[u8]) -> bool {
    copy_virt(va, data.len(), false, data.as_ptr() as *mut u8, true) == data.len()
}

pub fn init() {}

pub fn smoke_test() -> bool {
    let mut b = [0u8; 4];
    let n = read_virt(0x1000, &mut b);
    // A clean, unmapped guest VA must fail closed rather than expose
    // kernel scratch memory or fill bytes.
    n == 0 && !write_virt(0x1000, &[0x00; 4])
}
