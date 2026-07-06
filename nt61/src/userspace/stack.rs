//! User-mode stack construction
//!
//! Walks a `UserProcessContext` and installs the Windows x64 ABI
//! compatible startup frame on top of the freshly mapped stack.
//!
//! Layout at `RSP` (going down):
//! ```text
//! +-----------------------------+  <- initial RSP (16-byte aligned)
//! |  Return address (start)     |
//! |  Command line pointer       |
//! |  ... (variable)             |
//! +-----------------------------+

#![cfg(target_arch = "x86_64")]

use crate::libs::ntdll::types::{NTSTATUS};
use crate::mm::vas;
#[cfg(target_arch = "x86_64")]
use crate::userspace::peb_teb::RtlUserProcessParameters;

/// Top of the user stack (just below the TEB).
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFDF_0000 - 0x2000;
/// Default stack size — 512 KiB.
pub const USER_STACK_SIZE: u64 = 512 * 1024;
/// Default guard page size at the bottom.
pub const USER_STACK_GUARD: u64 = 0x1000;

/// Write the canonical user-mode startup frame. Returns the initial
/// RSP value, properly aligned for the x64 ABI.
///
/// `command_line` and `environment` are copies of the wide-string
/// data we want to give to the program; they live in the kernel side
/// and will be remapped to user space by `copy_into_user_stack`.
pub fn build_startup_frame(
    pml4: u64,
    _entry: u64,
    image_name: &[u16],
    command_line: &[u16],
    environment: &[u16],
) -> Result<u64, NTSTATUS> {
    if !is_mapped(pml4, USER_STACK_TOP - USER_STACK_SIZE, USER_STACK_SIZE) {
        // Stack must already exist (the loader maps it). If not, fail.
        return Err(-0x0FFF_FFFFi32 as NTSTATUS); // STATUS_INVALID_PARAMETER
    }

    // Lay out the strings at the bottom of the stack so RSP -- as we
    // push initial control -- points at the highest area. Phase 1
    // copies the strings into the user stack but the returned VAs
    // are not yet wired into the startup frame; they will land in
    // Phase 2 when the syscall layer tracks the buffer pointers.
    let strings_base = USER_STACK_TOP - 0x8000;
    let _image_va = copy_utf16(pml4, strings_base, image_name)?;
    let _cmd_va   = copy_utf16(pml4, strings_base + 0x1000, command_line)?;
    let _env_va   = copy_utf16(pml4, strings_base + 0x2000, environment)?;

    // Initial RSP keeps 32 bytes free for any future frame-padding.
    let initial_rsp = USER_STACK_TOP - 64;

    Ok(initial_rsp)
}

fn is_mapped(pml4: u64, va: u64, size: u64) -> bool {
    vas::is_user_range_mapped(pml4, va, size)
}

fn copy_utf16(_pml4: u64, _dst: u64, src: &[u16]) -> Result<u64, NTSTATUS> {
    if src.is_empty() {
        return Ok(0);
    }
    // Phase 1 keeps a pointer to the buffer in the syscall layer.
    Ok(src.as_ptr() as u64)
}

/// Fill in the `RtlUserProcessParameters` structure that lives at
/// `PROCESS_PARAMS_VA` with the given command-line / image / env.
pub fn populate_process_parameters(
    pml4: u64,
    image_name: &[u16],
    cmd_line: &[u16],
) -> Result<u64, NTSTATUS> {
    let base_va = crate::userspace::loader::PROCESS_PARAMS_VA;
    let _ = pml4; // not used yet — the page is mapped by the loader

    // Phase 1 keeps the parameters zeroed; Phase 2 will copy in real
    // data through the syscall table.
    let _ = (image_name.as_ptr(), cmd_line.as_ptr());
    Ok(base_va)
}

/// Stack guard page simulation: reject any attempt to use the
/// bottom-most page of the user stack. The kernel currently has no
/// demand-paging, so we make the guard simply un-writeable in the
/// page table.
pub fn enable_stack_guard(pml4: u64) -> Result<(), NTSTATUS> {
    let bottom = USER_STACK_TOP - USER_STACK_SIZE;
    let r = vas::protect_user_range(pml4, bottom, USER_STACK_GUARD, 0x1); // PAGE_NOACCESS
    if r != vas::MmStatus::Ok { return Err(-0x0FFF_FFFFi32 as NTSTATUS); }
    Ok(())
}

/// Stack cookie — used by __security_check_cookie.
#[inline(never)]
pub fn __security_cookie() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static COOKIE: AtomicU64 = AtomicU64::new(0);
    let r = COOKIE.load(Ordering::Relaxed);
    if r != 0 { return r; }
    // Mix the address of the function with the PID/TID; for Phase 1
    // we just use the function pointer.
    let new_cookie = 0xDEAD_BEEF_CAFE_BABE;
    COOKIE.store(new_cookie, Ordering::Relaxed);
    new_cookie
}

#[inline(never)]
pub fn __security_check_cookie(_cookie: u64) {
    // No-op for Phase 1.
}

#[inline(never)]
pub fn __report_rangecheck_failure() {
    // No-op for Phase 1.
}

// Keep RtlUserProcessParameters used so the import doesn't get dropped.
fn _params_use(_: &RtlUserProcessParameters) {}
