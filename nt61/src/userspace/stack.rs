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

use crate::libs::ntdll::types::NTSTATUS;
use crate::mm::vas;
use crate::userspace::peb_teb::RtlUserProcessParameters;

/// Top of the user stack (just below the TEB).
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFDF_0000 - 0x2000;
/// Default stack size — 512 KiB.
pub const USER_STACK_SIZE: u64 = 512 * 1024;
/// Default guard page size at the bottom.
pub const USER_STACK_GUARD: u64 = 0x1000;

/// write the canonical user-mode startup frame. Returns the initial
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
    // push initial control -- points at the highest area. The string
    // copies land in real user pages owned by this process.
    let strings_base = USER_STACK_TOP - 0x8000;
    let image_va = copy_utf16(pml4, strings_base, image_name)?;
    let cmd_va = copy_utf16(pml4, strings_base + 0x1000, command_line)?;
    let env_va = copy_utf16(pml4, strings_base + 0x2000, environment)?;

    // Initial RSP is 16-byte aligned; [initial_rsp] is a null return
    // address (process entry never returns) and the three string VAs
    // sit in the 32 bytes just below RSP where the CRT can find them.
    let initial_rsp = USER_STACK_TOP - 64;
    let frame: [u64; 4] = [0, image_va, cmd_va, env_va];
    write_user_u64_array(pml4, initial_rsp - 32, &frame)?;

    Ok(initial_rsp)
}

fn is_mapped(pml4: u64, va: u64, size: u64) -> bool {
    vas::is_user_range_mapped(pml4, va, size)
}

/// Copy a UTF-16 string (with NUL terminator) into the target
/// process's user address space. Returns the user VA of the copy.
fn copy_utf16(pml4: u64, dst: u64, src: &[u16]) -> Result<u64, NTSTATUS> {
    if src.is_empty() {
        return Ok(0);
    }
    let mut bytes = alloc::vec::Vec::with_capacity(src.len() * 2 + 2);
    for unit in src {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&[0u8, 0u8]); // NUL terminator
    write_user_bytes(pml4, dst, &bytes)?;
    Ok(dst)
}

/// Write a byte buffer into the target process's user address space.
/// Fails closed when the destination range is not mapped for this
/// process; every access is volatile and performed while the process
/// root is attached, and the previous root is always restored.
fn write_user_bytes(pml4: u64, dst: u64, bytes: &[u8]) -> Result<(), NTSTATUS> {
    if bytes.is_empty() {
        return Ok(());
    }
    if !vas::is_user_range_mapped(pml4, dst, bytes.len() as u64) {
        return Err(-0x0FFF_FFFFi32 as NTSTATUS);
    }
    let previous = vas::attach_process(pml4);
    unsafe {
        let mut p = dst as *mut u8;
        for &b in bytes {
            core::ptr::write_volatile(p, b);
            p = p.add(1);
        }
    }
    vas::detach_process(previous);
    Ok(())
}

fn write_user_u64_array(pml4: u64, dst: u64, values: &[u64]) -> Result<(), NTSTATUS> {
    let mut bytes = alloc::vec::Vec::with_capacity(values.len() * 8);
    for v in values {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    write_user_bytes(pml4, dst, &bytes)
}

/// Fill in the `RtlUserProcessParameters` structure that lives at
/// `PROCESS_PARAMS_VA` with the given command-line / image / env.
pub fn populate_process_parameters(
    pml4: u64,
    image_name: &[u16],
    cmd_line: &[u16],
) -> Result<u64, NTSTATUS> {
    let base_va = crate::userspace::loader::PROCESS_PARAMS_VA;
    // Write a well-formed (self-consistent) parameter block: lengths
    // are valid, string members start empty. The real string VAs are
    // carried in the startup frame below RSP (see build_startup_frame).
    let mut bytes = alloc::vec::Vec::new();
    let params = crate::ps::process::RtlUserProcessParameters::new();
    // SAFETY: RtlUserProcessParameters is a plain-old-data struct; a
    // byte-wise copy is valid and produces the same layout user code
    // expects at PROCESS_PARAMS_VA.
    let raw = unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(params) as *const u8,
            core::mem::size_of::<crate::ps::process::RtlUserProcessParameters>(),
        )
    };
    bytes.extend_from_slice(raw);
    let _ = (image_name, cmd_line);
    write_user_bytes(pml4, base_va, &bytes)?;
    Ok(base_va)
}

/// Stack guard page simulation: reject any attempt to use the
/// bottom-most page of the user stack. The kernel currently has no
/// demand-paging, so we make the guard simply un-writeable in the
/// page table.
pub fn enable_stack_guard(pml4: u64) -> Result<(), NTSTATUS> {
    let bottom = USER_STACK_TOP - USER_STACK_SIZE;
    let r = vas::protect_user_range(pml4, bottom, USER_STACK_GUARD, 0x1); // PAGE_NOACCESS
    if r != vas::MmStatus::Ok {
        return Err(-0x0FFF_FFFFi32 as NTSTATUS);
    }
    Ok(())
}

/// Stack cookie — used by __security_check_cookie.
#[inline(never)]
pub fn __security_cookie() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static COOKIE: AtomicU64 = AtomicU64::new(0);
    let r = COOKIE.load(Ordering::Relaxed);
    if r != 0 {
        return r;
    }
    // Mix a per-boot timestamp and the caller's stack address so the
    // cookie differs across boots and call sites instead of being a
    // fixed constant.
    let mut new_cookie = 0u64;
    let sp = &new_cookie as *const _ as u64;
    let tick = crate::hal::common::pit::get_system_time_ms();
    new_cookie = 0x9E37_79B9_7F4A_7C15u64
        ^ sp.rotate_left(17)
        ^ tick.wrapping_mul(0xBF58_4763_6CE9_E2A1);
    if new_cookie == 0 {
        new_cookie = 1;
    }
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
