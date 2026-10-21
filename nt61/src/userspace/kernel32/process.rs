//! Process / thread management wrappers (kernel32).
//!
//! Thin wrappers over `NT_TERMINATE_PROCESS` / `NT_CURRENT_PROCESS` /
//! `NT_CURRENT_THREAD`.  All pseudo-handle semantics follow the real
//! Windows convention: `-1` = current process, `-2` = current thread.

use crate::libs::ntdll::types::HANDLE;

pub const THREAD_ALL_ACCESS: u32 = 0x001F_03FF;
pub const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;

/// Pseudo-handle for the calling process (equivalent of `GetCurrentProcess`).
pub const CURRENT_PROCESS_HANDLE: HANDLE = -1_isize as HANDLE;
/// Pseudo-handle for the calling thread (equivalent of `GetCurrentThread`).
pub const CURRENT_THREAD_HANDLE: HANDLE = -2_isize as HANDLE;

#[inline]
pub fn get_current_process() -> HANDLE {
    CURRENT_PROCESS_HANDLE
}

#[inline]
pub fn get_current_thread() -> HANDLE {
    CURRENT_THREAD_HANDLE
}

/// `ExitProcess` — terminate the calling process via `nt_terminate_process`.
pub fn exit_process(exit_code: u32) -> ! {
    unsafe {
        crate::libs::ntdll::process::nt_terminate_process(CURRENT_PROCESS_HANDLE, exit_code as i32);
    }
    // If the kernel call returns (e.g. the handle table did not resolve
    // the pseudo-handle), we still need to never return.  Fall into a
    // safe halt so the system remains alive without spinning the CPU.
    loop {
        crate::arch::halt();
    }
}

/// `ExitThread` — terminate the calling thread via `nt_terminate_thread`.
pub fn exit_thread(exit_code: u32) -> ! {
    unsafe {
        crate::libs::ntdll::thread::nt_terminate_thread(CURRENT_THREAD_HANDLE, exit_code);
    }
    loop {
        crate::arch::halt();
    }
}
