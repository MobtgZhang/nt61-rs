//! kernel32 — thread management
//
//! `CreateThread`, `GetCurrentThread`, `GetCurrentThreadId`,
//! `ExitThread`, `TerminateThread`, `GetThreadId`,
//! `Sleep`, `SleepEx`, `SwitchToThread`, `ResumeThread`,
//! `SuspendThread`.

use super::error::{GetLastError, SetLastError};
use super::types::{BOOL, DWORD, FALSE, HANDLE, HANDLE_CURRENT_THREAD, TRUE};
use crate::libs::ntdll::status::{STATUS_INVALID_HANDLE, STATUS_SUCCESS};
use crate::libs::ntdll::thread as ntdll_thread;
use core::ptr;

/// `CreateThread`.
pub unsafe extern "C" fn CreateThread(
    _security: *const u8,
    stack_size: usize,
    start_routine: extern "C" fn(*mut u8) -> u32,
    parameter: *mut u8,
    creation_flags: DWORD,
    thread_id: *mut DWORD,
) -> HANDLE {
    let _ = (stack_size, start_routine, parameter, creation_flags);
    let mut h: HANDLE = ptr::null_mut();
    let mut oa = crate::libs::ntdll::types::ObjectAttributes::new();
    let status = ntdll_thread::NtCreateThread(
        &mut h, 0, &mut oa, ptr::null_mut(), ptr::null_mut(),
        ptr::null_mut(), ptr::null_mut(), 0, 0,
    );
    if status != STATUS_SUCCESS {
        SetLastError(8);
        return ptr::null_mut();
    }
    if !thread_id.is_null() {
        *thread_id = crate::ps::process::PID_SYSTEM.wrapping_add(1) as u32;
    }
    h
}

/// `GetCurrentThread` / `GetCurrentThreadId` / `GetThreadId`.
pub extern "C" fn GetCurrentThread() -> HANDLE { HANDLE_CURRENT_THREAD }
pub extern "C" fn GetCurrentThreadId() -> DWORD { crate::ps::process::PID_SYSTEM.wrapping_add(1) as u32 }
pub extern "C" fn GetThreadId(thread: HANDLE) -> DWORD {
    if thread.is_null() { return 0; }
    crate::ps::process::PID_SYSTEM.wrapping_add(1) as u32
}

/// `ExitThread` — terminate the current thread.
pub unsafe extern "C" fn ExitThread(exit_code: DWORD) -> ! {
    ntdll_thread::NtTerminateThread(HANDLE_CURRENT_THREAD, exit_code);
    loop { core::hint::spin_loop(); }
}

/// `TerminateThread`.
pub unsafe extern "C" fn TerminateThread(thread: HANDLE, exit_code: DWORD) -> BOOL {
    if ntdll_thread::NtTerminateThread(thread, exit_code) == STATUS_SUCCESS {
        TRUE
    } else { SetLastError(6); FALSE }
}

/// `SuspendThread` / `ResumeThread`.
pub unsafe extern "C" fn SuspendThread(thread: HANDLE) -> DWORD {
    let mut prev = 0u32;
    if ntdll_thread::NtSuspendThread(thread, &mut prev) != STATUS_SUCCESS {
        SetLastError(6);
        return -1i32 as u32;
    }
    prev
}
pub unsafe extern "C" fn ResumeThread(thread: HANDLE) -> DWORD {
    let mut prev = 0u32;
    if ntdll_thread::NtResumeThread(thread, &mut prev) != STATUS_SUCCESS {
        SetLastError(6);
        return -1i32 as u32;
    }
    prev
}

/// `Sleep` — forward to ntdll. The bootstrap ignores the
/// actual delay.
pub extern "C" fn Sleep(milliseconds: DWORD) {
    let mut interval: i64 = -(milliseconds as i64) * 10_000;
    let _ = crate::libs::ntdll::sync::NtDelayExecution(0, &mut interval);
}

/// `SleepEx` — same.
pub extern "C" fn SleepEx(milliseconds: DWORD, _alertable: BOOL) -> DWORD {
    Sleep(milliseconds);
    0
}

/// `SwitchToThread` — yield to the scheduler.
pub extern "C" fn SwitchToThread() -> BOOL {
    crate::ke::scheduler::yield_();
    TRUE
}

/// `GetThreadPriority` / `SetThreadPriority` — accept the call.
pub unsafe extern "C" fn GetThreadPriority(_thread: HANDLE) -> i32 { 0 }
pub unsafe extern "C" fn SetThreadPriority(_thread: HANDLE, _priority: i32) -> BOOL { TRUE }

/// `GetThreadTimes`.
#[repr(C)]
#[derive(Default)]
pub struct FileTime {
    pub low: u32,
    pub high: u32,
}

pub unsafe extern "C" fn GetThreadTimes(
    _thread: HANDLE,
    creation: *mut FileTime,
    exit: *mut FileTime,
    kernel: *mut FileTime,
    user: *mut FileTime,
) -> BOOL {
    if !creation.is_null() { *creation = FileTime::default(); }
    if !exit.is_null() { *exit = FileTime::default(); }
    if !kernel.is_null() { *kernel = FileTime::default(); }
    if !user.is_null() { *user = FileTime::default(); }
    TRUE
}
