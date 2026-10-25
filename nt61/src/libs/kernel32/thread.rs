//! kernel32 — thread management
//
//! `create_thread`, `get_current_thread`, `get_current_thread_id`,
//! `exit_thread`, `terminate_thread`, `get_thread_id`,
//! `sleep`, `sleep_ex`, `switch_to_thread`, `resume_thread`,
//! `suspend_thread`.

use super::error::set_last_error;
use super::types::{BOOL, DWORD, FALSE, HANDLE, HANDLE_CURRENT_THREAD, TRUE};
use crate::libs::ntdll::types::PVOID;
use crate::libs::ntdll::status::STATUS_SUCCESS;
use crate::libs::ntdll::thread as ntdll_thread;
use core::ptr;

/// `create_thread`.
pub unsafe extern "C" fn create_thread(
    _security: *const u8,
    stack_size: usize,
    start_routine: extern "C" fn(*mut u8) -> u32,
    parameter: *mut u8,
    creation_flags: DWORD,
    thread_id: *mut DWORD,
) -> HANDLE {
    let _ = creation_flags;
    let mut h: HANDLE = ptr::null_mut();
    let mut oa = crate::libs::ntdll::types::ObjectAttributes::new();
    let status = ntdll_thread::nt_create_thread(
        &mut h,
        0,
        &mut oa,
        ptr::null_mut(),
        ptr::null_mut(),
        parameter as PVOID,
        start_routine as PVOID,
        stack_size,
        stack_size,
    );
    if status != STATUS_SUCCESS {
        set_last_error(8);
        return ptr::null_mut();
    }
    if !thread_id.is_null() {
        *thread_id = crate::ps::process::PID_SYSTEM.wrapping_add(1) as u32;
    }
    h
}

/// `get_current_thread` / `get_current_thread_id` / `get_thread_id`.
pub extern "C" fn get_current_thread() -> HANDLE {
    HANDLE_CURRENT_THREAD
}
pub extern "C" fn get_current_thread_id() -> DWORD {
    crate::ps::process::PID_SYSTEM.wrapping_add(1) as u32
}
pub extern "C" fn get_thread_id(thread: HANDLE) -> DWORD {
    if thread.is_null() {
        return 0;
    }
    crate::ps::process::PID_SYSTEM.wrapping_add(1) as u32
}

/// `exit_thread` — terminate the current thread.
pub unsafe extern "C" fn exit_thread(exit_code: DWORD) -> ! {
    ntdll_thread::nt_terminate_thread(HANDLE_CURRENT_THREAD, exit_code);
    loop {
        core::hint::spin_loop();
    }
}

/// `terminate_thread`.
pub unsafe extern "C" fn terminate_thread(thread: HANDLE, exit_code: DWORD) -> BOOL {
    if ntdll_thread::nt_terminate_thread(thread, exit_code) == STATUS_SUCCESS {
        TRUE
    } else {
        set_last_error(6);
        FALSE
    }
}

/// `suspend_thread` / `resume_thread`.
pub unsafe extern "C" fn suspend_thread(thread: HANDLE) -> DWORD {
    let mut prev = 0u32;
    if ntdll_thread::nt_suspend_thread(thread, &mut prev) != STATUS_SUCCESS {
        set_last_error(6);
        return -1i32 as u32;
    }
    prev
}
pub unsafe extern "C" fn resume_thread(thread: HANDLE) -> DWORD {
    let mut prev = 0u32;
    if ntdll_thread::nt_resume_thread(thread, &mut prev) != STATUS_SUCCESS {
        set_last_error(6);
        return -1i32 as u32;
    }
    prev
}

/// `sleep` — forward to ntdll. The bootstrap ignores the
/// actual delay.
pub extern "C" fn sleep(milliseconds: DWORD) {
    let interval: i64 = -(milliseconds as i64) * 10_000;
    let _ = crate::libs::ntdll::sync::nt_delay_execution_kernel(0, interval);
}

/// `sleep_ex` — same.
pub extern "C" fn sleep_ex(milliseconds: DWORD, _alertable: BOOL) -> DWORD {
    sleep(milliseconds);
    0
}

/// `switch_to_thread` — yield to the scheduler.
pub extern "C" fn switch_to_thread() -> BOOL {
    crate::ke::scheduler::yield_();
    TRUE
}

/// `get_thread_priority` / `set_thread_priority` — accept the call.
pub unsafe extern "C" fn get_thread_priority(thread: HANDLE) -> i32 {
    if thread.is_null() {
        return 0;
    }
    let ethread = thread as *mut crate::ps::thread::Ethread;
    (*ethread).kthread.base_priority as i32
}
pub unsafe extern "C" fn set_thread_priority(thread: HANDLE, priority: i32) -> BOOL {
    if thread.is_null() {
        return FALSE;
    }
    let ethread = thread as *mut crate::ps::thread::Ethread;
    // Store the priority on the Kthread so `get_thread_priority`
    // can return the caller's value.
    (*ethread).kthread.base_priority = priority as i8;
    TRUE
}

/// `get_thread_times`.
#[repr(C)]
#[derive(Default)]
pub struct FileTime {
    pub low: u32,
    pub high: u32,
}

pub unsafe extern "C" fn get_thread_times(
    _thread: HANDLE,
    creation: *mut FileTime,
    exit: *mut FileTime,
    kernel: *mut FileTime,
    user: *mut FileTime,
) -> BOOL {
    if !creation.is_null() {
        *creation = FileTime::default();
    }
    if !exit.is_null() {
        *exit = FileTime::default();
    }
    if !kernel.is_null() {
        *kernel = FileTime::default();
    }
    if !user.is_null() {
        *user = FileTime::default();
    }
    TRUE
}
