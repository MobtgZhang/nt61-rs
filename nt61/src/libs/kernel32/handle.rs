//! kernel32 — handle management
//
//! `close_handle`, `duplicate_handle`, `is_valid_handle`,
//! `get_handle_information`, `set_handle_information`. Wraps
//! `ntdll!NT_CLOSE` with a slight layer that ignores
//! `HANDLE_CURRENT_PROCESS` / `HANDLE_CURRENT_THREAD`
//! (the pseudo-handles).

use super::types::{
    BOOL, DWORD, FALSE, HANDLE, HANDLE_CURRENT_PROCESS, HANDLE_CURRENT_THREAD, TRUE,
};
use crate::libs::ntdll::file::nt_close;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `close_handle`.
pub unsafe extern "C" fn close_handle(handle: HANDLE) -> BOOL {
    if handle == HANDLE_CURRENT_PROCESS || handle == HANDLE_CURRENT_THREAD {
        return TRUE;
    }
    if nt_close(handle) == 0 {
        TRUE
    } else {
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `duplicate_handle` — the bootstrap always fails this
/// because we do not own a real handle table.
pub unsafe extern "C" fn duplicate_handle(
    _source_process: HANDLE,
    _source: HANDLE,
    _target_process: HANDLE,
    target: *mut HANDLE,
    _desired_access: DWORD,
    _inherit: i32,
    _options: DWORD,
) -> BOOL {
    if !target.is_null() {
        *target = core::ptr::null_mut();
    }
    FALSE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `is_valid_handle` — true if the handle is non-null and
/// not a pseudo-handle.
pub unsafe extern "C" fn is_valid_handle(handle: HANDLE) -> BOOL {
    if handle.is_null() {
        return FALSE;
    }
    if handle == HANDLE_CURRENT_PROCESS || handle == HANDLE_CURRENT_THREAD {
        return TRUE;
    }
    1
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `get_handle_information` / `set_handle_information` — accept
/// the call and return TRUE.
pub unsafe extern "C" fn get_handle_information(_handle: HANDLE, flags: *mut DWORD) -> BOOL {
    if !flags.is_null() {
        *flags = 0;
    }
    TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn set_handle_information(
    _handle: HANDLE,
    _mask: DWORD,
    _flags: DWORD,
) -> BOOL {
    TRUE
}
