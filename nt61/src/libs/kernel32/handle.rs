//! kernel32 — handle management
//
//! `CloseHandle`, `DuplicateHandle`, `IsValidHandle`,
//! `GetHandleInformation`, `SetHandleInformation`. Wraps
//! `ntdll!NtClose` with a slight layer that ignores
//! `HANDLE_CURRENT_PROCESS` / `HANDLE_CURRENT_THREAD`
//! (the pseudo-handles).

use super::types::{BOOL, DWORD, FALSE, HANDLE, HANDLE_CURRENT_PROCESS, HANDLE_CURRENT_THREAD, TRUE};
use crate::libs::ntdll::file::NtClose;

/// `CloseHandle`.
pub unsafe extern "C" fn CloseHandle(handle: HANDLE) -> BOOL {
    if handle == HANDLE_CURRENT_PROCESS || handle == HANDLE_CURRENT_THREAD {
        return TRUE;
    }
    if NtClose(handle) == 0 { TRUE } else { FALSE }
}

/// `DuplicateHandle` — the bootstrap always fails this
/// because we do not own a real handle table.
pub unsafe extern "C" fn DuplicateHandle(
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

/// `IsValidHandle` — true if the handle is non-null and
/// not a pseudo-handle.
pub unsafe extern "C" fn IsValidHandle(handle: HANDLE) -> BOOL {
    if handle.is_null() { return FALSE; }
    if handle == HANDLE_CURRENT_PROCESS || handle == HANDLE_CURRENT_THREAD { return TRUE; }
    1
}

/// `GetHandleInformation` / `SetHandleInformation` — accept
/// the call and return TRUE.
pub unsafe extern "C" fn GetHandleInformation(_handle: HANDLE, flags: *mut DWORD) -> BOOL {
    if !flags.is_null() { *flags = 0; }
    TRUE
}

pub unsafe extern "C" fn SetHandleInformation(_handle: HANDLE, _mask: DWORD, _flags: DWORD) -> BOOL {
    TRUE
}
