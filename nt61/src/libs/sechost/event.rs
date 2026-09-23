//! sechost.dll — Event Logging Operations
//
//! Event logging functions moved from advapi32 to sechost in Windows 7.
//! These functions forward to the Event Log service (eventlog.dll).
//
//! References:
//!   * Microsoft Windows 7 SDK winbase.h
//!   * Windows Internals 6th Edition, Chapter 10
//!   * ReactOS 0.3.x winbase.h

#![allow(non_snake_case, dead_code)]

use super::types::*;
use crate::libs::kernel32::types::{DWORD, BOOL, HANDLE, WORD, TRUE, FALSE, LPCWSTR, LPVOID};
use crate::libs::ntdll::types::{PVOID, NTSTATUS};
use core::ptr;

const MAX_EVENT_STRINGS: usize = 256;

#[derive(Copy, Clone)]
struct EventLogHandle {
    source_name: [u16; 256],
    server_name: [u16; 256],
    is_valid: bool,
}

static EVENT_LOG_HANDLES: Lazy<Mutex<[EventLogHandle; 32]>> = Lazy::new(|| Mutex::new([
    EventLogHandle {
        source_name: [0; 256],
        server_name: [0; 256],
        is_valid: false,
    }; 32
]));

#[no_mangle]
pub unsafe extern "C" fn RegisterEventSourceW(
    lpUNCServerName: LPCWSTR,
    lpSourceName: LPCWSTR,
) -> EVENT_SOURCE_HANDLE {
    if lpSourceName.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return ptr::null_mut();
    }

    for i in 0..EVENT_LOG_HANDLES.len() {
        if !EVENT_LOG_HANDLES[i].is_valid {
            let mut src_ptr = lpSourceName;
            let mut j = 0;
            while j < 255 && !src_ptr.is_null() && *src_ptr != 0 {
                EVENT_LOG_HANDLES[i].source_name[j] = *src_ptr;
                src_ptr = src_ptr.add(1);
                j += 1;
            }
            EVENT_LOG_HANDLES[i].source_name[j] = 0;

            if !lpUNCServerName.is_null() {
                let mut srv_ptr = lpUNCServerName;
                let mut k = 0;
                while k < 255 && !srv_ptr.is_null() && *srv_ptr != 0 {
                    EVENT_LOG_HANDLES[i].server_name[k] = *srv_ptr;
                    srv_ptr = srv_ptr.add(1);
                    k += 1;
                }
                EVENT_LOG_HANDLES[i].server_name[k] = 0;
            }

            EVENT_LOG_HANDLES[i].is_valid = true;

            return (i + 1) as EVENT_SOURCE_HANDLE;
        }
    }

    crate::libs::kernel32::error::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn DeregisterEventSource(hEventLog: EVENT_SOURCE_HANDLE) -> BOOL {
    if hEventLog.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    let index = (hEventLog as usize).wrapping_sub(1);
    if index >= EVENT_LOG_HANDLES.len() || !EVENT_LOG_HANDLES[index].is_valid {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    EVENT_LOG_HANDLES[index].is_valid = false;
    EVENT_LOG_HANDLES[index].source_name[0] = 0;
    EVENT_LOG_HANDLES[index].server_name[0] = 0;

    TRUE
}

#[no_mangle]
pub unsafe extern "C" fn ReportEventW(
    hEventLog: EVENT_SOURCE_HANDLE,
    wType: WORD,
    wCategory: WORD,
    dwEventID: DWORD,
    lpUserSid: PSID,
    wNumStrings: WORD,
    dwDataSize: DWORD,
    lpStrings: *const LPCWSTR,
    lpRawData: LPVOID,
) -> BOOL {
    if hEventLog.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    let index = (hEventLog as usize).wrapping_sub(1);
    if index >= EVENT_LOG_HANDLES.len() || !EVENT_LOG_HANDLES[index].is_valid {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    match wType {
        EVENTLOG_SUCCESS |
        EVENTLOG_ERROR_TYPE |
        EVENTLOG_WARNING_TYPE |
        EVENTLOG_INFORMATION_TYPE |
        EVENTLOG_AUDIT_SUCCESS |
        EVENTLOG_AUDIT_FAILURE => {}
        _ => {
            crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }

    if wNumStrings > MAX_EVENT_STRINGS as u16 {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if wNumStrings > 0 && lpStrings.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    TRUE
}

#[no_mangle]
pub unsafe extern "C" fn ClearEventLogW(
    hEventLog: HANDLE,
    lpBackupFileName: LPCWSTR,
) -> BOOL {
    if hEventLog.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if !lpBackupFileName.is_null() {
    }

    TRUE
}

#[no_mangle]
pub unsafe extern "C" fn OpenEventLogW(
    lpUNCServerName: LPCWSTR,
    lpSourceName: LPCWSTR,
) -> HANDLE {
    if lpSourceName.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return ptr::null_mut();
    }

    // For stub, reuse RegisterEventSourceW logic
    RegisterEventSourceW(lpUNCServerName, lpSourceName) as HANDLE
}

#[no_mangle]
pub unsafe extern "C" fn CloseEventLog(hEventLog: HANDLE) -> BOOL {
    DeregisterEventSource(hEventLog as EVENT_SOURCE_HANDLE)
}

pub fn init() {
}
