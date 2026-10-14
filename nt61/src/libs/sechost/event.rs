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
use crate::libs::kernel32::types::{BOOL, DWORD, FALSE, HANDLE, LPCWSTR, LPVOID, TRUE, WORD};
use crate::libs::ntdll::types::{NTSTATUS, PVOID};
use core::ptr;
use spin::{Lazy, Mutex};

const MAX_EVENT_STRINGS: usize = 256;

#[derive(Copy, Clone)]
struct EventLogHandle {
    source_name: [u16; 256],
    server_name: [u16; 256],
    is_valid: bool,
}

static EVENT_LOG_HANDLES: Lazy<Mutex<[EventLogHandle; 32]>> = Lazy::new(|| {
    Mutex::new(
        [EventLogHandle {
            source_name: [0; 256],
            server_name: [0; 256],
            is_valid: false,
        }; 32],
    )
});

#[no_mangle]
pub unsafe extern "C" fn RegisterEventSourceW(
    lpUNCServerName: LPCWSTR,
    lpSourceName: LPCWSTR,
) -> EVENT_SOURCE_HANDLE {
    if lpSourceName.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return ptr::null_mut();
    }

    let mut handles = EVENT_LOG_HANDLES.lock();
    for i in 0..handles.len() {
        if !handles[i].is_valid {
            let mut src_ptr = lpSourceName;
            let mut j = 0;
            while j < 255 && !src_ptr.is_null() && *src_ptr != 0 {
                handles[i].source_name[j] = *src_ptr;
                src_ptr = src_ptr.add(1);
                j += 1;
            }
            handles[i].source_name[j] = 0;

            if !lpUNCServerName.is_null() {
                let mut srv_ptr = lpUNCServerName;
                let mut k = 0;
                while k < 255 && !srv_ptr.is_null() && *srv_ptr != 0 {
                    handles[i].server_name[k] = *srv_ptr;
                    srv_ptr = srv_ptr.add(1);
                    k += 1;
                }
                handles[i].server_name[k] = 0;
            }

            handles[i].is_valid = true;

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
    let mut handles = EVENT_LOG_HANDLES.lock();
    if index >= handles.len() || !handles[index].is_valid {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    handles[index].is_valid = false;
    handles[index].source_name[0] = 0;
    handles[index].server_name[0] = 0;

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
    let handles = EVENT_LOG_HANDLES.lock();
    if index >= handles.len() || !handles[index].is_valid {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    match wType {
        EVENTLOG_SUCCESS
        | EVENTLOG_ERROR_TYPE
        | EVENTLOG_WARNING_TYPE
        | EVENTLOG_INFORMATION_TYPE
        | EVENTLOG_AUDIT_SUCCESS
        | EVENTLOG_AUDIT_FAILURE => {}
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

    let level = match wType {
        EVENTLOG_ERROR_TYPE => crate::rtl::eventlog::EventLevel::Error,
        EVENTLOG_WARNING_TYPE | EVENTLOG_AUDIT_FAILURE => crate::rtl::eventlog::EventLevel::Warning,
        _ => crate::rtl::eventlog::EventLevel::Information,
    };

    let mut desc = alloc::string::String::new();
    for i in 0..wNumStrings as usize {
        let slot = lpStrings.add(i);
        if slot.is_null() {
            continue;
        }
        let mut p = *slot;
        while !p.is_null() && *p != 0 {
            desc.push(char::from_u32(*p as u32).unwrap_or('\u{FFFD}'));
            p = p.add(1);
        }
        if i + 1 < wNumStrings as usize {
            desc.push(' ');
        }
    }

    let mut source = alloc::string::String::new();
    for &c in &handles[index].source_name {
        if c == 0 {
            break;
        }
        source.push(char::from_u32(c as u32).unwrap_or('\u{FFFD}'));
    }

    // Audit events belong to the Security channel; everything a normal
    // event source reports goes to the Application channel.
    if matches!(wType, EVENTLOG_AUDIT_SUCCESS | EVENTLOG_AUDIT_FAILURE) {
        crate::rtl::eventlog::write_security_event(
            dwEventID as u16,
            level,
            source.as_bytes(),
            &desc,
        );
    } else {
        crate::rtl::eventlog::write_application_event(
            dwEventID as u16,
            level,
            source.as_bytes(),
            &desc,
        );
    }

    TRUE
}

#[no_mangle]
pub unsafe extern "C" fn ClearEventLogW(hEventLog: HANDLE, lpBackupFileName: LPCWSTR) -> BOOL {
    if hEventLog.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if !lpBackupFileName.is_null() {}

    // A source registered through `RegisterEventSourceW` reports to the
    // Application channel; audit sources report to the Security channel.
    let index = (hEventLog as usize).wrapping_sub(1);
    let channel = {
        let handles = EVENT_LOG_HANDLES.lock();
        if index >= handles.len() || !handles[index].is_valid {
            crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        crate::rtl::eventlog::EventChannel::Application
    };
    if !crate::rtl::eventlog::clear_channel(channel) {
        crate::libs::kernel32::error::SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    TRUE
}

#[no_mangle]
pub unsafe extern "C" fn OpenEventLogW(lpUNCServerName: LPCWSTR, lpSourceName: LPCWSTR) -> HANDLE {
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

pub fn init() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_event_writes_to_the_application_channel() {
        crate::rtl::eventlog::init();

        static SOURCE: [u16; 11] = [
            b'T' as u16,
            b'S' as u16,
            b'e' as u16,
            b'c' as u16,
            b'h' as u16,
            b'o' as u16,
            b's' as u16,
            b't' as u16,
            0,
            0,
            0,
        ];
        static DESC: [u16; 4] = [b'h' as u16, b'i' as u16, 0, 0];
        let strings: [LPCWSTR; 1] = [&DESC as *const u16];

        let handle = unsafe { RegisterEventSourceW(core::ptr::null(), &SOURCE as *const u16) };
        assert!(!handle.is_null());

        let before = crate::rtl::eventlog::application_log_count();
        unsafe {
            assert_eq!(
                ReportEventW(
                    handle,
                    EVENTLOG_INFORMATION_TYPE,
                    0,
                    1000,
                    core::ptr::null_mut(),
                    1,
                    0,
                    strings.as_ptr(),
                    core::ptr::null_mut(),
                ),
                TRUE,
            );
        }
        assert_eq!(crate::rtl::eventlog::application_log_count(), before + 1);

        unsafe {
            assert_eq!(ClearEventLogW(handle, core::ptr::null()), TRUE);
        }
        assert_eq!(crate::rtl::eventlog::application_log_count(), 0);

        unsafe {
            assert_eq!(DeregisterEventSource(handle), TRUE);
            // The handle is no longer registered, so reporting must fail rather
            // than write to a stale slot.
            assert_eq!(
                ReportEventW(
                    handle,
                    EVENTLOG_INFORMATION_TYPE,
                    0,
                    1000,
                    core::ptr::null_mut(),
                    0,
                    0,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                ),
                FALSE,
            );
        }
    }

    #[test]
    fn audit_events_go_to_the_security_channel() {
        crate::rtl::eventlog::init();

        static SOURCE: [u16; 7] = [
            b'A' as u16,
            b'u' as u16,
            b'd' as u16,
            b'i' as u16,
            b't' as u16,
            0,
            0,
        ];
        let handle = unsafe { RegisterEventSourceW(core::ptr::null(), &SOURCE as *const u16) };
        assert!(!handle.is_null());

        let before = crate::rtl::eventlog::security_log_count();
        unsafe {
            assert_eq!(
                ReportEventW(
                    handle,
                    EVENTLOG_AUDIT_FAILURE,
                    0,
                    4634,
                    core::ptr::null_mut(),
                    0,
                    0,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                ),
                TRUE,
            );
        }
        assert_eq!(crate::rtl::eventlog::security_log_count(), before + 1);
        assert_eq!(crate::rtl::eventlog::application_log_count(), 0);
        unsafe {
            DeregisterEventSource(handle);
        }
    }
}
