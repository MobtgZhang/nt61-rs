//! sechost.dll — Service Control Operations
//
//! Service control functions moved from advapi32 to sechost in Windows 7.
//! These functions manage service configuration and status.
//
//! References:
//!   * Microsoft Windows 7 SDK winsvc.h
//!   * Windows Internals 6th Edition, Chapter 4
//!   * ReactOS 0.3.x winsvc.h

#![allow(non_snake_case, dead_code)]

use super::types::*;
use crate::libs::kernel32::types::{DWORD, BOOL, HANDLE, BYTE, TRUE, FALSE, LPVOID};
use crate::libs::ntdll::types::{PVOID, NTSTATUS};


pub type SC_HANDLE = HANDLE;

#[no_mangle]
pub unsafe extern "C" fn ChangeServiceConfig2W(
    hService: SC_HANDLE,
    dwInfoLevel: DWORD,
    lpInfo: LPVOID,
) -> BOOL {
    if hService.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if lpInfo.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    match dwInfoLevel {
        SERVICE_CONFIG_DESCRIPTION => {
            let desc = &*(lpInfo as *const SERVICE_DESCRIPTIONW);
            TRUE
        }
        SERVICE_CONFIG_FAILURE_ACTIONS => {
            TRUE
        }
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO => {
            let info = &*(lpInfo as *const SERVICE_DELAYED_AUTO_START_INFO);
            TRUE
        }
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG |
        SERVICE_CONFIG_SERVICE_SID_INFO |
        SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO |
        SERVICE_CONFIG_PRESHUTDOWN_INFO |
        SERVICE_CONFIG_TRIGGER_INFO |
        SERVICE_CONFIG_PREFERRED_NODE => {
            TRUE
        }
        _ => {
            crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
            FALSE
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn QueryServiceConfig2W(
    hService: SC_HANDLE,
    dwInfoLevel: DWORD,
    lpBuffer: *mut BYTE,
    cbBufSize: DWORD,
    pcbBytesNeeded: *mut DWORD,
) -> BOOL {
    if hService.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if pcbBytesNeeded.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    match dwInfoLevel {
        SERVICE_CONFIG_DESCRIPTION => {
            let required_size = core::mem::size_of::<SERVICE_DESCRIPTIONW>() as DWORD;
            *pcbBytesNeeded = required_size;

            if cbBufSize < required_size || lpBuffer.is_null() {
                crate::libs::kernel32::error::SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }

            let desc = &mut *(lpBuffer as *mut SERVICE_DESCRIPTIONW);
            desc.lpDescription = core::ptr::null_mut();
            TRUE
        }
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO => {
            let required_size = core::mem::size_of::<SERVICE_DELAYED_AUTO_START_INFO>() as DWORD;
            *pcbBytesNeeded = required_size;

            if cbBufSize < required_size || lpBuffer.is_null() {
                crate::libs::kernel32::error::SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }

            let info = &mut *(lpBuffer as *mut SERVICE_DELAYED_AUTO_START_INFO);
            info.fDelayedAutostart = FALSE;
            TRUE
        }
        SERVICE_CONFIG_FAILURE_ACTIONS |
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG |
        SERVICE_CONFIG_SERVICE_SID_INFO |
        SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO |
        SERVICE_CONFIG_PRESHUTDOWN_INFO |
        SERVICE_CONFIG_TRIGGER_INFO |
        SERVICE_CONFIG_PREFERRED_NODE => {
            *pcbBytesNeeded = 16;
            if cbBufSize < 16 || lpBuffer.is_null() {
                crate::libs::kernel32::error::SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }
            TRUE
        }
        _ => {
            crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
            FALSE
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn QueryServiceStatusEx(
    hService: SC_HANDLE,
    InfoLevel: DWORD,
    lpBuffer: *mut BYTE,
    cbBufSize: DWORD,
    pcbBytesNeeded: *mut DWORD,
) -> BOOL {
    if hService.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if pcbBytesNeeded.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if InfoLevel != SC_ENUM_PROCESS_INFO {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    let required_size = core::mem::size_of::<SERVICE_STATUS_PROCESS>() as DWORD;
    *pcbBytesNeeded = required_size;

    if cbBufSize < required_size || lpBuffer.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    let status = &mut *(lpBuffer as *mut SERVICE_STATUS_PROCESS);
    status.dwServiceType = 0x10; // SERVICE_WIN32_OWN_PROCESS
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_CONTROL_STOP | SERVICE_CONTROL_PAUSE_CONTINUE;
    status.dwWin32ExitCode = 0;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    status.dwProcessId = 0; // Stub - no real process
    status.dwServiceFlags = 0;

    TRUE
}

#[no_mangle]
pub unsafe extern "C" fn ControlServiceEx(
    hService: SC_HANDLE,
    dwControl: DWORD,
    dwInfoLevel: DWORD,
    pControlParams: PVOID,
) -> BOOL {
    if hService.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    match dwControl {
        SERVICE_CONTROL_STOP |
        SERVICE_CONTROL_PAUSE |
        SERVICE_CONTROL_CONTINUE |
        SERVICE_CONTROL_INTERROGATE |
        SERVICE_CONTROL_SHUTDOWN => {
            TRUE
        }
        SERVICE_CONTROL_PARAMCHANGE |
        SERVICE_CONTROL_NETBINDADD |
        SERVICE_CONTROL_NETBINDREMOVE |
        SERVICE_CONTROL_NETBINDENABLE |
        SERVICE_CONTROL_NETBINDDISABLE => {
            TRUE
        }
        0x00000080..=0x000000FF => {
            TRUE
        }
        _ => {
            crate::libs::kernel32::error::SetLastError(ERROR_INVALID_SERVICE_CONTROL);
            FALSE
        }
    }
}

pub fn init() {
}
