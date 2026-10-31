//! sechost.dll — Service control Operations
//
//! Service control functions moved from advapi32 to sechost in Windows 7.
//! These functions manage service configuration and status.
//
//! References:
//!   * Microsoft Windows 7 SDK winsvc.h
//!   * Windows Internals 6th Edition, Chapter 4
//!   * ReactOS 0.3.x winsvc.h

use super::types::*;
use crate::libs::kernel32::types::{BOOL, BYTE, DWORD, FALSE, HANDLE, LPVOID, TRUE};
use crate::libs::ntdll::types::PVOID;

pub type ScHandle = HANDLE;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn ChangeServiceConfig2W(
    h_service: ScHandle,
    dw_info_level: DWORD,
    lp_info: LPVOID,
) -> BOOL {
    if h_service.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if lp_info.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    match dw_info_level {
        SERVICE_CONFIG_DESCRIPTION => {
            let _desc = &*(lp_info as *const SERVICE_DESCRIPTIONW);
            TRUE
        }
        SERVICE_CONFIG_FAILURE_ACTIONS => TRUE,
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO => {
            let _info = &*(lp_info as *const SERVICE_DELAYED_AUTO_START_INFO);
            TRUE
        }
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG
        | SERVICE_CONFIG_SERVICE_SID_INFO
        | SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO
        | SERVICE_CONFIG_PRESHUTDOWN_INFO
        | SERVICE_CONFIG_TRIGGER_INFO
        | SERVICE_CONFIG_PREFERRED_NODE => TRUE,
        _ => {
            crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
            FALSE
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn QueryServiceConfig2W(
    h_service: ScHandle,
    dw_info_level: DWORD,
    lp_buffer: *mut BYTE,
    cb_buf_size: DWORD,
    pcb_bytes_needed: *mut DWORD,
) -> BOOL {
    if h_service.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if pcb_bytes_needed.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    match dw_info_level {
        SERVICE_CONFIG_DESCRIPTION => {
            let required_size = core::mem::size_of::<SERVICE_DESCRIPTIONW>() as DWORD;
            *pcb_bytes_needed = required_size;

            if cb_buf_size < required_size || lp_buffer.is_null() {
                crate::libs::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }

            let desc = &mut *(lp_buffer as *mut SERVICE_DESCRIPTIONW);
            desc.lp_description = core::ptr::null_mut();
            TRUE
        }
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO => {
            let required_size = core::mem::size_of::<SERVICE_DELAYED_AUTO_START_INFO>() as DWORD;
            *pcb_bytes_needed = required_size;

            if cb_buf_size < required_size || lp_buffer.is_null() {
                crate::libs::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }

            let info = &mut *(lp_buffer as *mut SERVICE_DELAYED_AUTO_START_INFO);
            info.f_delayed_autostart = FALSE;
            TRUE
        }
        SERVICE_CONFIG_FAILURE_ACTIONS
        | SERVICE_CONFIG_FAILURE_ACTIONS_FLAG
        | SERVICE_CONFIG_SERVICE_SID_INFO
        | SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO
        | SERVICE_CONFIG_PRESHUTDOWN_INFO
        | SERVICE_CONFIG_TRIGGER_INFO
        | SERVICE_CONFIG_PREFERRED_NODE => {
            *pcb_bytes_needed = 16;
            if cb_buf_size < 16 || lp_buffer.is_null() {
                crate::libs::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }
            TRUE
        }
        _ => {
            crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
            FALSE
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn QueryServiceStatusEx(
    h_service: ScHandle,
    info_level: DWORD,
    lp_buffer: *mut BYTE,
    cb_buf_size: DWORD,
    pcb_bytes_needed: *mut DWORD,
) -> BOOL {
    if h_service.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if pcb_bytes_needed.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if info_level != SC_ENUM_PROCESS_INFO {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    let required_size = core::mem::size_of::<SERVICE_STATUS_PROCESS>() as DWORD;
    *pcb_bytes_needed = required_size;

    if cb_buf_size < required_size || lp_buffer.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    let status = &mut *(lp_buffer as *mut SERVICE_STATUS_PROCESS);
    status.dw_service_type = 0x10; // SERVICE_WIN32_OWN_PROCESS
    status.dw_current_state = SERVICE_RUNNING;
    status.dw_controls_accepted = SERVICE_CONTROL_STOP | SERVICE_CONTROL_PAUSE_CONTINUE;
    status.dw_win32_exit_code = 0;
    status.dw_service_specific_exit_code = 0;
    status.dw_check_point = 0;
    status.dw_wait_hint = 0;
    status.dw_process_id = 0; // Stub - no real process
    status.dw_service_flags = 0;

    TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn ControlServiceEx(
    h_service: ScHandle,
    dw_control: DWORD,
    _dw_info_level: DWORD,
    _p_control_params: PVOID,
) -> BOOL {
    if h_service.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    match dw_control {
        SERVICE_CONTROL_STOP
        | SERVICE_CONTROL_PAUSE
        | SERVICE_CONTROL_CONTINUE
        | SERVICE_CONTROL_INTERROGATE
        | SERVICE_CONTROL_SHUTDOWN => TRUE,
        SERVICE_CONTROL_PARAMCHANGE
        | SERVICE_CONTROL_NETBINDADD
        | SERVICE_CONTROL_NETBINDREMOVE
        | SERVICE_CONTROL_NETBINDENABLE
        | SERVICE_CONTROL_NETBINDDISABLE => TRUE,
        0x00000080..=0x000000FF => TRUE,
        _ => {
            crate::libs::kernel32::error::set_last_error(ERROR_INVALID_SERVICE_CONTROL);
            FALSE
        }
    }
}

pub fn init() {}
