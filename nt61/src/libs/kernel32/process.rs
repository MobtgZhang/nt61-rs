//! kernel32 — process management
//
//! `CreateProcessW`, `ExitProcess`, `TerminateProcess`,
//! `GetCurrentProcess`, `GetCurrentProcessId`,
//! `GetExitCodeProcess`, `WaitForSingleObject`,
//! `GetProcessId`.

extern crate alloc;

use super::error::SetLastError;
use super::types::{BOOL, DWORD, FALSE, HANDLE, HANDLE_CURRENT_PROCESS, LPSTR, TRUE};
use crate::libs::ntdll::process as ntdll_process;
use crate::libs::ntdll::status::{STATUS_SUCCESS};
use crate::libs::ntdll::sync as ntdll_sync;
use crate::libs::ntdll::types::{ClientId, ObjectAttributes};
use alloc::string::String;
use core::ptr;

pub mod creation {
    pub const DEBUG_PROCESS: u32 = 0x0000_0001;
    pub const DEBUG_ONLY_THIS_PROCESS: u32 = 0x0000_0002;
    pub const CREATE_SUSPENDED: u32 = 0x0000_0004;
    pub const DETACHED_PROCESS: u32 = 0x0000_0008;
    pub const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    pub const CREATE_SEPARATE_WOW_VDM: u32 = 0x0000_0800;
    pub const CREATE_SHARED_WOW_VDM: u32 = 0x0000_1000;
    pub const CREATE_FORCEDOS: u32 = 0x0000_2000;
    pub const CREATE_IGNORE_SYSTEM_DEFAULT: u32 = 0x8000_0000;
    pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    pub const CREATE_DEFAULT_ERROR_MODE: u32 = 0x0400_0000;
    pub const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
}

/// `STARTUPINFO` (subset).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StartupInfoW {
    pub cb: DWORD,
    pub lp_reserved: LPSTR,
    pub lp_desktop: LPSTR,
    pub lp_title: LPSTR,
    pub dw_x: DWORD,
    pub dw_y: DWORD,
    pub dw_x_size: DWORD,
    pub dw_y_size: DWORD,
    pub dw_x_count_chars: DWORD,
    pub dw_y_count_chars: DWORD,
    pub dw_fill_attribute: DWORD,
    pub dw_flags: DWORD,
    pub w_show_window: u16,
    pub cb_reserved2: u16,
    pub lp_reserved2: *mut u8,
    pub h_std_input: HANDLE,
    pub h_std_output: HANDLE,
    pub h_std_error: HANDLE,
}

impl Default for StartupInfoW {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// `PROCESS_INFORMATION`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcessInformation {
    pub h_process: HANDLE,
    pub h_thread: HANDLE,
    pub dw_process_id: DWORD,
    pub dw_thread_id: DWORD,
}

unsafe fn wide_to_string(p: *const u16) -> Option<String> {
    if p.is_null() { return None; }
    let mut len = 0;
    while *p.add(len) != 0 { len += 1; }
    let slice = core::slice::from_raw_parts(p, len);
    let mut out = String::new();
    for &c in slice {
        if let Some(ch) = char::from_u32(c as u32) { out.push(ch); }
    }
    Some(out)
}

/// `CreateProcessW`.
pub unsafe extern "C" fn CreateProcessW(
    application_name: *const u16,
    command_line: *mut u16,
    _process_attrs: *const u8,
    _thread_attrs: *const u8,
    inherit_handles: BOOL,
    creation_flags: DWORD,
    _environment: *const u16,
    _current_directory: *const u16,
    startup_info: *const StartupInfoW,
    process_info: *mut ProcessInformation,
) -> BOOL {
    let name_ptr = if application_name.is_null() { command_line } else { application_name };
    if name_ptr.is_null() { SetLastError(87); return FALSE; }
    let _name = match wide_to_string(name_ptr) {
        Some(s) => s,
        None => { SetLastError(123); return FALSE; },
    };
    let _ = (inherit_handles, creation_flags, startup_info);
    let mut h: HANDLE = ptr::null_mut();
    let mut oa = ObjectAttributes::new();
    let status = ntdll_process::NtCreateProcess(
        &mut h, 0, &mut oa, ptr::null_mut(), 0,
        ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
    );
    if status != STATUS_SUCCESS {
        SetLastError(50);
        return FALSE;
    }
    if !process_info.is_null() {
        (*process_info).h_process = h;
        (*process_info).h_thread = ptr::null_mut();
        (*process_info).dw_process_id = crate::ps::process::PID_SYSTEM as u32;
        (*process_info).dw_thread_id = 0;
    }
    TRUE
}

/// `ExitProcess` — terminate the current process with the
/// supplied exit code.
pub unsafe extern "C" fn ExitProcess(exit_code: u32) -> ! {
    ntdll_process::NtTerminateProcess(HANDLE_CURRENT_PROCESS, exit_code as i32);
    loop { core::hint::spin_loop(); }
}

/// `TerminateProcess`.
pub unsafe extern "C" fn TerminateProcess(process: HANDLE, exit_code: u32) -> BOOL {
    if ntdll_process::NtTerminateProcess(process, exit_code as i32) == STATUS_SUCCESS {
        TRUE
    } else { SetLastError(6); FALSE }
}

/// `GetCurrentProcess` / `GetCurrentProcessId`.
pub extern "C" fn GetCurrentProcess() -> HANDLE { HANDLE_CURRENT_PROCESS }
pub extern "C" fn GetCurrentProcessId() -> DWORD { crate::ps::process::PID_SYSTEM as u32 }
pub extern "C" fn GetProcessId(process: HANDLE) -> DWORD {
    if process.is_null() { return 0; }
    crate::ps::process::PID_SYSTEM as u32
}

/// `GetExitCodeProcess` — we always report `STILL_ACTIVE`.
pub unsafe extern "C" fn GetExitCodeProcess(_process: HANDLE, exit_code: *mut DWORD) -> BOOL {
    if exit_code.is_null() { SetLastError(87); return FALSE; }
    *exit_code = 259; // STILL_ACTIVE
    TRUE
}

/// `OpenProcess`.
pub unsafe extern "C" fn OpenProcess(
    _desired_access: DWORD,
    _inherit_handle: BOOL,
    process_id: DWORD,
) -> HANDLE {
    if process_id == 0 { SetLastError(87); return ptr::null_mut(); }
    let mut h: HANDLE = ptr::null_mut();
    let mut oa = ObjectAttributes::new();
    let mut cid = ClientId::new();
    cid.unique_process = process_id as HANDLE;
    let status = ntdll_process::NtOpenProcess(&mut h, 0, &mut oa, &mut cid);
    if status != STATUS_SUCCESS {
        SetLastError(87);
        return ptr::null_mut();
    }
    h
}

/// `WaitForSingleObject` re-exported for process wait.
///
/// `ms` is part of the Win32 ABI but the stub does not sleep
/// (it just round-trips to `NtWaitForSingleObject`). The
/// parameter is left in the signature for ABI compatibility;
/// the next phase will plumb it into the kernel scheduler.
pub unsafe extern "C" fn WaitForSingleObject(handle: HANDLE, #[allow(unused_variables)] ms: DWORD) -> DWORD {
    if handle.is_null() { SetLastError(6); return 0xFFFF_FFFF; }
    let status = ntdll_sync::NtWaitForSingleObject(handle, 0, ptr::null_mut());
    if status == STATUS_SUCCESS { 0 } else { 0xFFFF_FFFF }
}
