//! kernel32 — process management
//
//! `create_process_w`, `exit_process`, `terminate_process`,
//! `get_current_process`, `get_current_process_id`,
//! `get_exit_code_process`, `wait_for_single_object`,
//! `get_process_id`.

extern crate alloc;

use super::error::set_last_error;
use super::types::{BOOL, DWORD, FALSE, HANDLE, HANDLE_CURRENT_PROCESS, LPSTR, TRUE};
use crate::libs::ntdll::process as ntdll_process;
use crate::libs::ntdll::status::STATUS_SUCCESS;
use crate::libs::ntdll::sync as ntdll_sync;
use crate::libs::ntdll::types::{client_id, ObjectAttributes};
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
    if p.is_null() {
        return None;
    }
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(p, len);
    let mut out = String::new();
    for &c in slice {
        if let Some(ch) = char::from_u32(c as u32) {
            out.push(ch);
        }
    }
    Some(out)
}

/// `create_process_w`.
pub unsafe extern "C" fn create_process_w(
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
    let name_ptr = if application_name.is_null() {
        command_line
    } else {
        application_name
    };
    if name_ptr.is_null() {
        set_last_error(87);
        return FALSE;
    }
    let _name = match wide_to_string(name_ptr) {
        Some(s) => s,
        None => {
            set_last_error(123);
            return FALSE;
        }
    };
    let _ = (inherit_handles, creation_flags, startup_info);
    let mut h: HANDLE = ptr::null_mut();
    let name_units = _name.encode_utf16().count() + 1;
    let name_size = name_units * core::mem::size_of::<u16>();
    let storage_size = core::mem::size_of::<ObjectAttributes>()
        + core::mem::size_of::<crate::libs::ntdll::types::UnicodeString>()
        + name_size;
    let storage = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        storage_size,
    );
    if storage.is_null() {
        set_last_error(8);
        return FALSE;
    }
    let oa = storage as *mut ObjectAttributes;
    let name = storage.add(core::mem::size_of::<ObjectAttributes>())
        as *mut crate::libs::ntdll::types::UnicodeString;
    let buffer = storage
        .add(core::mem::size_of::<ObjectAttributes>())
        .add(core::mem::size_of::<crate::libs::ntdll::types::UnicodeString>())
        as *mut u16;
    let mut units = alloc::vec::Vec::with_capacity(name_units);
    units.extend(_name.encode_utf16());
    units.push(0);
    unsafe {
        core::ptr::write_bytes(storage, 0, storage_size);
        core::ptr::copy_nonoverlapping(units.as_ptr(), buffer, units.len());
        (*name).length = (units.len() * 2) as u16;
        (*name).maximum_length = (units.len() * 2) as u16;
        (*name).buffer = buffer;
        core::ptr::write(oa, ObjectAttributes::with_name(name));
    }
    let status = ntdll_process::nt_create_process(
        &mut h,
        0,
        oa,
        ptr::null_mut(),
        0,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    crate::mm::pool::free(storage);
    if status != STATUS_SUCCESS {
        set_last_error(50);
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

/// `exit_process` — terminate the current process with the
/// supplied exit code.
pub unsafe extern "C" fn exit_process(exit_code: u32) -> ! {
    ntdll_process::nt_terminate_process(HANDLE_CURRENT_PROCESS, exit_code as i32);
    loop {
        core::hint::spin_loop();
    }
}

/// `terminate_process`.
pub unsafe extern "C" fn terminate_process(process: HANDLE, exit_code: u32) -> BOOL {
    if ntdll_process::nt_terminate_process(process, exit_code as i32) == STATUS_SUCCESS {
        TRUE
    } else {
        set_last_error(6);
        FALSE
    }
}

/// `get_current_process` / `get_current_process_id`.
pub extern "C" fn get_current_process() -> HANDLE {
    HANDLE_CURRENT_PROCESS
}
pub extern "C" fn get_current_process_id() -> DWORD {
    crate::ps::process::PID_SYSTEM as u32
}
pub extern "C" fn get_process_id(process: HANDLE) -> DWORD {
    if process.is_null() {
        return 0;
    }
    crate::ps::process::PID_SYSTEM as u32
}

/// `get_exit_code_process` — we always report `STILL_ACTIVE`.
pub unsafe extern "C" fn get_exit_code_process(_process: HANDLE, exit_code: *mut DWORD) -> BOOL {
    if exit_code.is_null() {
        set_last_error(87);
        return FALSE;
    }
    *exit_code = 259; // STILL_ACTIVE
    TRUE
}

/// `open_process`.
pub unsafe extern "C" fn open_process(
    _desired_access: DWORD,
    _inherit_handle: BOOL,
    process_id: DWORD,
) -> HANDLE {
    if process_id == 0 {
        set_last_error(87);
        return ptr::null_mut();
    }
    let mut h: HANDLE = ptr::null_mut();
    let mut oa = ObjectAttributes::new();
    let mut cid = client_id::new();
    cid.unique_process = process_id as HANDLE;
    let status = ntdll_process::nt_open_process(&mut h, 0, &mut oa, &mut cid);
    if status != STATUS_SUCCESS {
        set_last_error(87);
        return ptr::null_mut();
    }
    h
}

/// `wait_for_single_object` re-exported for process wait.
///
/// `ms` is part of the Win32 ABI but the stub does not sleep
/// (it just round-trips to `NT_WAIT_FOR_SINGLE_OBJECT`). The
/// parameter is left in the signature for ABI compatibility;
/// the next phase will plumb it into the kernel scheduler.
pub unsafe extern "C" fn wait_for_single_object(handle: HANDLE, _ms: DWORD) -> DWORD {
    if handle.is_null() {
        set_last_error(6);
        return 0xFFFF_FFFF;
    }
    let status = ntdll_sync::nt_wait_for_single_object_kernel(handle, 0, None);
    if status == STATUS_SUCCESS {
        0
    } else {
        0xFFFF_FFFF
    }
}
