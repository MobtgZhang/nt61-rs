//! advapi32 — Registry API
//
//! Implements the Win32 registry API (RegOpenKeyEx, RegCreateKeyEx,
//! RegQueryValueEx, RegSetValueEx, RegDeleteKey, RegCloseKey, etc.).
//!
//! These functions wrap the native NT registry API (NT_CREATE_KEY,
//! NT_OPEN_KEY, NT_QUERY_VALUE_KEY, NT_SET_VALUE_KEY) exposed by ntdll.

use super::types::{
    is_predefined_key, nt_status_to_win32, KEY_ALL_ACCESS, REG_CREATED_NEW_KEY,
    REG_OPENED_EXISTING_KEY,
};
use super::types::{BYTE, DWORD, FILETIME, HKEY, LONG};
use super::types::{
    ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, ERROR_NOT_ENOUGH_MEMORY,
    ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
};
use crate::libs::ntdll::file::nt_close;
use crate::libs::ntdll::status::{
    STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_NO_MORE_ENTRIES,
};
use crate::libs::ntdll::types::{
    ObjectAttributes, UnicodeString, HANDLE, PCWSTR, PVOID, PWSTR, ULONG,
};
use core::ptr::null_mut;

const MAX_REG_HANDLES: usize = 256;

#[derive(Copy, Clone)]
struct RegHandle {
    nt_handle: HANDLE,
    access: DWORD,
    in_use: bool,
}

static mut REG_HANDLES: [RegHandle; MAX_REG_HANDLES] = [RegHandle {
    nt_handle: null_mut(),
    access: 0,
    in_use: false,
}; MAX_REG_HANDLES];

fn alloc_reg_handle(nt_handle: HANDLE, access: DWORD) -> Option<HKEY> {
    unsafe {
        for (i, entry) in (*core::ptr::addr_of_mut!(REG_HANDLES))
            .iter_mut()
            .enumerate()
        {
            if !entry.in_use {
                entry.nt_handle = nt_handle;
                entry.access = access;
                entry.in_use = true;
                return Some((0x1000 + i * 4) as HKEY);
            }
        }
    }
    None
}

fn free_reg_handle(key: HKEY) -> bool {
    if is_predefined_key(key) {
        return true; // Predefined keys don't need freeing
    }

    let index = ((key as usize) - 0x1000) / 4;
    unsafe {
        if index < MAX_REG_HANDLES && REG_HANDLES[index].in_use {
            REG_HANDLES[index].in_use = false;
            REG_HANDLES[index].nt_handle = null_mut();
            return true;
        }
    }
    false
}

fn get_nt_handle(key: HKEY) -> Option<HANDLE> {
    if is_predefined_key(key) {
        return Some(key); // Pass through to NT layer
    }

    let index = ((key as usize) - 0x1000) / 4;
    unsafe {
        if index < MAX_REG_HANDLES && REG_HANDLES[index].in_use {
            return Some(REG_HANDLES[index].nt_handle);
        }
    }
    None
}

unsafe fn wide_str_to_unicode_string(s: PCWSTR) -> Option<UnicodeString> {
    if s.is_null() {
        return None;
    }

    let mut len = 0;
    let mut p = s;
    while *p != 0 {
        len += 1;
        p = p.offset(1);
    }

    Some(UnicodeString {
        length: (len * 2) as u16,
        maximum_length: ((len + 1) * 2) as u16,
        buffer: s as PWSTR,
    })
}

pub unsafe fn copy_wide_string(dest: PWSTR, src: PCWSTR, max_chars: usize) -> usize {
    let mut count = 0;
    let mut s = src;
    let mut d = dest;

    while count < max_chars - 1 && !s.is_null() && *s != 0 {
        *d = *s;
        s = s.offset(1);
        d = d.offset(1);
        count += 1;
    }

    *d = 0; // Null terminate
    count
}

#[no_mangle]
pub unsafe extern "C" fn RegCreateKeyExW(
    h_key: HKEY,
    lp_sub_key: PCWSTR,
    _reserved: DWORD,
    _lp_class: PWSTR,
    dw_options: DWORD,
    sam_desired: DWORD,
    _lp_security_attributes: PVOID,
    phk_result: *mut HKEY,
    lpdw_disposition: *mut DWORD,
) -> LONG {
    if phk_result.is_null() {
        return ERROR_INVALID_PARAMETER as LONG;
    }

    let base_handle = match get_nt_handle(h_key) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let subkey_unicode = match wide_str_to_unicode_string(lp_sub_key) {
        Some(s) => s,
        None => return ERROR_INVALID_PARAMETER as LONG,
    };

    let mut obj_attr = ObjectAttributes::new();
    obj_attr.root_directory = base_handle;
    obj_attr.object_name = &subkey_unicode as *const _ as *mut _;

    let mut nt_handle: HANDLE = null_mut();
    let mut disposition: ULONG = 0;

    let status = crate::libs::ntdll::registry::nt_create_key(
        &mut nt_handle,
        sam_desired,
        &mut obj_attr,
        0,
        null_mut(),
        dw_options,
        if lpdw_disposition.is_null() {
            null_mut()
        } else {
            &mut disposition
        },
    );

    if status < 0 {
        return nt_status_to_win32(status) as LONG;
    }

    match alloc_reg_handle(nt_handle, sam_desired) {
        Some(handle) => {
            *phk_result = handle;
            if !lpdw_disposition.is_null() {
                *lpdw_disposition = if disposition == 0 {
                    REG_CREATED_NEW_KEY
                } else {
                    REG_OPENED_EXISTING_KEY
                };
            }
            ERROR_SUCCESS as LONG
        }
        None => {
            nt_close(nt_handle);
            ERROR_NOT_ENOUGH_MEMORY as LONG
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegOpenKeyExW(
    h_key: HKEY,
    lp_sub_key: PCWSTR,
    _ul_options: DWORD,
    sam_desired: DWORD,
    phk_result: *mut HKEY,
) -> LONG {
    if phk_result.is_null() {
        return ERROR_INVALID_PARAMETER as LONG;
    }

    if lp_sub_key.is_null() || *lp_sub_key == 0 {
        *phk_result = h_key;
        return ERROR_SUCCESS as LONG;
    }

    let base_handle = match get_nt_handle(h_key) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let subkey_unicode = match wide_str_to_unicode_string(lp_sub_key) {
        Some(s) => s,
        None => return ERROR_INVALID_PARAMETER as LONG,
    };

    let mut obj_attr = ObjectAttributes::new();
    obj_attr.root_directory = base_handle;
    obj_attr.object_name = &subkey_unicode as *const _ as *mut _;

    let mut nt_handle: HANDLE = null_mut();
    let status =
        crate::libs::ntdll::registry::nt_open_key(&mut nt_handle, sam_desired, &mut obj_attr);

    if status < 0 {
        return nt_status_to_win32(status) as LONG;
    }

    match alloc_reg_handle(nt_handle, sam_desired) {
        Some(handle) => {
            *phk_result = handle;
            ERROR_SUCCESS as LONG
        }
        None => {
            nt_close(nt_handle);
            ERROR_NOT_ENOUGH_MEMORY as LONG
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegCloseKey(h_key: HKEY) -> LONG {
    if is_predefined_key(h_key) {
        return ERROR_SUCCESS as LONG;
    }

    match get_nt_handle(h_key) {
        Some(nt_handle) => {
            let status = nt_close(nt_handle);
            free_reg_handle(h_key);
            if status < 0 {
                nt_status_to_win32(status) as LONG
            } else {
                ERROR_SUCCESS as LONG
            }
        }
        None => ERROR_INVALID_HANDLE as LONG,
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegQueryValueExW(
    h_key: HKEY,
    lp_value_name: PCWSTR,
    _lp_reserved: *mut DWORD,
    _lp_type: *mut DWORD,
    lp_data: *mut BYTE,
    lpcb_data: *mut DWORD,
) -> LONG {
    let nt_handle = match get_nt_handle(h_key) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let mut value_unicode = match wide_str_to_unicode_string(lp_value_name) {
        Some(s) => s,
        None => return ERROR_INVALID_PARAMETER as LONG,
    };

    let mut result_length: ULONG = 0;
    let buffer_size = if lpcb_data.is_null() { 0 } else { *lpcb_data };

    let status = crate::libs::ntdll::registry::nt_query_value_key(
        nt_handle,
        &mut value_unicode,
        1, // KeyValuePartialInformation
        lp_data as PVOID,
        buffer_size,
        &mut result_length,
    );

    if !lpcb_data.is_null() {
        *lpcb_data = result_length;
    }

    if status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL {
        return ERROR_MORE_DATA as LONG;
    }

    if status < 0 {
        return nt_status_to_win32(status) as LONG;
    }

    ERROR_SUCCESS as LONG
}

#[no_mangle]
pub unsafe extern "C" fn RegSetValueExW(
    h_key: HKEY,
    lp_value_name: PCWSTR,
    _reserved: DWORD,
    dw_type: DWORD,
    lp_data: *const BYTE,
    cb_data: DWORD,
) -> LONG {
    let nt_handle = match get_nt_handle(h_key) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let mut value_unicode = match wide_str_to_unicode_string(lp_value_name) {
        Some(s) => s,
        None => return ERROR_INVALID_PARAMETER as LONG,
    };

    let status = crate::libs::ntdll::registry::nt_set_value_key(
        nt_handle,
        &mut value_unicode,
        0,
        dw_type,
        lp_data as PVOID,
        cb_data,
    );

    if status < 0 {
        return nt_status_to_win32(status) as LONG;
    }

    ERROR_SUCCESS as LONG
}

#[no_mangle]
pub unsafe extern "C" fn RegDeleteKeyW(h_key: HKEY, lp_sub_key: PCWSTR) -> LONG {
    let mut subkey_handle: HKEY = null_mut();
    let result = RegOpenKeyExW(h_key, lp_sub_key, 0, KEY_ALL_ACCESS, &mut subkey_handle);

    if result != ERROR_SUCCESS as LONG {
        return result;
    }

    let nt_handle = match get_nt_handle(subkey_handle) {
        Some(h) => h,
        None => {
            RegCloseKey(subkey_handle);
            return ERROR_INVALID_HANDLE as LONG;
        }
    };

    let status = crate::libs::ntdll::registry::nt_delete_key(nt_handle);
    RegCloseKey(subkey_handle);

    if status < 0 {
        nt_status_to_win32(status) as LONG
    } else {
        ERROR_SUCCESS as LONG
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegDeleteValueW(h_key: HKEY, lp_value_name: PCWSTR) -> LONG {
    let nt_handle = match get_nt_handle(h_key) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let mut value_unicode = match wide_str_to_unicode_string(lp_value_name) {
        Some(s) => s,
        None => return ERROR_INVALID_PARAMETER as LONG,
    };

    let status = crate::libs::ntdll::registry::nt_delete_value_key(nt_handle, &mut value_unicode);

    if status < 0 {
        nt_status_to_win32(status) as LONG
    } else {
        ERROR_SUCCESS as LONG
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegEnumKeyExW(
    h_key: HKEY,
    dw_index: DWORD,
    lp_name: PWSTR,
    lpcch_name: *mut DWORD,
    _lp_reserved: *mut DWORD,
    _lp_class: PWSTR,
    _lpcch_class: *mut DWORD,
    _lpft_last_write_time: *mut FILETIME,
) -> LONG {
    if lp_name.is_null() || lpcch_name.is_null() {
        return ERROR_INVALID_PARAMETER as LONG;
    }

    let nt_handle = match get_nt_handle(h_key) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let mut buffer = [0u8; 512];
    let mut result_length: ULONG = 0;

    let status = crate::libs::ntdll::registry::nt_enumerate_key(
        nt_handle,
        dw_index,
        1, // KeyBasicInformation
        buffer.as_mut_ptr() as PVOID,
        buffer.len() as ULONG,
        &mut result_length,
    );

    if status == STATUS_NO_MORE_ENTRIES {
        return ERROR_NO_MORE_ITEMS as LONG;
    }

    if status < 0 {
        return nt_status_to_win32(status) as LONG;
    }

    ERROR_SUCCESS as LONG
}

#[no_mangle]
pub unsafe extern "C" fn RegEnumValueW(
    h_key: HKEY,
    dw_index: DWORD,
    lp_value_name: PWSTR,
    lpcch_value_name: *mut DWORD,
    _lp_reserved: *mut DWORD,
    _lp_type: *mut DWORD,
    _lp_data: *mut BYTE,
    _lpcb_data: *mut DWORD,
) -> LONG {
    if lp_value_name.is_null() || lpcch_value_name.is_null() {
        return ERROR_INVALID_PARAMETER as LONG;
    }

    let nt_handle = match get_nt_handle(h_key) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let mut buffer = [0u8; 512];
    let mut result_length: ULONG = 0;

    let status = crate::libs::ntdll::registry::nt_enumerate_value_key(
        nt_handle,
        dw_index,
        1, // KeyValuePartialInformation
        buffer.as_mut_ptr() as PVOID,
        buffer.len() as ULONG,
        &mut result_length,
    );

    if status == STATUS_NO_MORE_ENTRIES {
        return ERROR_NO_MORE_ITEMS as LONG;
    }

    if status < 0 {
        return nt_status_to_win32(status) as LONG;
    }

    ERROR_SUCCESS as LONG
}

#[no_mangle]
pub unsafe extern "C" fn RegFlushKey(h_key: HKEY) -> LONG {
    let nt_handle = match get_nt_handle(h_key) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let status = crate::libs::ntdll::registry::nt_flush_key(nt_handle);

    if status < 0 {
        nt_status_to_win32(status) as LONG
    } else {
        ERROR_SUCCESS as LONG
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegNotifyChangeKeyValue(
    h_key: HKEY,
    b_watch_subtree: LONG,
    dw_notify_filter: DWORD,
    h_event: HANDLE,
    f_asynchronous: LONG,
) -> LONG {
    let nt_handle = match get_nt_handle(h_key) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let status = crate::libs::ntdll::registry::nt_notify_change_key(
        nt_handle,
        h_event,
        null_mut(),
        null_mut(),
        null_mut(),
        dw_notify_filter,
        if b_watch_subtree != 0 { 1 } else { 0 },
        null_mut(),
        0,
        if f_asynchronous != 0 { 1 } else { 0 },
    );

    if status < 0 {
        nt_status_to_win32(status) as LONG
    } else {
        ERROR_SUCCESS as LONG
    }
}
