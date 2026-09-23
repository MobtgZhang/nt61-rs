//! advapi32 — Registry API
//
//! Implements the Win32 registry API (RegOpenKeyEx, RegCreateKeyEx,
//! RegQueryValueEx, RegSetValueEx, RegDeleteKey, RegCloseKey, etc.).
//!
//! These functions wrap the native NT registry API (NtCreateKey,
//! NtOpenKey, NtQueryValueKey, NtSetValueKey) exposed by ntdll.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

#[allow(non_snake_case, non_upper_case_globals, dead_code)]

use super::types::{DWORD, HKEY, LONG, REGSAM, LPCWSTR, LPWSTR, LPDWORD, LPBYTE, LPCBYTE, BYTE, FILETIME};
use super::types::{ERROR_SUCCESS, ERROR_INVALID_PARAMETER, ERROR_INVALID_HANDLE, ERROR_NOT_ENOUGH_MEMORY, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS};
use super::types::{REG_CREATED_NEW_KEY, REG_OPENED_EXISTING_KEY, KEY_ALL_ACCESS, nt_status_to_win32, is_predefined_key};
use crate::libs::ntdll::types::{HANDLE, PVOID, ULONG, PWSTR, PCWSTR, UnicodeString, ObjectAttributes};
use crate::libs::ntdll::status::{STATUS_SUCCESS, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_NO_MORE_ENTRIES};
use crate::libs::ntdll::types::NTSTATUS;
use crate::libs::ntdll::file::NtClose;
use core::ptr::{null_mut, null};
use core::slice;


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
        for (i, entry) in REG_HANDLES.iter_mut().enumerate() {
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
        Length: (len * 2) as u16,
        MaximumLength: ((len + 1) * 2) as u16,
        Buffer: s as PWSTR,
    })
}

unsafe fn copy_wide_string(dest: PWSTR, src: PCWSTR, max_chars: usize) -> usize {
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
    hKey: HKEY,
    lpSubKey: PCWSTR,
    Reserved: DWORD,
    lpClass: PWSTR,
    dwOptions: DWORD,
    samDesired: DWORD,
    lpSecurityAttributes: PVOID,
    phkResult: *mut HKEY,
    lpdwDisposition: *mut DWORD,
) -> LONG {
    if phkResult.is_null() {
        return ERROR_INVALID_PARAMETER as LONG;
    }

    let base_handle = match get_nt_handle(hKey) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let subkey_unicode = match wide_str_to_unicode_string(lpSubKey) {
        Some(s) => s,
        None => return ERROR_INVALID_PARAMETER as LONG,
    };

    let mut obj_attr = ObjectAttributes::new();
    obj_attr.root_directory = base_handle;
    obj_attr.object_name = &subkey_unicode as *const _ as *mut _;

    let mut nt_handle: HANDLE = null_mut();
    let mut disposition: ULONG = 0;

    let status = crate::libs::ntdll::registry::NtCreateKey(
        &mut nt_handle,
        samDesired,
        &mut obj_attr,
        0,
        null_mut(),
        dwOptions,
        if lpdwDisposition.is_null() { null_mut() } else { &mut disposition },
    );

    if status < 0 {
        return nt_status_to_win32(status) as LONG;
    }

    match alloc_reg_handle(nt_handle, samDesired) {
        Some(handle) => {
            *phkResult = handle;
            if !lpdwDisposition.is_null() {
                *lpdwDisposition = if disposition == 0 { REG_CREATED_NEW_KEY } else { REG_OPENED_EXISTING_KEY };
            }
            ERROR_SUCCESS as LONG
        }
        None => {
            NtClose(nt_handle);
            ERROR_NOT_ENOUGH_MEMORY as LONG
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegOpenKeyExW(
    hKey: HKEY,
    lpSubKey: PCWSTR,
    ulOptions: DWORD,
    samDesired: DWORD,
    phkResult: *mut HKEY,
) -> LONG {
    if phkResult.is_null() {
        return ERROR_INVALID_PARAMETER as LONG;
    }

    if lpSubKey.is_null() || *lpSubKey == 0 {
        *phkResult = hKey;
        return ERROR_SUCCESS as LONG;
    }

    let base_handle = match get_nt_handle(hKey) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let subkey_unicode = match wide_str_to_unicode_string(lpSubKey) {
        Some(s) => s,
        None => return ERROR_INVALID_PARAMETER as LONG,
    };

    let mut obj_attr = ObjectAttributes::new();
    obj_attr.root_directory = base_handle;
    obj_attr.object_name = &subkey_unicode as *const _ as *mut _;

    let mut nt_handle: HANDLE = null_mut();
    let status = crate::libs::ntdll::registry::NtOpenKey(
        &mut nt_handle,
        samDesired,
        &mut obj_attr,
    );

    if status < 0 {
        return nt_status_to_win32(status) as LONG;
    }

    match alloc_reg_handle(nt_handle, samDesired) {
        Some(handle) => {
            *phkResult = handle;
            ERROR_SUCCESS as LONG
        }
        None => {
            NtClose(nt_handle);
            ERROR_NOT_ENOUGH_MEMORY as LONG
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegCloseKey(hKey: HKEY) -> LONG {
    if is_predefined_key(hKey) {
        return ERROR_SUCCESS as LONG;
    }

    match get_nt_handle(hKey) {
        Some(nt_handle) => {
            let status = NtClose(nt_handle);
            free_reg_handle(hKey);
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
    hKey: HKEY,
    lpValueName: PCWSTR,
    lpReserved: *mut DWORD,
    lpType: *mut DWORD,
    lpData: *mut BYTE,
    lpcbData: *mut DWORD,
) -> LONG {
    let nt_handle = match get_nt_handle(hKey) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let mut value_unicode = match wide_str_to_unicode_string(lpValueName) {
        Some(s) => s,
        None => return ERROR_INVALID_PARAMETER as LONG,
    };

    let mut result_length: ULONG = 0;
    let buffer_size = if lpcbData.is_null() { 0 } else { *lpcbData };

    let status = crate::libs::ntdll::registry::NtQueryValueKey(
        nt_handle,
        &mut value_unicode,
        1, // KeyValuePartialInformation
        lpData as PVOID,
        buffer_size,
        &mut result_length,
    );

    if !lpcbData.is_null() {
        *lpcbData = result_length;
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
    hKey: HKEY,
    lpValueName: PCWSTR,
    Reserved: DWORD,
    dwType: DWORD,
    lpData: *const BYTE,
    cbData: DWORD,
) -> LONG {
    let nt_handle = match get_nt_handle(hKey) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let mut value_unicode = match wide_str_to_unicode_string(lpValueName) {
        Some(s) => s,
        None => return ERROR_INVALID_PARAMETER as LONG,
    };

    let status = crate::libs::ntdll::registry::NtSetValueKey(
        nt_handle,
        &mut value_unicode,
        0,
        dwType,
        lpData as PVOID,
        cbData,
    );

    if status < 0 {
        return nt_status_to_win32(status) as LONG;
    }

    ERROR_SUCCESS as LONG
}

#[no_mangle]
pub unsafe extern "C" fn RegDeleteKeyW(
    hKey: HKEY,
    lpSubKey: PCWSTR,
) -> LONG {
    let mut subkey_handle: HKEY = null_mut();
    let result = RegOpenKeyExW(hKey, lpSubKey, 0, KEY_ALL_ACCESS, &mut subkey_handle);

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

    let status = crate::libs::ntdll::registry::NtDeleteKey(nt_handle);
    RegCloseKey(subkey_handle);

    if status < 0 {
        nt_status_to_win32(status) as LONG
    } else {
        ERROR_SUCCESS as LONG
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegDeleteValueW(
    hKey: HKEY,
    lpValueName: PCWSTR,
) -> LONG {
    let nt_handle = match get_nt_handle(hKey) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let mut value_unicode = match wide_str_to_unicode_string(lpValueName) {
        Some(s) => s,
        None => return ERROR_INVALID_PARAMETER as LONG,
    };

    let status = crate::libs::ntdll::registry::NtDeleteValueKey(nt_handle, &mut value_unicode);

    if status < 0 {
        nt_status_to_win32(status) as LONG
    } else {
        ERROR_SUCCESS as LONG
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegEnumKeyExW(
    hKey: HKEY,
    dwIndex: DWORD,
    lpName: PWSTR,
    lpcchName: *mut DWORD,
    lpReserved: *mut DWORD,
    lpClass: PWSTR,
    lpcchClass: *mut DWORD,
    lpftLastWriteTime: *mut FILETIME,
) -> LONG {
    if lpName.is_null() || lpcchName.is_null() {
        return ERROR_INVALID_PARAMETER as LONG;
    }

    let nt_handle = match get_nt_handle(hKey) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let mut buffer = [0u8; 512];
    let mut result_length: ULONG = 0;

    let status = crate::libs::ntdll::registry::NtEnumerateKey(
        nt_handle,
        dwIndex,
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
    hKey: HKEY,
    dwIndex: DWORD,
    lpValueName: PWSTR,
    lpcchValueName: *mut DWORD,
    lpReserved: *mut DWORD,
    lpType: *mut DWORD,
    lpData: *mut BYTE,
    lpcbData: *mut DWORD,
) -> LONG {
    if lpValueName.is_null() || lpcchValueName.is_null() {
        return ERROR_INVALID_PARAMETER as LONG;
    }

    let nt_handle = match get_nt_handle(hKey) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let mut buffer = [0u8; 512];
    let mut result_length: ULONG = 0;

    let status = crate::libs::ntdll::registry::NtEnumerateValueKey(
        nt_handle,
        dwIndex,
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
pub unsafe extern "C" fn RegFlushKey(hKey: HKEY) -> LONG {
    let nt_handle = match get_nt_handle(hKey) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let status = crate::libs::ntdll::registry::NtFlushKey(nt_handle);

    if status < 0 {
        nt_status_to_win32(status) as LONG
    } else {
        ERROR_SUCCESS as LONG
    }
}

#[no_mangle]
pub unsafe extern "C" fn RegNotifyChangeKeyValue(
    hKey: HKEY,
    bWatchSubtree: LONG,
    dwNotifyFilter: DWORD,
    hEvent: HANDLE,
    fAsynchronous: LONG,
) -> LONG {
    let nt_handle = match get_nt_handle(hKey) {
        Some(h) => h,
        None => return ERROR_INVALID_HANDLE as LONG,
    };

    let status = crate::libs::ntdll::registry::NtNotifyChangeKey(
        nt_handle,
        hEvent,
        null_mut(),
        null_mut(),
        null_mut(),
        dwNotifyFilter,
        if bWatchSubtree != 0 { 1 } else { 0 },
        null_mut(),
        0,
        if fAsynchronous != 0 { 1 } else { 0 },
    );

    if status < 0 {
        nt_status_to_win32(status) as LONG
    } else {
        ERROR_SUCCESS as LONG
    }
}
