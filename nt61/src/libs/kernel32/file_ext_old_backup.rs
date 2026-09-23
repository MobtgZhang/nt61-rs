//! kernel32 — Additional file operations
//
//! Extended file operations: CopyFile, MoveFile, FindFirstFile,
//! FindNextFile, FindClose, GetFileAttributes, SetFileAttributes,
//! GetFileType, SetFilePointerEx.

use super::error::SetLastError;
use super::types::{BOOL, DWORD, FALSE, HANDLE, LPCWSTR, TRUE};
use crate::libs::ntdll::status::{STATUS_SUCCESS, STATUS_NO_MORE_ENTRIES};
use alloc::string::String;
use core::ptr;

extern crate alloc;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Win32FindDataW {
    pub file_attributes: DWORD,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub file_size_high: DWORD,
    pub file_size_low: DWORD,
    pub reserved0: DWORD,
    pub reserved1: DWORD,
    pub file_name: [u16; 260],
    pub alternate_file_name: [u16; 14],
}

impl Default for Win32FindDataW {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileTime {
    pub low_date_time: DWORD,
    pub high_date_time: DWORD,
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

pub unsafe extern "C" fn CopyFileW(
    existing_file_name: LPCWSTR,
    new_file_name: LPCWSTR,
    fail_if_exists: BOOL,
) -> BOOL {
    if existing_file_name.is_null() || new_file_name.is_null() {
        SetLastError(87); // ERROR_INVALID_PARAMETER
        return FALSE;
    }

    let _ = (existing_file_name, new_file_name, fail_if_exists);

    TRUE
}

pub unsafe extern "C" fn CopyFileExW(
    existing_file_name: LPCWSTR,
    new_file_name: LPCWSTR,
    progress_routine: *const (),
    data: *const (),
    cancel: *const BOOL,
    flags: DWORD,
) -> BOOL {
    let _ = (
        
        progress_routine, data, cancel, flags);
    CopyFileW(existing_file_name, new_file_name, 0)
}

pub unsafe extern "C" fn MoveFileW(
    existing_file_name: LPCWSTR,
    new_file_name: LPCWSTR,
) -> BOOL {
    if existing_file_name.is_null() || new_file_name.is_null() {
        SetLastError(87);
        return FALSE;
    }
    TRUE
}

struct FindHandle {
    pattern: String,
    index: usize,
    done: bool,
}

static FIND_HANDLES: Lazy<Mutex<[Option<FindHandle>; 16]>> = Lazy::new(|| Mutex::new([None, None, None, None, None, None, None, None,
                                                       None, None, None, None, None, None, None, None];

pub unsafe extern "C" fn FindFirstFileW(
    file_name: LPCWSTR,
    find_file_data: *mut Win32FindDataW,
) -> HANDLE {
    if file_name.is_null() || find_file_data.is_null() {
        SetLastError(87);
        return -1isize as HANDLE;
    }

    let pattern = match wide_to_string(file_name) {
        Some(s) => s,
        None => {
            SetLastError(2); // ERROR_FILE_NOT_FOUND
            return -1isize as HANDLE;
        }
    };

    let mut slot = None;
    for i in 0..16 {
        if FIND_HANDLES[i].is_none() {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => {
            SetLastError(8); // ERROR_NOT_ENOUGH_MEMORY
            return -1isize as HANDLE;
        }
    };

    FIND_HANDLES[slot] = Some(FindHandle {
        pattern,
        index: 0,
        done: false,
    });

    let data = &mut *find_file_data;
    *data = Win32FindDataW::default();
    data.file_attributes = 0x80; // FILE_ATTRIBUTE_NORMAL
    data.file_name[0] = b'.' as u16;
    data.file_name[1] = 0;

    (slot + 1) as HANDLE
}

pub unsafe extern "C" fn FindNextFileW(
    find_file: HANDLE,
    find_file_data: *mut Win32FindDataW,
) -> BOOL {
    if find_file.is_null() || find_file_data.is_null() {
        SetLastError(87);
        return FALSE;
    }

    let slot = (find_file as usize).wrapping_sub(1);
    if slot >= 16 || FIND_HANDLES[slot].is_none() {
        SetLastError(6); // ERROR_INVALID_HANDLE
        return FALSE;
    }

    let handle = FIND_HANDLES[slot].as_mut().unwrap();
    if handle.done {
        SetLastError(18); // ERROR_NO_MORE_FILES
        return FALSE;
    }

    handle.index += 1;
    if handle.index >= 2 {
        handle.done = true;
        SetLastError(18);
        return FALSE;
    }

    let data = &mut *find_file_data;
    *data = Win32FindDataW::default();
    data.file_attributes = 0x10; // FILE_ATTRIBUTE_DIRECTORY
    data.file_name[0] = b'.' as u16;
    data.file_name[1] = b'.' as u16;
    data.file_name[2] = 0;

    TRUE
}

pub unsafe extern "C" fn FindClose(find_file: HANDLE) -> BOOL {
    if find_file.is_null() {
        SetLastError(6);
        return FALSE;
    }

    let slot = (find_file as usize).wrapping_sub(1);
    if slot >= 16 {
        SetLastError(6);
        return FALSE;
    }

    FIND_HANDLES[slot] = None;
    TRUE
}

pub unsafe extern "C" fn GetFileAttributesW(file_name: LPCWSTR) -> DWORD {
    if file_name.is_null() {
        SetLastError(87);
        return 0xFFFF_FFFF;
    }

    0x80
}

pub unsafe extern "C" fn SetFileAttributesW(
    file_name: LPCWSTR,
    file_attributes: DWORD,
) -> BOOL {
    if file_name.is_null() {
        SetLastError(87);
        return FALSE;
    }

    let _ = file_attributes;
    TRUE
}

pub unsafe extern "C" fn GetFileType(file: HANDLE) -> DWORD {
    if file.is_null() {
        return 0; // FILE_TYPE_UNKNOWN
    }
    1 // FILE_TYPE_DISK
}

pub unsafe extern "C" fn SetFilePointerEx(
    file: HANDLE,
    distance_to_move: i64,
    new_file_pointer: *mut i64,
    move_method: DWORD,
) -> BOOL {
    if file.is_null() {
        SetLastError(6);
        return FALSE;
    }

    let _ = (distance_to_move, move_method);

    if !new_file_pointer.is_null() {
        *new_file_pointer = 0;
    }

    TRUE
}

pub use super::file::GetFileSizeEx;

pub const FILE_ATTRIBUTE_READONLY: DWORD = 0x0001;
pub const FILE_ATTRIBUTE_HIDDEN: DWORD = 0x0002;
pub const FILE_ATTRIBUTE_SYSTEM: DWORD = 0x0004;
pub const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x0010;
pub const FILE_ATTRIBUTE_ARCHIVE: DWORD = 0x0020;
pub const FILE_ATTRIBUTE_DEVICE: DWORD = 0x0040;
pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x0080;
pub const FILE_ATTRIBUTE_TEMPORARY: DWORD = 0x0100;
pub const FILE_ATTRIBUTE_SPARSE_FILE: DWORD = 0x0200;
pub const FILE_ATTRIBUTE_REPARSE_POINT: DWORD = 0x0400;
pub const FILE_ATTRIBUTE_COMPRESSED: DWORD = 0x0800;
pub const FILE_ATTRIBUTE_OFFLINE: DWORD = 0x1000;
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: DWORD = 0x2000;
pub const FILE_ATTRIBUTE_ENCRYPTED: DWORD = 0x4000;

pub const FILE_TYPE_UNKNOWN: DWORD = 0x0000;
pub const FILE_TYPE_DISK: DWORD = 0x0001;
pub const FILE_TYPE_CHAR: DWORD = 0x0002;
pub const FILE_TYPE_PIPE: DWORD = 0x0003;

pub const FILE_BEGIN: DWORD = 0;
pub const FILE_CURRENT: DWORD = 1;
pub const FILE_END: DWORD = 2;
