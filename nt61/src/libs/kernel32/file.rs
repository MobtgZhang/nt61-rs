//! kernel32 — file I/O
//
//! `CreateFileW`, `ReadFile`, `WriteFile`, `GetFileSize`,
//! `GetFileSizeEx`, `DeleteFileW`, `MoveFileExW`,
//! `FlushFileBuffers`, `SetFilePointer`, `SetEndOfFile`.
//! The wrappers thin out the ntdll native API into the
//! Win32 surface; the actual file I/O is still stubbed at
//! this layer (the underlying NtCreateFile returns
//! `STATUS_SUCCESS` with a placeholder handle).
//
//! References: MSDN Library "Windows 7" — kernel32 file I/O.

extern crate alloc;

use super::error::{GetLastError, SetLastError};
use super::handle::CloseHandle;
use super::types::{BOOL, DWORD, FALSE, HANDLE, LPCWSTR, TRUE};
use crate::libs::ntdll::file as ntdll_file;
use alloc::string::String;
use core::ptr;
use crate::libs::ntdll::status::{
    STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};
use crate::libs::ntdll::types::{IoStatusBlock, ObjectAttributes, UnicodeString};
use crate::libs::ntdll::status::nt_status_to_dos_error;

// ---------------------------------------------------------------------------
// Win32 access / share / creation flags (subset)
// ---------------------------------------------------------------------------

pub mod access {
    pub const GENERIC_READ: u32 = 0x8000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;
}

pub mod share {
    pub const FILE_SHARE_READ: u32 = 0x0000_0001;
    pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;
}

pub mod creation {
    pub const CREATE_NEW: u32 = 1;
    pub const CREATE_ALWAYS: u32 = 2;
    pub const OPEN_EXISTING: u32 = 3;
    pub const OPEN_ALWAYS: u32 = 4;
    pub const TRUNCATE_EXISTING: u32 = 5;
}

pub mod attribute {
    pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
    pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
    pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
    pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
    pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
}

pub mod flags {
    pub const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
    pub const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    pub const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
    pub const FILE_FLAG_RANDOM_ACCESS: u32 = 0x1000_0000;
    pub const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
}

pub mod movefile {
    pub const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    pub const MOVEFILE_COPY_ALLOWED: u32 = 0x0000_0002;
    pub const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x0000_0004;
    pub const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
}

const INVALID_SET_FILE_POINTER: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn map_nt_status(s: i32) -> u32 {
    if s == STATUS_SUCCESS { return 0; }
    let dos = nt_status_to_dos_error(s);
    SetLastError(dos);
    dos
}

fn map_create_disposition(c: u32) -> u32 {
    match c {
        1 => 0x0000_0002, // CREATE_NEW -> FILE_CREATE
        2 => 0x0000_0005, // CREATE_ALWAYS -> FILE_OVERWRITE_IF
        3 => 0x0000_0001, // OPEN_EXISTING -> FILE_OPEN
        4 => 0x0000_0003, // OPEN_ALWAYS -> FILE_OPEN_IF
        5 => 0x0000_0004, // TRUNCATE_EXISTING -> FILE_OVERWRITE
        _ => 0x0000_0001,
    }
}

fn map_desired_access(a: u32) -> u32 {
    let mut n = 0;
    if a & access::GENERIC_READ != 0 { n |= 0x001F_0000; }
    if a & access::GENERIC_WRITE != 0 { n |= 0x0012_0080; }
    if a & access::GENERIC_EXECUTE != 0 { n |= 0x0012_0000; }
    n
}

// ---------------------------------------------------------------------------
// CreateFileW
// ---------------------------------------------------------------------------

/// `CreateFileW`.
pub unsafe extern "C" fn CreateFileW(
    file_name: LPCWSTR,
    desired_access: DWORD,
    share_mode: DWORD,
    security_attributes: *const u8,
    creation_disposition: DWORD,
    flags_and_attributes: DWORD,
    template_file: HANDLE,
) -> HANDLE {
    if file_name.is_null() {
        SetLastError(87);
        return -1isize as HANDLE;
    }
    let name = match wide_to_string(file_name) {
        Some(s) => s,
        None => { SetLastError(123); return -1isize as HANDLE; },
    };
    // Convert to UTF-16 for ntdll.
    let mut buf: [u16; 256] = [0; 256];
    let mut i = 0;
    for c in name.encode_utf16() {
        if i + 1 >= buf.len() { break; }
        buf[i] = c;
        i += 1;
    }
    buf[i] = 0;
    let mut oa = ObjectAttributes::new();
    let mut name_us = UnicodeString {
        Length: (i * 2) as u16,
        MaximumLength: ((i + 1) * 2) as u16,
        Buffer: buf.as_mut_ptr(),
    };
    oa.object_name = &mut name_us;
    oa.attributes = 0x40; // OBJ_CASE_INSENSITIVE

    let mut handle: HANDLE = ptr::null_mut();
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let status = ntdll_file::NtCreateFile(
        &mut handle,
        map_desired_access(desired_access),
        &mut oa,
        &mut iosb,
        ptr::null_mut(),
        flags_and_attributes & 0xFFFF,
        share_mode,
        map_create_disposition(creation_disposition),
        flags_and_attributes & 0xFFFF_0000,
        ptr::null_mut(),
        0,
    );
    let _ = (security_attributes, template_file);
    if status != STATUS_SUCCESS {
        if status == STATUS_OBJECT_NAME_NOT_FOUND { SetLastError(2); }
        else { SetLastError(map_nt_status(status)); }
        return -1isize as HANDLE;
    }
    handle
}

// ---------------------------------------------------------------------------
// ReadFile / WriteFile
// ---------------------------------------------------------------------------

/// `ReadFile`.
pub unsafe extern "C" fn ReadFile(
    file: HANDLE,
    buffer: *mut u8,
    bytes_to_read: DWORD,
    bytes_read: *mut DWORD,
    overlapped: *const u8,
) -> BOOL {
    let _ = overlapped;
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let status = ntdll_file::NtReadFile(
        file, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
        &mut iosb, buffer as *mut _, bytes_to_read,
        ptr::null_mut(), ptr::null_mut(),
    );
    if status != STATUS_SUCCESS && status != crate::libs::ntdll::status::STATUS_END_OF_FILE as i32 {
        SetLastError(map_nt_status(status));
        return FALSE;
    }
    if !bytes_read.is_null() {
        *bytes_read = iosb.information as u32;
    }
    if status == crate::libs::ntdll::status::STATUS_END_OF_FILE as i32 {
        SetLastError(38); // ERROR_HANDLE_EOF
    }
    TRUE
}

/// `WriteFile`.
pub unsafe extern "C" fn WriteFile(
    file: HANDLE,
    buffer: *const u8,
    bytes_to_write: DWORD,
    bytes_written: *mut DWORD,
    overlapped: *const u8,
) -> BOOL {
    let _ = overlapped;
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let status = ntdll_file::NtWriteFile(
        file, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
        &mut iosb, buffer as *mut _, bytes_to_write,
        ptr::null_mut(), ptr::null_mut(),
    );
    if status != STATUS_SUCCESS {
        SetLastError(map_nt_status(status));
        return FALSE;
    }
    if !bytes_written.is_null() {
        *bytes_written = iosb.information as u32;
    }
    TRUE
}

// ---------------------------------------------------------------------------
// GetFileSize / GetFileSizeEx
// ---------------------------------------------------------------------------

/// `GetFileSize`.
pub unsafe extern "C" fn GetFileSize(file: HANDLE, file_size_high: *mut DWORD) -> DWORD {
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let mut fsi: ntdll_file::FileStandardInformation = ntdll_file::FileStandardInformation::default();
    let status = ntdll_file::NtQueryInformationFile(
        file, &mut iosb,
        &mut fsi as *mut _ as *mut _,
        core::mem::size_of::<ntdll_file::FileStandardInformation>() as u32,
        5, // FileStandardInformation
    );
    if status != STATUS_SUCCESS {
        SetLastError(map_nt_status(status));
        return INVALID_SET_FILE_POINTER;
    }
    let size = fsi.end_of_file as u64;
    if !file_size_high.is_null() {
        *file_size_high = (size >> 32) as u32;
    }
    size as u32
}

/// `GetFileSizeEx`.
pub unsafe extern "C" fn GetFileSizeEx(file: HANDLE, file_size: *mut i64) -> BOOL {
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let mut fsi: ntdll_file::FileStandardInformation = ntdll_file::FileStandardInformation::default();
    let status = ntdll_file::NtQueryInformationFile(
        file, &mut iosb,
        &mut fsi as *mut _ as *mut _,
        core::mem::size_of::<ntdll_file::FileStandardInformation>() as u32,
        5,
    );
    if status != STATUS_SUCCESS {
        SetLastError(map_nt_status(status));
        return FALSE;
    }
    if !file_size.is_null() {
        *file_size = fsi.end_of_file;
    }
    TRUE
}

// ---------------------------------------------------------------------------
// DeleteFileW / MoveFileExW
// ---------------------------------------------------------------------------

/// `DeleteFileW`.
pub unsafe extern "C" fn DeleteFileW(file_name: LPCWSTR) -> BOOL {
    if file_name.is_null() { SetLastError(87); return FALSE; }
    let name = match wide_to_string(file_name) {
        Some(s) => s,
        None => { SetLastError(123); return FALSE; },
    };
    let mut buf: [u16; 256] = [0; 256];
    let mut i = 0;
    for c in name.encode_utf16() { if i + 1 < buf.len() { buf[i] = c; i += 1; } }
    buf[i] = 0;
    let mut oa = ObjectAttributes::new();
    let mut name_us = UnicodeString {
        Length: (i * 2) as u16,
        MaximumLength: ((i + 1) * 2) as u16,
        Buffer: buf.as_mut_ptr(),
    };
    oa.object_name = &mut name_us;
    oa.attributes = 0x40;
    let status = ntdll_file::NtDeleteFile(&mut oa);
    if status == STATUS_SUCCESS { TRUE } else {
        SetLastError(map_nt_status(status));
        FALSE
    }
}

/// `MoveFileExW`.
pub unsafe extern "C" fn MoveFileExW(
    _existing: LPCWSTR,
    _new: LPCWSTR,
    _flags: DWORD,
) -> BOOL {
    SetLastError(50); // ERROR_NOT_IMPLEMENTED
    FALSE
}

// ---------------------------------------------------------------------------
// FlushFileBuffers / SetFilePointer / SetEndOfFile / CloseHandle
// ---------------------------------------------------------------------------

/// `FlushFileBuffers`.
pub unsafe extern "C" fn FlushFileBuffers(file: HANDLE) -> BOOL {
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let status = ntdll_file::NtFlushBuffersFile(file, &mut iosb);
    if status == STATUS_SUCCESS { TRUE } else {
        SetLastError(map_nt_status(status));
        FALSE
    }
}

/// `SetFilePointer`.
pub unsafe extern "C" fn SetFilePointer(
    file: HANDLE,
    distance_to_move: i32,
    distance_to_move_high: *mut i32,
    move_method: DWORD,
) -> DWORD {
    let _ = (file, distance_to_move, distance_to_move_high, move_method);
    0
}

/// `SetEndOfFile`.
pub unsafe extern "C" fn SetEndOfFile(_file: HANDLE) -> BOOL { TRUE }

/// Re-export `CloseHandle` for callers that only need this
/// file module.
pub use super::handle::CloseHandle as _CloseHandle;
