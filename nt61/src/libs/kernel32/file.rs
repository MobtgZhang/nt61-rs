//! kernel32 — file I/O
//
//! `create_file_w`, `read_file`, `write_file`, `get_file_size`,
//! `get_file_size_ex`, `delete_file_w`, `move_file_ex_w`,
//! `flush_file_buffers`, `set_file_pointer`, `set_end_of_file`.
//! The wrappers thin out the ntdll native API into the
//! Win32 surface; the actual file I/O is still stubbed at
//! this layer (the underlying NT_CREATE_FILE returns
//! `STATUS_SUCCESS` with a placeholder handle).
//
//! References: MSDN Library "Windows 7" — kernel32 file I/O.

extern crate alloc;

use super::error::set_last_error;
use super::types::{BOOL, DWORD, FALSE, HANDLE, LPCWSTR, TRUE};
use crate::libs::ntdll::file as ntdll_file;
use crate::libs::ntdll::status::nt_status_to_dos_error;
use crate::libs::ntdll::status::{STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS};
use crate::libs::ntdll::types::{IoStatusBlock, ObjectAttributes, UnicodeString};
use alloc::string::String;
use core::ptr;

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

fn map_nt_status(s: i32) -> u32 {
    if s == STATUS_SUCCESS {
        return 0;
    }
    let dos = nt_status_to_dos_error(s);
    set_last_error(dos);
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
    if a & access::GENERIC_READ != 0 {
        n |= 0x001F_0000;
    }
    if a & access::GENERIC_WRITE != 0 {
        n |= 0x0012_0080;
    }
    if a & access::GENERIC_EXECUTE != 0 {
        n |= 0x0012_0000;
    }
    n
}

// ---------------------------------------------------------------------------
// create_file_w
// ---------------------------------------------------------------------------

/// `create_file_w`.
pub unsafe extern "C" fn create_file_w(
    file_name: LPCWSTR,
    desired_access: DWORD,
    share_mode: DWORD,
    security_attributes: *const u8,
    creation_disposition: DWORD,
    flags_and_attributes: DWORD,
    template_file: HANDLE,
) -> HANDLE {
    if file_name.is_null() {
        set_last_error(87);
        return -1isize as HANDLE;
    }
    let name = match wide_to_string(file_name) {
        Some(s) => s,
        None => {
            set_last_error(123);
            return -1isize as HANDLE;
        }
    };
    // Convert to UTF-16 for ntdll.
    let mut buf: [u16; 256] = [0; 256];
    let mut i = 0;
    for c in name.encode_utf16() {
        if i + 1 >= buf.len() {
            break;
        }
        buf[i] = c;
        i += 1;
    }
    buf[i] = 0;
    let mut oa = ObjectAttributes::new();
    let mut name_us = UnicodeString {
        length: (i * 2) as u16,
        maximum_length: ((i + 1) * 2) as u16,
        buffer: buf.as_mut_ptr(),
    };
    oa.object_name = &mut name_us;
    oa.attributes = 0x40; // OBJ_CASE_INSENSITIVE

    let mut handle: HANDLE = ptr::null_mut();
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let status = ntdll_file::nt_create_file_kernel(
        &mut handle,
        map_desired_access(desired_access),
        &oa,
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
        if status == STATUS_OBJECT_NAME_NOT_FOUND {
            set_last_error(2);
        } else {
            set_last_error(map_nt_status(status));
        }
        return -1isize as HANDLE;
    }
    handle
}

// ---------------------------------------------------------------------------
// read_file / write_file
// ---------------------------------------------------------------------------

/// `read_file`.
pub unsafe extern "C" fn read_file(
    file: HANDLE,
    buffer: *mut u8,
    bytes_to_read: DWORD,
    bytes_read: *mut DWORD,
    overlapped: *const u8,
) -> BOOL {
    let _ = overlapped;
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let status = ntdll_file::nt_read_file_kernel(
        file,
        &mut iosb,
        core::slice::from_raw_parts_mut(buffer, bytes_to_read as usize),
        None,
    );
    if status != STATUS_SUCCESS && status != crate::libs::ntdll::status::STATUS_END_OF_FILE as i32 {
        set_last_error(map_nt_status(status));
        return FALSE;
    }
    if !bytes_read.is_null() {
        *bytes_read = iosb.information as u32;
    }
    if status == crate::libs::ntdll::status::STATUS_END_OF_FILE as i32 {
        set_last_error(38); // ERROR_HANDLE_EOF
    }
    TRUE
}

/// `write_file`.
pub unsafe extern "C" fn write_file(
    file: HANDLE,
    buffer: *const u8,
    bytes_to_write: DWORD,
    bytes_written: *mut DWORD,
    overlapped: *const u8,
) -> BOOL {
    let _ = overlapped;
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let status = ntdll_file::nt_write_file_kernel(
        file,
        &mut iosb,
        core::slice::from_raw_parts(buffer, bytes_to_write as usize),
        None,
    );
    if status != STATUS_SUCCESS {
        set_last_error(map_nt_status(status));
        return FALSE;
    }
    if !bytes_written.is_null() {
        *bytes_written = iosb.information as u32;
    }
    TRUE
}

// ---------------------------------------------------------------------------
// get_file_size / get_file_size_ex
// ---------------------------------------------------------------------------

/// `get_file_size`.
pub unsafe extern "C" fn get_file_size(file: HANDLE, file_size_high: *mut DWORD) -> DWORD {
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let mut fsi: ntdll_file::FileStandardInformation =
        ntdll_file::FileStandardInformation::default();
    let status = ntdll_file::nt_query_information_file_kernel(
        file,
        &mut iosb,
        core::slice::from_raw_parts_mut(
            &mut fsi as *mut _ as *mut u8,
            core::mem::size_of::<ntdll_file::FileStandardInformation>(),
        ),
        5, // FileStandardInformation
    );
    if status != STATUS_SUCCESS {
        set_last_error(map_nt_status(status));
        return INVALID_SET_FILE_POINTER;
    }
    let size = fsi.end_of_file as u64;
    if !file_size_high.is_null() {
        *file_size_high = (size >> 32) as u32;
    }
    size as u32
}

/// `get_file_size_ex`.
pub unsafe extern "C" fn get_file_size_ex(file: HANDLE, file_size: *mut i64) -> BOOL {
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let mut fsi: ntdll_file::FileStandardInformation =
        ntdll_file::FileStandardInformation::default();
    let status = ntdll_file::nt_query_information_file_kernel(
        file,
        &mut iosb,
        core::slice::from_raw_parts_mut(
            &mut fsi as *mut _ as *mut u8,
            core::mem::size_of::<ntdll_file::FileStandardInformation>(),
        ),
        5,
    );
    if status != STATUS_SUCCESS {
        set_last_error(map_nt_status(status));
        return FALSE;
    }
    if !file_size.is_null() {
        *file_size = fsi.end_of_file;
    }
    TRUE
}

// ---------------------------------------------------------------------------
// delete_file_w / move_file_ex_w
// ---------------------------------------------------------------------------

/// `delete_file_w`.
pub unsafe extern "C" fn delete_file_w(file_name: LPCWSTR) -> BOOL {
    if file_name.is_null() {
        set_last_error(87);
        return FALSE;
    }
    let name = match wide_to_string(file_name) {
        Some(s) => s,
        None => {
            set_last_error(123);
            return FALSE;
        }
    };
    let mut buf: [u16; 256] = [0; 256];
    let mut i = 0;
    for c in name.encode_utf16() {
        if i + 1 < buf.len() {
            buf[i] = c;
            i += 1;
        }
    }
    buf[i] = 0;
    let mut oa = ObjectAttributes::new();
    let mut name_us = UnicodeString {
        length: (i * 2) as u16,
        maximum_length: ((i + 1) * 2) as u16,
        buffer: buf.as_mut_ptr(),
    };
    oa.object_name = &mut name_us;
    oa.attributes = 0x40;
    let status = ntdll_file::nt_delete_file(&mut oa);
    if status == STATUS_SUCCESS {
        TRUE
    } else {
        set_last_error(map_nt_status(status));
        FALSE
    }
}

/// `move_file_ex_w`.
pub unsafe extern "C" fn move_file_ex_w(_existing: LPCWSTR, _new: LPCWSTR, _flags: DWORD) -> BOOL {
    set_last_error(50); // ERROR_NOT_IMPLEMENTED
    FALSE
}

// ---------------------------------------------------------------------------
// flush_file_buffers / set_file_pointer / set_end_of_file / close_handle
// ---------------------------------------------------------------------------

/// `flush_file_buffers`.
pub unsafe extern "C" fn flush_file_buffers(file: HANDLE) -> BOOL {
    let mut iosb: IoStatusBlock = IoStatusBlock::new();
    let status = ntdll_file::nt_flush_buffers_file(file, &mut iosb);
    if status == STATUS_SUCCESS {
        TRUE
    } else {
        set_last_error(map_nt_status(status));
        FALSE
    }
}

/// `set_file_pointer`.
pub unsafe extern "C" fn set_file_pointer(
    file: HANDLE,
    distance_to_move: i32,
    distance_to_move_high: *mut i32,
    move_method: DWORD,
) -> DWORD {
    let _ = (file, distance_to_move, distance_to_move_high, move_method);
    0
}

/// `set_end_of_file`.
pub unsafe extern "C" fn set_end_of_file(_file: HANDLE) -> BOOL {
    TRUE
}

/// Re-export `close_handle` for callers that only need this
/// file module.
pub use super::handle::close_handle as _CloseHandle;
