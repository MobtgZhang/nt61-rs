//! File I/O wrappers (kernel32).
//!
//! Thin wrappers over `NtCreateFile` / `NtReadFile` / `NtWriteFile` /
//! `NtClose` / `NtQueryInformationFile`.

#![allow(dead_code)]

use crate::libs::ntdll::types::{HANDLE, NTSTATUS};

pub const INVALID_HANDLE_VALUE: HANDLE = -1_isize as HANDLE;
pub const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
pub const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4;

pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;

pub const FILE_SHARE_READ: u32 = 0x1;
pub const FILE_SHARE_WRITE: u32 = 0x2;

pub const CREATE_NEW: u32 = 1;
pub const CREATE_ALWAYS: u32 = 2;
pub const OPEN_EXISTING: u32 = 3;
pub const OPEN_ALWAYS: u32 = 4;
pub const TRUNCATE_EXISTING: u32 = 5;

pub struct FileHandle(HANDLE);

impl FileHandle {
    pub fn as_handle(&self) -> HANDLE { self.0 }
}

pub fn create_file_w(
    _path: &[u16],
    _access: u32,
    _share: u32,
    _sec: *mut (),
    _disposition: u32,
    _flags: u32,
    _template: HANDLE,
) -> Result<HANDLE, NTSTATUS> {
    Err(-1)
}

pub fn read_file(
    _h: HANDLE,
    _buf: &mut [u8],
    _bytes_read: *mut u32,
    _overlapped: *mut (),
) -> Result<(), NTSTATUS> { Err(-1) }

pub fn write_file(
    _h: HANDLE,
    _buf: &[u8],
    _bytes_written: *mut u32,
    _overlapped: *mut (),
) -> Result<(), NTSTATUS> { Err(-1) }

pub fn close_handle(_h: HANDLE) -> Result<(), NTSTATUS> { Ok(()) }
