//! File I/O wrappers (kernel32).
//!
//! Thin wrappers over `NT_CREATE_FILE` / `NT_READ_FILE` / `NT_WRITE_FILE` /
//! `NT_CLOSE` / `NT_QUERY_INFORMATION_FILE`.  Every function forwards to the
//! real ntdll entry point and translates the `NTSTATUS` to the kernel32
//! `Result` convention (`Ok(())` / `Err(NTSTATUS)`).

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

pub struct FileHandle(pub HANDLE);

impl FileHandle {
    pub fn as_handle(&self) -> HANDLE {
        self.0
    }
}

/// `CreateFileW` — open or create a file.
///
/// The `path` is a UTF-16 wide string.  We build an `ObjectAttributes`
/// with a `UnicodeString` pointing at the caller's buffer and forward
/// to the real `nt_create_file`.
pub fn create_file_w(
    path: &[u16],
    access: u32,
    share: u32,
    _sec: *mut (),
    disposition: u32,
    flags: u32,
    _template: HANDLE,
) -> Result<HANDLE, NTSTATUS> {
    // Build a null-terminated wide string for the NT path.
    let mut wbuf: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(path.len() + 1);
    wbuf.extend_from_slice(path);
    wbuf.push(0);

    let mut us = crate::libs::ntdll::types::UnicodeString::default();
    unsafe { crate::libs::ntdll::string::rtl_init_unicode_string(&mut us, wbuf.as_ptr()) };

    let mut oa = crate::libs::ntdll::types::ObjectAttributes::new();
    oa.object_name = &mut us;
    oa.attributes = crate::libs::ntdll::types::obj::OBJ_CASE_INSENSITIVE;

    let mut iosb = crate::libs::ntdll::types::IoStatusBlock::default();
    let mut handle: HANDLE = core::ptr::null_mut();

    let status = unsafe {
        crate::libs::ntdll::file::nt_create_file(
            &mut handle,
            access,
            &mut oa,
            &mut iosb,
            core::ptr::null_mut(), // allocation size
            0,                     // file attributes
            share,
            disposition,
            flags,
            core::ptr::null_mut(), // EA buffer
            0,                     // EA length
        )
    };

    if status >= 0 {
        Ok(handle)
    } else {
        Err(status)
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `ReadFile` — read data from a file.
pub unsafe fn read_file(
    h: HANDLE,
    buf: &mut [u8],
    bytes_read: *mut u32,
    _overlapped: *mut (),
) -> Result<(), NTSTATUS> {
    let mut iosb = crate::libs::ntdll::types::IoStatusBlock::default();
    let mut offset: i64 = 0; // current file position (managed by the kernel)

    let status = unsafe {
        crate::libs::ntdll::file::nt_read_file(
            h,
            core::ptr::null_mut(), // event
            core::ptr::null_mut(), // APC routine
            core::ptr::null_mut(), // APC context
            &mut iosb,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            buf.len() as u32,
            &mut offset,
            core::ptr::null_mut(), // key
        )
    };

    if status >= 0 {
        if !bytes_read.is_null() {
            // IoStatusBlock.Information holds the bytes transferred.
            unsafe {
                *bytes_read = iosb.information as u32;
            }
        }
        Ok(())
    } else {
        Err(status)
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `WriteFile` — write data to a file.
pub unsafe fn write_file(
    h: HANDLE,
    buf: &[u8],
    bytes_written: *mut u32,
    _overlapped: *mut (),
) -> Result<(), NTSTATUS> {
    let mut iosb = crate::libs::ntdll::types::IoStatusBlock::default();
    let mut offset: i64 = 0;

    let status = unsafe {
        crate::libs::ntdll::file::nt_write_file(
            h,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut iosb,
            buf.as_ptr() as *mut core::ffi::c_void,
            buf.len() as u32,
            &mut offset,
            core::ptr::null_mut(),
        )
    };

    if status >= 0 {
        if !bytes_written.is_null() {
            unsafe {
                *bytes_written = iosb.information as u32;
            }
        }
        Ok(())
    } else {
        Err(status)
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `CloseHandle` — close a file or other kernel object handle.
pub unsafe fn close_handle(h: HANDLE) -> Result<(), NTSTATUS> {
    let status = unsafe { crate::libs::ntdll::file::nt_close(h) };
    if status >= 0 {
        Ok(())
    } else {
        Err(status)
    }
}
