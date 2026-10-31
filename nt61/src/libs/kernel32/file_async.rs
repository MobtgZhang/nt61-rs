//! kernel32 — Asynchronous I/O Support
//!
//! Windows 7 OVERLAPPED I/O for asynchronous file operations.
//! Allows non-blocking read_file/write_file with completion notification.
//!
//! References:
//!   * MSDN Library "Windows 7" — Synchronization and Overlapped I/O
//!   * Windows Internals 7th Ed. - Chapter 11

use super::error::set_last_error;
use super::types::{BOOL, DWORD, FALSE, HANDLE, TRUE};
use crate::ke::sync::Spinlock;
use core::ptr;

#[repr(C)]
pub struct OVERLAPPED {
    pub internal: usize,
    pub internal_high: usize,
    pub offset: u32,
    pub offset_high: u32,
    pub h_event: HANDLE,
}

impl OVERLAPPED {
    pub const fn new() -> Self {
        Self {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: ptr::null_mut(),
        }
    }
}

impl Default for OVERLAPPED {
    fn default() -> Self {
        Self::new()
    }
}

const IO_STATUS_PENDING: usize = 0x00000103;
const IO_STATUS_SUCCESS: usize = 0x00000000;
const IO_STATUS_ERROR: usize = 0xFFFFFFFF;

#[derive(Copy, Clone)]
pub struct AsyncIoState {
    handle: HANDLE,
    pub buffer: *mut u8,
    pub bytes_requested: u32,
    pub bytes_transferred: u32,
    pub status: usize,
    overlapped: *mut OVERLAPPED,
}

impl AsyncIoState {
    pub const fn new() -> Self {
        Self {
            handle: ptr::null_mut(),
            buffer: ptr::null_mut(),
            bytes_requested: 0,
            bytes_transferred: 0,
            status: 0,
            overlapped: ptr::null_mut(),
        }
    }
}

impl Default for AsyncIoState {
    fn default() -> Self {
        Self::new()
    }
}

const MAX_ASYNC_OPS: usize = 64;
static ASYNC_IO_TABLE: Spinlock<[Option<AsyncIoState>; MAX_ASYNC_OPS]> =
    Spinlock::new([None; MAX_ASYNC_OPS]);

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn read_file(
    h_file: HANDLE,
    buffer: *mut u8,
    number_of_bytes_to_read: DWORD,
    number_of_bytes_read: *mut DWORD,
    overlapped: *mut OVERLAPPED,
) -> BOOL {
    if h_file.is_null() || buffer.is_null() {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return FALSE;
    }

    if overlapped.is_null() {
        return super::file::read_file(
            h_file,
            buffer,
            number_of_bytes_to_read,
            number_of_bytes_read,
            ptr::null_mut(),
        );
    }

    let ovl = &mut *overlapped;
    ovl.internal = IO_STATUS_PENDING;
    ovl.internal_high = 0;

    let mut table = ASYNC_IO_TABLE.lock();
    let slot = match table.iter_mut().find(|s| s.is_none()) {
        Some(s) => s,
        None => {
            set_last_error(1450); // ERROR_NO_SYSTEM_RESOURCES
            return FALSE;
        }
    };

    *slot = Some(AsyncIoState {
        handle: h_file,
        buffer,
        bytes_requested: number_of_bytes_to_read,
        bytes_transferred: 0,
        status: IO_STATUS_PENDING,
        overlapped,
    });

    drop(table);

    let bytes_read = super::file::read_file(
        h_file,
        buffer,
        number_of_bytes_to_read,
        number_of_bytes_read,
        ptr::null_mut(),
    );

    if bytes_read != 0 {
        ovl.internal = IO_STATUS_SUCCESS;
        ovl.internal_high = if !number_of_bytes_read.is_null() {
            *number_of_bytes_read as usize
        } else {
            0
        };

        if !ovl.h_event.is_null() {
            crate::libs::ntdll::sync::nt_set_event(ovl.h_event, ptr::null_mut());
        }

        let mut table = ASYNC_IO_TABLE.lock();
        for slot in table.iter_mut() {
            if let Some(ref state) = slot {
                if state.overlapped == overlapped {
                    *slot = None;
                    break;
                }
            }
        }
    } else {
        ovl.internal = IO_STATUS_ERROR;
    }

    set_last_error(997); // ERROR_IO_PENDING
    FALSE // Asynchronous operations return FALSE with ERROR_IO_PENDING
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn write_file(
    h_file: HANDLE,
    buffer: *const u8,
    number_of_bytes_to_write: DWORD,
    number_of_bytes_written: *mut DWORD,
    overlapped: *mut OVERLAPPED,
) -> BOOL {
    if h_file.is_null() || buffer.is_null() {
        set_last_error(87);
        return FALSE;
    }

    if overlapped.is_null() {
        return super::file::write_file(
            h_file,
            buffer,
            number_of_bytes_to_write,
            number_of_bytes_written,
            ptr::null_mut(),
        );
    }

    let ovl = &mut *overlapped;
    ovl.internal = IO_STATUS_PENDING;
    ovl.internal_high = 0;

    let mut table = ASYNC_IO_TABLE.lock();
    let slot = match table.iter_mut().find(|s| s.is_none()) {
        Some(s) => s,
        None => {
            set_last_error(1450);
            return FALSE;
        }
    };

    *slot = Some(AsyncIoState {
        handle: h_file,
        buffer: buffer as *mut u8,
        bytes_requested: number_of_bytes_to_write,
        bytes_transferred: 0,
        status: IO_STATUS_PENDING,
        overlapped,
    });

    drop(table);

    let bytes_written = super::file::write_file(
        h_file,
        buffer,
        number_of_bytes_to_write,
        number_of_bytes_written,
        ptr::null_mut(),
    );

    if bytes_written != 0 {
        ovl.internal = IO_STATUS_SUCCESS;
        ovl.internal_high = if !number_of_bytes_written.is_null() {
            *number_of_bytes_written as usize
        } else {
            0
        };

        if !ovl.h_event.is_null() {
            crate::libs::ntdll::sync::nt_set_event(ovl.h_event, ptr::null_mut());
        }

        let mut table = ASYNC_IO_TABLE.lock();
        for slot in table.iter_mut() {
            if let Some(ref state) = slot {
                if state.overlapped == overlapped {
                    *slot = None;
                    break;
                }
            }
        }
    } else {
        ovl.internal = IO_STATUS_ERROR;
    }

    set_last_error(997); // ERROR_IO_PENDING
    FALSE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn get_overlapped_result(
    h_file: HANDLE,
    overlapped: *mut OVERLAPPED,
    number_of_bytes_transferred: *mut DWORD,
    wait: BOOL,
) -> BOOL {
    if h_file.is_null() || overlapped.is_null() || number_of_bytes_transferred.is_null() {
        set_last_error(87);
        return FALSE;
    }

    let ovl = &mut *overlapped;

    if wait != 0 && ovl.internal == IO_STATUS_PENDING {
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }

    match ovl.internal {
        IO_STATUS_SUCCESS => {
            *number_of_bytes_transferred = ovl.internal_high as DWORD;
            TRUE
        }
        IO_STATUS_PENDING => {
            set_last_error(996); // ERROR_IO_INCOMPLETE
            FALSE
        }
        _ => {
            set_last_error(31); // ERROR_GEN_FAILURE
            FALSE
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn has_overlapped_io_completed(overlapped: *const OVERLAPPED) -> BOOL {
    if overlapped.is_null() {
        return FALSE;
    }

    let ovl = &*overlapped;
    if ovl.internal != IO_STATUS_PENDING {
        TRUE
    } else {
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn cancel_io(h_file: HANDLE) -> BOOL {
    if h_file.is_null() {
        set_last_error(6); // ERROR_INVALID_HANDLE
        return FALSE;
    }

    let mut table = ASYNC_IO_TABLE.lock();
    let mut canceled = false;

    for slot in table.iter_mut() {
        if let Some(ref mut state) = slot {
            if state.handle == h_file {
                if !state.overlapped.is_null() {
                    (*state.overlapped).internal = IO_STATUS_ERROR;
                }
                *slot = None;
                canceled = true;
            }
        }
    }

    if canceled {
        TRUE
    } else {
        set_last_error(1168); // ERROR_NOT_FOUND
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn cancel_io_ex(h_file: HANDLE, overlapped: *mut OVERLAPPED) -> BOOL {
    if h_file.is_null() {
        set_last_error(6);
        return FALSE;
    }

    if overlapped.is_null() {
        return cancel_io(h_file);
    }

    let mut table = ASYNC_IO_TABLE.lock();

    for slot in table.iter_mut() {
        if let Some(ref mut state) = slot {
            if state.handle == h_file && state.overlapped == overlapped {
                (*state.overlapped).internal = IO_STATUS_ERROR;
                *slot = None;
                return TRUE;
            }
        }
    }

    set_last_error(1168);
    FALSE
}
