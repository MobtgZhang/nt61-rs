//! Example System Call Handlers with Parameter Validation
//!
//! This module demonstrates how to use the syscall_validation module
//! to safely handle user-mode parameters in system calls.

use super::syscall_validation::{
    probe_for_read, probe_for_write, probe_for_read_aligned, probe_for_write_aligned,
    capture_user_string, STATUS_ACCESS_VIOLATION,
};
use crate::libs::ntdll::types::{NTSTATUS, HANDLE};

/// All user-mode pointers are validated before access.
pub unsafe fn nt_read_file_validated(
    file_handle: HANDLE,
    buffer: *mut u8,
    length: u32,
    bytes_read: *mut u32,
) -> NTSTATUS {
    if let Err(status) = probe_for_write(buffer, length as usize) {
        return status;
    }

    if !bytes_read.is_null() {
        if let Err(status) = probe_for_write(bytes_read as *mut u8, 4) {
            return status;
        }
    }

    crate::libs::ntdll::file::NtReadFile(
        file_handle,
        core::ptr::null_mut(),
        core::ptr::null_mut(), // APC routine
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        buffer as *mut core::ffi::c_void,
        length,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    )
}

pub unsafe fn nt_write_file_validated(
    file_handle: HANDLE,
    buffer: *const u8,
    length: u32,
    bytes_written: *mut u32,
) -> NTSTATUS {
    if let Err(status) = probe_for_read(buffer, length as usize) {
        return status;
    }

    if !bytes_written.is_null() {
        if let Err(status) = probe_for_write(bytes_written as *mut u8, 4) {
            return status;
        }
    }

    crate::libs::ntdll::file::NtWriteFile(
        file_handle,
        core::ptr::null_mut(),
        core::ptr::null_mut(), // APC routine
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        buffer as *mut core::ffi::c_void, // Cast to *mut for API compatibility
        length,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    )
}

pub unsafe fn nt_allocate_virtual_memory_validated(
    process_handle: HANDLE,
    base_address: *mut *mut u8,
    size: *mut usize,
    allocation_type: u32,
    protection: u32,
) -> NTSTATUS {
    if let Err(status) = probe_for_write_aligned(
        base_address as *mut u8,
        core::mem::size_of::<*mut u8>(),
        core::mem::align_of::<*mut u8>(),
    ) {
        return status;
    }

    if let Err(status) = probe_for_write_aligned(
        size as *mut u8,
        core::mem::size_of::<usize>(),
        core::mem::align_of::<usize>(),
    ) {
        return status;
    }

    crate::libs::ntdll::virtual_mem::NtAllocateVirtualMemory(
        process_handle,
        base_address as *mut *mut core::ffi::c_void,
        0,
        size,
        allocation_type,
        protection,
    )
}

pub unsafe fn nt_create_file_validated(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_name_ptr: *const u8,  // UNICODE_STRING pointer
    share_access: u32,
    create_disposition: u32,
) -> NTSTATUS {
    if let Err(status) = probe_for_write_aligned(
        file_handle as *mut u8,
        core::mem::size_of::<HANDLE>(),
        core::mem::align_of::<HANDLE>(),
    ) {
        return status;
    }

    if let Err(status) = super::syscall_validation::probe_unicode_string(object_name_ptr) {
        return status;
    }

    crate::libs::ntdll::status::STATUS_NOT_IMPLEMENTED
}
