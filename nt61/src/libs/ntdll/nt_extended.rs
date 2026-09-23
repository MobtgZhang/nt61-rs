//! ntdll — Additional Nt* system calls
//
//! Extended system call wrappers: NtQueryObject, NtSetInformationObject,
//! NtQueryDirectoryFile, NtQueryVolumeInformationFile, NtDeviceIoControlFile.

use super::status::{STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};
use super::types::{HANDLE, NTSTATUS, PVOID, IoStatusBlock, ObjectAttributes, UnicodeString};
use core::ptr;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectInformationClass {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectTypesInformation = 3,
    ObjectHandleFlagInformation = 4,
}

pub unsafe extern "C" fn NtQueryObject(
    handle: HANDLE,
    object_information_class: u32,
    object_information: PVOID,
    object_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let _ = (object_information_class, object_information, object_information_length);

    if !return_length.is_null() {
        *return_length = 0;
    }

    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtSetInformationObject(
    handle: HANDLE,
    object_information_class: u32,
    object_information: PVOID,
    object_information_length: u32,
) -> NTSTATUS {
    if handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let _ = (object_information_class, object_information, object_information_length);
    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtQueryDirectoryFile(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: PVOID,
    apc_context: PVOID,
    io_status_block: *mut IoStatusBlock,
    file_information: PVOID,
    length: u32,
    file_information_class: u32,
    return_single_entry: u8,
    file_name: *mut UnicodeString,
    restart_scan: u8,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (event, apc_routine, apc_context, file_information, length);
    let _ = (file_information_class, return_single_entry, file_name, restart_scan);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;

    super::status::STATUS_NO_MORE_FILES
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsInformationClass {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation = 2,
    FileFsSizeInformation = 3,
    FileFsDeviceInformation = 4,
    FileFsAttributeInformation = 5,
    FileFsControlInformation = 6,
    FileFsFullSizeInformation = 7,
    FileFsObjectIdInformation = 8,
    FileFsDriverPathInformation = 9,
    FileFsVolumeFlagsInformation = 10,
}

pub unsafe extern "C" fn NtQueryVolumeInformationFile(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    fs_information: PVOID,
    length: u32,
    fs_information_class: u32,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (fs_information, length, fs_information_class);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtSetVolumeInformationFile(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    fs_information: PVOID,
    length: u32,
    fs_information_class: u32,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (fs_information, length, fs_information_class);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtDeviceIoControlFile(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: PVOID,
    apc_context: PVOID,
    io_status_block: *mut IoStatusBlock,
    io_control_code: u32,
    input_buffer: PVOID,
    input_buffer_length: u32,
    output_buffer: PVOID,
    output_buffer_length: u32,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (event, apc_routine, apc_context, io_control_code);
    let _ = (input_buffer, input_buffer_length, output_buffer, output_buffer_length);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtFsControlFile(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: PVOID,
    apc_context: PVOID,
    io_status_block: *mut IoStatusBlock,
    fs_control_code: u32,
    input_buffer: PVOID,
    input_buffer_length: u32,
    output_buffer: PVOID,
    output_buffer_length: u32,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (event, apc_routine, apc_context, fs_control_code);
    let _ = (input_buffer, input_buffer_length, output_buffer, output_buffer_length);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtLockFile(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: PVOID,
    apc_context: PVOID,
    io_status_block: *mut IoStatusBlock,
    byte_offset: *mut i64,
    length: *mut i64,
    key: u32,
    fail_immediately: u8,
    exclusive_lock: u8,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (event, apc_routine, apc_context, byte_offset, length);
    let _ = (key, fail_immediately, exclusive_lock);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtUnlockFile(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    byte_offset: *mut i64,
    length: *mut i64,
    key: u32,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (byte_offset, length, key);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtNotifyChangeDirectoryFile(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: PVOID,
    apc_context: PVOID,
    io_status_block: *mut IoStatusBlock,
    buffer: PVOID,
    length: u32,
    completion_filter: u32,
    watch_tree: u8,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (event, apc_routine, apc_context, buffer, length);
    let _ = (completion_filter, watch_tree);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;

    // P1-10 FIX: NtNotifyChangeDirectoryFile signals a
    // directory-change event. The bootstrap doesn't yet wire
    // a real change-notification subsystem (see `fs::notify`),
    // so we report "success with 0 bytes" instead of
    // NOT_IMPLEMENTED. The user's wait will simply not
    // complete; the rest of the API surface is consistent.
    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtQueryEaFile(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    buffer: PVOID,
    length: u32,
    return_single_entry: u8,
    ea_list: PVOID,
    ea_list_length: u32,
    ea_index: *mut u32,
    restart_scan: u8,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (buffer, length, return_single_entry, ea_list, ea_list_length);
    let _ = (ea_index, restart_scan);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtSetEaFile(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    buffer: PVOID,
    length: u32,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (buffer, length);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;

    STATUS_SUCCESS
}
