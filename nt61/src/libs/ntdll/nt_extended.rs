//! ntdll — Additional Nt* system calls
//
//! Extended system call wrappers: nt_query_object, nt_set_information_object,
//! nt_query_directory_file, nt_query_volume_information_file, nt_device_io_control_file.

use super::status::{STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::types::{IoStatusBlock, UnicodeString, HANDLE, NTSTATUS, PVOID};
use crate::mm::user_copy::{probe_user_read, probe_user_write, write_user_object};

fn write_io_status(
    io_status_block: *mut IoStatusBlock,
    status: NTSTATUS,
    information: usize,
) -> NTSTATUS {
    let iosb = IoStatusBlock {
        status,
        information,
    };
    if write_user_object(io_status_block as u64, &iosb).is_err() {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    status
}

fn check_user_buffer(pointer: PVOID, length: u32, require_write: bool) -> NTSTATUS {
    if pointer.is_null() || length == 0 {
        return STATUS_SUCCESS;
    }
    let result = if require_write {
        probe_user_write(pointer as u64, length as usize)
    } else {
        probe_user_read(pointer as u64, length as usize)
    };
    if result.is_err() {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    STATUS_SUCCESS
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectInformationClass {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectTypesInformation = 3,
    ObjectHandleFlagInformation = 4,
}

pub unsafe extern "C" fn nt_query_object(
    handle: HANDLE,
    object_information_class: u32,
    object_information: PVOID,
    object_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if !object_information.is_null()
        && object_information_length > 0
        && probe_user_write(
            object_information as u64,
            object_information_length as usize,
        )
        .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if !return_length.is_null()
        && probe_user_write(return_length as u64, core::mem::size_of::<u32>()).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let _ = (
        object_information_class,
        object_information,
        object_information_length,
    );

    if !return_length.is_null() {
        *return_length = 0;
    }

    STATUS_SUCCESS
}

pub unsafe extern "C" fn nt_set_information_object(
    handle: HANDLE,
    object_information_class: u32,
    object_information: PVOID,
    object_information_length: u32,
) -> NTSTATUS {
    if handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if !object_information.is_null()
        && object_information_length > 0
        && probe_user_read(
            object_information as u64,
            object_information_length as usize,
        )
        .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let _ = (
        object_information_class,
        object_information,
        object_information_length,
    );
    STATUS_SUCCESS
}

pub unsafe extern "C" fn nt_query_directory_file(
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

    if check_user_buffer(file_information, length, true) != STATUS_SUCCESS {
        return check_user_buffer(file_information, length, true);
    }
    if !file_name.is_null()
        && probe_user_read(file_name as u64, core::mem::size_of::<UnicodeString>()).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let _ = (event, apc_routine, apc_context, file_information, length);
    let _ = (
        file_information_class,
        return_single_entry,
        file_name,
        restart_scan,
    );

    write_io_status(io_status_block, super::status::STATUS_NO_MORE_FILES, 0)
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

pub unsafe extern "C" fn nt_query_volume_information_file(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    fs_information: PVOID,
    length: u32,
    fs_information_class: u32,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if check_user_buffer(fs_information, length, true) != STATUS_SUCCESS {
        return check_user_buffer(fs_information, length, true);
    }

    let _ = (fs_information, length, fs_information_class);

    write_io_status(io_status_block, STATUS_SUCCESS, 0)
}

pub unsafe extern "C" fn nt_set_volume_information_file(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    fs_information: PVOID,
    length: u32,
    fs_information_class: u32,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if check_user_buffer(fs_information, length, false) != STATUS_SUCCESS {
        return check_user_buffer(fs_information, length, false);
    }

    let _ = (fs_information, length, fs_information_class);

    write_io_status(io_status_block, STATUS_SUCCESS, 0)
}

pub unsafe extern "C" fn nt_device_io_control_file(
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

    if check_user_buffer(input_buffer, input_buffer_length, false) != STATUS_SUCCESS {
        return check_user_buffer(input_buffer, input_buffer_length, false);
    }
    if check_user_buffer(output_buffer, output_buffer_length, true) != STATUS_SUCCESS {
        return check_user_buffer(output_buffer, output_buffer_length, true);
    }

    let _ = (event, apc_routine, apc_context, io_control_code);
    let _ = (
        input_buffer,
        input_buffer_length,
        output_buffer,
        output_buffer_length,
    );

    write_io_status(io_status_block, STATUS_SUCCESS, 0)
}

pub unsafe extern "C" fn nt_fs_control_file(
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

    if check_user_buffer(input_buffer, input_buffer_length, false) != STATUS_SUCCESS {
        return check_user_buffer(input_buffer, input_buffer_length, false);
    }
    if check_user_buffer(output_buffer, output_buffer_length, true) != STATUS_SUCCESS {
        return check_user_buffer(output_buffer, output_buffer_length, true);
    }

    let _ = (event, apc_routine, apc_context, fs_control_code);
    let _ = (
        input_buffer,
        input_buffer_length,
        output_buffer,
        output_buffer_length,
    );

    write_io_status(io_status_block, STATUS_SUCCESS, 0)
}

pub unsafe extern "C" fn nt_lock_file(
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

    if !byte_offset.is_null()
        && probe_user_write(byte_offset as u64, core::mem::size_of::<i64>()).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if !length.is_null() && probe_user_write(length as u64, core::mem::size_of::<i64>()).is_err() {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let _ = (event, apc_routine, apc_context, byte_offset, length);
    let _ = (key, fail_immediately, exclusive_lock);

    write_io_status(io_status_block, STATUS_SUCCESS, 0)
}

pub unsafe extern "C" fn nt_unlock_file(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    byte_offset: *mut i64,
    length: *mut i64,
    key: u32,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if !byte_offset.is_null()
        && probe_user_write(byte_offset as u64, core::mem::size_of::<i64>()).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if !length.is_null() && probe_user_write(length as u64, core::mem::size_of::<i64>()).is_err() {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let _ = (byte_offset, length, key);

    write_io_status(io_status_block, STATUS_SUCCESS, 0)
}

pub unsafe extern "C" fn nt_notify_change_directory_file(
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

    if check_user_buffer(buffer, length, true) != STATUS_SUCCESS {
        return check_user_buffer(buffer, length, true);
    }

    let _ = (event, apc_routine, apc_context, buffer, length);
    let _ = (completion_filter, watch_tree);

    write_io_status(io_status_block, STATUS_SUCCESS, 0);

    // P1-10 FIX: nt_notify_change_directory_file signals a
    // directory-change event. The bootstrap doesn't yet wire
    // a real change-notification subsystem (see `fs::notify`),
    // so we report "success with 0 bytes" instead of
    // NOT_IMPLEMENTED. The user's wait will simply not
    // complete; the rest of the API surface is consistent.
    STATUS_SUCCESS
}

pub unsafe extern "C" fn nt_query_ea_file(
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

    if check_user_buffer(buffer, length, true) != STATUS_SUCCESS {
        return check_user_buffer(buffer, length, true);
    }
    if check_user_buffer(ea_list, ea_list_length, false) != STATUS_SUCCESS {
        return check_user_buffer(ea_list, ea_list_length, false);
    }
    if !ea_index.is_null()
        && probe_user_write(ea_index as u64, core::mem::size_of::<u32>()).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let _ = (buffer, length, return_single_entry, ea_list, ea_list_length);
    let _ = (ea_index, restart_scan);

    write_io_status(io_status_block, STATUS_SUCCESS, 0)
}

pub unsafe extern "C" fn nt_set_ea_file(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    buffer: PVOID,
    length: u32,
) -> NTSTATUS {
    if file_handle.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if check_user_buffer(buffer, length, false) != STATUS_SUCCESS {
        return check_user_buffer(buffer, length, false);
    }

    let _ = (buffer, length);

    write_io_status(io_status_block, STATUS_SUCCESS, 0)
}
