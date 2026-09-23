//! File System Control (FSCTL) Support
//!
//! FSCTLs are specialized I/O control codes for file system operations.
//! They are sent via NtFsControlFile and are handled by file system drivers.
//!
//! Common FSCTLs include:
//! - FSCTL_LOCK_VOLUME
//! - FSCTL_UNLOCK_VOLUME
//! - FSCTL_DISMOUNT_VOLUME
//! - FSCTL_GET_COMPRESSION
//! - FSCTL_SET_COMPRESSION
//! - FSCTL_GET_REPARSE_POINT
//! - FSCTL_SET_REPARSE_POINT

use core::ptr::null_mut;
use crate::libs::ntdll::status::*;
use super::{Irp, DeviceObject, IoStackLocation};

pub mod fsctl {
    pub const FSCTL_LOCK_VOLUME: u32 = 0x00090018;

    pub const FSCTL_UNLOCK_VOLUME: u32 = 0x0009001C;

    pub const FSCTL_DISMOUNT_VOLUME: u32 = 0x00090020;

    pub const FSCTL_GET_COMPRESSION: u32 = 0x0009003C;

    pub const FSCTL_SET_COMPRESSION: u32 = 0x0009C040;

    pub const FSCTL_GET_REPARSE_POINT: u32 = 0x000900A8;

    pub const FSCTL_SET_REPARSE_POINT: u32 = 0x000900A4;

    pub const FSCTL_DELETE_REPARSE_POINT: u32 = 0x000900AC;

    pub const FSCTL_GET_NTFS_VOLUME_DATA: u32 = 0x00090064;

    pub const FSCTL_IS_VOLUME_MOUNTED: u32 = 0x00090028;

    pub const FSCTL_MARK_VOLUME_DIRTY: u32 = 0x00090030;

    pub const FSCTL_QUERY_ALLOCATED_RANGES: u32 = 0x000940CF;

    pub const FSCTL_SET_SPARSE: u32 = 0x000900C4;

    pub const FSCTL_SET_ZERO_DATA: u32 = 0x000980C8;

    pub const FSCTL_GET_RETRIEVAL_POINTERS: u32 = 0x00090073;

    pub const FSCTL_MOVE_FILE: u32 = 0x00090074;

    pub const FSCTL_QUERY_FAT_BPB: u32 = 0x00090058;

    pub const FSCTL_REQUEST_OPLOCK: u32 = 0x00090000;

    pub const FSCTL_CREATE_OR_GET_OBJECT_ID: u32 = 0x000900C0;

    pub const FSCTL_SET_OBJECT_ID: u32 = 0x00090098;

    pub const FSCTL_DELETE_OBJECT_ID: u32 = 0x000900A0;

    pub const FSCTL_GET_OBJECT_ID: u32 = 0x0009009C;
}

#[repr(C)]
pub struct FsctlRequest {
    pub code: u32,
    pub input_buffer: *mut u8,
    pub input_length: u32,
    pub output_buffer: *mut u8,
    pub output_length: u32,
    pub bytes_returned: u32,
}

impl FsctlRequest {
    pub fn new(code: u32) -> Self {
        Self {
            code,
            input_buffer: null_mut(),
            input_length: 0,
            output_buffer: null_mut(),
            output_length: 0,
            bytes_returned: 0,
        }
    }
}

pub fn get_fsctl_code(stack: *const IoStackLocation) -> u32 {
    if stack.is_null() {
        return 0;
    }

    unsafe {
        ((*stack).parameters.as_u64 & 0xFFFFFFFF) as u32
    }
}

pub unsafe fn handle_lock_volume(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }


    (*irp).io_status.status = STATUS_SUCCESS as u32;
    (*irp).io_status.information = 0;
    super::IoCompleteRequest(irp, 0);
    STATUS_SUCCESS as i32
}

pub unsafe fn handle_unlock_volume(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }

    (*irp).io_status.status = STATUS_SUCCESS as u32;
    (*irp).io_status.information = 0;
    super::IoCompleteRequest(irp, 0);
    STATUS_SUCCESS as i32
}

pub unsafe fn handle_dismount_volume(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }


    (*irp).io_status.status = STATUS_SUCCESS as u32;
    (*irp).io_status.information = 0;
    super::IoCompleteRequest(irp, 0);
    STATUS_SUCCESS as i32
}

pub unsafe fn handle_is_volume_mounted(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }

    (*irp).io_status.status = STATUS_SUCCESS as u32;
    (*irp).io_status.information = 0;
    super::IoCompleteRequest(irp, 0);
    STATUS_SUCCESS as i32
}

pub unsafe fn dispatch_fsctl(
    device: *mut DeviceObject,
    irp: *mut Irp,
    fsctl_code: u32,
) -> i32 {
    match fsctl_code {
        fsctl::FSCTL_LOCK_VOLUME => handle_lock_volume(device, irp),
        fsctl::FSCTL_UNLOCK_VOLUME => handle_unlock_volume(device, irp),
        fsctl::FSCTL_DISMOUNT_VOLUME => handle_dismount_volume(device, irp),
        fsctl::FSCTL_IS_VOLUME_MOUNTED => handle_is_volume_mounted(device, irp),
        _ => {
            if !irp.is_null() {
                (*irp).io_status.status = STATUS_INVALID_DEVICE_REQUEST as u32;
                (*irp).io_status.information = 0;
                super::IoCompleteRequest(irp, 0);
            }
            STATUS_INVALID_DEVICE_REQUEST as i32
        }
    }
}

pub unsafe extern "C" fn file_system_control_dispatch(
    device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }

    let stack = (*irp).current_stack;
    if stack.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }

    let fsctl_code = get_fsctl_code(stack);
    dispatch_fsctl(device, irp, fsctl_code)
}
