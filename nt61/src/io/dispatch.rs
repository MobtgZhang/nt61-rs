//! I/O Dispatch
//
//! Complete IRP dispatch framework aligned with NT 6.1 IoCallDriver
//! semantics (wdm.h; "Windows Internals, 6th ed.", ch. 8):
//!
//! * A DispatchTable models a driver MajorFunction[28] array.
//! * install() copies a table onto a DriverObject.
//! * dispatch_irp is the IoCallDriver entry: it resolves the owning
//!   DriverObject from the DeviceObject, reads the current
//!   IoStackLocation major code, and calls the registered handler.
//! * forward_irp_to_lower models IoForwardIrpToLower across the device
//!   stack (DeviceObject::attached_device).
//!
//! Storage backends (AHCI, NVMe, virtio-blk, ramdisk) register
//! READ/WRITE handlers through this table; the storage class layer
//! sends sector I/O through dispatch_storage_request so no backend
//! is bypassed by direct calls.

use core::ptr::null_mut;

use super::{major, DeviceObject, DriverDispatch, IoParameters, Irp, ReadWriteParameters};
use crate::libs::ntdll::status::{
    STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER, STATUS_NO_SUCH_DEVICE, STATUS_SUCCESS,
};

/// Number of major function slots (wdm.h IRP_MJ_MAXIMUM_FUNCTION + 1).
pub const MAJOR_FUNCTION_COUNT: usize = 28;

/// Dispatch routine type re-exported for readability at use sites.
pub type DispatchRoutine = DriverDispatch;

/// Driver major-function dispatch table (wdm.h MajorFunction array).
pub struct DispatchTable {
    pub major_functions: [DispatchRoutine; MAJOR_FUNCTION_COUNT],
}

impl DispatchTable {
    /// An empty table: every major code is unhandled.
    pub const fn empty() -> Self {
        Self {
            major_functions: [None; MAJOR_FUNCTION_COUNT],
        }
    }

    /// NT-style defaults: lifecycle majors succeed, data majors report
    /// STATUS_INVALID_DEVICE_REQUEST (what an unimplemented handler in
    /// NT would complete with).
    pub const fn new() -> Self {
        let mut table = Self::empty();
        table.major_functions[major::IRP_MJ_CREATE as usize] = Some(default_create);
        table.major_functions[major::IRP_MJ_CLOSE as usize] = Some(default_close);
        table.major_functions[major::IRP_MJ_CLEANUP as usize] = Some(default_cleanup);
        table.major_functions[major::IRP_MJ_FLUSH_BUFFERS as usize] = Some(default_flush_buffers);
        table.major_functions[major::IRP_MJ_SHUTDOWN as usize] = Some(default_shutdown);
        table
    }

    /// Install this table onto a driver object, merging over whatever
    /// handlers are already present (wdm.h IoSetDispatchTable semantics).
    pub fn install(&self, driver: *mut super::DriverObject) {
        if driver.is_null() {
            return;
        }
        unsafe {
            for (index, handler) in self.major_functions.iter().enumerate() {
                if let Some(routine) = handler {
                    (*driver).major_functions[index] = Some(*routine);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Default handlers
// ---------------------------------------------------------------------------

unsafe extern "C" fn complete_irp_with(irp: *mut Irp, status: i32) -> i32 {
    if !irp.is_null() {
        (*irp).io_status.status = status as u32;
        super::io_complete_request(irp, 0);
    }
    status
}

unsafe extern "C" fn default_create(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    complete_irp_with(irp, STATUS_SUCCESS)
}

unsafe extern "C" fn default_close(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    complete_irp_with(irp, STATUS_SUCCESS)
}

unsafe extern "C" fn default_cleanup(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    complete_irp_with(irp, STATUS_SUCCESS)
}

unsafe extern "C" fn default_flush_buffers(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    complete_irp_with(irp, STATUS_SUCCESS)
}

unsafe extern "C" fn default_shutdown(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    complete_irp_with(irp, STATUS_SUCCESS)
}

// ---------------------------------------------------------------------------
// Dispatch core (IoCallDriver / IoForwardIrpToLower)
// ---------------------------------------------------------------------------

/// IoCallDriver: route an IRP to the device's driver using the current
/// stack location's major function code.
pub unsafe fn dispatch_irp(device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if device.is_null() || irp.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let stack = (*irp).current_stack;
    if stack.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let major_code = (*stack).major_function as usize;
    if major_code >= MAJOR_FUNCTION_COUNT {
        return complete_irp_with(irp, STATUS_INVALID_DEVICE_REQUEST);
    }

    let driver = (*device).driver_object;
    if driver.is_null() {
        return complete_irp_with(irp, STATUS_NO_SUCH_DEVICE);
    }

    (*stack).device_object = device;
    if let Some(handler) = (*driver).major_functions[major_code] {
        handler(device, irp)
    } else {
        complete_irp_with(irp, STATUS_INVALID_DEVICE_REQUEST)
    }
}

/// Attach a lower device object onto a device stack
/// (wdm.h IoAttachDeviceToDeviceStack).
pub unsafe fn attach_device(device: *mut DeviceObject, lower: *mut DeviceObject) {
    if device.is_null() || lower.is_null() {
        return;
    }
    (*device).attached_device = lower;
}

/// IoForwardIrpToLower: forward the IRP to the next lower device in
/// the stack, keeping the same stack location parameters.
pub unsafe fn forward_irp_to_lower(device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if device.is_null() || irp.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let lower = (*device).attached_device;
    if lower.is_null() {
        return complete_irp_with(irp, STATUS_INVALID_DEVICE_REQUEST);
    }
    dispatch_irp(lower, irp)
}

// ---------------------------------------------------------------------------
// Storage request helpers
// ---------------------------------------------------------------------------

/// Allocate and populate an IRP for a storage read/write request.
/// The data buffer pointer is carried in Irp::user_buffer, matching
/// NT's UserBuffer slot for buffered I/O requests.
pub unsafe fn build_storage_request(
    major_code: u8,
    device: *mut DeviceObject,
    byte_offset: u64,
    byte_count: u32,
    buffer: *mut u8,
) -> *mut Irp {
    let irp = super::allocate_irp(1);
    if irp.is_null() {
        return null_mut();
    }

    let stack = (*irp).current_stack;
    if stack.is_null() {
        super::free_irp(irp);
        return null_mut();
    }

    (*stack).major_function = major_code;
    (*stack).minor_function = 0;
    (*stack).device_object = device;
    (*stack).parameters = IoParameters {
        read_write: ReadWriteParameters {
            byte_offset,
            byte_count,
            key: 0,
        },
    };
    (*irp).user_buffer = buffer as *mut ();
    irp
}

/// Read the parameters of a storage read/write IRP from its stack
/// location: (byte offset, byte count, data buffer).
pub unsafe fn storage_request_parameters(irp: *mut Irp) -> (u64, u32, *mut u8) {
    if irp.is_null() {
        return (0, 0, null_mut());
    }
    let stack = (*irp).current_stack;
    if stack.is_null() {
        return (0, 0, null_mut());
    }
    let params = (*stack).parameters.read_write;
    (
        params.byte_offset,
        params.byte_count,
        (*irp).user_buffer as *mut u8,
    )
}

/// Send a sector read/write through the dispatcher to the device
/// stack rooted at device. Storage handlers must not complete the IRP
/// themselves; this function completes it exactly once. Returns the
/// final NTSTATUS.
pub unsafe fn dispatch_storage_request(
    device: *mut DeviceObject,
    is_write: bool,
    byte_offset: u64,
    byte_count: u32,
    buffer: *mut u8,
) -> i32 {
    let major_code = if is_write {
        major::IRP_MJ_WRITE
    } else {
        major::IRP_MJ_READ
    };
    let irp = build_storage_request(major_code, device, byte_offset, byte_count, buffer);
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let status = if device.is_null() {
        STATUS_NO_SUCH_DEVICE
    } else {
        let driver = (*device).driver_object;
        let stack = (*irp).current_stack;
        let handler = if driver.is_null() {
            None
        } else {
            (*driver).major_functions[(*stack).major_function as usize]
        };
        if let Some(routine) = handler {
            (*stack).device_object = device;
            routine(device, irp)
        } else {
            STATUS_NO_SUCH_DEVICE
        }
    };

    (*irp).io_status.status = status as u32;
    if status >= 0 {
        (*irp).io_status.information = byte_count as usize;
    }
    super::io_complete_request(irp, 0);
    status
}
