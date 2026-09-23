//! IRP Stack Management
//!
//! Each IRP contains a stack of I/O stack locations, one for each driver
//! in the device stack. As the IRP travels down the stack, each driver
//! gets its own stack location with parameters for that layer.

use core::ptr::null_mut;
use super::{Irp, IoStackLocation, DeviceObject, FileObject, IoParameters};

#[inline]
pub fn get_current_stack_location(irp: *mut Irp) -> *mut IoStackLocation {
    if irp.is_null() {
        return null_mut();
    }

    unsafe { (*irp).current_stack }
}

pub fn get_next_stack_location(irp: *mut Irp) -> *mut IoStackLocation {
    if irp.is_null() {
        return null_mut();
    }

    unsafe {
        let current_loc = (*irp).current_location;
        if current_loc == 0 {
            return null_mut();
        }

        let stack_base = (*irp).current_stack;
        if stack_base.is_null() {
            return null_mut();
        }

        let next = (stack_base as usize - core::mem::size_of::<IoStackLocation>())
            as *mut IoStackLocation;
        next
    }
}

pub fn skip_current_stack_location(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }

    unsafe {
        if (*irp).current_location > 0 {
            (*irp).current_location -= 1;
            let size = core::mem::size_of::<IoStackLocation>();
            (*irp).current_stack = ((*irp).current_stack as usize + size) as *mut IoStackLocation;
        }
    }
}

pub fn copy_current_irp_stack_location_to_next(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }

    unsafe {
        let current = (*irp).current_stack;
        let next = get_next_stack_location(irp);

        if !current.is_null() && !next.is_null() {
            core::ptr::copy_nonoverlapping(current, next, 1);
        }
    }
}

pub fn set_completion_routine(
    irp: *mut Irp,
    completion_routine: Option<
        unsafe extern "C" fn(*mut DeviceObject, *mut Irp, *mut ()) -> i32
    >,
    context: *mut (),
    invoke_on_success: bool,
    invoke_on_error: bool,
    invoke_on_cancel: bool,
) {
    if irp.is_null() {
        return;
    }

    unsafe {
        let stack = (*irp).current_stack;
        if stack.is_null() {
            return;
        }

        let mut control = (*stack).control;

        if invoke_on_success {
            control |= SL_INVOKE_ON_SUCCESS;
        }
        if invoke_on_error {
            control |= SL_INVOKE_ON_ERROR;
        }
        if invoke_on_cancel {
            control |= SL_INVOKE_ON_CANCEL;
        }

        (*stack).control = control;

        let _ = (completion_routine, context);
    }
}

pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x20;
pub const SL_INVOKE_ON_CANCEL: u8 = 0x10;
pub const SL_PENDING_RETURNED: u8 = 0x01;

pub fn mark_irp_pending(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }

    unsafe {
        let stack = (*irp).current_stack;
        if !stack.is_null() {
            (*stack).control |= SL_PENDING_RETURNED;
        }
        (*irp).pending_returned = 1;
    }
}

pub fn is_irp_pending(irp: *mut Irp) -> bool {
    if irp.is_null() {
        return false;
    }

    unsafe {
        (*irp).pending_returned != 0
    }
}

pub fn init_stack_location(
    stack: *mut IoStackLocation,
    major_function: u8,
    minor_function: u8,
    device: *mut DeviceObject,
    file: *mut FileObject,
) {
    if stack.is_null() {
        return;
    }

    unsafe {
        (*stack).major_function = major_function;
        (*stack).minor_function = minor_function;
        (*stack).flags = 0;
        (*stack).control = 0;
        (*stack).device_object = device;
        (*stack).file_object = file;
        (*stack).parameters = IoParameters { as_u64: 0 };
    }
}

pub fn build_synchronous_irp(
    major_function: u8,
    device: *mut DeviceObject,
    buffer: *mut u8,
    length: u32,
) -> *mut Irp {
    let irp = super::allocate_irp(1);
    if irp.is_null() {
        return null_mut();
    }

    unsafe {
        let stack = (*irp).current_stack;
        if !stack.is_null() {
            (*stack).major_function = major_function;
            (*stack).minor_function = 0;
            (*stack).device_object = device;
            (*stack).file_object = null_mut();

            let params = ((length as u64) << 32) | (buffer as u64 & 0xFFFFFFFF);
            (*stack).parameters = IoParameters { as_u64: params };
        }

        (*irp).flags |= super::cancel::IRP_SYNCHRONOUS_API;
    }

    irp
}

pub fn build_device_io_control_irp(
    io_control_code: u32,
    device: *mut DeviceObject,
    input_buffer: *mut u8,
    input_length: u32,
    output_buffer: *mut u8,
    output_length: u32,
) -> *mut Irp {
    let irp = super::allocate_irp(1);
    if irp.is_null() {
        return null_mut();
    }

    unsafe {
        let stack = (*irp).current_stack;
        if !stack.is_null() {
            (*stack).major_function = super::major::IRP_MJ_DEVICE_CONTROL;
            (*stack).minor_function = 0;
            (*stack).device_object = device;
            (*stack).file_object = null_mut();

            (*stack).parameters = IoParameters {
                as_u64: io_control_code as u64
            };
        }

        let _ = (input_buffer, input_length, output_buffer, output_length);
    }

    irp
}

pub fn get_read_write_parameters(
    stack: *const IoStackLocation,
) -> Option<(*mut u8, u32, u64)> {
    if stack.is_null() {
        return None;
    }

    unsafe {
        let params = (*stack).parameters.as_u64;
        let buffer = (params & 0xFFFFFFFF) as *mut u8;
        let length = ((params >> 32) & 0xFFFFFFFF) as u32;

        let offset = 0u64;

        Some((buffer, length, offset))
    }
}

pub fn set_read_write_parameters(
    stack: *mut IoStackLocation,
    buffer: *mut u8,
    length: u32,
    offset: u64,
) {
    if stack.is_null() {
        return;
    }

    unsafe {
        let params = ((length as u64) << 32) | (buffer as u64 & 0xFFFFFFFF);
        (*stack).parameters = IoParameters { as_u64: params };

        let _ = offset;
    }
}
