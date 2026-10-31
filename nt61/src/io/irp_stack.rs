//! IRP Stack Management
//!
//! Each IRP contains a stack of I/O stack locations, one for each driver
//! in the device stack. As the IRP travels down the stack, each driver
//! gets its own stack location with parameters for that layer.

use super::{
    DeviceIoControlParameters, DeviceObject, FileObject, IoParameters, IoStackLocation, Irp,
    ReadWriteParameters,
};
use core::ptr::null_mut;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[inline]
pub unsafe fn get_current_stack_location(irp: *mut Irp) -> *mut IoStackLocation {
    if irp.is_null() {
        return null_mut();
    }

    unsafe { (*irp).current_stack }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn get_next_stack_location(irp: *mut Irp) -> *mut IoStackLocation {
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

        (stack_base as usize - core::mem::size_of::<IoStackLocation>()) as *mut IoStackLocation
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn skip_current_stack_location(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }

    unsafe {
        // Stack locations are numbered 1..StackCount from the low end of
        // the IRP allocation (see `allocate_irp`): `current_location` is
        // the number of the slot `current_stack` points at. Skipping hands
        // this driver's stack location to the next lower driver, so move
        // the pointer one slot downwards — the same direction
        // `get_next_stack_location` uses — and renumber the current slot
        // accordingly. Refuse to skip when there is no lower slot: moving
        // past the bottom of the allocation would walk off the IRP.
        if (*irp).current_location <= 1 {
            return;
        }
        (*irp).current_location -= 1;
        (*irp).current_stack = ((*irp).current_stack as usize
            - core::mem::size_of::<IoStackLocation>())
            as *mut IoStackLocation;
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn copy_current_irp_stack_location_to_next(irp: *mut Irp) {
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn set_completion_routine(
    irp: *mut Irp,
    completion_routine: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp, *mut ()) -> i32>,
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

        // Store the routine and its context on the stack location so
        // `io_complete_request` can invoke it during IRP completion.
        (*stack).completion_routine = completion_routine;
        (*stack).completion_context = context;
    }
}

pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x20;
pub const SL_INVOKE_ON_CANCEL: u8 = 0x10;
pub const SL_PENDING_RETURNED: u8 = 0x01;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn mark_irp_pending(irp: *mut Irp) {
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn is_irp_pending(irp: *mut Irp) -> bool {
    if irp.is_null() {
        return false;
    }

    unsafe { (*irp).pending_returned != 0 }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn init_stack_location(
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

            (*stack).parameters = IoParameters {
                read_write: ReadWriteParameters {
                    byte_offset: buffer as u64,
                    byte_count: length,
                    key: 0,
                },
            };
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
                device_io_control: DeviceIoControlParameters {
                    output_buffer_length: output_length,
                    input_buffer_length: input_length,
                    io_control_code,
                    type3_input_buffer: input_buffer as *mut (),
                },
            };
        }

        // METHOD_BUFFERED / METHOD_OUT_DIRECT place the caller's output
        // buffer in _IRP.UserBuffer; the input buffer travels in
        // Parameters.DeviceIoControl.Type3InputBuffer.
        (*irp).user_buffer = output_buffer as *mut ();
    }

    irp
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn get_read_write_parameters(
    stack: *const IoStackLocation,
) -> Option<(*mut u8, u32, u64)> {
    if stack.is_null() {
        return None;
    }

    unsafe {
        let params = (*stack).parameters.read_write;
        let buffer = params.byte_offset as *mut u8;
        let length = params.byte_count;

        let offset = 0u64;

        Some((buffer, length, offset))
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn set_read_write_parameters(
    stack: *mut IoStackLocation,
    buffer: *mut u8,
    length: u32,
    offset: u64,
) {
    if stack.is_null() {
        return;
    }
    if length > 0 && buffer.is_null() {
        return;
    }

    unsafe {
        (*stack).parameters = IoParameters {
            read_write: ReadWriteParameters {
                byte_offset: offset,
                byte_count: length,
                key: 0,
            },
        };
    }
}
