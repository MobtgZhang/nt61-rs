//! `NtDeviceIoControlFile` — general-purpose IOCTL dispatcher.
//!
//! All AFD operations on the kernel boundary are issued via
//! `NtDeviceIoControlFile`. The syscall entry routes the
//! IOCTL code + input/output buffers to a registered dispatcher
//! based on the handle's `kind`. This keeps the file syscalls
//! focused on `File`/`Pipe` and lets AFD evolve independently.

use super::file::{lookup_handle, HandleKind};
use super::status::{STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::types::{HANDLE, IoStatusBlock, PVOID, ULONG};
use crate::mm::user_copy;
use core::ptr;

/// `NtDeviceIoControlFile(file, event, apc, apc_ctx, iosb,
/// ioctl, input, input_len, output, output_len)`
pub unsafe extern "C" fn NtDeviceIoControlFile(
    file_handle: HANDLE,
    _event: HANDLE,
    _apc: PVOID,
    _apc_ctx: PVOID,
    io_status_block: *mut IoStatusBlock,
    io_control_code: ULONG,
    input_buffer: PVOID,
    input_length: ULONG,
    output_buffer: PVOID,
    output_length: ULONG,
) -> i32 {
    if io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // Probe the IOSB before any handle lookup so that a bad user
    // pointer is rejected with STATUS_ACCESS_VIOLATION rather than
    // crashing the kernel.
    if user_copy::probe_user_write(io_status_block as u64,
        core::mem::size_of::<IoStatusBlock>()).is_err() {
        return STATUS_ACCESS_VIOLATION_VALUE;
    }

    let entry = lookup_handle(file_handle);
    let Some(entry) = entry else {
        (*io_status_block).status = STATUS_INVALID_HANDLE;
        (*io_status_block).information = 0;
        return STATUS_INVALID_HANDLE;
    };

    // The dispatcher is allowed to mutate the caller's output
    // buffer in place. Probe every page of the input and output
    // ranges up front; SMAP/SMEP is not yet enforced, so this is
    // the only thing standing between an attacker and a kernel
    // crash / kernel write through a user pointer.
    if input_buffer != ptr::null_mut() && input_length > 0 {
        if user_copy::probe_user_read(input_buffer as u64, input_length as usize).is_err() {
            (*io_status_block).status = STATUS_ACCESS_VIOLATION_VALUE;
            (*io_status_block).information = 0;
            return STATUS_ACCESS_VIOLATION_VALUE;
        }
    }
    if output_buffer != ptr::null_mut() && output_length > 0 {
        if user_copy::probe_user_write(output_buffer as u64, output_length as usize).is_err() {
            (*io_status_block).status = STATUS_ACCESS_VIOLATION_VALUE;
            (*io_status_block).information = 0;
            return STATUS_ACCESS_VIOLATION_VALUE;
        }
    }

    let input_slice: &[u8] = if input_buffer.is_null() || input_length == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(input_buffer as *const u8, input_length as usize)
    };
    let output_slice: &mut [u8] = if output_buffer.is_null() || output_length == 0 {
        &mut []
    } else {
        core::slice::from_raw_parts_mut(output_buffer as *mut u8, output_length as usize)
    };

    let status = match entry.kind {
        HandleKind::Afd => {
            let handle = entry.target;
            crate::netstack::afd::dispatch(handle, io_control_code, input_slice, output_slice)
        }
        _ => {
            // Unknown IOCTL kind — return STATUS_INVALID_HANDLE
            // because we cannot dispatch.
            STATUS_INVALID_HANDLE
        }
    };

    if status == 0 {
        (*io_status_block).status = STATUS_SUCCESS;
        (*io_status_block).information = output_length as usize;
        STATUS_SUCCESS
    } else {
        (*io_status_block).status = status;
        (*io_status_block).information = 0;
        status
    }
}

// STATUS_ACCESS_VIOLATION lives in `super::status` but the integer
// type is `i32`. Pull the numeric value into scope so we can use it
// without the cast for the early-return checks above.
const STATUS_ACCESS_VIOLATION_VALUE: i32 = 0xC0000005_u32 as i32;

/// Allocate an AFD endpoint and register it with the handle
/// table so the caller can issue `NtDeviceIoControlFile` against
/// it. Returns the NT HANDLE on success.
pub fn create_afd_handle(socket_id: u32) -> HANDLE {
    let handle = crate::netstack::afd::create(socket_id);
    let Some(h) = handle else { return ptr::null_mut(); };
    super::file::alloc_handle(HandleKind::Afd, h)
}
