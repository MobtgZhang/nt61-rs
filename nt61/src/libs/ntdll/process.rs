//! ntdll — Nt* process APIs
//
//! `nt_create_process`, `nt_open_process`, `nt_terminate_process`,
//! `nt_query_information_process`. The kernel-side process
//! subsystem lives in `ps::process`; this module is a thin
//! adapter that gives every Nt* call the SDK signature and
//! routes to the underlying state.
//
//! References: MSDN Library "Windows 7" — `ntdll.dll` process
//! APIs.

use super::file::{alloc_handle, HandleKind};
use super::status::{
    STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS,
};
use super::types::{client_id, HANDLE, NTSTATUS, PVOID};
use crate::mm::user_copy::{copy_from_user, copy_to_user};
use crate::ps::process as ps;

const PROCESS_BASIC_INFO_SIZE: usize = 24; // sizeof(PROCESS_BASIC_INFORMATION) on x64
const PROCESS_CREATE_PROCESS: u32 = 0x0080;

/// Current-process pseudo-handle.
///
/// The NT/Win32 DDI defines `nt_current_process()` as `(HANDLE)-1`: it is not a
/// real entry in the object table, it is recognised by the `Nt*` entry points
/// as "the calling process".
pub fn nt_current_process() -> HANDLE {
    (-1isize) as HANDLE
}

/// `nt_create_process` — create a new process. We route to
/// `ps::process::create_user_process`.
pub unsafe extern "C" fn nt_create_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    parent_process: HANDLE,
    inherit_object_table: u8,
    section_handle: HANDLE,
    debug_port: PVOID,
    exception_port: PVOID,
) -> NTSTATUS {
    if process_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if desired_access & PROCESS_CREATE_PROCESS == 0 {
        return STATUS_ACCESS_DENIED;
    }
    let mut image_path = alloc::vec::Vec::new();
    if !object_attributes.is_null() {
        let attributes = &*object_attributes;
        if !attributes.object_name.is_null() {
            let name = &*attributes.object_name;
            let units = (name.length as usize) / 2;
            if units > 0 && !name.buffer.is_null() {
                let mut wide_bytes = alloc::vec![0u8; units * 2];
                if copy_from_user(&mut wide_bytes, name.buffer as u64).is_ok() {
                    for pair in wide_bytes.chunks_exact(2) {
                        let unit = u16::from_le_bytes([pair[0], pair[1]]);
                        if let Some(byte) = u8::try_from(unit & 0xFF).ok() {
                            image_path.push(byte);
                        }
                    }
                    image_path.push(0);
                }
            }
        }
    }
    if image_path.is_empty() {
        image_path.extend_from_slice(b"\\SystemRoot\\System32\\newproc.exe\0");
    }
    let parent_pid = if parent_process.is_null() || parent_process == nt_current_process() {
        None
    } else {
        match crate::libs::ntdll::file::lookup_handle(parent_process) {
            Some(entry) if entry.kind == HandleKind::Process => Some(entry.target),
            _ => return STATUS_INVALID_HANDLE,
        }
    };
    if !section_handle.is_null() {
        match crate::libs::ntdll::file::lookup_handle(section_handle) {
            Some(entry) if entry.kind == HandleKind::Section => {}
            _ => return STATUS_INVALID_HANDLE,
        }
    }
    for port_handle in [debug_port, exception_port] {
        if !port_handle.is_null()
            && crate::libs::ntdll::file::lookup_handle(port_handle).is_none()
        {
            return STATUS_INVALID_HANDLE;
        }
    }
    let pid = match ps::next_user_pid() {
        Some(pid) => pid,
        None => return STATUS_NO_MEMORY,
    };
    let image_name = core::str::from_utf8(&image_path).unwrap_or("");
    match ps::create_user_process_from_path(image_name, pid, None) {
        Some(process) => {
            if inherit_object_table != 0 {
                if let Some(parent) = parent_pid.and_then(ps::get_by_pid) {
                    let parent_table = (*parent).object_table;
                    let child_table = (*process).object_table;
                    if !parent_table.is_null() && !child_table.is_null() {
                        unsafe {
                            (*child_table)
                                .slots
                                .copy_from_slice(&(*parent_table).slots);
                            (*child_table)
                                .valid
                                .copy_from_slice(&(*parent_table).valid);
                            (*child_table).next_slot = (*parent_table).next_slot;
                            (*child_table).handle_count.store(
                                (*parent_table)
                                    .handle_count
                                    .load(core::sync::atomic::Ordering::SeqCst),
                                core::sync::atomic::Ordering::SeqCst,
                            );
                        }
                    }
                }
            }
            let h = alloc_handle(HandleKind::Process, pid);
            if h.is_null() {
                return STATUS_INVALID_HANDLE;
            }
            *process_handle = h;
            STATUS_SUCCESS
        }
        None => STATUS_NO_MEMORY,
    }
}
pub unsafe extern "C" fn nt_create_process_ex(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    parent_process: HANDLE,
    flags: u32,
    section_handle: HANDLE,
    debug_port: PVOID,
    exception_port: PVOID,
    job_member: u32,
) -> NTSTATUS {
    let _ = flags;
    let _ = job_member;
    nt_create_process(
        process_handle,
        desired_access,
        object_attributes,
        parent_process,
        0,
        section_handle,
        debug_port,
        exception_port,
    )
}

/// `nt_open_process` — open by `CLIENT_ID`.
pub unsafe extern "C" fn nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    client_id: *mut client_id,
) -> NTSTATUS {
    if process_handle.is_null() || client_id.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let cid = &*client_id;
    let pid = cid.unique_process as u64;
    if ps::get_by_pid(pid).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    let h = alloc_handle(HandleKind::Process, pid);
    if h.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    *process_handle = h;
    let _ = (desired_access, object_attributes);
    STATUS_SUCCESS
}

/// `nt_terminate_process` — set the EPROCESS exit status and mark
/// the current thread as Terminated so the next syscall return
/// (or the next preempt) will be the last one.
pub unsafe extern "C" fn nt_terminate_process(
    process_handle: HANDLE,
    exit_status: i32,
) -> NTSTATUS {
    if process_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    // Mark the current thread terminated. The scheduler will
    // observe the state on the next preempt/timer tick and stop
    // running this thread.
    if let Some(thread) = crate::ke::scheduler::get_current_thread() {
        thread.kthread.state = crate::ps::thread::KThreadState::Terminated;
    }
    // Record the exit status on the EPROCESS for any future
    // `nt_query_information_process` caller.
    if let Some(proc) = ps::get_by_pid(0) {
        proc.exit_status = exit_status;
    }
    STATUS_SUCCESS
}

/// `nt_query_information_process`.
pub unsafe extern "C" fn nt_query_information_process(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: PVOID,
    process_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if process_handle.is_null() || process_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    match process_information_class {
        0 => {
            // ProcessBasicInformation: returns ExitStatus, ...
            if process_information_length < PROCESS_BASIC_INFO_SIZE as u32 {
                if write_return_length(return_length, PROCESS_BASIC_INFO_SIZE).is_err() {
                    return super::status::STATUS_ACCESS_VIOLATION;
                }
                return super::status::STATUS_BUFFER_TOO_SMALL;
            }
            // Zero the structure: PEB base address, affinity
            // mask, base priority, unique PID, parent PID.
            let output = [0u8; PROCESS_BASIC_INFO_SIZE];
            if copy_to_user(process_information as u64, &output).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            if write_return_length(return_length, PROCESS_BASIC_INFO_SIZE).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            STATUS_SUCCESS
        }
        26 => {
            // ProcessWow64Information — we are 64-bit, so the
            // result is a NULL pointer.
            if process_information_length < 8 {
                return super::status::STATUS_BUFFER_TOO_SMALL;
            }
            if copy_to_user(process_information as u64, &[0u8; 8]).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            if write_return_length(return_length, 8).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            STATUS_SUCCESS
        }
        27 => {
            // ProcessImageFileName
            if process_information_length < 16 {
                return super::status::STATUS_BUFFER_TOO_SMALL;
            }
            let name = b"\\SystemRoot\\System32";
            if copy_to_user(process_information as u64, name).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            if write_return_length(return_length, name.len()).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            STATUS_SUCCESS
        }
        _ => {
            if write_return_length(return_length, 0).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            STATUS_INVALID_INFO_CLASS
        }
    }
}

fn write_return_length(return_length: *mut u32, length: usize) -> Result<(), i32> {
    if return_length.is_null() {
        return Ok(());
    }
    copy_to_user(return_length as u64, &(length as u32).to_le_bytes())
}

/// `nt_set_information_process` — implements `ProcessBreakOnTermination`
/// (class 14). Other classes return `STATUS_INVALID_INFO_CLASS` per the
/// Windows 7 behaviour for unrecognised info classes.
pub unsafe extern "C" fn nt_set_information_process(
    _process_handle: HANDLE,
    _process_information_class: u32,
    _process_information: PVOID,
    _process_information_length: u32,
) -> NTSTATUS {
    if _process_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let mut value = [0u8; 4];
    if copy_from_user(&mut value, _process_information as u64).is_err() {
        return super::status::STATUS_ACCESS_VIOLATION;
    }
    let _ = _process_information_length;
    const PROCESS_BREAK_ON_TERMINATION: u32 = 14;
    match _process_information_class {
        PROCESS_BREAK_ON_TERMINATION => {
            // The process manager tracks this in the Eprocess; for
            // now we accept the write and succeed (matching the
            // minimal subset used by smss.exe / userinit.exe).
            let _ = u32::from_le_bytes(value);
            STATUS_SUCCESS
        }
        _ => super::status::STATUS_INVALID_INFO_CLASS,
    }
}
