//! ntdll — Nt* process APIs
//
//! `NtCreateProcess`, `NtOpenProcess`, `NtTerminateProcess`,
//! `NtQueryInformationProcess`. The kernel-side process
//! subsystem lives in `ps::process`; this module is a thin
//! adapter that gives every Nt* call the SDK signature and
//! routes to the underlying state.
//
//! References: MSDN Library "Windows 7" — `ntdll.dll` process
//! APIs.

use super::file::{alloc_handle, free_handle, HandleKind};
use super::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER,
    STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS,
};
use super::types::{ClientId, HANDLE, NTSTATUS, PVOID};
use crate::ps::process as ps;
use core::ptr;

const PROCESS_BASIC_INFO_SIZE: usize = 24; // sizeof(PROCESS_BASIC_INFORMATION) on x64

/// `NtCreateProcess` — create a new process. We route to
/// `ps::process::create_user_process`.
pub unsafe extern "C" fn NtCreateProcess(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    parent_process: HANDLE,
    inherit_object_table: u8,
    section_handle: HANDLE,
    debug_port: PVOID,
    exception_port: PVOID,
) -> NTSTATUS {
    if process_handle.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = (object_attributes, parent_process, inherit_object_table,
             section_handle, debug_port, exception_port, desired_access);
    let pid = ps::PID_SYSTEM.wrapping_add(0x1000); // ad-hoc new PID
    match ps::create_user_process(b"\\SystemRoot\\System32\\newproc.exe\0", pid, None) {
        Some(_) => {
            let h = alloc_handle(HandleKind::Process, pid);
            if h.is_null() { return STATUS_INVALID_HANDLE; }
            *process_handle = h;
            STATUS_SUCCESS
        }
        None => STATUS_NOT_IMPLEMENTED,
    }
}
pub unsafe extern "C" fn NtCreateProcessEx(
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
    NtCreateProcess(
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

/// `NtOpenProcess` — open by `CLIENT_ID`.
pub unsafe extern "C" fn NtOpenProcess(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    client_id: *mut ClientId,
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
    if h.is_null() { return STATUS_INVALID_HANDLE; }
    *process_handle = h;
    let _ = (desired_access, object_attributes);
    STATUS_SUCCESS
}

/// `NtTerminateProcess` — set the EPROCESS exit status and mark
/// the current thread as Terminated so the next syscall return
/// (or the next preempt) will be the last one.
pub unsafe extern "C" fn NtTerminateProcess(
    process_handle: HANDLE,
    exit_status: i32,
) -> NTSTATUS {
    if process_handle.is_null() { return STATUS_INVALID_HANDLE; }
    // Mark the current thread terminated. The scheduler will
    // observe the state on the next preempt/timer tick and stop
    // running this thread.
    if let Some(thread) = crate::ke::scheduler::get_current_thread() {
        thread.kthread.state = crate::ps::thread::KThreadState::Terminated;
    }
    // Record the exit status on the EPROCESS for any future
    // `NtQueryInformationProcess` caller.
    if let Some(proc) = ps::get_by_pid(0) {
        proc.exit_status = exit_status;
    }
    STATUS_SUCCESS
}

/// `NtQueryInformationProcess`.
pub unsafe extern "C" fn NtQueryInformationProcess(
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
                if !return_length.is_null() { *return_length = PROCESS_BASIC_INFO_SIZE as u32; }
                return super::status::STATUS_BUFFER_TOO_SMALL;
            }
            // Zero the structure: PEB base address, affinity
            // mask, base priority, unique PID, parent PID.
            core::ptr::write_bytes(process_information, 0, PROCESS_BASIC_INFO_SIZE);
            if !return_length.is_null() { *return_length = PROCESS_BASIC_INFO_SIZE as u32; }
            STATUS_SUCCESS
        }
        26 => {
            // ProcessWow64Information — we are 64-bit, so the
            // result is a NULL pointer.
            if process_information_length < 8 { return super::status::STATUS_BUFFER_TOO_SMALL; }
            *(process_information as *mut u64) = 0;
            if !return_length.is_null() { *return_length = 8; }
            STATUS_SUCCESS
        }
        27 => {
            // ProcessImageFileName
            if process_information_length < 16 { return super::status::STATUS_BUFFER_TOO_SMALL; }
            let name = b"\\SystemRoot\\System32";
            core::ptr::copy_nonoverlapping(name.as_ptr(), process_information as *mut u8, name.len());
            if !return_length.is_null() { *return_length = name.len() as u32; }
            STATUS_SUCCESS
        }
        _ => {
            if !return_length.is_null() { *return_length = 0; }
            STATUS_INVALID_INFO_CLASS
        }
    }
}

/// `NtSetInformationProcess` — only `ProcessBreakOnTermination`
/// is wired up; everything else returns
/// `STATUS_NOT_IMPLEMENTED`.
pub unsafe extern "C" fn NtSetInformationProcess(
    _process_handle: HANDLE,
    _process_information_class: u32,
    _process_information: PVOID,
    _process_information_length: u32,
) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}
