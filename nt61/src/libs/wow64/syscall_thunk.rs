//! syscall_thunk — 32-bit System Call Thunking for WoW64
//
//! When a 32-bit application issues a system call (via `syscall` instruction
//! on x86_64 or via `int 2e` on x86 compatibility mode), the call first
//! goes to ntdll.dll which then calls into wow64.dll's `wow64_system_service_ex`.
//! This module implements that entry point and dispatches to the appropriate
//! 64-bit kernel service.
//
//! # Call Flow
//! ```text
//! 32-bit App -> ntdll.dll (NtXxx) -> wow64.dll (wow64_system_service_ex)
//!     -> [syscall_thunk] -> 64-bit Kernel -> Return to Wow64
//!     -> Return to 32-bit App
//! ```
//
//! References:
//!   * geoffchappell.com — wow64 system service dispatching
//!   * ReactOS `win32ss/gdi/gdi32/objects/thunk.c`

use crate::libs::ntdll::exception::{
    Context as NtExceptionContext, ExceptionRecord as NtExceptionRecord,
};
use crate::libs::ntdll::thread::Context as NtThreadContext;
use crate::libs::ntdll::types::client_id as NtClientId;
use crate::libs::ntdll::types::PVOID as NtPVOID;
use crate::libs::wow64::ssd::{self, service_numbers};
use crate::libs::wow64::types::*;

// 32-bit NTSTATUS values (unsigned representation, see ssd.rs for context).
pub const STATUS_SUCCESS_32: ULONG32 = 0x00000000;
const STATUS_INVALID_SYSTEM_SERVICE_32: ULONG32 = 0xC000001C;
const STATUS_INVALID_PARAMETER_32: ULONG32 = 0xC000000D;
pub const STATUS_NO_MEMORY_32: ULONG32 = 0xC0000017;
const STATUS_INVALID_HANDLE_32: ULONG32 = 0xC0000008;
pub const STATUS_UNSUCCESSFUL_32: ULONG32 = 0xC0000001;
pub const STATUS_ACCESS_DENIED_32: ULONG32 = 0xC0000022;

// =============================================================================
// Wow64 System Service Entry Point
// =============================================================================

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `wow64_system_service_ex` — The main Wow64 system service dispatcher.
pub unsafe extern "C" fn wow64_system_service_ex(
    service_table: ULONG32,
    service_number: ULONG32,
    args: ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64SystemServiceEx tbl=0x{:08x} svc=0x{:03x} args=0x{:08x}",
        service_table,
        service_number,
        args
    );
    if service_table == 0 || args == 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    let table_index = ssd::get_table_index(service_number);
    let service_index = ssd::get_service_index(service_number);
    crate::wow64_klog!("Dispatch tbl={} idx=0x{:03x}", table_index, service_index);

    match ssd::lookup_service(service_number) {
        Some(handler) => handler(args as *const u32),
        None => dispatch_service(service_number, args as *const u32),
    }
}

// =============================================================================
// Service Dispatch
// =============================================================================

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn dispatch_service(service_number: ULONG32, args: *const u32) -> ULONG32 {
    if args.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    match service_number {
        service_numbers::NT_ALLOCATE_VIRTUAL_MEMORY => nt_allocate_virtual_memory_thunk(args),
        service_numbers::NT_FREE_VIRTUAL_MEMORY => nt_free_virtual_memory_thunk(args),
        service_numbers::NT_QUERY_VIRTUAL_MEMORY => nt_query_virtual_memory_thunk(args),
        service_numbers::NT_PROTECT_VIRTUAL_MEMORY => nt_protect_virtual_memory_thunk(args),
        service_numbers::NT_READ_PROCESS_MEMORY => nt_read_process_memory_thunk(args),
        service_numbers::NT_WRITE_PROCESS_MEMORY => nt_write_process_memory_thunk(args),

        service_numbers::NT_CREATE_PROCESS => nt_create_process_thunk(args),
        service_numbers::NT_OPEN_PROCESS => nt_open_process_thunk(args),
        service_numbers::NT_QUERY_INFORMATION_PROCESS => nt_query_information_process_thunk(args),
        service_numbers::NT_SET_INFORMATION_PROCESS => nt_set_information_process_thunk(args),

        service_numbers::NT_CREATE_THREAD => nt_create_thread_thunk(args),
        service_numbers::NT_OPEN_THREAD => nt_open_thread_thunk(args),
        service_numbers::NT_GET_CONTEXT_THREAD => nt_get_context_thread_thunk(args),
        service_numbers::NT_SET_CONTEXT_THREAD => nt_set_context_thread_thunk(args),
        service_numbers::NT_QUERY_INFORMATION_THREAD => nt_query_information_thread_thunk(args),
        service_numbers::NT_SET_INFORMATION_THREAD => nt_set_information_thread_thunk(args),

        service_numbers::NT_RAISE_EXCEPTION => nt_raise_exception_thunk(args),
        service_numbers::NT_DISPATCH_EXCEPTION => nt_dispatch_exception_thunk(args),

        _ => {
            crate::wow64_klog!("Unhandled service 0x{:03x}", service_number);
            STATUS_INVALID_SYSTEM_SERVICE_32
        }
    }
}

// =============================================================================
// Memory Management Thunks
// =============================================================================

unsafe extern "C" fn nt_allocate_virtual_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle = *args;
    let base_address_ptr = args.add(1) as *mut u32;
    let zero_bits = *args.add(2);
    let region_size_ptr = args.add(3) as *mut u32;
    let allocation_type = *args.add(4);
    let protect = *args.add(5);

    crate::wow64_klog!(
        "NtAllocateVirtualMemory proc=0x{:08x} type=0x{:08x} prot=0x{:08x} zb={:#x}",
        process_handle,
        allocation_type,
        protect,
        zero_bits
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if base_address_ptr.is_null() || region_size_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }

    let handle64 = process_handle as usize as *mut core::ffi::c_void;
    let mut base: usize = (*base_address_ptr) as usize;
    let mut size: usize = (*region_size_ptr) as usize;

    let status = crate::libs::ntdll::virtual_mem::nt_allocate_virtual_memory(
        handle64,
        &mut base as *mut usize as *mut NtPVOID,
        0,
        &mut size,
        allocation_type,
        protect,
    );

    if status >= 0 {
        *base_address_ptr = base as u32;
        *region_size_ptr = size as u32;
    }
    status as u32
}

unsafe extern "C" fn nt_free_virtual_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle = *args;
    let base_address_ptr = args.add(1) as *mut u32;
    let region_size_ptr = args.add(2) as *mut u32;
    let free_type = *args.add(3);

    crate::wow64_klog!(
        "NtFreeVirtualMemory proc=0x{:08x} type=0x{:08x}",
        process_handle,
        free_type
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if base_address_ptr.is_null() || region_size_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let handle64 = process_handle as usize as *mut core::ffi::c_void;
    let mut base: usize = (*base_address_ptr) as usize;
    let mut size: usize = (*region_size_ptr) as usize;
    let status = crate::libs::ntdll::virtual_mem::nt_free_virtual_memory(
        handle64,
        &mut base as *mut usize as *mut NtPVOID,
        &mut size,
        free_type,
    );
    if status >= 0 {
        *base_address_ptr = base as u32;
        *region_size_ptr = size as u32;
    }
    status as u32
}

unsafe extern "C" fn nt_query_virtual_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle = *args;
    let base_address = *args.add(1);
    let memory_info_class = *args.add(2);
    let memory_info_ptr = args.add(3) as *mut u8;
    let memory_info_length = *args.add(4);
    let return_length_ptr = args.add(5) as *mut u32;

    crate::wow64_klog!(
        "NtQueryVirtualMemory proc=0x{:08x} addr=0x{:08x} class={} len={}",
        process_handle,
        base_address,
        memory_info_class,
        memory_info_length
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if memory_info_ptr.is_null() || memory_info_length == 0 {
        return STATUS_INVALID_PARAMETER_32;
    }

    let handle64 = process_handle as usize as *mut core::ffi::c_void;
    let base64 = base_address as usize as *mut core::ffi::c_void;
    let mut return_length: usize = 0;

    let status = crate::libs::ntdll::virtual_mem::nt_query_virtual_memory(
        handle64,
        base64,
        memory_info_class,
        memory_info_ptr as *mut core::ffi::c_void,
        memory_info_length as usize,
        &mut return_length,
    );

    if status >= 0 && !return_length_ptr.is_null() {
        *return_length_ptr = return_length as u32;
    }
    status as u32
}

unsafe extern "C" fn nt_protect_virtual_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle = *args;
    let base_address_ptr = args.add(1) as *mut u32;
    let region_size_ptr = args.add(2) as *mut u32;
    let new_protect = *args.add(3);
    let old_protect_ptr = args.add(4) as *mut u32;

    crate::wow64_klog!(
        "NtProtectVirtualMemory proc=0x{:08x} prot=0x{:08x}",
        process_handle,
        new_protect
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if base_address_ptr.is_null() || region_size_ptr.is_null() || old_protect_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let handle64 = process_handle as usize as *mut core::ffi::c_void;
    let mut base: usize = (*base_address_ptr) as usize;
    let mut size: usize = (*region_size_ptr) as usize;
    let mut old_protect: u32 = 0;
    let status = crate::libs::ntdll::virtual_mem::nt_protect_virtual_memory(
        handle64,
        &mut base as *mut usize as *mut NtPVOID,
        &mut size,
        new_protect,
        &mut old_protect,
    );
    if status >= 0 {
        *base_address_ptr = base as u32;
        *region_size_ptr = size as u32;
        *old_protect_ptr = old_protect;
    }
    status as u32
}

unsafe extern "C" fn nt_read_process_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle = *args;
    let base_address = *args.add(1);
    let buffer = *args.add(2);
    let size = *args.add(3);
    let number_of_bytes_read_ptr = args.add(4) as *mut u32;

    crate::wow64_klog!(
        "NtReadProcessMemory proc=0x{:08x} addr=0x{:08x} size=0x{:08x}",
        process_handle,
        base_address,
        size
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if size == 0 || number_of_bytes_read_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let handle64 = process_handle as usize as *mut core::ffi::c_void;
    let base64 = base_address as usize as *mut core::ffi::c_void;
    let buffer64 = buffer as usize as *mut core::ffi::c_void;
    let mut bytes_read: usize = 0;
    let status = crate::libs::ntdll::virtual_mem::nt_read_virtual_memory(
        handle64,
        base64,
        buffer64,
        size as usize,
        &mut bytes_read,
    );
    if status >= 0 && !number_of_bytes_read_ptr.is_null() {
        *number_of_bytes_read_ptr = bytes_read as u32;
    }
    status as u32
}

unsafe extern "C" fn nt_write_process_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle = *args;
    let base_address = *args.add(1);
    let buffer = *args.add(2);
    let size = *args.add(3);
    let number_of_bytes_written_ptr = args.add(4) as *mut u32;

    crate::wow64_klog!(
        "NtWriteProcessMemory proc=0x{:08x} addr=0x{:08x} size=0x{:08x}",
        process_handle,
        base_address,
        size
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if size == 0 || number_of_bytes_written_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let handle64 = process_handle as usize as *mut core::ffi::c_void;
    let base64 = base_address as usize as *mut core::ffi::c_void;
    let buffer64 = buffer as usize as *mut core::ffi::c_void;
    let mut bytes_written: usize = 0;
    let status = crate::libs::ntdll::virtual_mem::nt_write_virtual_memory(
        handle64,
        base64,
        buffer64,
        size as usize,
        &mut bytes_written,
    );
    if status >= 0 && !number_of_bytes_written_ptr.is_null() {
        *number_of_bytes_written_ptr = bytes_written as u32;
    }
    status as u32
}

// =============================================================================
// Process Services Thunks
// =============================================================================

unsafe extern "C" fn nt_create_process_thunk(args: *const u32) -> ULONG32 {
    let process_handle_ptr = args.add(0) as *mut u32;
    let desired_access = *args.add(1);
    let object_attributes = *args.add(2);
    let parent_process = *args.add(3);
    let inherit_handle = *args.add(4);
    let section_handle = *args.add(5);
    let debug_port = *args.add(6);
    let token = *args.add(7);

    crate::wow64_klog!(
        "NtCreateProcess parent=0x{:08x} access=0x{:08x} inherit={} section=0x{:08x}",
        parent_process,
        desired_access,
        inherit_handle,
        section_handle
    );
    if process_handle_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = (object_attributes, debug_port, token, inherit_handle);
    let parent64 = parent_process as usize as *mut core::ffi::c_void;
    let mut handle64: crate::libs::ntdll::types::HANDLE = core::ptr::null_mut();
    let status = crate::libs::ntdll::process::nt_create_process(
        &mut handle64,
        desired_access,
        core::ptr::null_mut(),
        parent64,
        inherit_handle as u8,
        section_handle as usize as *mut core::ffi::c_void,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    if status >= 0 {
        *process_handle_ptr = handle64 as usize as u32;
    }
    status as u32
}

unsafe extern "C" fn nt_open_process_thunk(args: *const u32) -> ULONG32 {
    let process_handle_ptr = args.add(0) as *mut u32;
    let desired_access = *args.add(1);
    let object_attributes = *args.add(2);
    let client_id = args.add(3) as *const ClientId32;

    let pid = if !client_id.is_null() {
        (*client_id).unique_process
    } else {
        0
    };
    crate::wow64_klog!(
        "NtOpenProcess access=0x{:08x} pid=0x{:08x}",
        desired_access,
        pid
    );
    if process_handle_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = object_attributes;
    let mut handle64: crate::libs::ntdll::types::HANDLE = core::ptr::null_mut();
    let mut cid64 = NtClientId {
        unique_process: pid as usize as *mut core::ffi::c_void,
        unique_thread: core::ptr::null_mut(),
    };
    let status = crate::libs::ntdll::process::nt_open_process(
        &mut handle64,
        desired_access,
        core::ptr::null_mut(),
        &mut cid64,
    );
    if status >= 0 {
        *process_handle_ptr = handle64 as usize as u32;
    }
    status as u32
}

unsafe extern "C" fn nt_query_information_process_thunk(args: *const u32) -> ULONG32 {
    let process_handle = *args;
    let info_class = *args.add(1);
    let info_ptr = args.add(2) as *mut u8;
    let info_length = *args.add(3);
    let return_length_ptr = args.add(4) as *mut u32;

    crate::wow64_klog!(
        "NtQueryInformationProcess handle=0x{:08x} class={} len={}",
        process_handle,
        info_class,
        info_length
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if info_ptr.is_null() || info_length == 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    let handle64 = process_handle as usize as *mut core::ffi::c_void;
    let status = crate::libs::ntdll::process::nt_query_information_process(
        handle64,
        info_class,
        info_ptr as *mut core::ffi::c_void,
        info_length,
        return_length_ptr,
    );
    status as u32
}

unsafe extern "C" fn nt_set_information_process_thunk(args: *const u32) -> ULONG32 {
    let process_handle = *args;
    let info_class = *args.add(1);
    let info_ptr = *args.add(2);
    let info_length = *args.add(3);

    crate::wow64_klog!(
        "NtSetInformationProcess handle=0x{:08x} class={} len={:#x}",
        process_handle,
        info_class,
        info_length
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if info_ptr == 0 && info_length != 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    let handle64 = process_handle as usize as *mut core::ffi::c_void;
    let info64 = info_ptr as usize as *mut core::ffi::c_void;
    let status = crate::libs::ntdll::process::nt_set_information_process(
        handle64,
        info_class,
        info64,
        info_length,
    );
    status as u32
}

// =============================================================================
// Thread Services Thunks
// =============================================================================

unsafe extern "C" fn nt_create_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle_ptr = args.add(0) as *mut u32;
    let desired_access = *args.add(1);
    let object_attributes = *args.add(2);
    let process_handle = *args.add(3);
    let client_id_ptr = args.add(4) as *mut ClientId32;
    let thread_context = args.add(5) as *const Context32;
    let user_stack = args.add(6);
    let start_routine = *args.add(7);

    crate::wow64_klog!(
        "NtCreateThread proc=0x{:08x} start=0x{:08x} access=0x{:08x}",
        process_handle,
        start_routine,
        desired_access
    );
    if process_handle == 0 || start_routine == 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = (
        thread_handle_ptr,
        object_attributes,
        client_id_ptr,
        thread_context,
        user_stack,
    );
    let proc64 = process_handle as usize as *mut core::ffi::c_void;
    let mut handle64: crate::libs::ntdll::types::HANDLE = core::ptr::null_mut();
    let mut tid64 = NtClientId::new();
    let stack64 = user_stack as usize as *mut core::ffi::c_void;
    let start64 = start_routine as usize as *mut core::ffi::c_void;
    let status = crate::libs::ntdll::thread::nt_create_thread(
        &mut handle64,
        desired_access,
        core::ptr::null_mut(),
        proc64,
        &mut tid64,
        stack64,
        start64,
        0, // stack_committed
        0, // stack_size
    );
    if status >= 0 {
        if !thread_handle_ptr.is_null() {
            *thread_handle_ptr = handle64 as usize as u32;
        }
        if !client_id_ptr.is_null() {
            (*client_id_ptr).unique_thread = tid64.unique_thread as usize as u32;
            (*client_id_ptr).unique_process = process_handle;
        }
    }
    status as u32
}

unsafe extern "C" fn nt_open_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle_ptr = args.add(0) as *mut u32;
    let desired_access = *args.add(1);
    let object_attributes = *args.add(2);
    let client_id = args.add(3) as *const ClientId32;

    let tid = if !client_id.is_null() {
        (*client_id).unique_thread
    } else {
        0
    };
    crate::wow64_klog!(
        "NtOpenThread access=0x{:08x} tid=0x{:08x}",
        desired_access,
        tid
    );
    if thread_handle_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = object_attributes;
    let mut handle64: crate::libs::ntdll::types::HANDLE = core::ptr::null_mut();
    let mut cid64 = NtClientId {
        unique_process: core::ptr::null_mut(),
        unique_thread: tid as usize as *mut core::ffi::c_void,
    };
    let status = crate::libs::ntdll::thread::nt_open_thread(
        &mut handle64,
        desired_access,
        core::ptr::null_mut(),
        &mut cid64,
    );
    if status >= 0 {
        *thread_handle_ptr = handle64 as usize as u32;
    }
    status as u32
}

unsafe extern "C" fn nt_get_context_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle = *args;
    let context_ptr = args.add(1) as *mut Context32;
    let context_length = *args.add(2);

    crate::wow64_klog!(
        "NtGetContextThread handle=0x{:08x} len=0x{:08x}",
        thread_handle,
        context_length
    );
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if context_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let handle64 = thread_handle as usize as *mut core::ffi::c_void;
    let mut ctx64 = NtThreadContext::default();
    ctx64.context_flags = crate::libs::ntdll::thread::CONTEXT_FULL;
    let status = crate::libs::ntdll::thread::nt_get_context_thread(handle64, &mut ctx64);
    if status >= 0 {
        (*context_ptr).context_flags = Context32::CONTEXT_FULL;
        (*context_ptr).eax = ctx64.rax as u32;
        (*context_ptr).ebx = ctx64.rbx as u32;
        (*context_ptr).ecx = ctx64.rcx as u32;
        (*context_ptr).edx = ctx64.rdx as u32;
        (*context_ptr).esi = ctx64.rsi as u32;
        (*context_ptr).edi = ctx64.rdi as u32;
        (*context_ptr).ebp = ctx64.rbp as u32;
        (*context_ptr).esp = ctx64.rsp as u32;
        (*context_ptr).eip = ctx64.rip as u32;
        (*context_ptr).eflags = 0; // NtThreadContext does not carry EFLAGS
        (*context_ptr).cs = 0x23;
        (*context_ptr).ss = 0x2B;
    }
    status as u32
}

unsafe extern "C" fn nt_set_context_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle = *args;
    let context_ptr = args.add(1) as *const Context32;
    let context_length = *args.add(2);

    crate::wow64_klog!(
        "NtSetContextThread handle=0x{:08x} len=0x{:08x}",
        thread_handle,
        context_length
    );
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if context_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let handle64 = thread_handle as usize as *mut core::ffi::c_void;
    let mut ctx64 = NtThreadContext::default();
    ctx64.context_flags = (*context_ptr).context_flags;
    ctx64.rax = (*context_ptr).eax as u64;
    ctx64.rbx = (*context_ptr).ebx as u64;
    ctx64.rcx = (*context_ptr).ecx as u64;
    ctx64.rdx = (*context_ptr).edx as u64;
    ctx64.rsi = (*context_ptr).esi as u64;
    ctx64.rdi = (*context_ptr).edi as u64;
    ctx64.rbp = (*context_ptr).ebp as u64;
    ctx64.rsp = (*context_ptr).esp as u64;
    ctx64.rip = (*context_ptr).eip as u64;
    let status = crate::libs::ntdll::thread::nt_set_context_thread(handle64, &ctx64);
    status as u32
}

unsafe extern "C" fn nt_query_information_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle = *args;
    let info_class = *args.add(1);
    let info_ptr = args.add(2) as *mut u8;
    let info_length = *args.add(3);
    let return_length_ptr = args.add(4) as *mut u32;

    crate::wow64_klog!(
        "NtQueryInformationThread handle=0x{:08x} class={} len={}",
        thread_handle,
        info_class,
        info_length
    );
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if info_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let handle64 = thread_handle as usize as *mut core::ffi::c_void;
    let status = crate::libs::ntdll::thread::nt_query_information_thread(
        handle64,
        info_class,
        info_ptr as *mut core::ffi::c_void,
        info_length,
        return_length_ptr,
    );
    status as u32
}

unsafe extern "C" fn nt_set_information_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle = *args;
    let info_class = *args.add(1);
    let info_ptr = *args.add(2);
    let info_length = *args.add(3);

    crate::wow64_klog!(
        "NtSetInformationThread handle=0x{:08x} class={} len={:#x}",
        thread_handle,
        info_class,
        info_length
    );
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if info_ptr == 0 && info_length != 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    let handle64 = thread_handle as usize as *mut core::ffi::c_void;
    let info64 = info_ptr as usize as *mut core::ffi::c_void;
    let status = crate::libs::ntdll::thread::nt_set_information_thread(
        handle64,
        info_class,
        info64,
        info_length,
    );
    status as u32
}

// =============================================================================
// Exception Handling Thunks
// =============================================================================

unsafe extern "C" fn nt_raise_exception_thunk(args: *const u32) -> ULONG32 {
    let exception_record = args.add(0) as *const ExceptionRecord32;
    let context_ptr = args.add(1) as *mut Context32;
    let first_chance = *args.add(2);

    let code = if !exception_record.is_null() {
        (*exception_record).exception_code
    } else {
        0
    };
    crate::wow64_klog!(
        "NtRaiseException code=0x{:08x} first_chance={}",
        code,
        first_chance
    );
    if exception_record.is_null() || context_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let mut rec64 = NtExceptionRecord {
        exception_code: (*exception_record).exception_code,
        exception_flags: (*exception_record).exception_flags,
        exception_record: core::ptr::null_mut(),
        exception_address: (*exception_record).exception_address as usize as *mut core::ffi::c_void,
        number_parameters: (*exception_record).number_parameters,
        exception_information: [0; 15],
    };
    let mut ctx64 = NtExceptionContext::new();
    ctx64.context_flags = (*context_ptr).context_flags;
    ctx64.rip = (*context_ptr).eip as u64;
    ctx64.rsp = (*context_ptr).esp as u64;
    ctx64.rbp = (*context_ptr).ebp as u64;
    ctx64.rax = (*context_ptr).eax as u64;
    ctx64.rbx = (*context_ptr).ebx as u64;
    ctx64.rcx = (*context_ptr).ecx as u64;
    ctx64.rdx = (*context_ptr).edx as u64;
    ctx64.rsi = (*context_ptr).esi as u64;
    ctx64.rdi = (*context_ptr).edi as u64;
    let status = crate::libs::ntdll::exception::nt_raise_exception(
        &mut rec64,
        &mut ctx64,
        first_chance as u8,
    );
    status as u32
}

unsafe extern "C" fn nt_dispatch_exception_thunk(args: *const u32) -> ULONG32 {
    let exception_record = args.add(0) as *const ExceptionRecord32;
    let context_ptr = args.add(1) as *mut Context32;

    let code = if !exception_record.is_null() {
        (*exception_record).exception_code
    } else {
        0
    };
    crate::wow64_klog!("NtDispatchException code=0x{:08x}", code);
    if exception_record.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = context_ptr;
    // NtDispatchException in the kernel routes to the exception dispatcher;
    // the 64-bit side does not expose a standalone function, so we reuse
    // nt_raise_exception with first_chance = 0 (unhandled).
    let mut rec64 = NtExceptionRecord {
        exception_code: (*exception_record).exception_code,
        exception_flags: (*exception_record).exception_flags,
        exception_record: core::ptr::null_mut(),
        exception_address: (*exception_record).exception_address as usize as *mut core::ffi::c_void,
        number_parameters: (*exception_record).number_parameters,
        exception_information: [0; 15],
    };
    let mut ctx64 = NtExceptionContext::new();
    ctx64.context_flags = (*context_ptr).context_flags;
    ctx64.rip = (*context_ptr).eip as u64;
    ctx64.rsp = (*context_ptr).esp as u64;
    ctx64.rbp = (*context_ptr).ebp as u64;
    ctx64.rax = (*context_ptr).eax as u64;
    ctx64.rbx = (*context_ptr).ebx as u64;
    ctx64.rcx = (*context_ptr).ecx as u64;
    ctx64.rdx = (*context_ptr).edx as u64;
    ctx64.rsi = (*context_ptr).esi as u64;
    ctx64.rdi = (*context_ptr).edi as u64;
    let status = crate::libs::ntdll::exception::nt_raise_exception(&mut rec64, &mut ctx64, 0);
    status as u32
}

// =============================================================================
// Fast Path Helpers
// =============================================================================

pub fn fast_path_ntcurrentteb() -> ULONG32 {
    TEB32_BASE_ADDRESS
}

pub fn fast_path_get_current_processor() -> ULONG32 {
    0
}

// =============================================================================
// Initialization
// =============================================================================

pub fn init() {
    crate::wow64_klog!("Initializing syscall thunk layer");
    ssd::init_service_table();
    register_service_thunks();
    crate::wow64_klog!("Syscall thunk layer initialized");
}

fn register_service_thunks() {
    use crate::libs::wow64::ssd as ssd_mod;
    use crate::libs::wow64::ssd::service_numbers as svc;

    ssd_mod::update_service_handler(
        svc::NT_ALLOCATE_VIRTUAL_MEMORY,
        nt_allocate_virtual_memory_thunk,
    );
    ssd_mod::update_service_handler(svc::NT_FREE_VIRTUAL_MEMORY, nt_free_virtual_memory_thunk);
    ssd_mod::update_service_handler(svc::NT_QUERY_VIRTUAL_MEMORY, nt_query_virtual_memory_thunk);
    ssd_mod::update_service_handler(
        svc::NT_PROTECT_VIRTUAL_MEMORY,
        nt_protect_virtual_memory_thunk,
    );
    ssd_mod::update_service_handler(svc::NT_READ_PROCESS_MEMORY, nt_read_process_memory_thunk);
    ssd_mod::update_service_handler(svc::NT_WRITE_PROCESS_MEMORY, nt_write_process_memory_thunk);

    ssd_mod::update_service_handler(svc::NT_CREATE_PROCESS, nt_create_process_thunk);
    ssd_mod::update_service_handler(svc::NT_OPEN_PROCESS, nt_open_process_thunk);
    ssd_mod::update_service_handler(
        svc::NT_QUERY_INFORMATION_PROCESS,
        nt_query_information_process_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_SET_INFORMATION_PROCESS,
        nt_set_information_process_thunk,
    );

    ssd_mod::update_service_handler(svc::NT_CREATE_THREAD, nt_create_thread_thunk);
    ssd_mod::update_service_handler(svc::NT_OPEN_THREAD, nt_open_thread_thunk);
    ssd_mod::update_service_handler(svc::NT_GET_CONTEXT_THREAD, nt_get_context_thread_thunk);
    ssd_mod::update_service_handler(svc::NT_SET_CONTEXT_THREAD, nt_set_context_thread_thunk);
    ssd_mod::update_service_handler(
        svc::NT_QUERY_INFORMATION_THREAD,
        nt_query_information_thread_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_SET_INFORMATION_THREAD,
        nt_set_information_thread_thunk,
    );

    ssd_mod::update_service_handler(svc::NT_RAISE_EXCEPTION, nt_raise_exception_thunk);
    ssd_mod::update_service_handler(svc::NT_DISPATCH_EXCEPTION, nt_dispatch_exception_thunk);

    crate::wow64_klog!("Service thunks registered");
}
