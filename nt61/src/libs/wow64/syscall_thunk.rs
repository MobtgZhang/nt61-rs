//! syscall_thunk — 32-bit System Call Thunking for WoW64
//
//! When a 32-bit application issues a system call (via `syscall` instruction
//! on x86_64 or via `int 2e` on x86 compatibility mode), the call first
//! goes to ntdll.dll which then calls into wow64.dll's `Wow64SystemServiceEx`.
//! This module implements that entry point and dispatches to the appropriate
//! 64-bit kernel service.
//
//! # Call Flow
//! ```
//! 32-bit App -> ntdll.dll (NtXxx) -> wow64.dll (Wow64SystemServiceEx)
//!     -> [syscall_thunk] -> 64-bit Kernel -> Return to Wow64
//!     -> Return to 32-bit App
//! ```
//
//! References:
//!   * geoffchappell.com — wow64 system service dispatching
//!   * ReactOS `win32ss/gdi/gdi32/objects/thunk.c`

use crate::libs::wow64::types::*;
use crate::libs::wow64::ssd::{self, service_numbers};

// 32-bit NTSTATUS values (unsigned representation, see ssd.rs for context).
const STATUS_SUCCESS_32: ULONG32           = 0x00000000;
const STATUS_NOT_IMPLEMENTED_32: ULONG32   = 0xC0000002;
const STATUS_INVALID_PARAMETER_32: ULONG32 = 0xC000000D;
const STATUS_NO_MEMORY_32: ULONG32         = 0xC0000017;
const STATUS_INVALID_HANDLE_32: ULONG32    = 0xC0000008;
const STATUS_UNSUCCESSFUL_32: ULONG32      = 0xC0000001;
const STATUS_ACCESS_DENIED_32: ULONG32     = 0xC0000022;

// =============================================================================
// Wow64 System Service Entry Point
// =============================================================================

/// `Wow64SystemServiceEx` — The main Wow64 system service dispatcher.
///
/// This function is called from wow64.dll when a 32-bit application makes
/// a system call. It:
///
/// 1. Extracts the service number from the 32-bit registers/stack
/// 2. Looks up the service in the SSD tables
/// 3. Extracts arguments from the 32-bit stack
/// 4. Calls the appropriate 64-bit kernel service
/// 5. Translates the return value back to 32-bit
///
/// # Arguments
/// * `service_table` - 32-bit pointer to the service table descriptor
/// * `service_number` - The 32-bit system service number
/// * `args` - 32-bit pointer to the argument stack
///
/// # Returns
/// * NTSTATUS (32-bit) from the service
///
/// # Safety
/// This function manipulates CPU state and calls kernel services.
pub unsafe extern "C" fn Wow64SystemServiceEx(
    service_table: ULONG32,
    service_number: ULONG32,
    args: ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64SystemServiceEx tbl=0x{:08x} svc=0x{:03x} args=0x{:08x}",
        service_table, service_number, args
    );

    // Validate service table pointer
    if service_table == 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    if args == 0 {
        return STATUS_INVALID_PARAMETER_32;
    }

    // Decode service number: format is [table:4][index:12]
    let table_index = ssd::get_table_index(service_number);
    let service_index = ssd::get_service_index(service_number);
    crate::wow64_klog!(
        "Dispatch tbl={} idx=0x{:03x}",
        table_index, service_index
    );

    // Look up the service
    match ssd::lookup_service(service_number) {
        Some(handler) => {
            // Found in SSD table - call the registered handler directly
            handler(args as *const u32)
        }
        None => {
            // Service not in the SSD table — fall through to the
            // per-service dispatcher, which knows how to handle
            // the unhooked calls.
            let argv = args as *const u32;
            dispatch_service(service_number, argv)
        }
    }
}

// =============================================================================
// Service Handlers
// =============================================================================

/// Dispatch a specific service call. Called by
/// `Wow64SystemServiceEx` after the SSD lookup has been
/// performed. Each branch is responsible for parsing the
/// argument pointer (which already lives in low memory) and
/// forwarding to the appropriate 64-bit implementation.
pub unsafe fn dispatch_service(
    service_number: ULONG32,
    args: *const u32,
) -> ULONG32 {
    if args.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    match service_number {
        // Memory management services
        service_numbers::NT_ALLOCATE_VIRTUAL_MEMORY => {
            nt_allocate_virtual_memory_thunk(args)
        }
        service_numbers::NT_FREE_VIRTUAL_MEMORY => {
            nt_free_virtual_memory_thunk(args)
        }
        service_numbers::NT_QUERY_VIRTUAL_MEMORY => {
            nt_query_virtual_memory_thunk(args)
        }
        service_numbers::NT_PROTECT_VIRTUAL_MEMORY => {
            nt_protect_virtual_memory_thunk(args)
        }
        service_numbers::NT_READ_PROCESS_MEMORY => {
            nt_read_process_memory_thunk(args)
        }
        service_numbers::NT_WRITE_PROCESS_MEMORY => {
            nt_write_process_memory_thunk(args)
        }

        // Process services
        service_numbers::NT_CREATE_PROCESS => {
            nt_create_process_thunk(args)
        }
        service_numbers::NT_OPEN_PROCESS => {
            nt_open_process_thunk(args)
        }
        service_numbers::NT_QUERY_INFORMATION_PROCESS => {
            nt_query_information_process_thunk(args)
        }
        service_numbers::NT_SET_INFORMATION_PROCESS => {
            nt_set_information_process_thunk(args)
        }

        // Thread services
        service_numbers::NT_CREATE_THREAD => {
            nt_create_thread_thunk(args)
        }
        service_numbers::NT_OPEN_THREAD => {
            nt_open_thread_thunk(args)
        }
        service_numbers::NT_GET_CONTEXT_THREAD => {
            nt_get_context_thread_thunk(args)
        }
        service_numbers::NT_SET_CONTEXT_THREAD => {
            nt_set_context_thread_thunk(args)
        }
        service_numbers::NT_QUERY_INFORMATION_THREAD => {
            nt_query_information_thread_thunk(args)
        }
        service_numbers::NT_SET_INFORMATION_THREAD => {
            nt_set_information_thread_thunk(args)
        }

        // Exception services
        service_numbers::NT_RAISE_EXCEPTION => {
            nt_raise_exception_thunk(args)
        }
        service_numbers::NT_DISPATCH_EXCEPTION => {
            nt_dispatch_exception_thunk(args)
        }

        // Unknown service
        _ => {
            crate::wow64_klog!(
                "Unhandled service 0x{:03x}",
                service_number
            );
            STATUS_NOT_IMPLEMENTED_32
        }
    }
}

// =============================================================================
// Memory Management Thunks
// =============================================================================

/// NtAllocateVirtualMemory thunk (32-bit args).
///
/// # Arguments (from 32-bit stack)
/// * [0] ProcessHandle
/// * [1] BaseAddress (Ptr32*)
/// * [2] ZeroBits
/// * [3] RegionSize (Ptr32*)
/// * [4] AllocationType
/// * [5] Protect
unsafe extern "C" fn nt_allocate_virtual_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle   = *args;
    let base_address_ptr = args.add(1) as *mut u32;
    let zero_bits        = *args.add(2);
    let region_size_ptr  = args.add(3) as *mut u32;
    let allocation_type  = *args.add(4);
    let protect          = *args.add(5);

    crate::wow64_klog!(
        "NtAllocateVirtualMemory proc=0x{:08x} type=0x{:08x} prot=0x{:08x} zb={:#x}",
        process_handle, allocation_type, protect, zero_bits
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if base_address_ptr.is_null() || region_size_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }

    // In a real implementation:
    // 1. Convert 32-bit handle to 64-bit handle
    // 2. Convert 32-bit pointers to 64-bit
    // 3. Call the 64-bit NtAllocateVirtualMemory
    // 4. Convert results back to 32-bit
    //
    // For the wow64 layer we surface a stable
    // STATUS_NOT_IMPLEMENTED so the calling thread is told the
    // service is not yet wired up, rather than masking a real
    // failure as success.
    let _ = region_size_ptr;
    STATUS_NOT_IMPLEMENTED_32
}

/// NtFreeVirtualMemory thunk (32-bit args).
unsafe extern "C" fn nt_free_virtual_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle   = *args;
    let base_address_ptr = args.add(1) as *mut u32;
    let region_size_ptr  = args.add(2) as *mut u32;
    let free_type        = *args.add(3);

    crate::wow64_klog!(
        "NtFreeVirtualMemory proc=0x{:08x} type=0x{:08x}",
        process_handle, free_type
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if base_address_ptr.is_null() || region_size_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    STATUS_NOT_IMPLEMENTED_32
}

/// NtQueryVirtualMemory thunk (32-bit args).
unsafe extern "C" fn nt_query_virtual_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle        = *args;
    let base_address          = *args.add(1);
    let memory_info_class     = *args.add(2);
    let memory_info_ptr       = args.add(3) as *mut u8;
    let memory_info_length    = *args.add(4);
    let return_length_ptr     = args.add(5) as *mut u32;

    crate::wow64_klog!(
        "NtQueryVirtualMemory proc=0x{:08x} addr=0x{:08x} class={} len={}",
        process_handle, base_address, memory_info_class, memory_info_length
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if memory_info_ptr.is_null() || memory_info_length == 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    // MemoryInformationClass values:
    // 0 = MemoryBasicInformation
    // 1 = MemoryWorkingSetList
    // etc.

    let _ = return_length_ptr;
    STATUS_NOT_IMPLEMENTED_32
}

/// NtProtectVirtualMemory thunk (32-bit args).
unsafe extern "C" fn nt_protect_virtual_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle   = *args;
    let base_address_ptr = args.add(1) as *mut u32;
    let region_size_ptr  = args.add(2) as *mut u32;
    let new_protect      = *args.add(3);
    let old_protect_ptr  = args.add(4) as *mut u32;

    crate::wow64_klog!(
        "NtProtectVirtualMemory proc=0x{:08x} prot=0x{:08x}",
        process_handle, new_protect
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if base_address_ptr.is_null() || region_size_ptr.is_null()
        || old_protect_ptr.is_null()
    {
        return STATUS_INVALID_PARAMETER_32;
    }
    STATUS_NOT_IMPLEMENTED_32
}

/// NtReadProcessMemory thunk (32-bit args).
unsafe extern "C" fn nt_read_process_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle             = *args;
    let base_address               = *args.add(1);
    let _buffer                   = *args.add(2);
    let size                       = *args.add(3);
    let number_of_bytes_read_ptr   = args.add(4) as *mut u32;

    crate::wow64_klog!(
        "NtReadProcessMemory proc=0x{:08x} addr=0x{:08x} size=0x{:08x}",
        process_handle, base_address, size
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if size == 0 || number_of_bytes_read_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    STATUS_NOT_IMPLEMENTED_32
}

/// NtWriteProcessMemory thunk (32-bit args).
unsafe extern "C" fn nt_write_process_memory_thunk(args: *const u32) -> ULONG32 {
    let process_handle             = *args;
    let base_address               = *args.add(1);
    let _buffer                   = *args.add(2);
    let size                       = *args.add(3);
    let number_of_bytes_written_ptr = args.add(4) as *mut u32;

    crate::wow64_klog!(
        "NtWriteProcessMemory proc=0x{:08x} addr=0x{:08x} size=0x{:08x}",
        process_handle, base_address, size
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if size == 0 || number_of_bytes_written_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    STATUS_NOT_IMPLEMENTED_32
}

// =============================================================================
// Process Services Thunks
// =============================================================================

/// NtCreateProcess thunk (32-bit args).
unsafe extern "C" fn nt_create_process_thunk(args: *const u32) -> ULONG32 {
    let process_handle_ptr = args.add(0) as *mut u32;
    let desired_access     = *args.add(1);
    let object_attributes  = *args.add(2);
    let parent_process     = *args.add(3);
    let inherit_handle     = *args.add(4);
    let section_handle     = *args.add(5);
    let debug_port         = *args.add(6);
    let token              = *args.add(7);

    crate::wow64_klog!(
        "NtCreateProcess parent=0x{:08x} access=0x{:08x} inherit={} section=0x{:08x}",
        parent_process, desired_access, inherit_handle, section_handle
    );
    if process_handle_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = (object_attributes, debug_port, token);
    STATUS_NOT_IMPLEMENTED_32
}

/// NtOpenProcess thunk (32-bit args).
unsafe extern "C" fn nt_open_process_thunk(args: *const u32) -> ULONG32 {
    let process_handle_ptr = args.add(0) as *mut u32;
    let desired_access     = *args.add(1);
    let object_attributes  = *args.add(2);
    let client_id         = args.add(3) as *const ClientId32;

    let pid = if !client_id.is_null() {
        (*client_id).unique_process
    } else {
        0
    };
    crate::wow64_klog!(
        "NtOpenProcess access=0x{:08x} pid=0x{:08x}",
        desired_access, pid
    );
    if process_handle_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = object_attributes;
    STATUS_NOT_IMPLEMENTED_32
}

/// NtQueryInformationProcess thunk (32-bit args).
unsafe extern "C" fn nt_query_information_process_thunk(args: *const u32) -> ULONG32 {
    let process_handle    = *args;
    let info_class        = *args.add(1);
    let info_ptr          = args.add(2) as *mut u8;
    let info_length       = *args.add(3);
    let return_length_ptr = args.add(4) as *mut u32;

    crate::wow64_klog!(
        "NtQueryInformationProcess handle=0x{:08x} class={} len={}",
        process_handle, info_class, info_length
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if info_ptr.is_null() || info_length == 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    // ProcessWow64Information (26) - return 32-bit PEB address
    // ProcessBasicInformation (0) - return PROCESS_BASIC_INFORMATION
    // etc.
    let _ = return_length_ptr;
    STATUS_NOT_IMPLEMENTED_32
}

/// NtSetInformationProcess thunk (32-bit args).
unsafe extern "C" fn nt_set_information_process_thunk(args: *const u32) -> ULONG32 {
    let process_handle = *args;
    let info_class     = *args.add(1);
    let info_ptr       = *args.add(2);
    let info_length    = *args.add(3);

    crate::wow64_klog!(
        "NtSetInformationProcess handle=0x{:08x} class={} len={:#x}",
        process_handle, info_class, info_length
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if info_ptr == 0 && info_length != 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    STATUS_NOT_IMPLEMENTED_32
}

// =============================================================================
// Thread Services Thunks
// =============================================================================

/// NtCreateThread thunk (32-bit args).
unsafe extern "C" fn nt_create_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle_ptr = args.add(0) as *mut u32;
    let desired_access     = *args.add(1);
    let object_attributes  = *args.add(2);
    let process_handle     = *args.add(3);
    let client_id_ptr      = args.add(4) as *mut ClientId32;
    let thread_context     = args.add(5) as *const Context32;
    let user_stack         = args.add(6);
    let start_routine      = *args.add(7);

    crate::wow64_klog!(
        "NtCreateThread proc=0x{:08x} start=0x{:08x} access=0x{:08x}",
        process_handle, start_routine, desired_access
    );
    if process_handle == 0 || start_routine == 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = (thread_handle_ptr, object_attributes, client_id_ptr,
             thread_context, user_stack);
    STATUS_NOT_IMPLEMENTED_32
}

/// NtOpenThread thunk (32-bit args).
unsafe extern "C" fn nt_open_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle_ptr  = args.add(0) as *mut u32;
    let desired_access     = *args.add(1);
    let object_attributes  = *args.add(2);
    let client_id         = args.add(3) as *const ClientId32;

    let tid = if !client_id.is_null() {
        (*client_id).unique_thread
    } else {
        0
    };
    crate::wow64_klog!(
        "NtOpenThread access=0x{:08x} tid=0x{:08x}",
        desired_access, tid
    );
    if thread_handle_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = object_attributes;
    STATUS_NOT_IMPLEMENTED_32
}

/// NtGetContextThread thunk (32-bit args).
unsafe extern "C" fn nt_get_context_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle    = *args;
    let context_ptr      = args.add(1) as *mut Context32;
    let context_length   = *args.add(2);

    crate::wow64_klog!(
        "NtGetContextThread handle=0x{:08x} len=0x{:08x}",
        thread_handle, context_length
    );
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if context_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    STATUS_NOT_IMPLEMENTED_32
}

/// NtSetContextThread thunk (32-bit args).
unsafe extern "C" fn nt_set_context_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle    = *args;
    let context_ptr      = args.add(1) as *const Context32;
    let context_length   = *args.add(2);

    crate::wow64_klog!(
        "NtSetContextThread handle=0x{:08x} len=0x{:08x}",
        thread_handle, context_length
    );
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if context_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    STATUS_NOT_IMPLEMENTED_32
}

/// NtQueryInformationThread thunk (32-bit args).
unsafe extern "C" fn nt_query_information_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle    = *args;
    let info_class        = *args.add(1);
    let info_ptr          = args.add(2) as *mut u8;
    let info_length       = *args.add(3);
    let return_length_ptr = args.add(4) as *mut u32;

    crate::wow64_klog!(
        "NtQueryInformationThread handle=0x{:08x} class={} len={}",
        thread_handle, info_class, info_length
    );
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if info_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = return_length_ptr;
    STATUS_NOT_IMPLEMENTED_32
}

/// NtSetInformationThread thunk (32-bit args).
unsafe extern "C" fn nt_set_information_thread_thunk(args: *const u32) -> ULONG32 {
    let thread_handle = *args;
    let info_class     = *args.add(1);
    let info_ptr       = *args.add(2);
    let info_length    = *args.add(3);

    crate::wow64_klog!(
        "NtSetInformationThread handle=0x{:08x} class={} len={:#x}",
        thread_handle, info_class, info_length
    );
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE_32;
    }
    if info_ptr == 0 && info_length != 0 {
        return STATUS_INVALID_PARAMETER_32;
    }
    STATUS_NOT_IMPLEMENTED_32
}

// =============================================================================
// Exception Handling Thunks
// =============================================================================

/// NtRaiseException thunk (32-bit args).
unsafe extern "C" fn nt_raise_exception_thunk(args: *const u32) -> ULONG32 {
    let exception_record = args.add(0) as *const ExceptionRecord32;
    let context_ptr      = args.add(1) as *mut Context32;
    let first_chance     = *args.add(2);

    let code = if !exception_record.is_null() {
        (*exception_record).exception_code
    } else {
        0
    };
    crate::wow64_klog!(
        "NtRaiseException code=0x{:08x} first_chance={}",
        code, first_chance
    );
    if exception_record.is_null() || context_ptr.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    STATUS_NOT_IMPLEMENTED_32
}

/// NtDispatchException thunk (32-bit args).
unsafe extern "C" fn nt_dispatch_exception_thunk(args: *const u32) -> ULONG32 {
    let exception_record = args.add(0) as *const ExceptionRecord32;
    let context_ptr      = args.add(1) as *mut Context32;

    let code = if !exception_record.is_null() {
        (*exception_record).exception_code
    } else {
        0
    };
    crate::wow64_klog!(
        "NtDispatchException code=0x{:08x}",
        code
    );
    if exception_record.is_null() {
        return STATUS_INVALID_PARAMETER_32;
    }
    let _ = context_ptr;
    STATUS_NOT_IMPLEMENTED_32
}

// =============================================================================
// Fast Path Helpers
// =============================================================================

/// Fast path for NtCurrentTeb.
/// This avoids the full thunk overhead for frequently called functions.
pub fn fast_path_ntcurrentteb() -> ULONG32 {
    // On x86: mov eax, fs:[0x18]; ret
    // On x64: Need to go through Wow64Pcrb or similar
    // For now, return the TEB32 base address
    TEB32_BASE_ADDRESS
}

/// Fast path for NtGetCurrentProcessorNumber.
pub fn fast_path_get_current_processor() -> ULONG32 {
    // In a real implementation, read from per-CPU data
    0
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the syscall thunk layer.
pub fn init() {
    crate::wow64_klog!("Initializing syscall thunk layer");

    // Initialize the service descriptor table
    ssd::init_service_table();

    // Wire up the real thunks into the SSD tables
    register_service_thunks();

    crate::wow64_klog!("Syscall thunk layer initialized");
}

/// Register all service thunks into the SSD tables.
/// This wires the actual thunk implementations from this module
/// into the base service table so dispatch_service() calls them.
fn register_service_thunks() {
    use crate::libs::wow64::ssd as ssd_mod;
    use crate::libs::wow64::ssd::service_numbers as svc;

    // Memory management services
    ssd_mod::update_service_handler(
        svc::NT_ALLOCATE_VIRTUAL_MEMORY,
        nt_allocate_virtual_memory_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_FREE_VIRTUAL_MEMORY,
        nt_free_virtual_memory_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_QUERY_VIRTUAL_MEMORY,
        nt_query_virtual_memory_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_PROTECT_VIRTUAL_MEMORY,
        nt_protect_virtual_memory_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_READ_PROCESS_MEMORY,
        nt_read_process_memory_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_WRITE_PROCESS_MEMORY,
        nt_write_process_memory_thunk,
    );

    // Process services
    ssd_mod::update_service_handler(
        svc::NT_OPEN_PROCESS,
        nt_open_process_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_QUERY_INFORMATION_PROCESS,
        nt_query_information_process_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_SET_INFORMATION_PROCESS,
        nt_set_information_process_thunk,
    );

    // Thread services
    ssd_mod::update_service_handler(
        svc::NT_CREATE_THREAD,
        nt_create_thread_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_OPEN_THREAD,
        nt_open_thread_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_GET_CONTEXT_THREAD,
        nt_get_context_thread_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_SET_CONTEXT_THREAD,
        nt_set_context_thread_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_QUERY_INFORMATION_THREAD,
        nt_query_information_thread_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_SET_INFORMATION_THREAD,
        nt_set_information_thread_thunk,
    );

    // Exception services
    ssd_mod::update_service_handler(
        svc::NT_RAISE_EXCEPTION,
        nt_raise_exception_thunk,
    );
    ssd_mod::update_service_handler(
        svc::NT_DISPATCH_EXCEPTION,
        nt_dispatch_exception_thunk,
    );

    crate::wow64_klog!("Service thunks registered");
}
