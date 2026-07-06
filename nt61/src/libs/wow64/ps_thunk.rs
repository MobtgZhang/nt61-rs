//! ps_thunk — Wow64 Process/Thread Information Thunks
//
//! This module implements the process and thread information thunks that
//! translate 32-bit process/thread queries to their 64-bit equivalents.
//
//! The key functions are:
//!   * Wow64QueryInformationProcess
//!   * Wow64SetInformationProcess
//!   * Wow64QueryInformationThread
//!   * Wow64SetInformationThread
//!   * Wow64GetContextThread
//!   * Wow64SetContextThread
//
//! References:
//!   * geoffchappell.com — wow64 process/thread information

use crate::libs::wow64::types::*;

// =============================================================================
// Wow64QueryInformationProcess
// =============================================================================

/// Query information about a process (32-bit).
///
/// # Arguments
/// * `process_handle` - Handle to the process
/// * `information_class` - Type of information to query
/// * `buffer` - Output buffer (32-bit pointer)
/// * `buffer_size` - Size of output buffer
/// * `return_length` - Actual size needed (output)
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64QueryInformationProcess(
    process_handle: HANDLE32,
    information_class: ULONG32,
    buffer: ULONG32,
    buffer_size: ULONG32,
    return_length: ULONG32_PTR,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64QueryInformationProcess handle=0x{:08x} class={} \
         buf=0x{:08x} sz={} retlen_ptr=0x{:08x}",
        process_handle, information_class, buffer, buffer_size, return_length
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE;
    }

    match information_class {
        // ProcessWow64Information - Return 32-bit PEB address
        26 => {
            // Return the PEB32 virtual address
            if buffer != 0 && buffer_size >= 4 {
                // In real implementation: write PEB32_VIRTUAL_ADDRESS to buffer
                STATUS_SUCCESS
            } else {
                if return_length != 0 {
                    // Would write 4 to return_length
                }
                STATUS_BUFFER_TOO_SMALL
            }
        }

        // ProcessBasicInformation - Return basic process info
        0 => {
            // Return PROCESS_BASIC_INFORMATION32
            // This would be a 32-bit version of the 64-bit structure
            if buffer_size < 24 {
                // sizeof(PROCESS_BASIC_INFORMATION32)
                STATUS_BUFFER_TOO_SMALL
            } else {
                // In real implementation:
                // - ExitStatus (4 bytes)
                // - PebBaseAddress (4 bytes, 64-bit PEB)
                // - AffinityMask (4 bytes)
                // - BasePriority (4 bytes)
                // - UniqueProcessId (4 bytes)
                // - InheritedFromUniqueProcessId (4 bytes)
                STATUS_SUCCESS
            }
        }

        // ProcessImageFileName - Return process image path
        27 => {
            // Return UNICODE_STRING32 for the image path
            STATUS_NOT_IMPLEMENTED
        }

        // ProcessDebugPortHandle - Return debug port
        7 => STATUS_NOT_IMPLEMENTED,

        // ProcessDebugObjectHandle - Return debug object
        30 => STATUS_NOT_IMPLEMENTED,

        // ProcessDebugFlags - Return debug flags
        31 => STATUS_NOT_IMPLEMENTED,

        // ProcessDefaultHardErrorMode - Return default hard error mode
        12 => STATUS_NOT_IMPLEMENTED,

        // ProcessIoPriority - Return I/O priority
        18 => STATUS_NOT_IMPLEMENTED,

        // ProcessAffinityMask - Return affinity mask
        20 => STATUS_NOT_IMPLEMENTED,

        // ProcessPriorityClass - Return priority class
        21 => STATUS_NOT_IMPLEMENTED,

        _ => {
            crate::wow64_klog!(
                "Unknown process information class {}",
                information_class
            );
            STATUS_INVALID_PARAMETER
        }
    }
}

// =============================================================================
// Wow64SetInformationProcess
// =============================================================================

/// Set information about a process (32-bit).
///
/// # Arguments
/// * `process_handle` - Handle to the process
/// * `information_class` - Type of information to set
/// * `buffer` - Input buffer (32-bit pointer)
/// * `buffer_size` - Size of input buffer
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64SetInformationProcess(
    process_handle: HANDLE32,
    information_class: ULONG32,
    buffer: ULONG32,
    buffer_size: ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64SetInformationProcess handle=0x{:08x} class={} \
         buf=0x{:08x} sz={}",
        process_handle, information_class, buffer, buffer_size
    );
    if process_handle == 0 {
        return STATUS_INVALID_HANDLE;
    }
    if buffer == 0 && buffer_size != 0 {
        return STATUS_INVALID_PARAMETER;
    }

    match information_class {
        // ProcessDefaultHardErrorMode - Set default hard error mode
        12 => STATUS_NOT_IMPLEMENTED,
        // ProcessIoPriority - Set I/O priority
        18 => STATUS_NOT_IMPLEMENTED,
        // ProcessAffinityMask - Set affinity mask
        20 => STATUS_NOT_IMPLEMENTED,
        // ProcessPriorityClass - Set priority class
        21 => STATUS_NOT_IMPLEMENTED,
        _ => {
            crate::wow64_klog!(
                "Unknown process set information class {}",
                information_class
            );
            STATUS_INVALID_PARAMETER
        }
    }
}

// =============================================================================
// Wow64QueryInformationThread
// =============================================================================

/// Query information about a thread (32-bit).
///
/// # Arguments
/// * `thread_handle` - Handle to the thread
/// * `information_class` - Type of information to query
/// * `buffer` - Output buffer (32-bit pointer)
/// * `buffer_size` - Size of output buffer
/// * `return_length` - Actual size needed (output)
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64QueryInformationThread(
    thread_handle: HANDLE32,
    information_class: ULONG32,
    buffer: ULONG32,
    buffer_size: ULONG32,
    return_length: ULONG32_PTR,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64QueryInformationThread handle=0x{:08x} class={} \
         buf=0x{:08x} sz={} retlen_ptr=0x{:08x}",
        thread_handle, information_class, buffer, buffer_size, return_length
    );
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE;
    }

    match information_class {
        // ThreadBasicInformation - Return basic thread info
        0 => {
            // Return THREAD_BASIC_INFORMATION32
            // - ExitStatus (4 bytes)
            // - TebBaseAddress (4 bytes, 32-bit TEB)
            // - ClientId (8 bytes)
            // - AffinityMask (4 bytes)
            // - Priority (4 bytes)
            // - BasePriority (4 bytes)
            if buffer_size < 28 {
                STATUS_BUFFER_TOO_SMALL
            } else {
                STATUS_SUCCESS
            }
        }

        // ThreadTimes - Return thread timing info
        1 => STATUS_NOT_IMPLEMENTED,
        // ThreadPriority - Return thread priority
        2 => STATUS_NOT_IMPLEMENTED,
        // ThreadBasePriority - Return base priority
        3 => STATUS_NOT_IMPLEMENTED,
        // ThreadAffinityMask - Return affinity mask
        4 => STATUS_NOT_IMPLEMENTED,

        // ThreadWow64State - Return Wow64 thread state
        11 => {
            // Return one of:
            // 0 = Wow64ThreadNotPresent
            // 1 = Wow64ThreadPresent
            // 2 = Wow64ThreadUsingFiber
            if buffer != 0 && buffer_size >= 4 {
                // Return Wow64ThreadPresent (1)
                STATUS_SUCCESS
            } else {
                STATUS_BUFFER_TOO_SMALL
            }
        }

        // ThreadIsTerminated - Check if thread is terminated
        12 => STATUS_NOT_IMPLEMENTED,

        _ => {
            crate::wow64_klog!(
                "Unknown thread information class {}",
                information_class
            );
            STATUS_INVALID_PARAMETER
        }
    }
}

// =============================================================================
// Wow64SetInformationThread
// =============================================================================

/// Set information about a thread (32-bit).
///
/// # Arguments
/// * `thread_handle` - Handle to the thread
/// * `information_class` - Type of information to set
/// * `buffer` - Input buffer (32-bit pointer)
/// * `buffer_size` - Size of input buffer
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64SetInformationThread(
    thread_handle: HANDLE32,
    information_class: ULONG32,
    buffer: ULONG32,
    buffer_size: ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64SetInformationThread handle=0x{:08x} class={} \
         buf=0x{:08x} sz={}",
        thread_handle, information_class, buffer, buffer_size
    );
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE;
    }
    if buffer == 0 && buffer_size != 0 {
        return STATUS_INVALID_PARAMETER;
    }

    match information_class {
        // ThreadPriority - Set thread priority
        2 => STATUS_NOT_IMPLEMENTED,
        // ThreadBasePriority - Set base priority
        3 => STATUS_NOT_IMPLEMENTED,
        // ThreadAffinityMask - Set affinity mask
        4 => STATUS_NOT_IMPLEMENTED,
        // ThreadImpersonationToken - Set impersonation token
        5 => STATUS_NOT_IMPLEMENTED,
        _ => {
            crate::wow64_klog!(
                "Unknown thread set information class {}",
                information_class
            );
            STATUS_INVALID_PARAMETER
        }
    }
}

// =============================================================================
// Wow64GetContextThread
// =============================================================================

/// Get the context of a thread (32-bit).
///
/// # Arguments
/// * `thread_handle` - Handle to the thread
/// * `context` - Context buffer (32-bit pointer to CONTEXT32)
/// * `context_size` - Size of context buffer
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64GetContextThread(
    thread_handle: HANDLE32,
    context: ULONG32,
    context_size: ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64GetContextThread handle=0x{:08x} ctx=0x{:08x} sz=0x{:x}",
        thread_handle, context, context_size
    );

    // Validate context buffer
    if context == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE;
    }

    // Validate context size
    if context_size < core::mem::size_of::<Context32>() as u32 {
        crate::wow64_klog!(
            "Context size too small {} < {}",
            context_size,
            core::mem::size_of::<Context32>()
        );
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    // Get context pointer
    let ctx = context as *mut Context32;

    // In a real implementation:
    // 1. Get the 64-bit ETHREAD from the 32-bit handle
    // 2. Get the 64-bit context from the thread
    // 3. Convert 64-bit CONTEXT to 32-bit CONTEXT32
    // 4. Copy to the output buffer

    // Set up a default context for now
    (*ctx).context_flags = Context32::CONTEXT_FULL;
    (*ctx).eax = 0;
    (*ctx).ebx = 0;
    (*ctx).ecx = 0;
    (*ctx).edx = 0;
    (*ctx).esi = 0;
    (*ctx).edi = 0;
    (*ctx).ebp = 0;
    (*ctx).esp = 0;
    (*ctx).eip = 0;
    (*ctx).eflags = 0;
    (*ctx).cs = 0x23;  // USER_CS
    (*ctx).ss = 0x2B;  // USER_SS
    (*ctx).ds = 0;
    (*ctx).es = 0;
    (*ctx).fs = 0;
    (*ctx).gs = 0;

    STATUS_SUCCESS
}

// =============================================================================
// Wow64SetContextThread
// =============================================================================

/// Set the context of a thread (32-bit).
///
/// # Arguments
/// * `thread_handle` - Handle to the thread
/// * `context` - Context buffer (32-bit pointer to CONTEXT32)
/// * `context_size` - Size of context buffer
///
/// # Returns
/// * NTSTATUS
///
/// # Safety
/// This function modifies thread state and can cause undefined behavior
/// if used incorrectly.
pub unsafe extern "C" fn Wow64SetContextThread(
    thread_handle: HANDLE32,
    context: ULONG32,
    context_size: ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64SetContextThread handle=0x{:08x} ctx=0x{:08x} sz=0x{:x}",
        thread_handle, context, context_size
    );

    // Validate context buffer
    if context == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if thread_handle == 0 {
        return STATUS_INVALID_HANDLE;
    }
    if context_size < core::mem::size_of::<Context32>() as u32 {
        crate::wow64_klog!(
            "Context size too small {} < {}",
            context_size,
            core::mem::size_of::<Context32>()
        );
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    // Get context pointer
    let ctx = context as *const Context32;

    // In a real implementation:
    // 1. Validate the context
    // 2. Get the 64-bit ETHREAD from the 32-bit handle
    // 3. Convert 32-bit CONTEXT32 to 64-bit CONTEXT
    // 4. Set the 64-bit context on the thread

    crate::wow64_klog!(
        "Context to set: eip=0x{:08x} esp=0x{:08x} ebp=0x{:08x}",
        (*ctx).eip,
        (*ctx).esp,
        (*ctx).ebp
    );

    STATUS_SUCCESS
}

// =============================================================================
// Wow64ThreadWow64State
// =============================================================================

/// Get or set the Wow64 state of a thread.
///
/// These are additional thread-related functions used by the Wow64 layer.
pub mod wow64_state {
    use super::*;

    /// Thread is not a Wow64 thread.
    pub const WOW64_THREAD_NOT_PRESENT: u32 = 0;
    /// Thread is a Wow64 thread.
    pub const WOW64_THREAD_PRESENT: u32 = 1;
    /// Thread is a Wow64 fiber thread.
    pub const WOW64_THREAD_USING_FIBER: u32 = 2;

    /// Check if a thread is a Wow64 thread.
    pub fn is_wow64_thread(thread_handle: HANDLE32) -> bool {
        let _ = thread_handle;
        // In real implementation, check the ETHREAD Wow64Flags
        true
    }

    /// Get the TEB32 address for a Wow64 thread.
    pub fn get_teb32_address(thread_handle: HANDLE32) -> ULONG32 {
        let _ = thread_handle;
        // In real implementation:
        // 1. Get ETHREAD from handle
        // 2. Get Teb32 from ETHREAD.WoW64Extension.Teb32
        TEB32_BASE_ADDRESS
    }
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the process/thread thunk layer.
pub fn init() {
    crate::wow64_klog!("Initializing process/thread thunk layer");
    crate::wow64_klog!("Process/thread thunk layer initialized");
}

// =============================================================================
// Public Entry Points (for thunk.rs forwarding)
// =============================================================================

/// `wow64_query_information_process` — wrapper for Wow64QueryInformationProcess.
pub unsafe extern "C" fn wow64_query_information_process(
    process_handle: u32,
    information_class: u32,
    buffer: u32,
    buffer_size: u32,
) -> u32 {
    crate::wow64_klog!(
        "wow64_query_information_process proc={:#x} class={:#x} buf={:#x} sz={}",
        process_handle, information_class, buffer, buffer_size
    );
    // Forward to the actual implementation
    Wow64QueryInformationProcess(
        process_handle,
        information_class,
        buffer,
        buffer_size,
        0 // return_length_ptr
    )
}

/// `wow64_set_information_thread` — wrapper for Wow64SetInformationThread.
pub unsafe extern "C" fn wow64_set_information_thread(
    thread_handle: u32,
    information_class: u32,
    buffer: u32,
    buffer_size: u32,
) -> u32 {
    crate::wow64_klog!(
        "wow64_set_information_thread thr={:#x} class={:#x} buf={:#x} sz={}",
        thread_handle, information_class, buffer, buffer_size
    );
    // Forward to the actual implementation
    Wow64SetInformationThread(
        thread_handle,
        information_class,
        buffer,
        buffer_size
    )
}
