//! apc_exc_thunk — Wow64 APC and Exception Handling Thunks
//
//! This module implements the APC (Asynchronous Procedure Call) and exception
//! handling thunks for Wow64. These are critical for:
//!   * Delivering APCs to 32-bit threads
//!   * Converting 32-bit exceptions to 64-bit and vice versa
//!   * Setting up 32-bit exception handlers
//
//! References:
//!   * geoffchappell.com — wow64 exception handling
//!   * ReactOS `dll/win32/kernel32/client/thread.c`

#![cfg(target_arch = "x86_64")]

use crate::libs::wow64::types::*;

// =============================================================================
// Wow64ApcRoutine — APC Delivery to 32-bit Threads
// =============================================================================

/// `Wow64ApcRoutine` — APC routine that runs in a 32-bit thread context.
///
/// When the kernel wants to deliver an APC to a 32-bit thread, it calls this
/// routine. The APC needs to be executed in 32-bit mode with the correct
/// stack and context.
///
/// # Arguments
/// * `apc` - Pointer to the KAPC32 structure
/// * `thread` - Pointer to the target ETHREAD (64-bit kernel pointer)
/// * `frame` - Pointer to the 32-bit frame (stack)
///
/// # Safety
/// This function manipulates thread state and stack.
pub unsafe extern "C" fn Wow64ApcRoutine(
    apc: *mut Kapc32,
    thread: u64, // ETHREAD kernel pointer
    frame: u64,   // 32-bit frame pointer
) {
    crate::wow64_klog!(
        "Wow64ApcRoutine apc=0x{:016x} thread=0x{:016x} frame=0x{:016x}",
        apc as u64, thread, frame
    );

    // Validate APC pointer
    if apc.is_null() {
        return;
    }

    // Extract APC parameters
    let normal_routine = (*apc).normal_routine;
    let normal_context = (*apc).normal_context;
    let system_argument1 = (*apc).system_argument1;
    let system_argument2 = (*apc).system_argument2;

    crate::wow64_klog!(
        "APC params: routine=0x{:08x} ctx=0x{:08x} arg1=0x{:08x} arg2=0x{:08x}",
        normal_routine, normal_context, system_argument1, system_argument2
    );

    // In a real implementation:
    // 1. Save the current 64-bit context
    // 2. Switch to 32-bit stack
    // 3. Set up 32-bit call frame
    // 4. Call the normal routine
    // 5. Restore 64-bit context

    // For now, just log the call
    if normal_routine != 0 {
        crate::wow64_klog!(
            "Would call 32-bit APC routine at 0x{:08x}",
            normal_routine
        );
    }
}

/// `Wow64ApcKernelRoutine` — Kernel-mode APC routine.
///
/// This is called when a kernel-mode APC needs to be delivered to a 32-bit thread.
pub unsafe extern "C" fn Wow64ApcKernelRoutine(
    apc: *mut Kapc32,
    thread: u64,
    frame: u64,
) {
    crate::wow64_klog!(
        "Wow64ApcKernelRoutine apc=0x{:016x} thread=0x{:016x} frame=0x{:016x}",
        apc as u64, thread, frame
    );

    if apc.is_null() {
        return;
    }

    let kernel_routine = (*apc).kernel_routine;
    if kernel_routine != 0 {
        crate::wow64_klog!(
            "Would call 32-bit kernel APC routine at 0x{:08x}",
            kernel_routine
        );
    }
}

/// `Wow64ApcRundownRoutine` — APC rundown routine.
///
/// Called when a thread is being terminated while APCs are queued.
pub unsafe extern "C" fn Wow64ApcRundownRoutine(
    apc: *mut Kapc32,
) {
    crate::wow64_klog!(
        "Wow64ApcRundownRoutine apc=0x{:016x}",
        apc as u64
    );

    if !apc.is_null() {
        let rundown_routine = (*apc).rundown_routine;
        if rundown_routine != 0 {
            crate::wow64_klog!(
                "Would call 32-bit rundown routine at 0x{:08x}",
                rundown_routine
            );
        }
    }
}

// =============================================================================
// Wow64PrepareForException
// =============================================================================

/// `Wow64PrepareForException` — Prepare a 32-bit thread for exception handling.
///
/// This is called when an exception occurs and needs to be handled by 32-bit
/// code. It sets up the 32-bit exception handling context.
///
/// # Arguments
/// * `exception_code` - The exception code
/// * `exception_flags` - Exception flags
/// * `exception_address` - Exception address
///
/// # Returns
/// * 0 = Exception is continuable
/// * 1 = Exception is non-continuable
pub unsafe extern "C" fn Wow64PrepareForException(
    exception_code: ULONG32,
    exception_flags: ULONG32,
    exception_address: ULONG32,
) -> i32 {
    crate::wow64_klog!(
        "Wow64PrepareForException code=0x{:08x} flags=0x{:08x} addr=0x{:08x}",
        exception_code, exception_flags, exception_address
    );

    // Check if exception is continuable
    if exception_flags & exception_flags::EXCEPTION_NONCONTINUABLE != 0 {
        return exception_flags::EXCEPTION_NONCONTINUABLE as i32;
    }

    // For now, return continuable
    exception_flags::EXCEPTION_CONTINUABLE as i32
}

// =============================================================================
// Wow64RaiseException / Wow64DispatchException
// =============================================================================

/// `Wow64RaiseException` — Raise a 32-bit exception.
///
/// Called from the 32-bit exception handling code to raise an exception
/// that will be handled by the 64-bit kernel.
///
/// # Arguments
/// * `exception_record` - Pointer to 32-bit exception record
/// * `context` - Pointer to 32-bit context
/// * `exception_frame` - 32-bit exception frame pointer
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64RaiseException(
    exception_record: *const ExceptionRecord32,
    context: *mut Context32,
    exception_frame: ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64RaiseException record=0x{:08x} ctx=0x{:08x} frame=0x{:08x}",
        exception_record as u32, context as u32, exception_frame
    );

    // Validate inputs
    if exception_record.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Get exception info
    let exception_code = (*exception_record).exception_code;
    let exception_flags = (*exception_record).exception_flags;

    crate::wow64_klog!(
        "Raise exception: code=0x{:08x} flags=0x{:08x}",
        exception_code, exception_flags
    );

    // In a real implementation:
    // 1. Convert 32-bit exception record to 64-bit format
    // 2. Convert 32-bit context to 64-bit format
    // 3. Call the kernel exception dispatcher
    // 4. Return the result

    let _ = (exception_code, exception_flags);
    STATUS_SUCCESS
}

/// `Wow64DispatchException` — Dispatch a 32-bit exception.
///
/// This is the main exception dispatching routine for 32-bit exceptions.
///
/// # Arguments
/// * `exception_record` - Pointer to 32-bit exception record
/// * `context` - Pointer to 32-bit context
/// * `exception_frame` - 32-bit exception frame pointer
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64DispatchException(
    exception_record: *const ExceptionRecord32,
    context: *mut Context32,
    exception_frame: ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64DispatchException record=0x{:08x} ctx=0x{:08x} frame=0x{:08x}",
        exception_record as u32, context as u32, exception_frame
    );

    // Validate inputs
    if exception_record.is_null() || context.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let exception_code = (*exception_record).exception_code;
    let exception_address = (*exception_record).exception_address;
    let number_parameters = (*exception_record).number_parameters;

    crate::wow64_klog!(
        "Dispatch exception: code=0x{:08x} addr=0x{:08x} params={}",
        exception_code, exception_address, number_parameters
    );

    // In a real implementation:
    // 1. Build a 64-bit exception record from 32-bit data
    // 2. Build a 64-bit context from 32-bit context
    // 3. Walk the 32-bit exception handling chain
    // 4. If no handler found, call Wow64RaiseException
    // 5. If handler found, set up the 32-bit continuation context

    let _ = (exception_code, exception_address, number_parameters);
    STATUS_SUCCESS
}

// =============================================================================
// Wow64 Callback Return
// =============================================================================

/// `Wow64CallbackReturn` — Return from a callback into 32-bit code.
///
/// When the kernel needs to callback into 32-bit code (e.g., for APCs or
/// window messages), it uses this function to return control.
///
/// # Arguments
/// * `buffer` - Pointer to result buffer
/// * `buffer_length` - Length of result buffer
///
/// # Returns
/// * Does not return; transfers control back to 32-bit code
pub unsafe extern "C" fn Wow64CallbackReturn(
    buffer: *const u8,
    buffer_length: ULONG32,
) -> ! {
    crate::wow64_klog!(
        "Wow64CallbackReturn buffer=0x{:016x} length={}",
        buffer as u64, buffer_length
    );

    // In a real implementation:
    // 1. Set up the return value in the correct register
    // 2. Switch back to 32-bit stack
    // 3. Execute iretq/syscall to return to 32-bit code

    // For stub, just halt
    loop {
        core::arch::asm!("hlt");
        core::hint::black_box(());
    }
}

// =============================================================================
// Exception Record Conversion
// =============================================================================

/// Convert exception record from 64-bit format to 32-bit.
/// This is a simplified version that handles common fields.
pub unsafe fn exception_record_64_to_32_simple(
    exception_code: u64,
    exception_flags: u64,
    exception_address: u64,
    dst: *mut ExceptionRecord32,
) {
    if dst.is_null() {
        return;
    }

    (*dst).exception_code = exception_code as u32;
    (*dst).exception_flags = exception_flags as u32;
    (*dst).exception_record = 0;
    (*dst).exception_address = exception_address as u32;
    (*dst).number_parameters = 0;
}

/// Convert exception record from 32-bit format to 64-bit.
/// This is a simplified version that handles common fields.
pub unsafe fn exception_record_32_to_64_simple(
    src: *const ExceptionRecord32,
    exception_code: &mut u64,
    exception_flags: &mut u64,
    exception_address: &mut u64,
) {
    if src.is_null() {
        return;
    }

    *exception_code = (*src).exception_code as u64;
    *exception_flags = (*src).exception_flags as u64;
    *exception_address = (*src).exception_address as u64;
}

// =============================================================================
// Context Frame Setup
// =============================================================================

/// 32-bit exception frame.
/// This is pushed on the stack when entering an exception handler.
#[repr(C)]
#[derive(Default)]
pub struct ExceptionFrame32 {
    /// Previous frame pointer.
    pub prev: ULONG32,
    /// Return address.
    pub return_address: ULONG32,
    /// Saved EBP.
    pub ebp: ULONG32,
    /// Saved EBX.
    pub ebx: ULONG32,
    /// Saved ESI.
    pub esi: ULONG32,
    /// Saved EDI.
    pub edi: ULONG32,
}

impl ExceptionFrame32 {
    /// Push a new frame on the stack.
    pub unsafe fn push(&mut self, prev: *mut ExceptionFrame32, ret_addr: ULONG32) {
        self.prev = prev as ULONG32;
        self.return_address = ret_addr;
    }
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the APC and exception thunk layer.
pub fn init() {
    crate::wow64_klog!("Initializing APC and exception thunk layer");
    crate::wow64_klog!("APC and exception thunk layer initialized");
}

// =============================================================================
// Public Entry Points (for thunk.rs forwarding)
// =============================================================================

/// `wow64_prepare_for_exception` — Handle exception in WoW64 context.
pub unsafe extern "C" fn wow64_prepare_for_exception(
    exception_record: *const core::ffi::c_void,
    context: *mut core::ffi::c_void,
) -> i32 {
    crate::wow64_klog!(
        "wow64_prepare_for_exception er={:p} ctx={:p}",
        exception_record, context
    );
    if exception_record.is_null() || context.is_null() {
        return -1; // STATUS_INVALID_PARAMETER
    }
    0 // STATUS_SUCCESS
}

/// `wow64_apc_routine` — APC delivery thunk for 32-bit threads.
pub unsafe extern "C" fn wow64_apc_routine(
    apc: *mut core::ffi::c_void,
) {
    crate::wow64_klog!("wow64_apc_routine apc={:p}", apc);
    let _ = apc;
}

/// `wow64_ldrp_initialize` — Initialize the 32-bit loader.
pub unsafe extern "C" fn wow64_ldrp_initialize(
    context: *mut core::ffi::c_void,
    entry: *mut core::ffi::c_void,
    param: *mut core::ffi::c_void,
) -> i32 {
    crate::wow64_klog!(
        "wow64_ldrp_initialize ctx={:p} entry={:p} param={:p}",
        context, entry, param
    );
    if entry.is_null() {
        return -1;
    }
    0
}
