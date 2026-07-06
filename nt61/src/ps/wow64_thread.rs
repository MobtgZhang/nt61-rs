//! wow64_thread — Wow64 Thread Creation
//
//! This module implements the 32-bit thread creation functionality for Wow64.
//! It extends the standard 64-bit thread creation with Wow64-specific fields
//! and initialization.
//
//! Key functions:
//!   * Wow64 thread extension creation
//!   * TEB32 initialization
//!   * 32-bit stack setup
//!   * CONTEXT32 initialization
//
//! References:
//!   * geoffchappell.com — WoW64 thread creation

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::ps::thread::{Ethread, create_thread};
use crate::libs::wow64::types::*;
use crate::libs::wow64::wow64vas;
use alloc::boxed::Box;

// =============================================================================
// Wow64 Thread Extension
// =============================================================================

/// ETHREAD extension for Wow64 threads.
/// This structure contains Wow64-specific thread information.
#[repr(C)]
#[derive(Default)]
pub struct EthreadWow64Extension {
    /// Whether this is a Wow64 thread.
    pub is_wow64_thread: bool,
    /// 32-bit TEB address (user-mode virtual address).
    pub teb32_address: ULONG32,
    /// Pointer to TEB32 structure (kernel-mode).
    pub teb32: *mut Teb32,
    /// Initial 32-bit stack pointer (top of stack).
    pub initial_stack_32: ULONG32,
    /// Initial 32-bit stack size.
    pub stack_size_32: ULONG32,
    /// Pointer to CONTEXT32 (32-bit thread context).
    pub context_32: *mut Context32,
    /// Last 32-bit error code.
    pub last_error_32: ULONG32,
}

impl EthreadWow64Extension {
    /// Create a new Wow64 extension.
    pub fn new() -> Self {
        Self {
            is_wow64_thread: true,
            teb32_address: TEB32_BASE_ADDRESS,
            teb32: core::ptr::null_mut(),
            initial_stack_32: 0,
            stack_size_32: 0,
            context_32: core::ptr::null_mut(),
            last_error_32: 0,
        }
    }

    /// Check if this thread is a Wow64 thread.
    pub fn is_wow64(&self) -> bool {
        self.is_wow64_thread
    }

    /// Get the TEB32 address.
    pub fn get_teb32_address(&self) -> ULONG32 {
        self.teb32_address
    }

    /// Get the initial stack pointer.
    pub fn get_initial_stack(&self) -> ULONG32 {
        self.initial_stack_32
    }

    /// Set the last error for the 32-bit thread.
    pub fn set_last_error(&mut self, error: ULONG32) {
        self.last_error_32 = error;
    }

    /// Get the last error for the 32-bit thread.
    pub fn get_last_error(&self) -> ULONG32 {
        self.last_error_32
    }
}

// =============================================================================
// Wow64 Thread Creation
// =============================================================================

/// Default stack size for 32-bit threads.
const DEFAULT_WOW64_STACK_SIZE: u32 = 0x100000; // 1MB

/// Create a new Wow64 (32-bit) thread.
///
/// This function creates a new 32-bit thread that will run under
/// the Wow64 compatibility layer.
///
/// # Arguments
/// * `process` - The parent Wow64 process
/// * `start_address` - 32-bit entry point address
/// * `parameter` - 32-bit parameter to pass to the thread
///
/// # Returns
/// * `Some(&'static mut Ethread)` on success
/// * `None` on failure
pub fn create_wow64_thread(
    process: &'static mut crate::ps::process::Eprocess,
    start_address: ULONG32,
    parameter: ULONG32,
) -> Option<&'static mut Ethread> {

    // 1. Create a standard 64-bit thread first
    let thread = create_thread(process, 0)?;

    // 2. Allocate TEB32
    let teb32 = allocate_teb32()?;
    // 3. Allocate 32-bit stack
    let stack_base = allocate_32bit_stack(DEFAULT_WOW64_STACK_SIZE)?;
    let stack_top = stack_base + DEFAULT_WOW64_STACK_SIZE;

    // 4. Initialize CONTEXT32
    let context = Box::new(init_thread_context32(
        start_address,
        parameter,
        stack_top,
    ));
    let _context_ptr = Box::into_raw(context);
    // _context_ptr is reserved for future use - thread context tracking

    // 5. Initialize TEB32
    unsafe {
        init_teb32(teb32, thread, process, stack_top);
    }

    Some(thread)
}

/// Allocate TEB32 for a Wow64 thread.
fn allocate_teb32() -> Option<*mut Teb32> {
    // In a real implementation, we would allocate a page from the process's
    // address space at a TEB32 slot (TEB32_BASE_ADDRESS + n * 0x1000)
    // For the stub, we use a static allocation
    static mut TEB32_BUFFER: [u8; 0x1100] = [0; 0x1100];
    Some(unsafe { TEB32_BUFFER.as_mut_ptr() as *mut Teb32 })
}

/// Allocate 32-bit user stack for a Wow64 thread.
fn allocate_32bit_stack(size: u32) -> Option<ULONG32> {
    wow64vas::allocate(
        size,
        wow64vas::WOW64_ALLOCATION_GRANULARITY,
        0, // Any base
        memory_allocation_type::MEM_COMMIT | memory_allocation_type::MEM_RESERVE,
        memory_protect::PAGE_READWRITE,
    )
    .map(|(base, _)| base)
}

/// Initialize CONTEXT32 for a new Wow64 thread.
fn init_thread_context32(
    start_address: ULONG32,
    parameter: ULONG32,
    stack_top: ULONG32,
) -> Context32 {
    let mut context = Context32::new();

    // Set context flags
    context.context_flags = Context32::CONTEXT_FULL;

    // Set up the 32-bit register state
    // These will be restored when the thread starts executing
    context.eip = start_address;       // Entry point
    context.esp = stack_top - 4;       // Stack pointer (leave room for return address)
    context.ebp = 0;                    // Frame pointer
    context.eax = parameter;           // First argument in eax
    context.ebx = 0;
    context.ecx = 0;
    context.edx = 0;
    context.esi = 0;
    context.edi = 0;

    // Set up segment registers for user mode
    context.cs = 0x23;  // USER_CS (Ring 3 code segment)
    context.ds = 0x2B; // USER_DS (Ring 3 data segment)
    context.es = 0x2B;
    context.fs = 0x53; // TEB selector (Ring 3)
    context.gs = 0x2B;
    context.ss = 0x2B; // USER_SS (Ring 3 stack segment)

    // Set up EFLAGS
    // IF = 0 (interrupts disabled initially)
    // ID = 0 (no CPUID usage)
    // IOPL = 0 (kernel level, but we're in user mode)
    // TF = 0 (no trap flag)
    context.eflags = 0x200; // Bit 9 = IF (Interrupt Enable)

    // Push a fake return address on the stack
    // This will be popped when the thread starts
    // In practice, the return address should point to ExitThread

    context
}

/// Initialize TEB32 for a Wow64 thread.
unsafe fn init_teb32(
    teb: *mut Teb32,
    thread: &Ethread,
    process: &crate::ps::process::Eprocess,
    stack_top: ULONG32,
) {
    if teb.is_null() {
        return;
    }

    let teb_addr = teb as ULONG32;

    // Initialize NT_TIB (Thread Information Block)
    (*teb).exception_list = 0xFFFFFFFF;     // Initial SEH chain (no handlers)
    (*teb).stack_base = stack_top;        // Top of stack (highest address)
    (*teb).stack_limit = stack_top - DEFAULT_WOW64_STACK_SIZE; // Stack grows down
    (*teb).sub_system_tib = 0;
    (*teb).fiber_data = 0;
    (*teb).arbitrary_user_pointer = 0;
    (*teb).self_ = teb_addr;               // TEB points to itself

    // Client ID
    (*teb).client_id.unique_process = process.unique_process_id as u32;
    (*teb).client_id.unique_thread = thread.client_id.unique_thread as u32;

    // Thread local storage pointer
    (*teb).thread_local_storage_pointer = teb_addr + 0x2C;

    // PEB pointer (points to PEB32)
    (*teb).process_environment_block = PEB32_VIRTUAL_ADDRESS;

    // Last error value
    (*teb).last_error_value = 0;

    // Initialize user32 reserved area
    for i in 0..26 {
        (*teb).user32_reserved[i] = 0;
    }

    // Initialize user reserved area
    for i in 0..5 {
        (*teb).user_reserved[i] = 0;
    }

    // Initialize GS/FS register save area
    (*teb).gs_fs_register_save_area[0] = 0;
    (*teb).gs_fs_register_save_area[1] = 0;

    // Initialize Wow64 reserved area
    for i in 0..8 {
        (*teb).wow64_reserved[i] = 0;
    }

    // Current locale
    (*teb).current_locale = 0x0409; // US English

    // Exception code (0 = no exception)
    (*teb).exception_code = 0;

}

// =============================================================================
// Wow64 Thread State
// =============================================================================

/// Wow64 thread state flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Wow64ThreadState {
    /// Thread is not a Wow64 thread.
    NotPresent = 0,
    /// Thread is a Wow64 thread.
    Present = 1,
    /// Thread is a Wow64 fiber thread.
    UsingFiber = 2,
}

/// Get the Wow64 state of a thread.
pub fn get_wow64_thread_state(_thread: &Ethread) -> Wow64ThreadState {
    // _thread is intentionally unused - reserved for future Wow64 extension lookup
    // In a real implementation, check the thread's Wow64 extension
    // For the stub, return NotPresent
    Wow64ThreadState::NotPresent
}

/// Check if a thread is a Wow64 thread.
pub fn is_wow64_thread(_thread: &Ethread) -> bool {
    // _thread is intentionally unused - reserved for future Wow64 extension lookup
    // In a real implementation, check a flag in ETHREAD
    false
}

// =============================================================================
// CONTEXT32 Operations
// =============================================================================

/// Get the CONTEXT32 for a Wow64 thread.
pub fn get_thread_context32(_thread: &Ethread) -> Option<&Context32> {
    // _thread is intentionally unused - reserved for future Wow64 extension lookup
    // In a real implementation, get from the Wow64 extension
    None
}

/// Set the CONTEXT32 for a Wow64 thread.
pub fn set_thread_context32(_thread: &mut Ethread, _context: &Context32) {
    // _thread and _context are intentionally unused - reserved for future Wow64 extension
    // In a real implementation, store in the Wow64 extension
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the Wow64 thread module.
pub fn init() {
    crate::wow64_klog!("Initializing Wow64 thread module");
    crate::wow64_klog!("Wow64 thread module initialized");
}
