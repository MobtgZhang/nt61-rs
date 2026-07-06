//
//! This module implements the 32-bit process creation functionality for Wow64.
//! It extends the standard 64-bit process creation with Wow64-specific fields
//! and initialization.
//
//! Key functions:
//!   * Wow64 process extension creation
//!   * PEB32 initialization
//!   * Wow64 VAS initialization
//!   * 32-bit system DLL loading
//
//! References:
//!   * geoffchappell.com — WoW64 process creation

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::ps::process::{Eprocess, create_user_process};
use crate::libs::wow64::types::*;
use crate::libs::wow64::wow64vas::WOW64_HEAP_VIRTUAL_ALLOC_BASE;
use alloc::boxed::Box;

// =============================================================================
// Wow64 Process Extension
// =============================================================================

/// EPROCESS extension for Wow64 processes.
/// This structure is stored alongside the standard EPROCESS
/// and contains Wow64-specific information.
#[repr(C)]
#[derive(Default)]
pub struct EprocessWow64Extension {
    /// Whether this is a Wow64 process.
    pub is_wow64_process: bool,
    /// 32-bit PEB address (user-mode virtual address).
    pub peb32_address: ULONG32,
    /// Pointer to PEB32 structure (kernel-mode).
    pub peb32: *mut Peb32,
    /// Wow64 VAS manager pointer.
    pub wow64vas: *mut Wow64VasState,
    /// Base address of 32-bit ntdll.dll.
    pub ntdll32_base: ULONG32,
    /// Base address of 32-bit kernel32.dll.
    pub kernel32_base: ULONG32,
    /// Base address of 32-bit user32.dll.
    pub user32_base: ULONG32,
    /// Last 32-bit error code (NtCurrentTeb()->LastErrorValue).
    pub last_error32: ULONG32,
}

impl EprocessWow64Extension {
    /// Create a new Wow64 extension.
    pub fn new() -> Self {
        Self {
            is_wow64_process: true,
            peb32_address: PEB32_VIRTUAL_ADDRESS,
            peb32: core::ptr::null_mut(),
            wow64vas: core::ptr::null_mut(),
            ntdll32_base: 0,
            kernel32_base: 0,
            user32_base: 0,
            last_error32: 0,
        }
    }

    /// Check if this process is a Wow64 process.
    pub fn is_wow64(&self) -> bool {
        self.is_wow64_process
    }

    /// Get the PEB32 address.
    pub fn get_peb32_address(&self) -> ULONG32 {
        self.peb32_address
    }

    /// Set the last error for the 32-bit process.
    pub fn set_last_error(&mut self, error: ULONG32) {
        self.last_error32 = error;
    }

    /// Get the last error for the 32-bit process.
    pub fn get_last_error(&self) -> ULONG32 {
        self.last_error32
    }
}

/// Wow64 VAS state for a single process.
pub struct Wow64VasState {
    /// Next allocation base (bump pointer).
    pub next_alloc: u32,
    /// End of user space (exclusive).
    pub end_of_space: u32,
    /// Number of allocations made.
    pub allocation_count: u32,
    /// Peak usage.
    pub peak_usage: u32,
}

impl Default for Wow64VasState {
    fn default() -> Self {
        Self {
            next_alloc: WOW64_USER_SPACE_START,
            end_of_space: WOW64_USER_SPACE_END,
            allocation_count: 0,
            peak_usage: 0,
        }
    }
}

impl Wow64VasState {
    /// Create a new VAS state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        self.next_alloc = WOW64_USER_SPACE_START;
        self.allocation_count = 0;
    }

    /// Get current usage.
    pub fn current_usage(&self) -> u32 {
        self.next_alloc - WOW64_USER_SPACE_START
    }
}

// =============================================================================
// Wow64 Process Creation
// =============================================================================

/// Create a new Wow64 (32-bit) process.
///
/// This function creates a new 32-bit process that will run under
/// the Wow64 compatibility layer.
///
/// # Arguments
/// * `image_path` - Path to the 32-bit executable
/// * `parent_process` - Parent process (optional)
///
/// # Returns
/// * `Some(&'static mut Eprocess)` on success
/// * `None` on failure
pub fn create_wow64_process(
    image_path: &[u8],
    _parent_process: Option<&'static mut Eprocess>,
) -> Option<&'static mut Eprocess> {
    // _parent_process is intentionally unused - Wow64 child processes inherit via the loader

    // 1. Create a standard 64-bit process first
    //
    // `create_user_process` only takes a `user_entry_override` (an optional RIP
    // override), so the parent handle is not threaded through here. Wow64
    // child processes inherit via the loader instead.
    let process = create_user_process(image_path, 0, None)?;

    // 2. Initialize the Wow64 extension
    // Note: In a real implementation, we would add fields to Eprocess
    // For now, we create a separate extension structure

    // 3. Allocate PEB32
    let peb32 = allocate_peb32()?;
    // 4. Initialize PEB32
    unsafe {
        init_peb32(peb32, process);
    }

    // 5. Initialize Wow64 VAS
    let _vas = Box::new(Wow64VasState::new());
    // _vas is reserved for future use - Wow64 VAS tracking
    // 6. Load 32-bit system DLLs
    if load_wow64_system_dlls(process).is_err() {
        return None;
    }

    Some(process)
}

/// Allocate and initialize PEB32 for a Wow64 process.
fn allocate_peb32() -> Option<*mut Peb32> {
    // In a real implementation, we would allocate a page from the process's
    // address space at PEB32_VIRTUAL_ADDRESS
    // For the stub, we use a static allocation
    static mut PEB32_BUFFER: [u8; 0x200] = [0; 0x200];
    Some(unsafe { PEB32_BUFFER.as_mut_ptr() as *mut Peb32 })
}

/// Initialize PEB32 for a Wow64 process.
unsafe fn init_peb32(peb: *mut Peb32, process: &Eprocess) {
    if peb.is_null() {
        return;
    }

    // Basic PEB32 initialization
    (*peb).image_base_address = process.user_image_base as u32;
    (*peb).being_debugged = 0; // Not being debugged initially
    (*peb).bit_field = 0;
    (*peb).process_heap = WOW64_HEAP_VIRTUAL_ALLOC_BASE;
    (*peb).ldr = 0; // Will be set when ntdll32 is loaded
    (*peb).process_parameters = 0; // Will be set by RTL

    // OS version information
    (*peb).os_major_version = 6;
    (*peb).os_minor_version = 1; // Windows 7
    (*peb).os_build_number = 7600;

}

/// Load 32-bit system DLLs into the Wow64 process.
///
/// These DLLs include:
///   * ntdll.dll - Native API
///   * kernel32.dll - Win32 kernel API
///   * user32.dll - Win32 user API
///   * gdi32.dll - Win32 GDI API
fn load_wow64_system_dlls(_process: &Eprocess) -> Result<(), u32> {
    // In a real implementation:
    // 1. Load ntdll.dll at 0x7FFE0000 (standard 32-bit ntdll base)
    // 2. Load kernel32.dll at 0x7FFE1000
    // 3. Load user32.dll at 0x7FFE2000
    // 4. Load gdi32.dll at 0x7FFE3000
    // 5. Initialize the PEB loader data with these DLLs

    // For the stub, just log
    Ok(())
}

// =============================================================================
// Wow64 Process Query Functions
// =============================================================================

/// Get the PEB32 address for a Wow64 process.
pub fn get_peb32_address(_process: &Eprocess) -> ULONG32 {
    // _process is intentionally unused - reserved for future Wow64 extension lookup
    // In a real implementation, this would check the process's Wow64 extension
    // For the stub, return the standard PEB32 address
    PEB32_VIRTUAL_ADDRESS
}

/// Check if a process is a Wow64 process.
pub fn is_wow64_process(_process: &Eprocess) -> bool {
    // _process is intentionally unused - reserved for future Wow64 extension lookup
    // In a real implementation, this would check a flag in EPROCESS
    // For the stub, return false
    false
}

/// Get the last error for a 32-bit process.
pub fn get_wow64_last_error(_process: &Eprocess) -> ULONG32 {
    // _process is intentionally unused - reserved for future Wow64 extension lookup
    // In a real implementation, read from the Wow64 extension
    0
}

/// Set the last error for a 32-bit process.
pub fn set_wow64_last_error(_process: &mut Eprocess, _error: ULONG32) {
    // _process and _error are intentionally unused - reserved for future Wow64 extension
}

// =============================================================================
// Wow64 Process Information
// =============================================================================

/// Information class for Wow64 process queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Wow64ProcessInformationClass {
    /// Return PEB32 address.
    Wow64Information = 0,
    /// Return whether process is using XeKeys.
    XeKeys = 1,
    /// Return session ID.
    SessionInformation = 2,
}

/// Query Wow64-specific process information.
pub fn query_wow64_information(
    process: &Eprocess,
    info_class: Wow64ProcessInformationClass,
) -> ULONG32 {
    match info_class {
        Wow64ProcessInformationClass::Wow64Information => {
            // Return non-zero if Wow64 process
            if is_wow64_process(process) {
                1
            } else {
                0
            }
        }
        Wow64ProcessInformationClass::XeKeys => {
            0 // XeKeys not used
        }
        Wow64ProcessInformationClass::SessionInformation => {
            process.session_id as u32
        }
    }
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the Wow64 process module.
pub fn init() {
    crate::wow64_klog!("Initializing Wow64 process module");
    crate::wow64_klog!("Wow64 process module initialized");
}
