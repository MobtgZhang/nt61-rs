//! This module provides the thunk layer for 32-bit Win32 (User/GDI) calls
//! going to the 64-bit win32k.sys kernel driver.
//
//! In WoW64, when a 32-bit application calls a Win32 API function (like
//! CreateWindow, SendMessage, GetDC), the call path is:
//
//! ```
//! 32-bit App -> user32.dll (32-bit) -> wow64win.dll (32-bit)
//!     -> Wow64Win32kSyscall -> 64-bit win32k.sys
//!     -> Return to 32-bit app
//! ```
//
//! Key functions:
//!   * Wow64Win32kInitializeThunk - Initialize the thunk
//!   * Wow64Win32kSyscall - Make a syscall to win32k.sys
//!   * Wow64Win32kCallbackReturn - Return from a callback
//
//! References:
//!   * geoffchappell.com — Win32k syscalls in WoW64
//!   * ReactOS `win32ss/gdi/gdi32/objects/thunk.c`

#![cfg(target_arch = "x86_64")]
#![allow(non_camel_case_types)]

use crate::libs::wow64::types::{ULONG32, STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};

// Re-export all Win32k thunk functions
pub mod user32_thunk;
pub mod gdi32_thunk;

// =============================================================================
// Win32k Constants
// =============================================================================

/// Win32k syscall service table index.
pub const WIN32K_SERVICE_TABLE: usize = 1;

/// Maximum number of Win32k services.
pub const MAX_WIN32K_SERVICES: usize = 1024;

/// Win32k subsystem type.
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

// =============================================================================
// Win32k Syscall Numbers
// =============================================================================

/// Win32k syscall numbers.
/// These are used to index into the Win32k service table.
pub mod syscall_numbers {
    use super::ULONG32;

    // User32 functions
    pub const NtUserCreateWindowEx: ULONG32 = 0x0001;
    pub const NtUserDestroyWindow: ULONG32 = 0x0002;
    pub const NtUserShowWindow: ULONG32 = 0x0003;
    pub const NtUserMoveWindow: ULONG32 = 0x0004;
    pub const NtUserSetWindowPos: ULONG32 = 0x0005;
    pub const NtUserGetMessage: ULONG32 = 0x0006;
    pub const NtUserPeekMessage: ULONG32 = 0x0007;
    pub const NtUserPostMessage: ULONG32 = 0x0008;
    pub const NtUserSendMessage: ULONG32 = 0x0009;
    pub const NtUserReplyMessage: ULONG32 = 0x000A;
    pub const NtUserRegisterClassEx: ULONG32 = 0x000B;
    pub const NtUserGetClassName: ULONG32 = 0x000C;
    pub const NtUserSetCapture: ULONG32 = 0x000D;
    pub const NtUserReleaseCapture: ULONG32 = 0x000E;
    pub const NtUserGetForegroundWindow: ULONG32 = 0x000F;
    pub const NtUserSetForegroundWindow: ULONG32 = 0x0010;
    pub const NtUserGetActiveWindow: ULONG32 = 0x0011;
    pub const NtUserSetActiveWindow: ULONG32 = 0x0012;

    // GDI functions
    pub const NtGdiGetDC: ULONG32 = 0x0100;
    pub const NtGdiReleaseDC: ULONG32 = 0x0101;
    pub const NtGdiCreateCompatibleDC: ULONG32 = 0x0102;
    pub const NtGdiDeleteDC: ULONG32 = 0x0103;
    pub const NtGdiSelectObject: ULONG32 = 0x0104;
    pub const NtGdiDeleteObject: ULONG32 = 0x0105;
    pub const NtGdiTextOut: ULONG32 = 0x0106;
    pub const NtGdiBitBlt: ULONG32 = 0x0107;
    pub const NtGdiPatBlt: ULONG32 = 0x0108;
    pub const NtGdiCreatePen: ULONG32 = 0x0109;
    pub const NtGdiCreateBrush: ULONG32 = 0x010A;
    pub const NtGdiCreateCompatibleBitmap: ULONG32 = 0x010B;
    pub const NtGdiGetObject: ULONG32 = 0x010C;
    pub const NtGdiExtTextOut: ULONG32 = 0x010D;
    pub const NtGdiDrawText: ULONG32 = 0x010E;
    pub const NtGdiGetPixel: ULONG32 = 0x010F;
    pub const NtGdiSetPixel: ULONG32 = 0x0110;
}

// =============================================================================
// Wow64Win32kSyscallEntry
// =============================================================================

/// Entry in the Win32k syscall dispatch table.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Win32kSyscallEntry {
    /// Service ID.
    pub service_id: ULONG32,
    /// Number of parameters.
    pub param_count: ULONG32,
    /// Parameter sizes (4 bytes each).
    pub param_sizes: [u8; 16],
}

impl Win32kSyscallEntry {
    /// Create a new syscall entry.
    pub fn new(service_id: ULONG32, param_count: ULONG32) -> Self {
        Self {
            service_id,
            param_count,
            param_sizes: [0; 16],
        }
    }
}

// =============================================================================
// Global Win32k Syscall Table
// =============================================================================

/// The Win32k syscall dispatch table.
static WIN32K_SYSCALL_TABLE: [Option<Win32kSyscallEntry>; MAX_WIN32K_SERVICES] =
    [None; MAX_WIN32K_SERVICES];

// =============================================================================
// Wow64Win32kInitializeThunk
// =============================================================================

/// Initialize the Win32k thunk layer.
///
/// This function is called during Wow64 process initialization to set up
/// the Win32k syscall dispatch table.
///
/// # Arguments
/// * `callback_info` - Pointer to callback information
///
/// # Returns
/// * NTSTATUS
pub unsafe extern "C" fn Wow64Win32kInitializeThunk(
    callback_info: *const Wow64CallbackInfo,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64Win32kInitializeThunk info=0x{:016x}",
        callback_info as u64
    );

    // Validate callback info
    if callback_info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // In a real implementation:
    // 1. Parse the callback info structure
    // 2. Set up the Win32k service descriptor table
    // 3. Initialize the syscall dispatch table
    // 4. Set up the callback return mechanism

    // Initialize the Win32k syscall table with known services
    init_win32k_table();

    STATUS_SUCCESS
}

/// Callback information structure.
#[repr(C)]
#[derive(Default)]
pub struct Wow64CallbackInfo {
    /// Size of the structure.
    pub size: ULONG32,
    /// Pointer to shared user data.
    pub shared_user_data: ULONG32,
    /// Callback return address.
    pub callback_return: ULONG32,
    /// Spare.
    pub spare: ULONG32,
}

// =============================================================================
// Wow64Win32kSyscall
// =============================================================================

/// Make a syscall to win32k.sys from 32-bit code.
///
/// This function translates the 32-bit syscall parameters to 64-bit
/// format and calls into the 64-bit win32k.sys.
///
/// # Arguments
/// * `syscall_id` - The Win32k syscall ID
/// * `params` - Pointer to 32-bit parameters
///
/// # Returns
/// * LRESULT (typically 0 for success)
pub unsafe extern "C" fn Wow64Win32kSyscall(
    syscall_id: ULONG32,
    params: *const ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64Win32kSyscall id=0x{:08x} params=0x{:08x}",
        syscall_id, params as ULONG32
    );

    // Validate parameters
    if params.is_null() {
        return STATUS_INVALID_PARAMETER as ULONG32;
    }

    // Look up the syscall
    let table_idx = syscall_id as usize;
    if table_idx >= MAX_WIN32K_SERVICES {
        crate::wow64_klog!("Invalid syscall ID: {}", table_idx);
        return STATUS_INVALID_PARAMETER as ULONG32;
    }

    // Get the syscall entry
    let entry = &WIN32K_SYSCALL_TABLE[table_idx];
    if entry.is_none() {
        crate::wow64_klog!("Unregistered syscall: {}", syscall_id);
        return STATUS_NOT_IMPLEMENTED as ULONG32;
    }

    let entry = entry.as_ref().unwrap();
    crate::wow64_klog!(
        "Dispatching syscall {} with {} params",
        entry.service_id,
        entry.param_count
    );

    // In a real implementation:
    // 1. Copy parameters from 32-bit to 64-bit format
    // 2. Set up the 64-bit syscall frame
    // 3. Call into win32k.sys
    // 4. Translate the return value back to 32-bit

    // For stub, return 0 (success)
    0
}

// =============================================================================
// Wow64Win32kCallbackReturn
// =============================================================================

/// Return from a callback into 32-bit code.
///
/// When win32k.sys needs to call back into 32-bit code (e.g., for
/// window procedures or hook callbacks), this function is used to
/// transfer control back.
///
/// # Arguments
/// * `buffer` - Pointer to callback result buffer
/// * `buffer_length` - Length of the result buffer
///
/// # Returns
/// * Does not return normally
pub unsafe extern "C" fn Wow64Win32kCallbackReturn(
    buffer: *const u8,
    buffer_length: ULONG32,
) -> ! {
    crate::wow64_klog!(
        "Wow64Win32kCallbackReturn buffer=0x{:016x} length={}",
        buffer as u64, buffer_length
    );

    // In a real implementation:
    // 1. Set up the return value
    // 2. Switch to 32-bit stack
    // 3. Return control to 32-bit code

    // For stub, halt
    loop {
        core::arch::asm!("hlt");
        core::hint::black_box(());
    }
}

// =============================================================================
// Win32k Table Initialization
// =============================================================================

/// Initialize the Win32k syscall dispatch table.
fn init_win32k_table() {
    crate::wow64_klog!("Initializing Win32k syscall table");

    // Register User32 syscalls
    register_win32k_syscall(
        syscall_numbers::NtUserCreateWindowEx as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtUserCreateWindowEx, 12),
    );
    register_win32k_syscall(
        syscall_numbers::NtUserDestroyWindow as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtUserDestroyWindow, 1),
    );
    register_win32k_syscall(
        syscall_numbers::NtUserShowWindow as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtUserShowWindow, 2),
    );
    register_win32k_syscall(
        syscall_numbers::NtUserGetMessage as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtUserGetMessage, 4),
    );
    register_win32k_syscall(
        syscall_numbers::NtUserPeekMessage as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtUserPeekMessage, 4),
    );
    register_win32k_syscall(
        syscall_numbers::NtUserPostMessage as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtUserPostMessage, 4),
    );
    register_win32k_syscall(
        syscall_numbers::NtUserSendMessage as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtUserSendMessage, 4),
    );

    // Register GDI syscalls
    register_win32k_syscall(
        syscall_numbers::NtGdiGetDC as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtGdiGetDC, 1),
    );
    register_win32k_syscall(
        syscall_numbers::NtGdiReleaseDC as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtGdiReleaseDC, 2),
    );
    register_win32k_syscall(
        syscall_numbers::NtGdiSelectObject as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtGdiSelectObject, 2),
    );
    register_win32k_syscall(
        syscall_numbers::NtGdiDeleteObject as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtGdiDeleteObject, 1),
    );
    register_win32k_syscall(
        syscall_numbers::NtGdiTextOut as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtGdiTextOut, 5),
    );
    register_win32k_syscall(
        syscall_numbers::NtGdiBitBlt as usize,
        Win32kSyscallEntry::new(syscall_numbers::NtGdiBitBlt, 9),
    );

    crate::wow64_klog!("Win32k syscall table initialized");
}

/// Register a Win32k syscall in the dispatch table.
fn register_win32k_syscall(index: usize, entry: Win32kSyscallEntry) {
    if index < MAX_WIN32K_SERVICES {
        // Safety: We're writing to a static array during initialization
        unsafe {
            let table_ptr = &WIN32K_SYSCALL_TABLE as *const _ as *mut Option<Win32kSyscallEntry>;
            table_ptr.add(index).write(Some(entry));
        }
    }
}

// =============================================================================
// Win32k Message Structures
// =============================================================================

/// 32-bit MSG structure.
#[repr(C)]
#[derive(Default)]
pub struct Msg32 {
    pub hwnd: ULONG32,        // Window handle
    pub message: ULONG32,    // Message ID
    pub wparam: ULONG32,     // Word parameter
    pub lparam: ULONG32,     // Long parameter
    pub time: ULONG32,       // Message time
    pub pt_x: ULONG32,       // Mouse X position
    pub pt_y: ULONG32,       // Mouse Y position
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the Win32k thunk module.
pub fn init() {
    crate::wow64_klog!("Initializing Win32k thunk module");
    init_win32k_table();
    crate::wow64_klog!("Win32k thunk module initialized");
}
