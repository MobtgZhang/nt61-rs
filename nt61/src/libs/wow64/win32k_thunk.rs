//! This module provides the thunk layer for 32-bit Win32 (User/GDI) calls
//! going to the 64-bit win32k.sys kernel driver.
//
//! In WoW64, when a 32-bit application calls a Win32 API function (like
//! CreateWindow, SendMessage, get_dc), the call path is:
//
//! ```text
//! 32-bit App -> user32.dll (32-bit) -> wow64win.dll (32-bit)
//!     -> wow64_win32k_syscall -> 64-bit win32k.sys
//!     -> Return to 32-bit app
//! ```
//
//! Key functions:
//!   * wow64_win32k_initialize_thunk - Initialize the thunk
//!   * wow64_win32k_syscall - Make a syscall to win32k.sys
//!   * wow64_win32k_callback_return - Return from a callback
//
//! References:
//!   * geoffchappell.com — Win32k syscalls in WoW64
//!   * ReactOS `win32ss/gdi/gdi32/objects/thunk.c`

use super::types::{
    STATUS_INVALID_PARAMETER, STATUS_INVALID_SYSTEM_SERVICE, STATUS_SUCCESS, ULONG32,
};

pub use super::win32k_gdi32;
pub use super::win32k_user32;

pub const WIN32K_SERVICE_TABLE: usize = 1;

pub const MAX_WIN32K_SERVICES: usize = 1024;

pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

/// These are used to index into the Win32k service table.

pub mod syscall_numbers {
    use super::ULONG32;

    pub const NT_USER_CREATE_WINDOW_EX: ULONG32 = 0x0001;
    pub const NT_USER_DESTROY_WINDOW: ULONG32 = 0x0002;
    pub const NT_USER_SHOW_WINDOW: ULONG32 = 0x0003;
    pub const NT_USER_MOVE_WINDOW: ULONG32 = 0x0004;
    pub const NT_USER_SET_WINDOW_POS: ULONG32 = 0x0005;
    pub const NT_USER_GET_MESSAGE: ULONG32 = 0x0006;
    pub const NT_USER_PEEK_MESSAGE: ULONG32 = 0x0007;
    pub const NT_USER_POST_MESSAGE: ULONG32 = 0x0008;
    pub const NT_USER_SEND_MESSAGE: ULONG32 = 0x0009;
    pub const NT_USER_REPLY_MESSAGE: ULONG32 = 0x000A;
    pub const NT_USER_REGISTER_CLASS_EX: ULONG32 = 0x000B;
    pub const NT_USER_GET_CLASS_NAME: ULONG32 = 0x000C;
    pub const NT_USER_SET_CAPTURE: ULONG32 = 0x000D;
    pub const NT_USER_RELEASE_CAPTURE: ULONG32 = 0x000E;
    pub const NT_USER_GET_FOREGROUND_WINDOW: ULONG32 = 0x000F;
    pub const NT_USER_SET_FOREGROUND_WINDOW: ULONG32 = 0x0010;
    pub const NT_USER_GET_ACTIVE_WINDOW: ULONG32 = 0x0011;
    pub const NT_USER_SET_ACTIVE_WINDOW: ULONG32 = 0x0012;

    pub const NT_GDI_GET_DC: ULONG32 = 0x0100;
    pub const NT_GDI_RELEASE_DC: ULONG32 = 0x0101;
    pub const NT_GDI_CREATE_COMPATIBLE_DC: ULONG32 = 0x0102;
    pub const NT_GDI_DELETE_DC: ULONG32 = 0x0103;
    pub const NT_GDI_SELECT_OBJECT: ULONG32 = 0x0104;
    pub const NT_GDI_DELETE_OBJECT: ULONG32 = 0x0105;
    pub const NT_GDI_TEXT_OUT: ULONG32 = 0x0106;
    pub const NT_GDI_BIT_BLT: ULONG32 = 0x0107;
    pub const NT_GDI_PAT_BLT: ULONG32 = 0x0108;
    pub const NT_GDI_CREATE_PEN: ULONG32 = 0x0109;
    pub const NT_GDI_CREATE_BRUSH: ULONG32 = 0x010A;
    pub const NT_GDI_CREATE_COMPATIBLE_BITMAP: ULONG32 = 0x010B;
    pub const NT_GDI_GET_OBJECT: ULONG32 = 0x010C;
    pub const NT_GDI_EXT_TEXT_OUT: ULONG32 = 0x010D;
    pub const NT_GDI_DRAW_TEXT: ULONG32 = 0x010E;
    pub const NT_GDI_GET_PIXEL: ULONG32 = 0x010F;
    pub const NT_GDI_SET_PIXEL: ULONG32 = 0x0110;
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Win32kSyscallEntry {
    pub service_id: ULONG32,
    pub param_count: ULONG32,
    pub param_sizes: [u8; 16],
}

impl Win32kSyscallEntry {
    pub fn new(service_id: ULONG32, param_count: ULONG32) -> Self {
        Self {
            service_id,
            param_count,
            param_sizes: [0; 16],
        }
    }
}

static WIN32K_SYSCALL_TABLE: [Option<Win32kSyscallEntry>; MAX_WIN32K_SERVICES] =
    [None; MAX_WIN32K_SERVICES];

pub unsafe extern "C" fn wow64_win32k_initialize_thunk(
    callback_info: *const Wow64CallbackInfo,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64Win32kInitializeThunk info=0x{:016x}",
        callback_info as u64
    );

    if callback_info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    init_win32k_table();

    STATUS_SUCCESS
}

#[repr(C)]
#[derive(Default)]
pub struct Wow64CallbackInfo {
    pub size: ULONG32,
    /// Pointer to shared user data.
    pub shared_user_data: ULONG32,
    pub callback_return: ULONG32,
    pub spare: ULONG32,
}

pub unsafe extern "C" fn wow64_win32k_syscall(
    syscall_id: ULONG32,
    params: *const ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64Win32kSyscall id=0x{:08x} params=0x{:08x}",
        syscall_id,
        params as ULONG32
    );

    if params.is_null() {
        return STATUS_INVALID_PARAMETER as ULONG32;
    }

    let table_idx = syscall_id as usize;
    if table_idx >= MAX_WIN32K_SERVICES {
        crate::wow64_klog!("Invalid syscall ID: {}", table_idx);
        return STATUS_INVALID_PARAMETER as ULONG32;
    }

    let entry = &WIN32K_SYSCALL_TABLE[table_idx];
    if entry.is_none() {
        crate::wow64_klog!("Unregistered syscall: {}", syscall_id);
        return STATUS_INVALID_SYSTEM_SERVICE as ULONG32;
    }

    let entry = entry.as_ref().unwrap();
    crate::wow64_klog!(
        "Dispatching syscall {} with {} params",
        entry.service_id,
        entry.param_count
    );

    0
}

/// window procedures or hook callbacks), this function is used to
pub unsafe extern "C" fn wow64_win32k_callback_return(
    buffer: *const u8,
    buffer_length: ULONG32,
) -> ! {
    crate::wow64_klog!(
        "Wow64Win32kCallbackReturn buffer=0x{:016x} length={}",
        buffer as u64,
        buffer_length
    );

    crate::arch::halt_loop()
}

fn init_win32k_table() {
    crate::wow64_klog!("Initializing Win32k syscall table");

    register_win32k_syscall(
        syscall_numbers::NT_USER_CREATE_WINDOW_EX as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_USER_CREATE_WINDOW_EX, 12),
    );
    register_win32k_syscall(
        syscall_numbers::NT_USER_DESTROY_WINDOW as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_USER_DESTROY_WINDOW, 1),
    );
    register_win32k_syscall(
        syscall_numbers::NT_USER_SHOW_WINDOW as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_USER_SHOW_WINDOW, 2),
    );
    register_win32k_syscall(
        syscall_numbers::NT_USER_GET_MESSAGE as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_USER_GET_MESSAGE, 4),
    );
    register_win32k_syscall(
        syscall_numbers::NT_USER_PEEK_MESSAGE as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_USER_PEEK_MESSAGE, 4),
    );
    register_win32k_syscall(
        syscall_numbers::NT_USER_POST_MESSAGE as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_USER_POST_MESSAGE, 4),
    );
    register_win32k_syscall(
        syscall_numbers::NT_USER_SEND_MESSAGE as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_USER_SEND_MESSAGE, 4),
    );

    register_win32k_syscall(
        syscall_numbers::NT_GDI_GET_DC as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_GDI_GET_DC, 1),
    );
    register_win32k_syscall(
        syscall_numbers::NT_GDI_RELEASE_DC as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_GDI_RELEASE_DC, 2),
    );
    register_win32k_syscall(
        syscall_numbers::NT_GDI_SELECT_OBJECT as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_GDI_SELECT_OBJECT, 2),
    );
    register_win32k_syscall(
        syscall_numbers::NT_GDI_DELETE_OBJECT as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_GDI_DELETE_OBJECT, 1),
    );
    register_win32k_syscall(
        syscall_numbers::NT_GDI_TEXT_OUT as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_GDI_TEXT_OUT, 5),
    );
    register_win32k_syscall(
        syscall_numbers::NT_GDI_BIT_BLT as usize,
        Win32kSyscallEntry::new(syscall_numbers::NT_GDI_BIT_BLT, 9),
    );

    crate::wow64_klog!("Win32k syscall table initialized");
}

fn register_win32k_syscall(index: usize, entry: Win32kSyscallEntry) {
    if index < MAX_WIN32K_SERVICES {
        unsafe {
            let table_ptr = &WIN32K_SYSCALL_TABLE as *const _ as *mut Option<Win32kSyscallEntry>;
            table_ptr.add(index).write(Some(entry));
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct Msg32 {
    pub hwnd: ULONG32,    // Window handle
    pub message: ULONG32, // Message ID
    pub wparam: ULONG32,  // Word parameter
    pub lparam: ULONG32,  // Long parameter
    pub time: ULONG32,    // Message time
    pub pt_x: ULONG32,    // Mouse X position
    pub pt_y: ULONG32,    // Mouse Y position
}

pub fn init() {
    crate::wow64_klog!("Initializing Win32k thunk module");
    init_win32k_table();
    crate::wow64_klog!("Win32k thunk module initialized");
}
