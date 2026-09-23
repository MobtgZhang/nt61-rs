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

use super::types::{ULONG32, STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};

pub use super::win32k_user32;
pub use super::win32k_gdi32;


pub const WIN32K_SERVICE_TABLE: usize = 1;

pub const MAX_WIN32K_SERVICES: usize = 1024;

pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;


/// These are used to index into the Win32k service table.

pub mod syscall_numbers {
    use super::ULONG32;

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


pub unsafe extern "C" fn Wow64Win32kInitializeThunk(
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


pub unsafe extern "C" fn Wow64Win32kSyscall(
    syscall_id: ULONG32,
    params: *const ULONG32,
) -> ULONG32 {
    crate::wow64_klog!(
        "Wow64Win32kSyscall id=0x{:08x} params=0x{:08x}",
        syscall_id, params as ULONG32
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
        return STATUS_NOT_IMPLEMENTED as ULONG32;
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
pub unsafe extern "C" fn Wow64Win32kCallbackReturn(
    buffer: *const u8,
    buffer_length: ULONG32,
) -> ! {
    crate::wow64_klog!(
        "Wow64Win32kCallbackReturn buffer=0x{:016x} length={}",
        buffer as u64, buffer_length
    );


    loop {
        core::arch::asm!("hlt");
        core::hint::black_box(());
    }
}


fn init_win32k_table() {
    crate::wow64_klog!("Initializing Win32k syscall table");

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
    pub hwnd: ULONG32,        // Window handle
    pub message: ULONG32,    // Message ID
    pub wparam: ULONG32,     // Word parameter
    pub lparam: ULONG32,     // Long parameter
    pub time: ULONG32,       // Message time
    pub pt_x: ULONG32,       // Mouse X position
    pub pt_y: ULONG32,       // Mouse Y position
}


pub fn init() {
    crate::wow64_klog!("Initializing Win32k thunk module");
    init_win32k_table();
    crate::wow64_klog!("Win32k thunk module initialized");
}
