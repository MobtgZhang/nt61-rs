//! user32 — window APIs
//
//! NT 6.1 window class: every entry in the user32.spec
//! corresponds to one of these stubs. The signature comes from
//! the SDK; the body is a placeholder that returns a deterministic
//! "stub" value so the smoke test can exercise the call paths.

extern crate alloc;

use super::{alloc_window_handle, has_window_handle};
use super::types::{BOOL, DWORD, FALSE, HANDLE, HWND, LPARAM, LPCWSTR, TRUE, WPARAM};
use core::ptr;

/// Window creation flags (subset).
pub mod style {
    pub const WS_OVERLAPPED: u32 = 0x0000_0000;
    pub const WS_CAPTION: u32 = 0x00C0_0000;
    pub const WS_SYSMENU: u32 = 0x0008_0000;
    pub const WS_THICKFRAME: u32 = 0x0004_0000;
    pub const WS_MINIMIZEBOX: u32 = 0x0002_0000;
    pub const WS_MAXIMIZEBOX: u32 = 0x0001_0000;
    pub const WS_VISIBLE: u32 = 0x1000_0000;
    pub const WS_CHILD: u32 = 0x4000_0000;
    pub const WS_POPUP: u32 = 0x8000_0000;
}

/// Window messages (subset).
pub mod msg {
    pub const WM_NULL: u32 = 0x0000;
    pub const WM_CREATE: u32 = 0x0001;
    pub const WM_DESTROY: u32 = 0x0002;
    pub const WM_PAINT: u32 = 0x000F;
    pub const WM_CLOSE: u32 = 0x0010;
    pub const WM_QUIT: u32 = 0x0012;
    pub const WM_KEYDOWN: u32 = 0x0100;
    pub const WM_KEYUP: u32 = 0x0101;
    pub const WM_CHAR: u32 = 0x0102;
    pub const WM_MOUSEMOVE: u32 = 0x0200;
    pub const WM_LBUTTONDOWN: u32 = 0x0201;
    pub const WM_LBUTTONUP: u32 = 0x0202;
    pub const WM_USER: u32 = 0x0400;
}

pub mod class {
    pub const CS_VREDRAW: u32 = 0x0001;
    pub const CS_HREDRAW: u32 = 0x0002;
    pub const CS_DBLCLKS: u32 = 0x0008;
    pub const CS_OWNDC: u32 = 0x0020;
    pub const CS_CLASSDC: u32 = 0x0040;
    pub const CS_PARENTDC: u32 = 0x0080;
    pub const CS_GLOBALCLASS: u32 = 0x4000;
}

pub mod sw {
    pub const SW_HIDE: i32 = 0;
    pub const SW_SHOWNORMAL: i32 = 1;
    pub const SW_NORMAL: i32 = 1;
    pub const SW_SHOWMINIMIZED: i32 = 2;
    pub const SW_SHOWMAXIMIZED: i32 = 3;
    pub const SW_MAXIMIZE: i32 = 3;
    pub const SW_SHOWNOACTIVATE: i32 = 4;
    pub const SW_SHOW: i32 = 5;
    pub const SW_MINIMIZE: i32 = 6;
    pub const SW_SHOWMINNOACTIVE: i32 = 7;
    pub const SW_SHOWNA: i32 = 8;
    pub const SW_RESTORE: i32 = 9;
}

/// MSG structure (NT 6.1).
#[repr(C)]
pub struct Msg {
    pub hwnd: HWND,
    pub message: u32,
    pub wparam: WPARAM,
    pub lparam: LPARAM,
    pub time: u32,
    pub pt_x: i32,
    pub pt_y: i32,
    pub lprivate: u32,
}

/// `CreateWindowExW` — allocate a new window handle and
/// return it. The bootstrap does not actually register a
/// window with a window station; it just gives the caller
/// a placeholder.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn CreateWindowExW(
    _ex_style: DWORD,
    class_name: LPCWSTR,
    window_name: LPCWSTR,
    style: DWORD,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: HWND,
    menu: HANDLE,
    instance: HANDLE,
    param: *mut (),
) -> HWND {
    let _ = (class_name, window_name, style, x, y, width, height, parent, menu, instance, param);
    alloc_window_handle() as HWND
}

/// `DefWindowProcW` — default message handler. Returns 0.
pub unsafe extern "C" fn DefWindowProcW(
    hwnd: HWND,
    msg: u32,
    w: WPARAM,
    l: LPARAM,
) -> isize {
    let _ = (hwnd, msg, w, l);
    0
}

/// `DestroyWindow` — release the placeholder window.
pub unsafe extern "C" fn DestroyWindow(hwnd: HWND) -> BOOL {
    if has_window_handle(hwnd as u64) { TRUE } else { FALSE }
}

/// `ShowWindow` — placeholder.
pub unsafe extern "C" fn ShowWindow(_hwnd: HWND, cmd: i32) -> BOOL {
    let _ = cmd;
    TRUE
}

/// `UpdateWindow` — placeholder.
pub unsafe extern "C" fn UpdateWindow(_hwnd: HWND) -> BOOL { TRUE }

/// `GetMessageW` — read the next message from the thread queue.
/// The bootstrap always returns `-1` (no message) and a
/// `WM_QUIT` flag set to `false`.
pub unsafe extern "C" fn GetMessageW(
    msg: *mut Msg,
    hwnd: HWND,
    min: u32,
    max: u32,
) -> i32 {
    let _ = (hwnd, min, max);
    if !msg.is_null() {
        ptr::write_bytes(msg, 0, 1);
    }
    -1
}

/// `PeekMessageW` — placeholder that returns 0 (no message).
pub unsafe extern "C" fn PeekMessageW(
    msg: *mut Msg,
    hwnd: HWND,
    min: u32,
    max: u32,
    remove: u32,
) -> BOOL {
    let _ = (hwnd, min, max, remove);
    if !msg.is_null() {
        ptr::write_bytes(msg, 0, 1);
    }
    FALSE
}

/// `TranslateMessage` — placeholder, returns the original value.
pub unsafe extern "C" fn TranslateMessage(_msg: *const Msg) -> BOOL { TRUE }

/// `DispatchMessageW` — placeholder, returns 0.
pub unsafe extern "C" fn DispatchMessageW(_msg: *const Msg) -> isize { 0 }

/// `PostQuitMessage` — placeholder.
pub unsafe extern "C" fn PostQuitMessage(code: i32) {
    let _ = code;
}

/// `GetForegroundWindow` — return a placeholder window.
pub unsafe extern "C" fn GetForegroundWindow() -> HWND {
    core::ptr::null_mut()
}

/// `SetForegroundWindow` — placeholder.
pub unsafe extern "C" fn SetForegroundWindow(_hwnd: HWND) -> BOOL { TRUE }
