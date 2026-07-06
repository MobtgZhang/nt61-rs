//! This module implements the thunk functions for 32-bit User32.dll API calls
//! going to the 64-bit win32k.sys driver.
//
//! References:
//!   * Microsoft Windows SDK
//!   * ReactOS user32 implementation

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::libs::wow64win::{
    Msg32, syscall_numbers,
    Wow64Win32kSyscall, Wow64Win32kCallbackReturn,
};
use crate::libs::wow64::types::*;

// =============================================================================
// Handle Types
// =============================================================================

/// 32-bit HWND (Window Handle).
pub type HWND32 = ULONG32;
/// 32-bit HINSTANCE (Instance Handle).
pub type HINSTANCE32 = ULONG32;
/// 32-bit HMODULE (Module Handle).
pub type HMODULE32 = ULONG32;
/// 32-bit HANDLE (Generic Handle).
pub type HANDLE32 = ULONG32;
/// 32-bit HMENU (Menu Handle).
pub type HMENU32 = ULONG32;
/// 32-bit HCURSOR (Cursor Handle).
pub type HCURSOR32 = ULONG32;
/// 32-bit HICON (Icon Handle).
pub type HICON32 = ULONG32;
/// 32-bit HBRUSH (Brush Handle).
pub type HBRUSH32 = ULONG32;
/// 32-bit HDC (Device Context Handle).
pub type HDC32 = ULONG32;
/// 32-bit HPEN (Pen Handle).
pub type HPEN32 = ULONG32;
/// 32-bit HBITMAP (Bitmap Handle).
pub type HBITMAP32 = ULONG32;

/// 32-bit BOOL.
pub type BOOL32 = i32;
/// 32-bit LRESULT (Long Result - return value).
pub type LRESULT32 = i64;
/// 32-bit WPARAM (Word Parameter).
pub type WPARAM32 = ULONG32;
/// 32-bit LPARAM (Long Parameter).
pub type LPARAM32 = ULONG32;

// =============================================================================
// Window Styles
// =============================================================================

/// Window style flags.
pub mod window_style {
    use super::ULONG32;
    pub const WS_OVERLAPPED: ULONG32 = 0x00000000;
    pub const WS_POPUP: ULONG32 = 0x80000000;
    pub const WS_CHILD: ULONG32 = 0x40000000;
    pub const WS_MINIMIZE: ULONG32 = 0x20000000;
    pub const WS_VISIBLE: ULONG32 = 0x10000000;
    pub const WS_DISABLED: ULONG32 = 0x08000000;
    pub const WS_CLIPSIBLINGS: ULONG32 = 0x04000000;
    pub const WS_CLIPCHILDREN: ULONG32 = 0x02000000;
    pub const WS_MAXIMIZE: ULONG32 = 0x01000000;
    pub const WS_CAPTION: ULONG32 = 0x00C00000;
    pub const WS_BORDER: ULONG32 = 0x00800000;
    pub const WS_DLGFRAME: ULONG32 = 0x00400000;
    pub const WS_VSCROLL: ULONG32 = 0x00200000;
    pub const WS_HSCROLL: ULONG32 = 0x00100000;
    pub const WS_SYSMENU: ULONG32 = 0x00080000;
    pub const WS_THICKFRAME: ULONG32 = 0x00040000;
    pub const WS_GROUP: ULONG32 = 0x00020000;
    pub const WS_TABSTOP: ULONG32 = 0x00010000;
}

/// Extended window style flags.
pub mod window_style_ex {
    use super::ULONG32;
    pub const WS_EX_DLGMODALFRAME: ULONG32 = 0x00000001;
    pub const WS_EX_NOPARENTNOTIFY: ULONG32 = 0x00000004;
    pub const WS_EX_TOPMOST: ULONG32 = 0x00000008;
    pub const WS_EX_ACCEPTFILES: ULONG32 = 0x00000010;
    pub const WS_EX_TRANSPARENT: ULONG32 = 0x00000020;
    pub const WS_EX_MDICHILD: ULONG32 = 0x00000040;
    pub const WS_EX_TOOLWINDOW: ULONG32 = 0x00000080;
    pub const WS_EX_WINDOWEDGE: ULONG32 = 0x00000100;
    pub const WS_EX_CLIENTEDGE: ULONG32 = 0x00000200;
    pub const WS_EX_CONTEXTHELP: ULONG32 = 0x00000400;
}

// =============================================================================
// Show Window Commands
// =============================================================================

/// ShowWindow commands.
pub mod show_window {
    use super::ULONG32;
    pub const SW_HIDE: ULONG32 = 0;
    pub const SW_SHOWNORMAL: ULONG32 = 1;
    pub const SW_NORMAL: ULONG32 = 1;
    pub const SW_SHOWMINIMIZED: ULONG32 = 2;
    pub const SW_SHOWMAXIMIZED: ULONG32 = 3;
    pub const SW_MAXIMIZE: ULONG32 = 3;
    pub const SW_SHOWNOACTIVATE: ULONG32 = 4;
    pub const SW_SHOW: ULONG32 = 5;
    pub const SW_MINIMIZE: ULONG32 = 6;
    pub const SW_SHOWMINNOACTIVE: ULONG32 = 7;
    pub const SW_SHOWNA: ULONG32 = 8;
    pub const SW_RESTORE: ULONG32 = 9;
    pub const SW_SHOWDEFAULT: ULONG32 = 10;
}

// =============================================================================
// Message Constants
// =============================================================================

/// Common window messages.
pub mod messages {
    use super::ULONG32;
    pub const WM_NULL: ULONG32 = 0x0000;
    pub const WM_CREATE: ULONG32 = 0x0001;
    pub const WM_DESTROY: ULONG32 = 0x0002;
    pub const WM_MOVE: ULONG32 = 0x0003;
    pub const WM_SIZE: ULONG32 = 0x0005;
    pub const WM_ACTIVATE: ULONG32 = 0x0006;
    pub const WM_SETFOCUS: ULONG32 = 0x0007;
    pub const WM_KILLFOCUS: ULONG32 = 0x0008;
    pub const WM_ENABLE: ULONG32 = 0x000A;
    pub const WM_SETREDRAW: ULONG32 = 0x000B;
    pub const WM_SETTEXT: ULONG32 = 0x000C;
    pub const WM_GETTEXT: ULONG32 = 0x000D;
    pub const WM_GETTEXTLENGTH: ULONG32 = 0x000E;
    pub const WM_PAINT: ULONG32 = 0x000F;
    pub const WM_CLOSE: ULONG32 = 0x0010;
    pub const WM_QUERYENDSESSION: ULONG32 = 0x0011;
    pub const WM_QUIT: ULONG32 = 0x0012;
    pub const WM_QUERYOPEN: ULONG32 = 0x0013;
    pub const WM_ERASEBKGND: ULONG32 = 0x0014;
    pub const WM_SYSCOLORCHANGE: ULONG32 = 0x0015;
    pub const WM_SHOWWINDOW: ULONG32 = 0x0018;
    pub const WM_WININICHANGE: ULONG32 = 0x001A;
    pub const WM_SETTINGCHANGE: ULONG32 = 0x001A;
    pub const WM_QUERYSENDSMSG: ULONG32 = 0x0022;
    pub const WM_GETMINMAXINFO: ULONG32 = 0x0024;
    pub const WM_PAINTICON: ULONG32 = 0x0026;
    pub const WM_ICONERASEBKGND: ULONG32 = 0x0027;
    pub const WM_NEXTDLGCTL: ULONG32 = 0x0028;
    pub const WM_SPOOLERSTATUS: ULONG32 = 0x002A;
    pub const WM_DRAWITEM: ULONG32 = 0x002B;
    pub const WM_MEASUREITEM: ULONG32 = 0x002C;
    pub const WM_DELETEITEM: ULONG32 = 0x002D;
    pub const WM_VKEYTOITEM: ULONG32 = 0x002E;
    pub const WM_CHARTOITEM: ULONG32 = 0x002F;
    pub const WM_SETFONT: ULONG32 = 0x0030;
    pub const WM_GETFONT: ULONG32 = 0x0031;
    pub const WM_SETHOTKEY: ULONG32 = 0x0032;
    pub const WM_GETHOTKEY: ULONG32 = 0x0033;
    pub const WM_QUERYDRAGICON: ULONG32 = 0x0037;
    pub const WM_COMPAREITEM: ULONG32 = 0x0039;
    pub const WM_GETOBJECT: ULONG32 = 0x003D;
    pub const WM_COMPACTING: ULONG32 = 0x0041;
    pub const WM_WINDOWPOSCHANGING: ULONG32 = 0x0046;
    pub const WM_WINDOWPOSCHANGED: ULONG32 = 0x0047;
    pub const WM_INPUTLANGCHANGEREQUEST: ULONG32 = 0x0050;
    pub const WM_INPUTLANGCHANGE: ULONG32 = 0x0051;
    pub const WM_TCARD: ULONG32 = 0x0052;
    pub const WM_HELP: ULONG32 = 0x0053;
    pub const WM_USERCHANGED: ULONG32 = 0x0054;
    pub const WM_NOTIFY: ULONG32 = 0x004E;
    pub const WM_NOTIFYFORMAT: ULONG32 = 0x0055;
    pub const WM_CONTEXTMENU: ULONG32 = 0x007B;
    pub const WM_STYLECHANGING: ULONG32 = 0x007C;
    pub const WM_STYLECHANGED: ULONG32 = 0x007D;
    pub const WM_DISPLAYCHANGE: ULONG32 = 0x007E;
    pub const WM_GETICON: ULONG32 = 0x007F;
    pub const WM_SETICON: ULONG32 = 0x0080;
    pub const WM_NCCREATE: ULONG32 = 0x0081;
    pub const WM_NCDESTROY: ULONG32 = 0x0082;
    pub const WM_NCCALCSIZE: ULONG32 = 0x0083;
    pub const WM_NCHITTEST: ULONG32 = 0x0084;
    pub const WM_NCPAINT: ULONG32 = 0x0085;
    pub const WM_NCACTIVATE: ULONG32 = 0x0086;
    pub const WM_GETDLGCODE: ULONG32 = 0x0087;
    pub const WM_NCMOUSEMOVE: ULONG32 = 0x00A0;
    pub const WM_NCLBUTTONDOWN: ULONG32 = 0x00A1;
    pub const WM_NCLBUTTONUP: ULONG32 = 0x00A2;
    pub const WM_NCLBUTTONDBLCLK: ULONG32 = 0x00A3;
    pub const WM_NCRBUTTONDOWN: ULONG32 = 0x00A4;
    pub const WM_NCRBUTTONUP: ULONG32 = 0x00A5;
    pub const WM_NCRBUTTONDBLCLK: ULONG32 = 0x00A6;
    pub const WM_KEYDOWN: ULONG32 = 0x0100;
    pub const WM_KEYUP: ULONG32 = 0x0101;
    pub const WM_CHAR: ULONG32 = 0x0102;
    pub const WM_DEADCHAR: ULONG32 = 0x0103;
    pub const WM_SYSKEYDOWN: ULONG32 = 0x0104;
    pub const WM_SYSKEYUP: ULONG32 = 0x0105;
    pub const WM_SYSCHAR: ULONG32 = 0x0106;
    pub const WM_SYSDEADCHAR: ULONG32 = 0x0107;
    pub const WM_INITDIALOG: ULONG32 = 0x0110;
    pub const WM_COMMAND: ULONG32 = 0x0111;
    pub const WM_SYSCOMMAND: ULONG32 = 0x0112;
    pub const WM_TIMER: ULONG32 = 0x0113;
    pub const WM_HSCROLL: ULONG32 = 0x0114;
    pub const WM_VSCROLL: ULONG32 = 0x0115;
    pub const WM_INITMENU: ULONG32 = 0x0116;
    pub const WM_INITMENUPOPUP: ULONG32 = 0x0117;
    pub const WM_MENUSELECT: ULONG32 = 0x011F;
    pub const WM_MENUCHAR: ULONG32 = 0x0120;
    pub const WM_ENTERIDLE: ULONG32 = 0x0121;
    pub const WM_CTLCOLORMSGBOX: ULONG32 = 0x0132;
    pub const WM_CTLCOLOREDIT: ULONG32 = 0x0133;
    pub const WM_CTLCOLORLISTBOX: ULONG32 = 0x0134;
    pub const WM_CTLCOLORBTN: ULONG32 = 0x0135;
    pub const WM_CTLCOLORDLG: ULONG32 = 0x0136;
    pub const WM_CTLCOLORSCROLLBAR: ULONG32 = 0x0137;
    pub const WM_CTLCOLORSTATIC: ULONG32 = 0x0138;
    pub const WM_MOUSEMOVE: ULONG32 = 0x0200;
    pub const WM_LBUTTONDOWN: ULONG32 = 0x0201;
    pub const WM_LBUTTONUP: ULONG32 = 0x0202;
    pub const WM_LBUTTONDBLCLK: ULONG32 = 0x0203;
    pub const WM_RBUTTONDOWN: ULONG32 = 0x0204;
    pub const WM_RBUTTONUP: ULONG32 = 0x0205;
    pub const WM_RBUTTONDBLCLK: ULONG32 = 0x0206;
    pub const WM_MBUTTONDOWN: ULONG32 = 0x0207;
    pub const WM_MBUTTONUP: ULONG32 = 0x0208;
    pub const WM_MBUTTONDBLCLK: ULONG32 = 0x0209;
    pub const WM_MOUSEWHEEL: ULONG32 = 0x020A;
    pub const WM_MOUSEHOVER: ULONG32 = 0x02A1;
    pub const WM_MOUSELEAVE: ULONG32 = 0x02A3;
}

// =============================================================================
// CreateWindowExW
// =============================================================================

/// Create a window with extended styles (Unicode version).
///
/// # Arguments
/// * `ex_style` - Extended window style
/// * `class_name` - 32-bit pointer to class name string
/// * `window_name` - 32-bit pointer to window name string
/// * `style` - Window style
/// * `x`, `y` - Position
/// * `width`, `height` - Size
/// * `parent` - Parent window handle
/// * `menu` - Menu handle
/// * `instance` - Instance handle
/// * `param` - Creation parameters
///
/// # Returns
/// * Window handle or NULL
pub unsafe extern "C" fn Wow64CreateWindowExW(
    ex_style: ULONG32,
    class_name: ULONG32,
    window_name: ULONG32,
    style: ULONG32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: HWND32,
    menu: HMENU32,
    instance: HINSTANCE32,
    param: ULONG32,
) -> HWND32 {

    // Build parameter array for syscall
    let params: [ULONG32; 12] = [
        ex_style,
        class_name,
        window_name,
        style,
        x as ULONG32,
        y as ULONG32,
        width as ULONG32,
        height as ULONG32,
        parent,
        menu,
        instance,
        param,
    ];

    // Make Win32k syscall
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtUserCreateWindowEx,
        params.as_ptr(),
    );

    // log via wow64_klog!; using wow64_klog! instead
    result
}

// =============================================================================
// DestroyWindow
// =============================================================================

/// Destroy a window.
///
/// # Returns
/// * TRUE on success, FALSE on failure
pub unsafe extern "C" fn Wow64DestroyWindow(hwnd: HWND32) -> BOOL32 {
    // log via wow64_klog!; using wow64_klog! instead

    let params: [ULONG32; 1] = [hwnd];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtUserDestroyWindow,
        params.as_ptr(),
    );

    result as BOOL32
}

// =============================================================================
// ShowWindow
// =============================================================================

/// Set the specified window's show state.
///
/// # Returns
/// * TRUE if the window was previously visible, FALSE otherwise
pub unsafe extern "C" fn Wow64ShowWindow(hwnd: HWND32, cmd_show: ULONG32) -> BOOL32 {

    let params: [ULONG32; 2] = [hwnd, cmd_show];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtUserShowWindow,
        params.as_ptr(),
    );

    result as BOOL32
}

// =============================================================================
// GetMessageW
// =============================================================================

/// Retrieves a message from the message queue.
///
/// # Returns
/// * FALSE if WM_QUIT is received, TRUE otherwise
pub unsafe extern "C" fn Wow64GetMessageW(
    msg: *mut Msg32,
    _hwnd: HWND32,
    _msg_filter_min: ULONG32,
    _msg_filter_max: ULONG32,
) -> BOOL32 {

    if msg.is_null() {
        return 0;
    }

    // In a real implementation, this would:
    // 1. Copy parameters to the 64-bit structure
    // 2. Call into win32k.sys
    // 3. Copy the result back to the 32-bit structure

    // For stub, return FALSE (quit)
    0
}

// =============================================================================
// PeekMessageW
// =============================================================================

/// Checks the message queue for messages.
///
/// # Returns
/// * TRUE if a message is available, FALSE otherwise
pub unsafe extern "C" fn Wow64PeekMessageW(
    _msg: *mut Msg32,
    _hwnd: HWND32,
    _msg_filter_min: ULONG32,
    _msg_filter_max: ULONG32,
    _remove_msg: ULONG32,
) -> BOOL32 {

    0
}

// =============================================================================
// TranslateMessage
// =============================================================================

/// Translates virtual-key messages into character messages.
///
/// # Returns
/// * TRUE if the message was translated, FALSE otherwise
pub unsafe extern "C" fn Wow64TranslateMessage(_msg: *const Msg32) -> BOOL32 {
    // log via wow64_klog!; using wow64_klog! instead

    // This is typically handled by the message loop
    0
}

// =============================================================================
// DispatchMessageW
// =============================================================================

/// Dispatches a message to the window procedure.
///
/// # Returns
/// * The result of the window procedure
pub unsafe extern "C" fn Wow64DispatchMessageW(_msg: *const Msg32) -> LRESULT32 {
    // log via wow64_klog!; using wow64_klog! instead

    // In a real implementation, call the window procedure
    0
}

// =============================================================================
// PostMessageW
// =============================================================================

/// Places a message in the message queue and returns without waiting.
///
/// # Returns
/// * TRUE if successful, FALSE otherwise
pub unsafe extern "C" fn Wow64PostMessageW(
    hwnd: HWND32,
    msg: ULONG32,
    wparam: WPARAM32,
    lparam: LPARAM32,
) -> BOOL32 {

    let params: [ULONG32; 4] = [hwnd, msg, wparam, lparam];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtUserPostMessage,
        params.as_ptr(),
    );

    result as BOOL32
}

// =============================================================================
// SendMessageW
// =============================================================================

/// Sends a message to the window procedure and waits for a result.
///
/// # Returns
/// * The result of the window procedure
pub unsafe extern "C" fn Wow64SendMessageW(
    hwnd: HWND32,
    msg: ULONG32,
    wparam: WPARAM32,
    lparam: LPARAM32,
) -> LRESULT32 {

    let params: [ULONG32; 4] = [hwnd, msg, wparam, lparam];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtUserSendMessage,
        params.as_ptr(),
    );

    result as LRESULT32
}

// =============================================================================
// GetDC / ReleaseDC
// =============================================================================

/// Retrieves the device context for the entire window.
///
/// # Returns
/// * DC handle or NULL
pub unsafe extern "C" fn Wow64GetDC(hwnd: HWND32) -> HDC32 {
    // log via wow64_klog!; using wow64_klog! instead

    let params: [ULONG32; 1] = [hwnd];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtGdiGetDC,
        params.as_ptr(),
    );

    result
}

/// Releases a device context.
///
/// # Returns
/// * 1 if successful, 0 otherwise
pub unsafe extern "C" fn Wow64ReleaseDC(hwnd: HWND32, hdc: HDC32) -> i32 {

    let params: [ULONG32; 2] = [hwnd, hdc];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtGdiReleaseDC,
        params.as_ptr(),
    );

    result as i32
}
