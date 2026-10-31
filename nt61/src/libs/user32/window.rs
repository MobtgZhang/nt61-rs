//! user32 — window management (real window table)
//!
//! `create_window_ex_w` resolves the class through the class table
//! (by name, or by a MAKEINTATOM value), allocates a handle from the
//! user32 handle table, stores a full WINDOW object and delivers
//! WM_NCCREATE / WM_CREATE to the class procedure. `destroy_window`
//! runs WM_DESTROY / WM_NCDESTROY and frees the object;
//! `show_window` / `update_window` update the visibility flag and
//! deliver WM_SHOWWINDOW / WM_PAINT.
//!
//! References:
//!   * MSDN Library "Windows 7" — CreateWindowExW / DestroyWindow /
//!     ShowWindow / UpdateWindow
//!   * ReactOS win32ss/user/ntuser/window.c

extern crate alloc;

use super::class::{lookup_by_atom, lookup_by_name, WndProcFn};
use super::types::*;
use super::wstr;
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

// The message pump entry points are implemented once in the
// `message` module; window consumers reach them through this
// module so the pump and the window table share one MSG type.
pub use super::message::MSG as Msg;
pub use super::message::{
    dispatch_message_w, get_message_a, get_message_w, peek_message_a, peek_message_w,
    post_message_a, post_message_w, post_quit_message, send_message_a, send_message_w,
    translate_message, wait_message,
};

/// Window class style flags (winuser.h CS_*).
pub mod class {
    pub const CS_VREDRAW: u32 = 0x0000_0001;
    pub const CS_HREDRAW: u32 = 0x0000_0002;
    pub const CS_DBLCLKS: u32 = 0x0000_0008;
    pub const CS_OWNDC: u32 = 0x0000_0020;
    pub const CS_CLASSDC: u32 = 0x0000_0040;
    pub const CS_PARENTDC: u32 = 0x0000_0080;
    pub const CS_NOCLOSE: u32 = 0x0000_0200;
    pub const CS_SAVEBITS: u32 = 0x0000_0800;
    pub const CS_BYTEALIGNCLIENT: u32 = 0x0000_1000;
    pub const CS_BYTEALIGNWINDOW: u32 = 0x0000_2000;
    pub const CS_GLOBALCLASS: u32 = 0x0000_4000;
    pub const CS_IME: u32 = 0x0001_0000;
}

/// ShowWindow commands (winuser.h SW_*).
pub mod sw {
    pub const SW_HIDE: i32 = 0;
    pub const SW_SHOWNORMAL: i32 = 1;
    pub const SW_SHOWMINIMIZED: i32 = 2;
    pub const SW_SHOWMAXIMIZED: i32 = 3;
    pub const SW_MAXIMIZE: i32 = 3;
    pub const SW_SHOWNOACTIVATE: i32 = 4;
    pub const SW_SHOW: i32 = 5;
    pub const SW_MINIMIZE: i32 = 6;
    pub const SW_SHOWMINNOACTIVE: i32 = 7;
    pub const SW_SHOWNA: i32 = 8;
    pub const SW_RESTORE: i32 = 9;
    pub const SW_SHOWDEFAULT: i32 = 10;
    pub const SW_FORCEMINIMIZE: i32 = 11;
}

/// Window styles (winuser.h WS_*).
pub mod ws {
    pub const WS_OVERLAPPED: u32 = 0x0000_0000;
    pub const WS_TABSTOP: u32 = 0x0001_0000;
    pub const WS_MAXIMIZEBOX: u32 = 0x0002_0000;
    pub const WS_MINIMIZEBOX: u32 = 0x0004_0000;
    pub const WS_GROUP: u32 = 0x0008_0000;
    pub const WS_SYSMENU: u32 = 0x0008_0000;
    pub const WS_HSCROLL: u32 = 0x0010_0000;
    pub const WS_VSCROLL: u32 = 0x0020_0000;
    pub const WS_CLIPCHILDREN: u32 = 0x0300_0000;
    pub const WS_CAPTION: u32 = 0x00C0_0000;
    pub const WS_MAXIMIZE: u32 = 0x0100_0000;
    pub const WS_CLIPSIBLINGS: u32 = 0x0400_0000;
    pub const WS_DISABLED: u32 = 0x0800_0000;
    pub const WS_VISIBLE: u32 = 0x1000_0000;
    pub const WS_MINIMIZE: u32 = 0x2000_0000;
    pub const WS_CHILD: u32 = 0x4000_0000;
    pub const WS_POPUP: u32 = 0x8000_0000;
    pub const WS_BORDER: u32 = 0x0080_0000;
    pub const WS_DLGFRAME: u32 = 0x0040_0000;
    pub const WS_THICKFRAME: u32 = 0x0004_0000;
}

/// GetWindowLongPtrW index constants (winuser.h GWL_*).
pub mod gwl {
    pub const GWL_WNDPROC: i32 = -4;
    pub const GWL_HINSTANCE: i32 = -6;
    pub const GWL_HWNDPARENT: i32 = -8;
    pub const GWL_STYLE: i32 = -16;
    pub const GWL_EXSTYLE: i32 = -20;
}

/// RECT (winuser.h) — window rectangle in screen coordinates.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RectW {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// CREATESTRUCTW (winuser.h) — lParam of WM_NCCREATE.
#[repr(C)]
pub struct CreateStructW {
    pub lp_create_params: LPVOID,
    pub h_instance: HINSTANCE,
    pub h_menu: HMENU,
    pub hwnd_parent: HWND,
    pub cy: i32,
    pub cx: i32,
    pub y: i32,
    pub x: i32,
    pub style: i32,
    pub lpsz_name: LPCWSTR,
    pub lpsz_class: LPCWSTR,
    pub dw_ex_style: DWORD,
}

/// One live window: the full state CreateWindowExW captured plus
/// the mutable visibility flag ShowWindow toggles.
pub(crate) struct WindowObject {
    pub handle: u64,
    pub class_atom: ATOM,
    pub wnd_proc: Option<WndProcFn>,
    pub style: u32,
    pub ex_style: u32,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub text: Vec<u16>,
    pub parent: HWND,
    pub menu: HMENU,
    pub instance: HINSTANCE,
    pub create_param: LPARAM,
    pub visible: bool,
}

static WINDOW_OBJECT_TABLE: Spinlock<Vec<Option<WindowObject>>> = Spinlock::new(Vec::new());

static FOREGROUND_WINDOW: Spinlock<u64> = Spinlock::new(0);

/// MAKEINTATOM values arrive as a value strictly below 0x10000.
const MAKEINTATOM_MAX: usize = 0x0001_0000;

fn push_window(window: WindowObject) {
    WINDOW_OBJECT_TABLE.lock().push(Some(window));
}

fn remove_window(handle: u64) -> bool {
    let mut table = WINDOW_OBJECT_TABLE.lock();
    let position = table
        .iter()
        .position(|slot| matches!(slot, Some(w) if w.handle == handle));
    match position {
        Some(index) => {
            table.remove(index);
            true
        }
        None => false,
    }
}

fn window_exists(handle: u64) -> bool {
    WINDOW_OBJECT_TABLE
        .lock()
        .iter()
        .any(|slot| matches!(slot, Some(w) if w.handle == handle))
}

fn with_window_mut<F: FnOnce(&mut WindowObject)>(handle: u64, f: F) -> bool {
    let mut table = WINDOW_OBJECT_TABLE.lock();
    let found = table
        .iter_mut()
        .find(|slot| matches!(slot, Some(w) if w.handle == handle));
    match found {
        Some(Some(window)) => {
            f(window);
            true
        }
        _ => false,
    }
}

fn window_wnd_proc(handle: u64) -> Option<WndProcFn> {
    WINDOW_OBJECT_TABLE.lock().iter().find_map(|slot| {
        let window = slot.as_ref()?;
        if window.handle == handle {
            window.wnd_proc
        } else {
            None
        }
    })
}

/// Copy of the window text stored with the WINDOW object.
fn window_text(handle: u64) -> Option<Vec<u16>> {
    let mut text: Option<Vec<u16>> = None;
    with_window_mut(handle, |window| text = Some(window.text.clone()));
    text
}

/// The create parameter the WINDOW object carries for the
/// WM_CREATE delivery.
fn window_create_param(handle: u64) -> LPARAM {
    let mut param: LPARAM = 0;
    with_window_mut(handle, |window| param = window.create_param);
    param
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Deliver a message to the procedure behind `hwnd`; proc-less
/// classes fall through to DefWindowProcW.
pub unsafe fn call_window_procedure(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match window_wnd_proc(hwnd as u64) {
        Some(wnd_proc) => wnd_proc(hwnd, message, wparam, lparam),
        None => def_window_proc_w(hwnd, message, wparam, lparam),
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// DefWindowProcW — default handling for messages no class
/// procedure claimed. The default procedure acknowledges
/// WM_NCCREATE so window creation is not mistaken for an abort.
pub unsafe extern "C" fn def_window_proc_w(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let _ = (hwnd, wparam, lparam);
    match message {
        super::message::wm::WM_NCCREATE => TRUE as LRESULT,
        _ => 0,
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// CreateWindowExW — resolve the class, allocate the WINDOW
/// object and run WM_NCCREATE / WM_CREATE. WM_CREATE returning -1
/// aborts creation and returns NULL.
pub unsafe extern "C" fn create_window_ex_w(
    ex_style: u32,
    class_name: LPCWSTR,
    window_name: LPCWSTR,
    style: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: HWND,
    menu: HMENU,
    instance: HINSTANCE,
    param: LPVOID,
) -> HWND {
    let name_value = class_name as usize;
    let resolved_class = if name_value < MAKEINTATOM_MAX {
        lookup_by_atom(name_value as ATOM)
    } else {
        lookup_by_name(&wstr::units_of(class_name))
    };
    let Some(registered) = resolved_class else {
        return core::ptr::null_mut();
    };

    let text = wstr::units_of(window_name);
    let handle = super::alloc_window_handle();
    let hwnd = handle as HWND;
    let visible = (style & ws::WS_VISIBLE) != 0;

    push_window(WindowObject {
        handle,
        class_atom: registered.atom,
        wnd_proc: registered.wnd_proc,
        style,
        ex_style,
        x,
        y,
        width,
        height,
        text,
        parent,
        menu,
        instance,
        create_param: param as LPARAM,
        visible,
    });

    let create_struct = CreateStructW {
        lp_create_params: param,
        h_instance: instance,
        h_menu: menu,
        hwnd_parent: parent,
        cy: height,
        cx: width,
        y,
        x,
        style: style as i32,
        lpsz_name: window_name,
        lpsz_class: class_name,
        dw_ex_style: ex_style,
    };
    let _ = call_window_procedure(
        hwnd,
        super::message::wm::WM_NCCREATE,
        0,
        core::ptr::addr_of!(create_struct) as LPARAM,
    );
    if call_window_procedure(
        hwnd,
        super::message::wm::WM_CREATE,
        0,
        window_create_param(handle),
    ) == -1
    {
        remove_window(handle);
        return core::ptr::null_mut();
    }
    if visible {
        call_window_procedure(hwnd, super::message::wm::WM_SHOWWINDOW, 1, 0);
    }
    hwnd
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// DestroyWindow — run WM_DESTROY / WM_NCDESTROY and free the
/// WINDOW object. The foreground handle is cleared when the
/// destroyed window owned it.
pub unsafe extern "C" fn destroy_window(hwnd: HWND) -> BOOL {
    if hwnd.is_null() {
        return FALSE;
    }
    let handle = hwnd as u64;
    if !window_exists(handle) {
        return FALSE;
    }
    {
        let mut foreground = FOREGROUND_WINDOW.lock();
        if *foreground == handle {
            *foreground = 0;
        }
    }
    call_window_procedure(hwnd, super::message::wm::WM_DESTROY, 0, 0);
    call_window_procedure(hwnd, super::message::wm::WM_NCDESTROY, 0, 0);
    remove_window(handle);
    TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// ShowWindow — toggle visibility per the SW_* command and
/// deliver WM_SHOWWINDOW. Returns whether the window was
/// previously visible.
pub unsafe extern "C" fn show_window(hwnd: HWND, cmd: i32) -> BOOL {
    if hwnd.is_null() {
        return FALSE;
    }
    let handle = hwnd as u64;
    let mut was_visible = false;
    if !with_window_mut(handle, |window| {
        was_visible = window.visible;
        window.visible = cmd != sw::SW_HIDE;
    }) {
        return FALSE;
    }
    let shown = if cmd != sw::SW_HIDE { 1 } else { 0 };
    call_window_procedure(hwnd, super::message::wm::WM_SHOWWINDOW, shown, 0);
    if was_visible {
        TRUE
    } else {
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// UpdateWindow — deliver WM_PAINT for a live window.
pub unsafe extern "C" fn update_window(hwnd: HWND) -> BOOL {
    if hwnd.is_null() || !window_exists(hwnd as u64) {
        return FALSE;
    }
    call_window_procedure(hwnd, super::message::wm::WM_PAINT, 0, 0);
    TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// GetWindowTextW — copy the window text into the caller buffer,
/// NUL-terminated, and return the number of characters copied.
pub unsafe extern "C" fn get_window_text_w(hwnd: HWND, buffer: LPWSTR, max_count: i32) -> i32 {
    if buffer.is_null() || max_count <= 0 {
        return 0;
    }
    let Some(text) = window_text(hwnd as u64) else {
        return 0;
    };
    let max_chars = max_count as usize;
    let copy_len = text.len().min(max_chars - 1);
    for (index, unit) in text.iter().take(copy_len).enumerate() {
        *buffer.add(index) = *unit;
    }
    *buffer.add(copy_len) = 0;
    copy_len as i32
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// GetWindowRectW — screen-coordinate rectangle of the window.
pub unsafe extern "C" fn get_window_rect_w(hwnd: HWND, rect: *mut RectW) -> BOOL {
    if hwnd.is_null() || rect.is_null() {
        return FALSE;
    }
    let mut out = RectW {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    let found = with_window_mut(hwnd as u64, |window| {
        out = RectW {
            left: window.x,
            top: window.y,
            right: window.x + window.width,
            bottom: window.y + window.height,
        };
    });
    if !found {
        return FALSE;
    }
    *rect = out;
    TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// GetWindowLongPtrW — read a window word by GWL_* index.
pub unsafe extern "C" fn get_window_long_ptr_w(hwnd: HWND, index: i32) -> LongPtr {
    if hwnd.is_null() {
        return 0;
    }
    let mut result: LongPtr = 0;
    let found = with_window_mut(hwnd as u64, |window| {
        result = match index {
            gwl::GWL_WNDPROC => window.wnd_proc.map_or(0, |proc| proc as isize),
            gwl::GWL_HINSTANCE => window.instance as LongPtr,
            gwl::GWL_HWNDPARENT => window.parent as LongPtr,
            gwl::GWL_STYLE => window.style as LongPtr,
            gwl::GWL_EXSTYLE => window.ex_style as LongPtr,
            _ => 0,
        };
    });
    if found {
        result
    } else {
        0
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// GetParentW — parent handle captured at creation.
pub unsafe extern "C" fn get_parent_w(hwnd: HWND) -> HWND {
    let mut parent: HWND = core::ptr::null_mut();
    with_window_mut(hwnd as u64, |window| parent = window.parent);
    parent
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// GetMenuW — menu handle captured at creation.
pub unsafe extern "C" fn get_menu_w(hwnd: HWND) -> HMENU {
    let mut menu: HMENU = core::ptr::null_mut();
    with_window_mut(hwnd as u64, |window| menu = window.menu);
    menu
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// GetForegroundWindow — the last window handed to
/// SetForegroundWindow (NULL until one is set).
pub unsafe extern "C" fn get_foreground_window() -> HWND {
    *FOREGROUND_WINDOW.lock() as HWND
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// SetForegroundWindow — record the foreground handle.
pub unsafe extern "C" fn set_foreground_window(hwnd: HWND) -> BOOL {
    *FOREGROUND_WINDOW.lock() = hwnd as u64;
    TRUE
}

/// True while any live window still references the class —
/// UnregisterClassW must refuse to remove such classes.
pub(crate) fn has_windows_of_class(atom: ATOM) -> bool {
    WINDOW_OBJECT_TABLE
        .lock()
        .iter()
        .any(|slot| matches!(slot, Some(w) if w.class_atom == atom))
}
