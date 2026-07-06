//! Window Management for win32k.sys
//
//! Implements window objects, window classes, and the USER subsystem.
//! This module provides the core windowing infrastructure for GDI.
//
//! ## Window Architecture
//
//! In NT win32k, windows are managed through:
//! - Window objects: Describe each window's properties
//! - Window classes: Define window behavior via WndProc
//! - Window messages: Communication between windows and the system
//! - Desktop/WindowStation: Organize windows in a hierarchy

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::vec::Vec;
use alloc::sync::Arc;
use crate::kprintln;

/// Maximum number of windows in the system.
const MAX_WINDOWS: usize = 4096;

/// Maximum number of window classes.
const MAX_WINDOW_CLASSES: usize = 256;

/// Window style flags as a bitmask wrapper.
/// These are bitmask values matching Windows WS_* constants.
/// Use the `bits()` and `from_bits()` methods for value access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct WindowStyle(u32);

impl WindowStyle {
    pub const BORDER: u32 = 0x00800000;
    pub const CAPTION: u32 = 0x00C00000;
    pub const CHILD: u32 = 0x40000000;
    pub const CLIP_CHILDREN: u32 = 0x02000000;
    pub const CLIP_SIBLINGS: u32 = 0x04000000;
    pub const DISABLED: u32 = 0x08000000;
    pub const GROUP: u32 = 0x00020000;
    pub const HORIZONTAL_SCROLL: u32 = 0x00100000;
    pub const VERTICAL_SCROLL: u32 = 0x00200000;
    pub const ICONIC: u32 = 0x20000000;
    pub const MAXIMIZE: u32 = 0x01000000;
    pub const MAXIMIZE_BOX: u32 = 0x00010000;
    pub const MINIMIZE: u32 = 0x20000000;
    pub const POPUP: u32 = 0x80000000;
    pub const SIZE_BOX: u32 = 0x00040000;
    pub const SYS_MENU: u32 = 0x00080000;
    pub const TAB_STOP: u32 = 0x00010000;
    pub const VISIBLE: u32 = 0x10000000;

    pub const fn new(bits: u32) -> Self { Self(bits) }
    pub const fn bits(&self) -> u32 { self.0 }
    pub fn set(&mut self, flag: u32) { self.0 |= flag; }
    pub fn contains(&self, flag: u32) -> bool { (self.0 & flag) == flag }
}

/// Extended window style flags as a bitmask wrapper.
/// Matches Windows WS_EX_* constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct WindowStyleEx(u32);

impl WindowStyleEx {
    pub const APP_WINDOW: u32 = 0x00040000;
    pub const CLIENT_EDGE: u32 = 0x00000200;
    pub const COMBINE_RECT: u32 = 0x00000020;
    pub const CONTEXT_HELP: u32 = 0x00000400;
    pub const DLG_MODAL_FRAME: u32 = 0x00000001;
    pub const LEFT: u32 = 0x00000000;
    pub const RIGHT: u32 = 0x00001000;
    pub const LTR_READING: u32 = 0x00000000;
    pub const NO_ACTIVATE: u32 = 0x08000000;
    pub const NO_INHERIT_LAYOUT: u32 = 0x00100000;
    pub const OVERLAPPED_WINDOW: u32 = 0x00000300;
    pub const RIGHT_SCROLLBAR: u32 = 0x00000000;
    pub const RTL_READING: u32 = 0x00002000;
    pub const STATIC_EDGE: u32 = 0x00020000;
    pub const TOOL_WINDOW: u32 = 0x00000080;
    pub const TOPMOST: u32 = 0x00000008;
    pub const TRANSPARENT: u32 = 0x00000020;
    pub const WINDOW_EDGE: u32 = 0x00000100;

    pub const fn new(bits: u32) -> Self { Self(bits) }
    pub const fn bits(&self) -> u32 { self.0 }
    pub fn set(&mut self, flag: u32) { self.0 |= flag; }
    pub fn contains(&self, flag: u32) -> bool { (self.0 & flag) == flag }
}

/// Window message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WindowMessage {
    WM_CREATE = 0x0001,
    WM_DESTROY = 0x0002,
    WM_MOVE = 0x0003,
    WM_SIZE = 0x0005,
    WM_ACTIVATE = 0x0006,
    WM_SETFOCUS = 0x0007,
    WM_KILLFOCUS = 0x0008,
    WM_ENABLE = 0x000A,
    WM_SETREDRAW = 0x000B,
    WM_SETTEXT = 0x000C,
    WM_GETTEXT = 0x000D,
    WM_GETTEXTLENGTH = 0x000E,
    WM_PAINT = 0x000F,
    WM_CLOSE = 0x0010,
    WM_QUERYENDSESSION = 0x0011,
    WM_QUIT = 0x0012,
    WM_QUERYOPEN = 0x0013,
    WM_ERASEBKGND = 0x0014,
    WM_SYSCOLORCHANGE = 0x0015,
    WM_SHOWWINDOW = 0x0018,
    WM_WININICHANGE = 0x001A,
    WM_SETCURSOR = 0x0020,
    WM_MOUSEACTIVATE = 0x0021,
    WM_CHILDACTIVATE = 0x0022,
    WM_QUEUESYNC = 0x0023,
    WM_GETMINMAXINFO = 0x0024,
    WM_PAINTICON = 0x0026,
    WM_ICONERASEBKGND = 0x0027,
    WM_SPOOLER_STATUS = 0x002A,
    WM_DRAWITEM = 0x002B,
    WM_MEASUREITEM = 0x002C,
    WM_DELETEITEM = 0x002D,
    WM_VKEYTOITEM = 0x002E,
    WM_CHARTOITEM = 0x002F,
    WM_SETFONT = 0x0030,
    WM_GETFONT = 0x0031,
    WM_SETHOTKEY = 0x0032,
    WM_GETHOTKEY = 0x0033,
    WM_QUERYDRAGICON = 0x0037,
    WM_COMPAREITEM = 0x0039,
    WM_GETOBJECT = 0x003D,
    WM_COMPACTING = 0x0041,
    WM_WINDOWPOSCHANGING = 0x0046,
    WM_WINDOWPOSCHANGED = 0x0047,
    WM_COPYDATA = 0x004A,
    WM_CANCELJOURNAL = 0x004B,
    WM_CANCELMODE = 0x001F,
    WM_NOTIFY = 0x004E,
    WM_INPUTLANGCHANGEREQUEST = 0x0050,
    WM_INPUTLANGCHANGE = 0x0051,
    WM_TCARD = 0x0052,
    WM_HELP = 0x0053,
    WM_USERCHANGED = 0x0054,
    WM_NOTIFYFORMAT = 0x0055,
    WM_CONTEXTMENU = 0x007B,
    WM_STYLECHANGING = 0x007C,
    WM_STYLECHANGED = 0x007D,
    WM_DISPLAYCHANGE = 0x007E,
    WM_GETICON = 0x007F,
    WM_SETICON = 0x0080,
    WM_NCCREATE = 0x0081,
    WM_NCDESTROY = 0x0082,
    WM_NCCALCSIZE = 0x0083,
    WM_NCHITTEST = 0x0084,
    WM_NCPAINT = 0x0085,
    WM_NCACTIVATE = 0x0086,
    WM_GETDLGCODE = 0x0087,
    WM_SYNCPAINT = 0x0088,
    WM_NCMOUSEMOVE = 0x00A0,
    WM_NCLBUTTONDOWN = 0x00A1,
    WM_NCLBUTTONUP = 0x00A2,
    WM_NCLBUTTONDBLCLK = 0x00A3,
    WM_NCRBUTTONDOWN = 0x00A4,
    WM_NCRBUTTONUP = 0x00A5,
    WM_NCRBUTTONDBLCLK = 0x00A6,
    WM_NCMBUTTONDOWN = 0x00A7,
    WM_NCMBUTTONUP = 0x00A8,
    WM_NCMBUTTONDBLCLK = 0x00A9,
    WM_KEYDOWN = 0x0100,
    WM_KEYUP = 0x0101,
    WM_CHAR = 0x0102,
    WM_DEADCHAR = 0x0103,
    WM_SYSKEYDOWN = 0x0104,
    WM_SYSKEYUP = 0x0105,
    WM_SYSCHAR = 0x0106,
    WM_SYSDEADCHAR = 0x0107,
    WM_KEYLAST = 0x0108,
    WM_INITDIALOG = 0x0110,
    WM_COMMAND = 0x0111,
    WM_SYSCOMMAND = 0x0112,
    WM_TIMER = 0x0113,
    WM_HSCROLL = 0x0114,
    WM_VSCROLL = 0x0115,
    WM_INITMENU = 0x0116,
    WM_INITMENUPOPUP = 0x0117,
    WM_MENUSELECT = 0x011F,
    WM_MENUCHAR = 0x0120,
    WM_ENTERIDLE = 0x0121,
    WM_MENURBUTTONUP = 0x0122,
    WM_MENUDRAG = 0x0123,
    WM_MENUGETOBJECT = 0x0124,
    WM_UNINITMENUPOPUP = 0x0125,
    WM_MENUCOMMAND = 0x0126,
    WM_CHANGEUISTATE = 0x0127,
    WM_UPDATEUISTATE = 0x0128,
    WM_QUERYUISTATE = 0x0129,
    WM_CTLCOLORMSGBOX = 0x0132,
    WM_CTLCOLOREDIT = 0x0133,
    WM_CTLCOLORLISTBOX = 0x0134,
    WM_CTLCOLORBTN = 0x0135,
    WM_CTLCOLORDLG = 0x0136,
    WM_CTLCOLORSCROLLBAR = 0x0137,
    WM_CTLCOLORSTATIC = 0x0138,
    WM_MOUSEMOVE = 0x0200,
    WM_LBUTTONDOWN = 0x0201,
    WM_LBUTTONUP = 0x0202,
    WM_LBUTTONDBLCLK = 0x0203,
    WM_RBUTTONDOWN = 0x0204,
    WM_RBUTTONUP = 0x0205,
    WM_RBUTTONDBLCLK = 0x0206,
    WM_MBUTTONDOWN = 0x0207,
    WM_MBUTTONUP = 0x0208,
    WM_MBUTTONDBLCLK = 0x0209,
    WM_MOUSEWHEEL = 0x020A,
    WM_XBUTTONDOWN = 0x020B,
    WM_XBUTTONUP = 0x020C,
    WM_XBUTTONDBLCLK = 0x020D,
    WM_MOUSEHOVER = 0x02A1,
    WM_MOUSELEAVE = 0x02A3,
    WM_MOUSEHWHEEL = 0x020E,
}

/// Window rectangle - uses shared Rect from objects.rs
pub use crate::libs::win32k::objects::Rect;

/// Window class structure
#[derive(Debug, Clone, Copy)]
pub struct WindowClass {
    pub name: [u16; 64],
    pub instance: u64,
    pub style: u32,
    pub wndproc: u64,
    pub cls_extra: i32,
    pub wnd_extra: i32,
    pub h_icon: u64,
    pub h_cursor: u64,
    pub h_brbackground: u64,
    pub menu_name: u64,
}

/// Window object
#[derive(Debug, Clone)]
pub struct WindowObject {
    pub hwnd: u64,
    pub class_name: [u16; 64],
    pub title: [u16; 256],
    pub style: u32,
    pub ex_style: u32,
    pub rect: Rect,
    pub client_rect: Rect,
    pub parent: Option<u64>,
    pub owner: Option<u64>,
    pub children: Vec<u64>,
    pub visible: bool,
    pub enabled: bool,
    pub foreground: bool,
    pub dirty: bool,
    pub dirty_rects: Vec<Rect>,
    pub wndproc: u64,
    pub user_data: u64,
}

impl WindowObject {
    pub fn new(hwnd: u64) -> Self {
        Self {
            hwnd,
            class_name: [0; 64],
            title: [0; 256],
            style: 0,
            ex_style: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            client_rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            parent: None,
            owner: None,
            children: Vec::new(),
            visible: false,
            enabled: true,
            foreground: false,
            dirty: false,
            dirty_rects: Vec::new(),
            wndproc: 0,
            user_data: 0,
        }
    }

    pub fn set_rect(&mut self, x: i32, y: i32, width: i32, height: i32) {
        self.rect.left = x;
        self.rect.top = y;
        self.rect.right = x + width;
        self.rect.bottom = y + height;
        self.dirty = true;
        self.update_client_rect();
    }

    pub fn update_client_rect(&mut self) {
        // Subtract window chrome (caption, border)
        let caption_height = if self.style & 0x00C00000 != 0 { 20 } else { 0 };
        let _ = &caption_height;
        let _ = &caption_height;
        let border_width = if self.style & 0x00800000 != 0 { 2 } else { 0 };
        let _ = &border_width;
        let _ = &border_width;
        self.client_rect = Rect {
            left: border_width,
            top: caption_height + border_width,
            right: self.rect.width() - border_width,
            bottom: self.rect.height() - border_width,
        };
    }
}

/// Window manager state
pub struct WindowManager {
    windows: Vec<Option<WindowObject>>,
    /// Linear search index table: (hwnd, index) pairs for O(n) lookup
    /// In a full implementation, this would be a proper HashMap
    /// For now, we maintain a parallel index for O(n) lookups
    hwnd_index: Vec<(u64, usize)>,
    next_hwnd: AtomicU64,
    window_count: AtomicUsize,
    classes: Vec<Option<WindowClass>>,
    next_class_atom: AtomicU64,
    foreground_window: AtomicU64,
    active_window: AtomicU64,
    capture_window: AtomicU64,
    focus_window: AtomicU64,
    desktop_window: AtomicU64,
}

impl WindowManager {
    pub const fn new() -> Self {
        Self {
            windows: Vec::new(),
            hwnd_index: Vec::new(),
            next_hwnd: AtomicU64::new(1), // HWND 0 is invalid
            window_count: AtomicUsize::new(0),
            classes: Vec::new(),
            next_class_atom: AtomicU64::new(1),
            foreground_window: AtomicU64::new(0),
            active_window: AtomicU64::new(0),
            capture_window: AtomicU64::new(0),
            focus_window: AtomicU64::new(0),
            desktop_window: AtomicU64::new(0),
        }
    }

    /// Allocate a new HWND.
    fn alloc_hwnd(&self) -> Option<u64> {
        let hwnd = self.next_hwnd.fetch_add(1, Ordering::SeqCst);
        let _ = &hwnd;
        let _ = &hwnd;
        if hwnd == 0 {
            None // Overflow
        } else {
            Some(hwnd)
        }
    }

    /// Create a new window.
    pub fn create_window(
        &mut self,
        class_name: &[u16],
        title: &[u16],
        style: u32,
        ex_style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        parent: Option<u64>,
        wndproc: u64,
    ) -> Option<u64> {
        let hwnd = self.alloc_hwnd()?;
        let _ = &hwnd;
        let _ = &hwnd;
        let mut window = WindowObject::new(hwnd);

        // Copy class name
        for (i, &c) in class_name.iter().take(63).enumerate() {
            window.class_name[i] = c;
        }

        // Copy title
        for (i, &c) in title.iter().take(255).enumerate() {
            window.title[i] = c;
        }

        window.style = style;
        window.ex_style = ex_style;
        window.set_rect(x, y, width, height);
        window.parent = parent;
        window.wndproc = wndproc;
        window.visible = style & 0x10000000 != 0;
        window.enabled = style & 0x08000000 == 0;

        // Add to children list if has parent
        if let Some(parent_hwnd) = parent {
            if let Some(parent_window) = self.get_window_mut(parent_hwnd) {
                parent_window.children.push(hwnd);
            }
        }

        // Add to windows Vec and register in index
        let index = self.windows.len();
        let _ = &index;
        let _ = &index;
        self.windows.push(Some(window));
        self.hwnd_index.push((hwnd, index));
        self.window_count.fetch_add(1, Ordering::Relaxed);

        // kprintln!("[win32k] CreateWindow: hwnd={:#x}, class={:?}, style={:#x}",  // kprintln disabled (memcpy crash workaround)
//             hwnd, "WindowClass", style);

        Some(hwnd)
    }

    /// Get a window by HWND using linear index lookup.
    pub fn get_window(&self, hwnd: u64) -> Option<&WindowObject> {
        // Linear search in index - acceptable for small window counts
        for &(h, idx) in &self.hwnd_index {
            if h == hwnd {
                return self.windows.get(idx)?.as_ref();
            }
        }
        None
    }

    /// Get a mutable window by HWND using linear index lookup.
    pub fn get_window_mut(&mut self, hwnd: u64) -> Option<&mut WindowObject> {
        // Linear search in index
        for &(h, idx) in &self.hwnd_index {
            if h == hwnd {
                return self.windows.get_mut(idx)?.as_mut();
            }
        }
        None
    }

    /// Destroy a window and all its children.
    pub fn destroy_window(&mut self, hwnd: u64) -> bool {
        // Step 1: Find window index
        let window_index = self.hwnd_index.iter()
            .find(|(h, _)| *h == hwnd)
            .map(|(_, idx)| *idx);
        let _ = &window_index;
        
        let window_index = match window_index {
            Some(idx) => idx,
            None => return false, // Window doesn't exist
        };
        
        let _ = &window_index;

        // Get window info before we modify anything
        let (parent_hwnd, children) = {
            if let Some(window) = self.windows[window_index].as_ref() {
                (window.parent, window.children.clone())
            } else {
                return false;
            }
        };

        // Step 2: Recursively destroy children first
        for child_hwnd in children {
            self.destroy_window(child_hwnd);
        }

        // Step 3: Remove from parent's children list
        if let Some(p_hwnd) = parent_hwnd {
            for &(h, idx) in &self.hwnd_index {
                if h == p_hwnd {
                    self.windows[idx]
                        .as_mut()
                        .map(|w| w.children.retain(|&h| h != hwnd));
                    break;
                }
            }
        }

        // Step 4: Send WM_DESTROY message before removal
        self.post_message(hwnd, WindowMessage::WM_DESTROY as u32, 0, 0);

        // Step 5: Remove from index
        self.hwnd_index.retain(|(h, _)| *h != hwnd);


        // Step 6: Mark slot as None (don't shift Vec elements)
        self.windows[window_index] = None;
        self.window_count.fetch_sub(1, Ordering::Relaxed);

        // kprintln!("[win32k] DestroyWindow: hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
        true
    }

    /// Show or hide a window.
    pub fn show_window(&mut self, hwnd: u64, show: bool) -> bool {
        if let Some(window) = self.get_window_mut(hwnd) {
            let was_visible = window.visible;
            let _ = &was_visible;
            let _ = &was_visible;
            window.visible = show;
            window.dirty = true;

            if show && !was_visible {
                self.post_message(hwnd, WindowMessage::WM_SHOWWINDOW as u32, 1, 0);
                self.post_message(hwnd, WindowMessage::WM_PAINT as u32, 0, 0);
            } else if !show && was_visible {
                self.post_message(hwnd, WindowMessage::WM_SHOWWINDOW as u32, 0, 0);
            }

            // kprintln!("[win32k] ShowWindow: hwnd={:#x}, show={}", hwnd, show)  // kprintln disabled (memcpy crash workaround);
            true
        } else {
            false
        }
    }

    /// Set window position.
    pub fn set_window_pos(
        &mut self,
        hwnd: u64,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) -> bool {
        if let Some(window) = self.get_window_mut(hwnd) {
            let old_rect = window.rect;
            let _ = &old_rect;
            let _ = &old_rect;
            window.set_rect(x, y, width, height);

            if window.visible {
                self.post_message(hwnd, WindowMessage::WM_MOVE as u32,
                    x as u64, y as i64);
                self.post_message(hwnd, WindowMessage::WM_SIZE as u32,
                    width as u64, height as i64);
                self.post_message(hwnd, WindowMessage::WM_PAINT as u32, 0, 0);
            }

            // kprintln!("[win32k] SetWindowPos: hwnd={:#x}, ({},{}) {}x{}",  // kprintln disabled (memcpy crash workaround)
//                 hwnd, x, y, width, height);
            true
        } else {
            false
        }
    }

    /// Get window rectangle.
    pub fn get_window_rect(&self, hwnd: u64) -> Option<Rect> {
        self.get_window(hwnd).map(|w| w.rect)
    }

    /// Get client rectangle.
    pub fn get_client_rect(&self, hwnd: u64) -> Option<Rect> {
        self.get_window(hwnd).map(|w| w.client_rect)
    }

    /// Post a message to a window's message queue.
    pub fn post_message(&mut self, hwnd: u64, msg: u32, wparam: u64, lparam: i64) -> bool {
        let _ = (hwnd, msg, wparam, lparam);
        // kprintln!("[win32k] PostMessage: hwnd={:#x}, msg={:#x}", hwnd, msg)  // kprintln disabled (memcpy crash workaround);
        // In a full implementation, this would add to the message queue
        true
    }

    /// Send a message directly to a window procedure.
    pub fn send_message(&mut self, hwnd: u64, msg: u32, wparam: u64, lparam: i64) -> i64 {
        let _ = (hwnd, msg, wparam, lparam);
        if let Some(window) = self.get_window(hwnd) {
            let _ = window;
            // kprintln!("[win32k] SendMessage: hwnd={:#x}, msg={:#x}, wparam={:#x}",  // kprintln disabled (memcpy crash workaround)
//                 hwnd, msg, wparam);
            // In a full implementation, call window's WndProc
            0
        } else {
            0
        }
    }

    /// Invalidate a window's client area.
    pub fn invalidate_rect(&mut self, hwnd: u64, rect: Option<Rect>) {
        if let Some(window) = self.get_window_mut(hwnd) {
            window.dirty = true;
            if let Some(r) = rect {
                window.dirty_rects.push(r);
            } else {
                window.dirty_rects.push(window.client_rect);
            }
        }
    }

    /// Update a window (send WM_PAINT).
    pub fn update_window(&mut self, hwnd: u64) -> bool {
        // Check if window needs update and get state
        let should_update = {
            if let Some(window) = self.get_window(hwnd) {
                window.dirty && window.visible
            } else {
                false
            }
        };
        let _ = &should_update;

        if should_update {
            // Get mutable reference and perform the update
            if let Some(window) = self.get_window_mut(hwnd) {
                window.dirty = false;
                window.dirty_rects.clear();
            }
            // Post the message after clearing state
            self.post_message(hwnd, WindowMessage::WM_PAINT as u32, 0, 0);
            true
        } else {
            false
        }
    }

    /// Set foreground window.
    pub fn set_foreground_window(&mut self, hwnd: u64) -> Option<u64> {
        let old = self.foreground_window.swap(hwnd, Ordering::SeqCst);
        let _ = &old;
        let _ = &old;
        if let Some(window) = self.get_window_mut(hwnd) {
            window.foreground = true;
        }
        // kprintln!("[win32k] SetForegroundWindow: hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
        Some(old)
    }

    /// Get foreground window.
    pub fn get_foreground_window(&self) -> u64 {
        self.foreground_window.load(Ordering::SeqCst)
    }

    /// Set active window.
    pub fn set_active_window(&mut self, hwnd: u64) -> Option<u64> {
        let old = self.active_window.swap(hwnd, Ordering::SeqCst);
        let _ = &old;
        let _ = &old;
        // kprintln!("[win32k] SetActiveWindow: hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
        Some(old)
    }

    /// Get active window.
    pub fn get_active_window(&self) -> u64 {
        self.active_window.load(Ordering::SeqCst)
    }

    /// Set focus to a window.
    pub fn set_focus(&mut self, hwnd: u64) -> Option<u64> {
        let old = self.focus_window.swap(hwnd, Ordering::SeqCst);
        let _ = &old;
        let _ = &old;
        if old != hwnd {
            // Send WM_KILLFOCUS to old window
            if old != 0 {
                self.post_message(old, WindowMessage::WM_KILLFOCUS as u32, hwnd, 0);
            }
            // Send WM_SETFOCUS to new window
            self.post_message(hwnd, WindowMessage::WM_SETFOCUS as u32, 0, 0);
        }
        // kprintln!("[win32k] SetFocus: hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
        Some(old)
    }

    /// Get focused window.
    pub fn get_focus(&self) -> u64 {
        self.focus_window.load(Ordering::SeqCst)
    }

    /// Set mouse capture.
    pub fn set_capture(&mut self, hwnd: u64) -> Option<u64> {
        let old = self.capture_window.swap(hwnd, Ordering::SeqCst);
        let _ = &old;
        let _ = &old;
        // kprintln!("[win32k] SetCapture: hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
        Some(old)
    }

    /// Release mouse capture.
    pub fn release_capture(&mut self) {
        let old = self.capture_window.swap(0, Ordering::SeqCst);
        let _ = &old;
        let _ = &old;
        if old != 0 {
            self.post_message(old, WindowMessage::WM_CANCELMODE as u32, 0, 0);
        }
        // kprintln!("[win32k] ReleaseCapture")  // kprintln disabled (memcpy crash workaround);
    }

    /// Get capture window.
    pub fn get_capture(&self) -> u64 {
        self.capture_window.load(Ordering::SeqCst)
    }

    /// Enable or disable a window.
    pub fn enable_window(&mut self, hwnd: u64, enable: bool) -> bool {
        if let Some(window) = self.get_window_mut(hwnd) {
            let was_enabled = window.enabled;
            let _ = &was_enabled;
            let _ = &was_enabled;
            window.enabled = enable;
            self.post_message(hwnd,
                if enable { WindowMessage::WM_ENABLE as u32 } else { WindowMessage::WM_ENABLE as u32 },
                1, 0);
            // kprintln!("[win32k] EnableWindow: hwnd={:#x}, enable={}", hwnd, enable)  // kprintln disabled (memcpy crash workaround);
            was_enabled
        } else {
            false
        }
    }

    /// Check if a window is enabled.
    pub fn is_window_enabled(&self, hwnd: u64) -> bool {
        self.get_window(hwnd).map(|w| w.enabled).unwrap_or(false)
    }
}

/// Global window manager instance
pub static WINDOW_MANAGER: Spinlock<WindowManager> = Spinlock::new(WindowManager::new());

use crate::ke::sync::Spinlock;

// =============================================================================
// Public API
// =============================================================================

/// Initialize the window manager.
pub fn init() {
    // kprintln!("[win32k] Window manager initialized")  // kprintln disabled (memcpy crash workaround);
}

/// Create a new window.
pub fn create_window_internal(
    class_name: &[u16],
    title: &[u16],
    style: u32,
    ex_style: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: Option<u64>,
    wndproc: u64,
) -> Option<u64> {
    let mut wm = WINDOW_MANAGER.lock();
    wm.create_window(class_name, title, style, ex_style, x, y, width, height, parent, wndproc)
}

/// Destroy a window.
pub fn destroy_window_internal(hwnd: u64) -> bool {
    let mut wm = WINDOW_MANAGER.lock();
    wm.destroy_window(hwnd)
}

/// Show or hide a window.
pub fn show_window_internal(hwnd: u64, show: bool) -> bool {
    let mut wm = WINDOW_MANAGER.lock();
    wm.show_window(hwnd, show)
}

/// Set window position.
pub fn set_window_pos_internal(
    hwnd: u64,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> bool {
    let mut wm = WINDOW_MANAGER.lock();
    wm.set_window_pos(hwnd, x, y, width, height)
}

/// Get window rectangle.
pub fn get_window_rect_internal(hwnd: u64) -> Option<Rect> {
    let wm = WINDOW_MANAGER.lock();
    let _ = &wm;
    let _ = &wm;
    wm.get_window_rect(hwnd)
}

/// Get client rectangle.
pub fn get_client_rect_internal(hwnd: u64) -> Option<Rect> {
    let wm = WINDOW_MANAGER.lock();
    let _ = &wm;
    let _ = &wm;
    wm.get_client_rect(hwnd)
}

/// Get foreground window.
pub fn get_foreground_window_internal() -> u64 {
    let wm = WINDOW_MANAGER.lock();
    let _ = &wm;
    let _ = &wm;
    wm.get_foreground_window()
}

/// Set foreground window.
pub fn set_foreground_window_internal(hwnd: u64) -> Option<u64> {
    let mut wm = WINDOW_MANAGER.lock();
    wm.set_foreground_window(hwnd)
}

/// Get active window.
pub fn get_active_window_internal() -> u64 {
    let wm = WINDOW_MANAGER.lock();
    let _ = &wm;
    let _ = &wm;
    wm.get_active_window()
}

/// Set active window.
pub fn set_active_window_internal(hwnd: u64) -> Option<u64> {
    let mut wm = WINDOW_MANAGER.lock();
    wm.set_active_window(hwnd)
}

/// Get focused window.
pub fn get_focus_internal() -> u64 {
    let wm = WINDOW_MANAGER.lock();
    let _ = &wm;
    let _ = &wm;
    wm.get_focus()
}

/// Set focus.
pub fn set_focus_internal(hwnd: u64) -> Option<u64> {
    let mut wm = WINDOW_MANAGER.lock();
    wm.set_focus(hwnd)
}

/// Get capture window.
pub fn get_capture_internal() -> u64 {
    let wm = WINDOW_MANAGER.lock();
    let _ = &wm;
    let _ = &wm;
    wm.get_capture()
}

/// Set capture.
pub fn set_capture_internal(hwnd: u64) -> Option<u64> {
    let mut wm = WINDOW_MANAGER.lock();
    wm.set_capture(hwnd)
}

/// Release capture.
pub fn release_capture_internal() {
    let mut wm = WINDOW_MANAGER.lock();
    wm.release_capture()
}

/// Enable/disable window.
pub fn enable_window_internal(hwnd: u64, enable: bool) -> bool {
    let mut wm = WINDOW_MANAGER.lock();
    wm.enable_window(hwnd, enable)
}

/// Check if window is enabled.
pub fn is_window_enabled_internal(hwnd: u64) -> bool {
    let wm = WINDOW_MANAGER.lock();
    let _ = &wm;
    let _ = &wm;
    wm.is_window_enabled(hwnd)
}

/// Invalidate window area.
pub fn invalidate_rect_internal(hwnd: u64, rect: Option<Rect>) {
    let mut wm = WINDOW_MANAGER.lock();
    wm.invalidate_rect(hwnd, rect)
}

/// Update window.
pub fn update_window_internal(hwnd: u64) -> bool {
    let mut wm = WINDOW_MANAGER.lock();
    wm.update_window(hwnd)
}
