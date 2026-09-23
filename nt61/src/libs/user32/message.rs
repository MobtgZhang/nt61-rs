//! user32 — Message Processing
//!
//! Windows message queue and message processing functions.
//! Core messaging functions for the Win32 event-driven architecture.
//!
//! References:
//!   * MSDN Library "Windows 7" — Windows Messages
//!   * Windows Internals 7th Ed. - Chapter 7

use super::types::*;
use crate::ke::sync::Spinlock;
use core::ptr;


#[repr(C)]
#[derive(Clone, Copy)]
pub struct MSG {
    pub hwnd: HWND,
    pub message: u32,
    pub wparam: usize,
    pub lparam: isize,
    pub time: u32,
    pub pt: POINT,
}

impl MSG {
    pub const fn new() -> Self {
        Self {
            hwnd: ptr::null_mut(),
            message: 0,
            wparam: 0,
            lparam: 0,
            time: 0,
            pt: POINT { x: 0, y: 0 },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct POINT {
    pub x: i32,
    pub y: i32,
}


#[derive(Clone, Copy)]
struct MessageEntry {
    msg: MSG,
    in_use: bool,
}

impl MessageEntry {
    const fn new() -> Self {
        Self {
            msg: MSG::new(),
            in_use: false,
        }
    }
}

const MAX_MESSAGES: usize = 128;

struct MessageQueue {
    messages: [MessageEntry; MAX_MESSAGES],
    count: usize,
    read_pos: usize,
}

impl MessageQueue {
    const fn new() -> Self {
        Self {
            messages: [MessageEntry::new(); MAX_MESSAGES],
            count: 0,
            read_pos: 0,
        }
    }

    fn post(&mut self, msg: MSG) -> bool {
        if self.count >= MAX_MESSAGES {
            return false;
        }

        for entry in self.messages.iter_mut() {
            if !entry.in_use {
                entry.msg = msg;
                entry.in_use = true;
                self.count += 1;
                return true;
            }
        }
        false
    }

    fn peek(&mut self, remove: bool) -> Option<MSG> {
        if self.count == 0 {
            return None;
        }

        for i in 0..MAX_MESSAGES {
            let idx = (self.read_pos + i) % MAX_MESSAGES;
            if self.messages[idx].in_use {
                let msg = self.messages[idx].msg;
                if remove {
                    self.messages[idx].in_use = false;
                    self.count -= 1;
                    self.read_pos = (idx + 1) % MAX_MESSAGES;
                }
                return Some(msg);
            }
        }
        None
    }
}

const MAX_THREADS: usize = 64;
static MESSAGE_QUEUES: Spinlock<[MessageQueue; MAX_THREADS]> =
    Spinlock::new([MessageQueue::new(); MAX_THREADS]);

fn get_current_thread_id() -> usize {
    1
}


pub unsafe extern "C" fn GetMessageW(
    lp_msg: *mut MSG,
    h_wnd: HWND,
    w_msg_filter_min: u32,
    w_msg_filter_max: u32,
) -> i32 {
    if lp_msg.is_null() {
        return -1;
    }

    let tid = get_current_thread_id();
    let slot = tid % MAX_THREADS;

    loop {
        let mut queues = MESSAGE_QUEUES.lock();
        if let Some(msg) = queues[slot].peek(true) {
            if !h_wnd.is_null() && msg.hwnd != h_wnd {
                continue;
            }

            if w_msg_filter_min != 0 || w_msg_filter_max != 0 {
                if msg.message < w_msg_filter_min || msg.message > w_msg_filter_max {
                    continue;
                }
            }

            *lp_msg = msg;

            if msg.message == 0x0012 {
                return 0;
            }

            return 1;
        }
        drop(queues);

        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

pub unsafe extern "C" fn GetMessageA(
    lp_msg: *mut MSG,
    h_wnd: HWND,
    w_msg_filter_min: u32,
    w_msg_filter_max: u32,
) -> i32 {
    GetMessageW(lp_msg, h_wnd, w_msg_filter_min, w_msg_filter_max)
}


pub const PM_NOREMOVE: u32 = 0x0000;
pub const PM_REMOVE: u32 = 0x0001;
pub const PM_NOYIELD: u32 = 0x0002;

pub unsafe extern "C" fn PeekMessageW(
    lp_msg: *mut MSG,
    h_wnd: HWND,
    w_msg_filter_min: u32,
    w_msg_filter_max: u32,
    w_remove_msg: u32,
) -> i32 {
    if lp_msg.is_null() {
        return 0;
    }

    let tid = get_current_thread_id();
    let slot = tid % MAX_THREADS;
    let remove = (w_remove_msg & PM_REMOVE) != 0;

    let mut queues = MESSAGE_QUEUES.lock();
    if let Some(msg) = queues[slot].peek(remove) {
        if !h_wnd.is_null() && msg.hwnd != h_wnd {
            return 0;
        }

        if w_msg_filter_min != 0 || w_msg_filter_max != 0 {
            if msg.message < w_msg_filter_min || msg.message > w_msg_filter_max {
                return 0;
            }
        }

        *lp_msg = msg;
        return 1;
    }

    0
}

pub unsafe extern "C" fn PeekMessageA(
    lp_msg: *mut MSG,
    h_wnd: HWND,
    w_msg_filter_min: u32,
    w_msg_filter_max: u32,
    w_remove_msg: u32,
) -> i32 {
    PeekMessageW(lp_msg, h_wnd, w_msg_filter_min, w_msg_filter_max, w_remove_msg)
}


pub unsafe extern "C" fn PostMessageW(
    h_wnd: HWND,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> i32 {
    let tid = get_current_thread_id();
    let slot = tid % MAX_THREADS;

    let message = MSG {
        hwnd: h_wnd,
        message: msg,
        wparam: w_param,
        lparam: l_param,
        time: 0, // Should be GetTickCount()
        pt: POINT { x: 0, y: 0 },
    };

    let mut queues = MESSAGE_QUEUES.lock();
    if queues[slot].post(message) {
        1
    } else {
        0
    }
}

pub unsafe extern "C" fn PostMessageA(
    h_wnd: HWND,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> i32 {
    PostMessageW(h_wnd, msg, w_param, l_param)
}

pub unsafe extern "C" fn SendMessageW(
    h_wnd: HWND,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {

    PostMessageW(h_wnd, msg, w_param, l_param);
    0
}

pub unsafe extern "C" fn SendMessageA(
    h_wnd: HWND,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    SendMessageW(h_wnd, msg, w_param, l_param)
}


pub unsafe extern "C" fn DispatchMessageW(lp_msg: *const MSG) -> isize {
    if lp_msg.is_null() {
        return 0;
    }

    let msg = &*lp_msg;


    let _ = msg;
    0
}

pub unsafe extern "C" fn DispatchMessageA(lp_msg: *const MSG) -> isize {
    DispatchMessageW(lp_msg)
}

pub unsafe extern "C" fn TranslateMessage(lp_msg: *const MSG) -> i32 {
    if lp_msg.is_null() {
        return 0;
    }

    let msg = &*lp_msg;


    let _ = msg;
    0
}


pub unsafe extern "C" fn PostQuitMessage(n_exit_code: i32) {
    PostMessageW(ptr::null_mut(), 0x0012, n_exit_code as usize, 0);
}


pub unsafe extern "C" fn WaitMessage() -> i32 {
    let tid = get_current_thread_id();
    let slot = tid % MAX_THREADS;

    loop {
        {
            let queues = MESSAGE_QUEUES.lock();
            if queues[slot].count > 0 {
                return 1;
            }
        }

        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}


pub mod wm {
    pub const WM_NULL: u32 = 0x0000;
    pub const WM_CREATE: u32 = 0x0001;
    pub const WM_DESTROY: u32 = 0x0002;
    pub const WM_MOVE: u32 = 0x0003;
    pub const WM_SIZE: u32 = 0x0005;
    pub const WM_ACTIVATE: u32 = 0x0006;
    pub const WM_SETFOCUS: u32 = 0x0007;
    pub const WM_KILLFOCUS: u32 = 0x0008;
    pub const WM_ENABLE: u32 = 0x000A;
    pub const WM_PAINT: u32 = 0x000F;
    pub const WM_CLOSE: u32 = 0x0010;
    pub const WM_QUIT: u32 = 0x0012;
    pub const WM_ERASEBKGND: u32 = 0x0014;
    pub const WM_SHOWWINDOW: u32 = 0x0018;
    pub const WM_ACTIVATEAPP: u32 = 0x001C;
    pub const WM_SETCURSOR: u32 = 0x0020;
    pub const WM_MOUSEACTIVATE: u32 = 0x0021;
    pub const WM_GETMINMAXINFO: u32 = 0x0024;
    pub const WM_NCCREATE: u32 = 0x0081;
    pub const WM_NCDESTROY: u32 = 0x0082;
    pub const WM_NCCALCSIZE: u32 = 0x0083;
    pub const WM_NCHITTEST: u32 = 0x0084;
    pub const WM_NCPAINT: u32 = 0x0085;
    pub const WM_NCACTIVATE: u32 = 0x0086;
    pub const WM_KEYDOWN: u32 = 0x0100;
    pub const WM_KEYUP: u32 = 0x0101;
    pub const WM_CHAR: u32 = 0x0102;
    pub const WM_SYSKEYDOWN: u32 = 0x0104;
    pub const WM_SYSKEYUP: u32 = 0x0105;
    pub const WM_SYSCHAR: u32 = 0x0106;
    pub const WM_COMMAND: u32 = 0x0111;
    pub const WM_SYSCOMMAND: u32 = 0x0112;
    pub const WM_TIMER: u32 = 0x0113;
    pub const WM_MOUSEMOVE: u32 = 0x0200;
    pub const WM_LBUTTONDOWN: u32 = 0x0201;
    pub const WM_LBUTTONUP: u32 = 0x0202;
    pub const WM_LBUTTONDBLCLK: u32 = 0x0203;
    pub const WM_RBUTTONDOWN: u32 = 0x0204;
    pub const WM_RBUTTONUP: u32 = 0x0205;
    pub const WM_RBUTTONDBLCLK: u32 = 0x0206;
    pub const WM_MBUTTONDOWN: u32 = 0x0207;
    pub const WM_MBUTTONUP: u32 = 0x0208;
    pub const WM_MBUTTONDBLCLK: u32 = 0x0209;
    pub const WM_MOUSEWHEEL: u32 = 0x020A;
    pub const WM_USER: u32 = 0x0400;
}
