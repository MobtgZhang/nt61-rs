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

const MAX_MESSAGES: usize = 128;

/// How many spin iterations the message pump waits between queue
/// polls while no matching message is queued.
const SPIN_WAIT_ITERATIONS: u32 = 1000;

#[derive(Clone, Copy)]
struct MessageQueue {
    /// Ring of queued messages; `head` is the next message to
    /// deliver and `len` the number of occupied slots.
    slots: [MSG; MAX_MESSAGES],
    head: usize,
    len: usize,
}

impl MessageQueue {
    const fn new() -> Self {
        Self {
            slots: [MSG::new(); MAX_MESSAGES],
            head: 0,
            len: 0,
        }
    }

    fn post(&mut self, msg: MSG) -> bool {
        if self.len == MAX_MESSAGES {
            return false;
        }
        let tail = (self.head + self.len) % MAX_MESSAGES;
        self.slots[tail] = msg;
        self.len += 1;
        true
    }

    /// First queued message that matches the window and message
    /// range filter, in FIFO order. Messages that do not match
    /// stay queued, mirroring GetMessageW semantics. With
    /// `remove` the matching message is taken off the queue.
    fn next_matching(
        &mut self,
        h_wnd: HWND,
        filter_min: u32,
        filter_max: u32,
        remove: bool,
    ) -> Option<MSG> {
        for i in 0..self.len {
            let idx = (self.head + i) % MAX_MESSAGES;
            let msg = self.slots[idx];
            if !h_wnd.is_null() && msg.hwnd != h_wnd {
                continue;
            }
            if filter_min != 0 || filter_max != 0 {
                if msg.message < filter_min || msg.message > filter_max {
                    continue;
                }
            }
            if remove {
                let tail = (self.head + self.len) % MAX_MESSAGES;
                let mut current = idx;
                loop {
                    let next = (current + 1) % MAX_MESSAGES;
                    if next == tail {
                        break;
                    }
                    self.slots[current] = self.slots[next];
                    current = next;
                }
                self.len -= 1;
            }
            return Some(msg);
        }
        None
    }

    fn count(&self) -> usize {
        self.len
    }
}

const MAX_THREADS: usize = 64;
static MESSAGE_QUEUES: Spinlock<[MessageQueue; MAX_THREADS]> =
    Spinlock::new([MessageQueue::new(); MAX_THREADS]);

fn get_current_thread_id() -> usize {
    let thread = crate::arch::common::percpu::get_current_thread();
    if thread.is_null() {
        return 0;
    }
    unsafe { (*thread).client_id.unique_thread as usize }
}

fn current_thread_slot() -> usize {
    get_current_thread_id() % MAX_THREADS
}

pub unsafe extern "C" fn get_message_w(
    lp_msg: *mut MSG,
    h_wnd: HWND,
    w_msg_filter_min: u32,
    w_msg_filter_max: u32,
) -> i32 {
    if lp_msg.is_null() {
        return -1;
    }

    loop {
        let next = {
            let mut queues = MESSAGE_QUEUES.lock();
            queues[current_thread_slot()].next_matching(
                h_wnd,
                w_msg_filter_min,
                w_msg_filter_max,
                true,
            )
        };
        if let Some(msg) = next {
            *lp_msg = msg;
            if msg.message == wm::WM_QUIT {
                return 0;
            }
            return 1;
        }

        for _ in 0..SPIN_WAIT_ITERATIONS {
            core::hint::spin_loop();
        }
    }
}

pub unsafe extern "C" fn get_message_a(
    lp_msg: *mut MSG,
    h_wnd: HWND,
    w_msg_filter_min: u32,
    w_msg_filter_max: u32,
) -> i32 {
    get_message_w(lp_msg, h_wnd, w_msg_filter_min, w_msg_filter_max)
}

pub const PM_NOREMOVE: u32 = 0x0000;
pub const PM_REMOVE: u32 = 0x0001;
pub const PM_NOYIELD: u32 = 0x0002;

pub unsafe extern "C" fn peek_message_w(
    lp_msg: *mut MSG,
    h_wnd: HWND,
    w_msg_filter_min: u32,
    w_msg_filter_max: u32,
    w_remove_msg: u32,
) -> i32 {
    if lp_msg.is_null() {
        return 0;
    }

    let remove = (w_remove_msg & PM_REMOVE) != 0;

    let mut queues = MESSAGE_QUEUES.lock();
    match queues[current_thread_slot()].next_matching(
        h_wnd,
        w_msg_filter_min,
        w_msg_filter_max,
        remove,
    ) {
        Some(msg) => {
            *lp_msg = msg;
            1
        }
        None => 0,
    }
}

pub unsafe extern "C" fn peek_message_a(
    lp_msg: *mut MSG,
    h_wnd: HWND,
    w_msg_filter_min: u32,
    w_msg_filter_max: u32,
    w_remove_msg: u32,
) -> i32 {
    peek_message_w(
        lp_msg,
        h_wnd,
        w_msg_filter_min,
        w_msg_filter_max,
        w_remove_msg,
    )
}

pub unsafe extern "C" fn post_message_w(
    h_wnd: HWND,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> i32 {
    let message = MSG {
        hwnd: h_wnd,
        message: msg,
        wparam: w_param,
        lparam: l_param,
        time: crate::ke::time::get_tick_count(),
        pt: POINT { x: 0, y: 0 },
    };

    let mut queues = MESSAGE_QUEUES.lock();
    if queues[current_thread_slot()].post(message) {
        1
    } else {
        0
    }
}

pub unsafe extern "C" fn post_message_a(
    h_wnd: HWND,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> i32 {
    post_message_w(h_wnd, msg, w_param, l_param)
}

pub unsafe extern "C" fn send_message_w(
    h_wnd: HWND,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    // SendMessageW is synchronous: the procedure runs before the
    // call returns and its result is the return value.
    super::window::call_window_procedure(h_wnd, msg, w_param, l_param)
}

pub unsafe extern "C" fn send_message_a(
    h_wnd: HWND,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    send_message_w(h_wnd, msg, w_param, l_param)
}

pub unsafe extern "C" fn dispatch_message_w(lp_msg: *const MSG) -> isize {
    if lp_msg.is_null() {
        return 0;
    }

    let msg = &*lp_msg;
    super::window::call_window_procedure(msg.hwnd, msg.message, msg.wparam, msg.lparam)
}

pub unsafe extern "C" fn dispatch_message_a(lp_msg: *const MSG) -> isize {
    dispatch_message_w(lp_msg)
}

pub unsafe extern "C" fn translate_message(lp_msg: *const MSG) -> i32 {
    if lp_msg.is_null() {
        return 0;
    }

    let msg = &*lp_msg;
    let is_keydown = msg.message == wm::WM_KEYDOWN || msg.message == wm::WM_SYSKEYDOWN;
    if !is_keydown {
        return 0;
    }
    if !VK_TRANSLATABLE_RANGE.contains(&msg.wparam) {
        return 0;
    }
    let char_message = if msg.message == wm::WM_SYSKEYDOWN {
        wm::WM_SYSCHAR
    } else {
        wm::WM_CHAR
    };
    post_message_w(msg.hwnd, char_message, msg.wparam, msg.lparam);
    1
}

pub unsafe extern "C" fn post_quit_message(n_exit_code: i32) {
    post_message_w(ptr::null_mut(), 0x0012, n_exit_code as usize, 0);
}

pub unsafe extern "C" fn wait_message() -> i32 {
    loop {
        {
            let queues = MESSAGE_QUEUES.lock();
            if queues[current_thread_slot()].count() > 0 {
                return 1;
            }
        }

        for _ in 0..SPIN_WAIT_ITERATIONS {
            core::hint::spin_loop();
        }
    }
}

/// VK code range the default layout translates straight to a
/// character: VK_SPACE (0x20) through VK_Z (0x5A); the digit
/// keys 0x30..0x39 sit inside.
const VK_TRANSLATABLE_RANGE: core::ops::RangeInclusive<WPARAM> = 0x20..=0x5A;

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
