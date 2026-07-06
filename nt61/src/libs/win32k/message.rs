//! Message Queue and Event Dispatch for win32k.sys
//
//! Implements the USER message queue for window messages.
//! Messages are posted to a per-thread message queue and retrieved
//! by GetMessage/PeekMessage.

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use crate::kprintln;

/// Maximum messages in a queue.
const MAX_QUEUE_MESSAGES: usize = 256;

/// Window message with parameters
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Msg {
    pub hwnd: u64,
    pub message: u32,
    pub wparam: u64,
    pub lparam: i64,
    pub time: u32,
    pub pt_x: i32,
    pub pt_y: i32,
}

/// Message queue for a thread
pub struct MessageQueue {
    messages: VecDeque<Msg>,
    quit_flag: AtomicBool,
    exit_code: AtomicI32,
    /// Paint rectangles pending WM_PAINT
    paint_rects: Vec<crate::libs::win32k::window::Rect>,
    /// Current message being processed
    current_msg: Option<Msg>,
    /// Posted message count
    msg_count: AtomicU32,
    /// Event signaled when message is available
    has_messages: AtomicBool,
}

impl MessageQueue {
    pub fn new() -> Self {
        Self {
            messages: VecDeque::with_capacity(MAX_QUEUE_MESSAGES),
            quit_flag: AtomicBool::new(false),
            exit_code: AtomicI32::new(0),
            paint_rects: Vec::new(),
            current_msg: None,
            msg_count: AtomicU32::new(0),
            has_messages: AtomicBool::new(false),
        }
    }

    /// Post a message to the queue.
    pub fn post_message(&mut self, msg: Msg) -> bool {
        if self.messages.len() >= MAX_QUEUE_MESSAGES {
            // kprintln!("[msgq] PostMessage: queue full")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
        self.messages.push_back(msg);
        self.msg_count.fetch_add(1, Ordering::SeqCst);
        // Signal that a message is available
        self.has_messages.store(true, Ordering::SeqCst);
        // kprintln!("[msgq] PostMessage: msg={:#x}, hwnd={:#x}, count={}",  // kprintln disabled (memcpy crash workaround)
//             msg.message, msg.hwnd, self.messages.len());
        true
    }

    /// Post a quit message.
    pub fn post_quit(&mut self, exit_code: i32) {
        self.quit_flag.store(true, Ordering::SeqCst);
        self.exit_code.store(exit_code, Ordering::SeqCst);
        // Signal that a message (WM_QUIT) is available
        self.has_messages.store(true, Ordering::SeqCst);
    }

    /// Check if there are messages in the queue.
    pub fn peek_has_messages(&self) -> bool {
        !self.messages.is_empty() || self.quit_flag.load(Ordering::SeqCst)
    }

    /// Get message count.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Check if quit has been posted.
    pub fn is_quit(&self) -> bool {
        self.quit_flag.load(Ordering::SeqCst)
    }

    /// Get exit code.
    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(Ordering::SeqCst)
    }

    /// Check if message event is signaled.
    pub fn is_message_available(&self) -> bool {
        self.has_messages.load(Ordering::SeqCst)
    }

    /// Clear the message available flag.
    pub fn clear_message_flag(&mut self) {
        if self.messages.is_empty() && !self.quit_flag.load(Ordering::SeqCst) {
            self.has_messages.store(false, Ordering::SeqCst);
        }
    }

    /// Helper to check if a message matches the filter criteria.
    fn matches_filter(msg: &Msg, hwnd_filter: u64, min: u32, max: u32) -> bool {
        if hwnd_filter != 0 && msg.hwnd != hwnd_filter {
            return false;
        }
        if min != 0 && msg.message < min {
            return false;
        }
        if max != 0 && msg.message > max {
            return false;
        }
        true
    }

    /// Get next message (blocking with event synchronization).
    /// Returns None when no messages are available (non-blocking) or on timeout.
    pub fn get_message(&mut self, hwnd_filter: u64, msg_filter_min: u32, 
                       msg_filter_max: u32, timeout_ms: u32) -> Option<Msg> {
        loop {
            // Check for quit first
            if self.quit_flag.load(Ordering::SeqCst) {
                return Some(Msg {
                    hwnd: 0,
                    message: 0x0012, // WM_QUIT
                    wparam: self.exit_code.load(Ordering::SeqCst) as u64,
                    lparam: 0,
                    time: 0,
                    pt_x: 0,
                    pt_y: 0,
                });
            }

            // Try to find a matching message
            for i in 0..self.messages.len() {
                if let Some(msg) = self.messages.get(i).copied() {
                    if Self::matches_filter(&msg, hwnd_filter, msg_filter_min, msg_filter_max) {
                        self.messages.remove(i);
                        self.current_msg = Some(msg);
                        
                        // Clear flag if no more messages
                        if self.messages.is_empty() && !self.quit_flag.load(Ordering::SeqCst) {
                            self.has_messages.store(false, Ordering::SeqCst);
                        }
                        return Some(msg);
                    }
                }
            }

            // No matching message found
            // Check if non-blocking mode
            if timeout_ms == 0 {
                return None;
            }

            // For blocking mode, we would wait on the event here
            // Since we don't have full scheduler integration yet,
            // we'll yield to other threads with a spin hint
            if !self.has_messages.load(Ordering::SeqCst) {
                // kprintln!("[msgq] GetMessage: waiting for message...")  // kprintln disabled (memcpy crash workaround);
                // In a full implementation, this would block on the event
                // For now, use spin loop hint (would integrate with scheduler)
                for _ in 0..1000 {
                    core::hint::spin_loop();
                    if self.has_messages.load(Ordering::SeqCst) {
                        break;
                    }
                }
            }
            
            // If still no message and timeout not infinite, return
            if timeout_ms != 0xFFFFFFFF && !self.has_messages.load(Ordering::SeqCst) {
                return None;
            }
        }
    }

    /// Peek at a message without blocking.
    pub fn peek_message(&mut self, hwnd_filter: u64, msg_filter_min: u32, msg_filter_max: u32, remove: bool) -> Option<Msg> {
        // Find a matching message
        for i in 0..self.messages.len() {
            if let Some(msg) = self.messages.get(i).copied() {
                if hwnd_filter != 0 && msg.hwnd != hwnd_filter {
                    continue;
                }
                if msg_filter_min != 0 && msg.message < msg_filter_min {
                    continue;
                }
                if msg_filter_max != 0 && msg.message > msg_filter_max {
                    continue;
                }

                if remove {
                    self.messages.remove(i);
                }
                return Some(msg);
            }
        }
        None
    }

    /// Send a message directly (no queue).
    /// In real implementation, this calls the window procedure directly.
    pub fn send_message(&self, msg: &Msg) -> i64 {
        let _ = msg;
        // kprintln!("[msgq] SendMessage: msg={:#x}", msg.message)  // kprintln disabled (memcpy crash workaround);
        // In a full implementation, call the window's WndProc
        0
    }

    /// Translate keyboard message.
    /// Converts WM_KEYDOWN to WM_CHAR if appropriate.
    /// Handles extended keys, shift state, and special characters.
    pub fn translate_message(msg: &Msg) -> Option<Msg> {
        match msg.message {
            0x0100 => { // WM_KEYDOWN
                let vk = msg.wparam as u32;
                let _ = &vk;
                let _ = &vk;
                let lparam = msg.lparam;
                let _ = &lparam;
                let _ = &lparam;
                
                // Check for extended key (bit 24)
                let extended = (lparam & 0x01000000) != 0;
                let _ = &extended;
                let _ = &extended;
                
                // Check for key repeat (bits 0-15 of lparam)
                let repeat_count = (lparam & 0xFFFF) as u32;
                let _ = &repeat_count;
                let _ = &repeat_count;
                if repeat_count > 1 {
                    // Don't translate repeated keys to WM_CHAR
                    return None;
                }

                // Check shift state from lparam bits 16-23 (scan code or shift flags)
                let shift_pressed = (lparam & 0xFF0000) != 0;
                let _ = &shift_pressed;
                let _ = &shift_pressed;

                // Virtual key to character translation
                let ch = match vk {
                    // Numbers 0-9
                    0x30..=0x39 if !shift_pressed => vk as u16,
                    0x30..=0x39 if shift_pressed => match vk {
                        0x30 => ')' as u16, // shift+0
                        0x31 => '!' as u16,
                        0x32 => '@' as u16,
                        0x33 => '#' as u16,
                        0x34 => '$' as u16,
                        0x35 => '%' as u16,
                        0x36 => '^' as u16,
                        0x37 => '&' as u16,
                        0x38 => '*' as u16,
                        0x39 => '(' as u16,
                        _ => 0,
                    },
                    
                    // Letters A-Z (uppercase without shift, lowercase with shift)
                    0x41..=0x5A if !shift_pressed => (vk + 0x20) as u16, // lowercase
                    0x41..=0x5A if shift_pressed => vk as u16, // uppercase
                    
                    // Space
                    0x20 => 0x20,
                    
                    // punctuation and special characters
                    0xBA => if shift_pressed { ':' as u16 } else { ';' as u16 }, // ;:
                    0xBB => if shift_pressed { '+' as u16 } else { '=' as u16 }, // =+
                    0xBC => if shift_pressed { '<' as u16 } else { ',' as u16 }, // ,<
                    0xBD => if shift_pressed { '_' as u16 } else { '-' as u16 }, // -_
                    0xBE => if shift_pressed { '>' as u16 } else { '.' as u16 }, // .>
                    0xBF => if shift_pressed { '?' as u16 } else { '/' as u16 }, // /?
                    0xC0 => if shift_pressed { '~' as u16 } else { '`' as u16 }, // `~
                    0xDB => if shift_pressed { '{' as u16 } else { '[' as u16 }, // [{
                    0xDC => if shift_pressed { '|' as u16 } else { '\\' as u16 }, // \|
                    0xDD => if shift_pressed { '}' as u16 } else { ']' as u16 }, // ]}
                    0xDE => if shift_pressed { '"' as u16 } else { '\'' as u16 }, // '"
                    
                    // Extended keys - these typically don't translate to characters
                    // but we log them for debugging
                    _ if extended => {
                        match vk {
                            0x21..=0x29 => { // Page Up/Down, Home, End, Arrow keys
                                // kprintln!("[msgq] translate: extended vk=0x{:02x}", vk)  // kprintln disabled (memcpy crash workaround);
                                return None;
                            }
                            0x2D..=0x2F => { // Insert, Delete, Help
                                // kprintln!("[msgq] translate: extended vk=0x{:02x}", vk)  // kprintln disabled (memcpy crash workaround);
                                return None;
                            }
                            0x5B..=0x5C => { // Windows keys
                                return None;
                            }
                            _ => return None,
                        }
                    }
                    
                    // Function keys don't translate
                    0x70..=0x87 => return None, // F1-F24
                    
                    // Navigation and control keys don't translate
                    0x01..=0x2F => return None, // Mouse, shift, ctrl, alt, etc.
                    
                    _ => {
                        // kprintln!("[msgq] translate: unhandled vk=0x{:02x}", vk)  // kprintln disabled (memcpy crash workaround);
                        return None;
                    }
                };

                if ch != 0 {
                    return Some(Msg {
                        hwnd: msg.hwnd,
                        message: 0x0102, // WM_CHAR
                        wparam: ch as u64,
                        lparam: msg.lparam,
                        time: msg.time,
                        pt_x: msg.pt_x,
                        pt_y: msg.pt_y,
                    });
                }
            }
            0x0101 => { // WM_KEYUP
                // WM_CHAR is not generated on key up in Windows
            }
            0x0104 => { // WM_SYSKEYDOWN (Alt key combinations)
                // Handle system key combinations
                let vk = msg.wparam as u32;
                let _ = &vk;
                let _ = &vk;
                // For Alt+<key>, we might want to handle accelarators
                // but for now, just pass through
            }
            _ => {}
        }
        None // No translation
    }

    /// Dispatch a message to a window procedure.
    pub fn dispatch_message(&self, msg: &Msg) -> i64 {
        if msg.hwnd == 0 {
            return 0;
        }

        // kprintln!("[msgq] DispatchMessage: hwnd={:#x}, msg={:#x}",  // kprintln disabled (memcpy crash workaround)
//             msg.hwnd, msg.message);

        // In a full implementation, look up the window's WndProc
        // and call it: result = WndProc(hwnd, msg, wparam, lparam)
        0
    }

    /// Add a paint rectangle.
    pub fn add_paint_rect(&mut self, rect: crate::libs::win32k::window::Rect) {
        self.paint_rects.push(rect);
    }

    /// Get and clear paint rectangles.
    pub fn get_paint_rects(&mut self) -> Vec<crate::libs::win32k::window::Rect> {
        let rects: Vec<_> = self.paint_rects.drain(..).collect();
        rects
    }

    /// Clear all messages.
    pub fn clear(&mut self) {
        self.messages.clear();
        self.paint_rects.clear();
        self.current_msg = None;
    }
}

// =============================================================================
// Thread-Local Message Queue
// =============================================================================

/// Per-thread message queue storage using spinlock for thread safety.
/// Note: For true per-thread storage, this should use proper TLS.
/// The spinlock protects initialization; after init, access is typically
/// single-threaded per queue.
static CURRENT_QUEUE: crate::ke::sync::Spinlock<Option<MessageQueue>> =
    crate::ke::sync::Spinlock::new(None);
static mut CURRENT_QUEUE_PTR: *mut MessageQueue = core::ptr::null_mut();

/// Get the current thread's message queue.
pub fn get_current_queue() -> &'static mut MessageQueue {
    let ptr = unsafe { CURRENT_QUEUE_PTR };
    let _ = &ptr;
    let _ = &ptr;
    if !ptr.is_null() {
        return unsafe { &mut *ptr };
    }
    let mut guard = CURRENT_QUEUE.lock();
    if guard.is_none() {
        *guard = Some(MessageQueue::new());
    }
    let inner = guard.as_mut().unwrap() as *mut MessageQueue;
    let _ = &inner;
    let _ = &inner;
    unsafe { CURRENT_QUEUE_PTR = inner; }
    unsafe { &mut *inner }
}

/// Post a message to the current thread's queue.
pub fn post_message(hwnd: u64, message: u32, wparam: u64, lparam: i64) -> bool {
    let msg = Msg {
        hwnd,
        message,
        wparam,
        lparam,
        time: 0, // Would get from system time
        pt_x: 0,
        pt_y: 0,
    };
    let _ = &msg;
    get_current_queue().post_message(msg)
}

/// Post a quit message.
pub fn post_quit_message(exit_code: i32) {
    get_current_queue().post_quit(exit_code)
}

/// Check if quit has been posted.
pub fn is_quit_posted() -> bool {
    get_current_queue().is_quit()
}

/// Get exit code.
pub fn get_exit_code() -> i32 {
    get_current_queue().exit_code()
}

// =============================================================================
// Default Window Procedure
// =============================================================================

/// Default window procedure handler.
/// Processes messages that most windows handle by default.
pub fn default_wndproc(hwnd: u64, msg: u32, wparam: u64, lparam: i64) -> i64 {
    use crate::libs::win32k::window::WindowMessage;
    let _ = (hwnd, wparam, lparam);

    match msg {
        0x0001 => { // WM_CREATE
            // kprintln!("[wndproc] WM_CREATE hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
            0 // Continue creation
        }
        0x0002 => { // WM_DESTROY
            // kprintln!("[wndproc] WM_DESTROY hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
            post_quit_message(0);
            0
        }
        0x000F => { // WM_PAINT
            // kprintln!("[wndproc] WM_PAINT hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
            // InvalidateRect was already called, so just validate
            0
        }
        0x0014 => { // WM_ERASEBKGND
            // Return 1 to indicate background will be erased
            1
        }
        0x0005 => { // WM_SIZE
            let width = lparam as u32;
            let _ = &width;
            let _ = &width;
            let height = (lparam >> 32) as u32;
            let _ = &height;
            let _ = &height;
            // kprintln!("[wndproc] WM_SIZE hwnd={:#x} {}x{}", hwnd, width, height)  // kprintln disabled (memcpy crash workaround);
            0
        }
        0x0003 => { // WM_MOVE
            let x = lparam as u32;
            let _ = &x;
            let _ = &x;
            let y = (lparam >> 32) as u32;
            let _ = &y;
            let _ = &y;
            // kprintln!("[wndproc] WM_MOVE hwnd={:#x} ({},{})", hwnd, x, y)  // kprintln disabled (memcpy crash workaround);
            0
        }
        0x0010 => { // WM_CLOSE
            // kprintln!("[wndproc] WM_CLOSE hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
            // Default: destroy the window
            crate::libs::win32k::window::destroy_window_internal(hwnd);
            0
        }
        0x0100 => { // WM_KEYDOWN
            // kprintln!("[wndproc] WM_KEYDOWN hwnd={:#x} vk={:#x}", hwnd, wparam)  // kprintln disabled (memcpy crash workaround);
            0
        }
        0x0101 => { // WM_KEYUP
            // kprintln!("[wndproc] WM_KEYUP hwnd={:#x} vk={:#x}", hwnd, wparam)  // kprintln disabled (memcpy crash workaround);
            0
        }
        0x0200 => { // WM_MOUSEMOVE
            let x = (lparam as i32) & 0xFFFF;
            let _ = &x;
            let _ = &x;
            let y = ((lparam >> 16) as i32) & 0xFFFF;
            let _ = &y;
            let _ = &y;
            // kprintln!("[wndproc] WM_MOUSEMOVE hwnd={:#x} ({},{})", hwnd, x, y)  // kprintln disabled (memcpy crash workaround);
            0
        }
        0x0201 => { // WM_LBUTTONDOWN
            // kprintln!("[wndproc] WM_LBUTTONDOWN hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
            0
        }
        0x0202 => { // WM_LBUTTONUP
            // kprintln!("[wndproc] WM_LBUTTONUP hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);
            0
        }
        _ => {
            // Return 0 for unhandled messages (DefWindowProc behavior)
            // kprintln!("[wndproc] unhandled msg={:#x} hwnd={:#x}", msg, hwnd)  // kprintln disabled (memcpy crash workaround);
            0
        }
    }
}
