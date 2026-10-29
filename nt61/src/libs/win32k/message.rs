//! Message Queue and Event Dispatch for win32k.sys
//
//! Implements the USER message queue for window messages.
//! Messages are posted to a per-thread message queue and retrieved
//! by GetMessage/PeekMessage.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

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
    /// Paint rectangles pending WmPaint
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
            // kprintln!("[msgq] PostMessage: queue full");
            return false;
        }
        self.messages.push_back(msg);
        self.msg_count.fetch_add(1, Ordering::SeqCst);
        // Signal that a message is available
        self.has_messages.store(true, Ordering::SeqCst);
        // kprintln!("[msgq] PostMessage: msg={:#x}, hwnd={:#x}, count={}",
        //             msg.message, msg.hwnd, self.messages.len());
        true
    }

    /// Post a quit message.
    pub fn post_quit(&mut self, exit_code: i32) {
        self.quit_flag.store(true, Ordering::SeqCst);
        self.exit_code.store(exit_code, Ordering::SeqCst);
        // Signal that a message (WmQuit) is available
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
    pub fn get_message(
        &mut self,
        hwnd_filter: u64,
        msg_filter_min: u32,
        msg_filter_max: u32,
        timeout_ms: u32,
    ) -> Option<Msg> {
        loop {
            // Check for quit first
            if self.quit_flag.load(Ordering::SeqCst) {
                return Some(Msg {
                    hwnd: 0,
                    message: 0x0012, // WmQuit
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
                // kprintln!("[msgq] GetMessage: waiting for message...");
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
    pub fn peek_message(
        &mut self,
        hwnd_filter: u64,
        msg_filter_min: u32,
        msg_filter_max: u32,
        remove: bool,
    ) -> Option<Msg> {
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

    /// Send a message directly (no queue). The kernel cannot invoke a
    /// user-mode WndProc directly; the window manager queues a
    /// `KeUserModeCallback`-style request and returns the callback
    /// placeholder result to the kernel-side caller.
    pub fn send_message(&self, msg: &Msg) -> i64 {
        let mut wm = crate::libs::win32k::window::WINDOW_MANAGER.lock();
        wm.send_message(msg.hwnd, msg.message, msg.wparam, msg.lparam)
    }

    /// Translate keyboard message.
    /// Converts WmKeydown to WmChar if appropriate.
    /// Handles extended keys, shift state, and special characters.
    pub fn translate_message(msg: &Msg) -> Option<Msg> {
        match msg.message {
            0x0100 => {
                // WmKeydown
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
                    // Don't translate repeated keys to WmChar
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
                    0x41..=0x5A if shift_pressed => vk as u16,           // uppercase

                    // Space
                    0x20 => 0x20,

                    // punctuation and special characters
                    0xBA => {
                        if shift_pressed {
                            ':' as u16
                        } else {
                            ';' as u16
                        }
                    } // ;:
                    0xBB => {
                        if shift_pressed {
                            '+' as u16
                        } else {
                            '=' as u16
                        }
                    } // =+
                    0xBC => {
                        if shift_pressed {
                            '<' as u16
                        } else {
                            ',' as u16
                        }
                    } // ,<
                    0xBD => {
                        if shift_pressed {
                            '_' as u16
                        } else {
                            '-' as u16
                        }
                    } // -_
                    0xBE => {
                        if shift_pressed {
                            '>' as u16
                        } else {
                            '.' as u16
                        }
                    } // .>
                    0xBF => {
                        if shift_pressed {
                            '?' as u16
                        } else {
                            '/' as u16
                        }
                    } // /?
                    0xC0 => {
                        if shift_pressed {
                            '~' as u16
                        } else {
                            '`' as u16
                        }
                    } // `~
                    0xDB => {
                        if shift_pressed {
                            '{' as u16
                        } else {
                            '[' as u16
                        }
                    } // [{
                    0xDC => {
                        if shift_pressed {
                            '|' as u16
                        } else {
                            '\\' as u16
                        }
                    } // \|
                    0xDD => {
                        if shift_pressed {
                            '}' as u16
                        } else {
                            ']' as u16
                        }
                    } // ]}
                    0xDE => {
                        if shift_pressed {
                            '"' as u16
                        } else {
                            '\'' as u16
                        }
                    } // '"

                    // Extended keys - these typically don't translate to characters
                    // but we log them for debugging
                    _ if extended => {
                        match vk {
                            0x21..=0x29 => {
                                // Page Up/Down, Home, End, Arrow keys
                                // kprintln!("[msgq] translate: extended vk=0x{:02x}", vk);
                                return None;
                            }
                            0x2D..=0x2F => {
                                // Insert, Delete, Help
                                // kprintln!("[msgq] translate: extended vk=0x{:02x}", vk);
                                return None;
                            }
                            0x5B..=0x5C => {
                                // Windows keys
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
                        // kprintln!("[msgq] translate: unhandled vk=0x{:02x}", vk);
                        return None;
                    }
                };

                if ch != 0 {
                    return Some(Msg {
                        hwnd: msg.hwnd,
                        message: 0x0102, // WmChar
                        wparam: ch as u64,
                        lparam: msg.lparam,
                        time: msg.time,
                        pt_x: msg.pt_x,
                        pt_y: msg.pt_y,
                    });
                }
            }
            0x0101 => { // WmKeyup
                 // WmChar is not generated on key up in Windows
            }
            0x0104 => {
                // WmSyskeydown (Alt key combinations)
                // handle system key combinations
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
        let mut wm = crate::libs::win32k::window::WINDOW_MANAGER.lock();
        wm.send_message(msg.hwnd, msg.message, msg.wparam, msg.lparam)
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

/// One thread's message queue, keyed by the thread's client ID.
struct ThreadQueueEntry {
    thread_id: u64,
    queue: MessageQueue,
}

/// Upper bound on tracked per-thread queues. When the table is full the
/// oldest entry is evicted; messages for an evicted (exited) thread are
/// discarded, which is acceptable because only the owning thread could
/// have drained them anyway.
const THREAD_QUEUE_MAX: usize = 64;

/// Per-thread message queues, serialized by a spinlock. Every message-queue
/// operation holds the lock only for the duration of the operation, so
/// concurrent threads never share a queue.
static THREAD_QUEUES: crate::ke::sync::Spinlock<Vec<ThreadQueueEntry>> =
    crate::ke::sync::Spinlock::new(Vec::new());

/// Client ID of the current thread, or 0 when the thread subsystem has not
/// started yet (early callers then share one fallback queue keyed by 0).
fn current_thread_id() -> u64 {
    let ethread = crate::ps::thread::get_current_ethread();
    if ethread.is_null() {
        return 0;
    }
    unsafe { (*ethread).client_id.unique_thread }
}

/// Run `f` with exclusive access to the current thread's message queue,
/// creating the queue on first use. This replaces the old global-singleton
/// queue: every thread now gets its own queue, so two threads no longer
/// steal each other's messages.
pub fn with_current_queue<R>(f: impl FnOnce(&mut MessageQueue) -> R) -> R {
    let tid = current_thread_id();
    let mut table = THREAD_QUEUES.lock();
    let slot = match table.iter_mut().find(|e| e.thread_id == tid) {
        Some(entry) => entry,
        None => {
            if table.len() >= THREAD_QUEUE_MAX {
                table.remove(0);
            }
            table.push(ThreadQueueEntry {
                thread_id: tid,
                queue: MessageQueue::new(),
            });
            table.last_mut().unwrap()
        }
    };
    f(&mut slot.queue)
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
    with_current_queue(|queue| queue.post_message(msg))
}

/// Post a quit message.
pub fn post_quit_message(exit_code: i32) {
    with_current_queue(|queue| queue.post_quit(exit_code))
}

/// Check if quit has been posted.
pub fn is_quit_posted() -> bool {
    with_current_queue(|queue| queue.is_quit())
}

/// Get exit code.
pub fn get_exit_code() -> i32 {
    with_current_queue(|queue| queue.exit_code())
}

// =============================================================================
// Default Window Procedure
// =============================================================================

/// Default window procedure handler.
/// Processes messages that most windows handle by default.
pub fn default_wndproc(hwnd: u64, msg: u32, wparam: u64, lparam: i64) -> i64 {
    let _ = (hwnd, wparam, lparam);

    match msg {
        0x0001 => {
            // WmCreate
            // kprintln!("[wndproc] WmCreate hwnd={:#x}", hwnd);
            0 // Continue creation
        }
        0x0002 => {
            // WmDestroy
            // kprintln!("[wndproc] WmDestroy hwnd={:#x}", hwnd);
            post_quit_message(0);
            0
        }
        0x000F => {
            // WmPaint
            // kprintln!("[wndproc] WmPaint hwnd={:#x}", hwnd);
            // invalidate_rect was already called, so just validate
            0
        }
        0x0014 => {
            // WmErasebkgnd
            // Return 1 to indicate background will be erased
            1
        }
        0x0005 => {
            // WmSize
            let width = lparam as u32;
            let _ = &width;
            let _ = &width;
            let height = (lparam >> 32) as u32;
            let _ = &height;
            let _ = &height;
            // kprintln!("[wndproc] WmSize hwnd={:#x} {}x{}", hwnd, width, height);
            0
        }
        0x0003 => {
            // WmMove
            let x = lparam as u32;
            let _ = &x;
            let _ = &x;
            let y = (lparam >> 32) as u32;
            let _ = &y;
            let _ = &y;
            // kprintln!("[wndproc] WmMove hwnd={:#x} ({},{})", hwnd, x, y);
            0
        }
        0x0010 => {
            // WmClose
            // kprintln!("[wndproc] WmClose hwnd={:#x}", hwnd);
            // Default: destroy the window
            crate::libs::win32k::window::destroy_window_internal(hwnd);
            0
        }
        0x0100 => {
            // WmKeydown
            // kprintln!("[wndproc] WmKeydown hwnd={:#x} vk={:#x}", hwnd, wparam);
            0
        }
        0x0101 => {
            // WmKeyup
            // kprintln!("[wndproc] WmKeyup hwnd={:#x} vk={:#x}", hwnd, wparam);
            0
        }
        0x0200 => {
            // WmMousemove
            let x = (lparam as i32) & 0xFFFF;
            let _ = &x;
            let _ = &x;
            let y = ((lparam >> 16) as i32) & 0xFFFF;
            let _ = &y;
            let _ = &y;
            // kprintln!("[wndproc] WmMousemove hwnd={:#x} ({},{})", hwnd, x, y);
            0
        }
        0x0201 => {
            // WmLbuttondown
            // kprintln!("[wndproc] WmLbuttondown hwnd={:#x}", hwnd);
            0
        }
        0x0202 => {
            // WmLbuttonup
            // kprintln!("[wndproc] WmLbuttonup hwnd={:#x}", hwnd);
            0
        }
        _ => {
            // Return 0 for unhandled messages (DefWindowProc behavior)
            // kprintln!("[wndproc] unhandled msg={:#x} hwnd={:#x}", msg, hwnd);
            0
        }
    }
}
