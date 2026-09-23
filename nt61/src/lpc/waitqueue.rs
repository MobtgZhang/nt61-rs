//! Wait queue and thread blocking support
//!
//! ALPC ports need to block threads when:
//! - Receiving from an empty queue
//! - Waiting for a reply to a request
//! - Waiting for connection acceptance
//!
//! This module implements a simple wait queue for thread blocking.

use core::sync::atomic::{AtomicU32, Ordering};

#[repr(C)]
pub struct WaitEntry {
    pub thread_id: u64,
    pub port_index: u32,
    pub wait_reason: WaitReason,
    pub active: bool,
    pub message_id: u64,
}

impl WaitEntry {
    pub const fn empty() -> Self {
        Self {
            thread_id: 0,
            port_index: 0,
            wait_reason: WaitReason::Message,
            active: false,
            message_id: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WaitReason {
    Message = 0,
    Reply = 1,
    Connection = 2,
    PortAvailable = 3,
}

pub const MAX_WAIT_ENTRIES: usize = 64;

pub struct WaitQueue {
    pub entries: [WaitEntry; MAX_WAIT_ENTRIES],
    pub count: u32,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            entries: [const { WaitEntry::empty() }; MAX_WAIT_ENTRIES],
            count: 0,
        }
    }
}

static WAIT_COUNT: AtomicU32 = AtomicU32::new(0);
static WAKE_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn wait_on_port(
    thread_id: u64,
    port_index: u32,
    reason: WaitReason,
    message_id: u64,
    queue: &mut WaitQueue,
) -> Option<u32> {
    for i in 0..queue.entries.len() {
        if !queue.entries[i].active {
            queue.entries[i].thread_id = thread_id;
            queue.entries[i].port_index = port_index;
            queue.entries[i].wait_reason = reason;
            queue.entries[i].message_id = message_id;
            queue.entries[i].active = true;
            queue.count = queue.count + 1;
            WAIT_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(i as u32);
        }
    }
    None
}

pub fn wake_thread(wait_entry_id: u32, queue: &mut WaitQueue) -> bool {
    if (wait_entry_id as usize) >= queue.entries.len() {
        return false;
    }

    if queue.entries[wait_entry_id as usize].active {
        queue.entries[wait_entry_id as usize].active = false;
        queue.count = queue.count.saturating_sub(1);
        WAKE_COUNT.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

pub fn wake_port_waiters(port_index: u32, queue: &mut WaitQueue) -> u32 {
    let mut woken = 0;
    for i in 0..queue.entries.len() {
        if queue.entries[i].active && queue.entries[i].port_index == port_index {
            queue.entries[i].active = false;
            queue.count = queue.count.saturating_sub(1);
            woken += 1;
            WAKE_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }
    woken
}

pub fn wake_reply_waiter(
    port_index: u32,
    message_id: u64,
    queue: &mut WaitQueue,
) -> Option<u64> {
    for i in 0..queue.entries.len() {
        if queue.entries[i].active
            && queue.entries[i].port_index == port_index
            && queue.entries[i].wait_reason == WaitReason::Reply
            && queue.entries[i].message_id == message_id
        {
            let thread_id = queue.entries[i].thread_id;
            queue.entries[i].active = false;
            queue.count = queue.count.saturating_sub(1);
            WAKE_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(thread_id);
        }
    }
    None
}

pub fn is_thread_waiting(thread_id: u64, queue: &WaitQueue) -> bool {
    for entry in &queue.entries {
        if entry.active && entry.thread_id == thread_id {
            return true;
        }
    }
    false
}

pub fn wait_stats() -> (u32, u32) {
    (
        WAIT_COUNT.load(Ordering::Relaxed),
        WAKE_COUNT.load(Ordering::Relaxed),
    )
}
