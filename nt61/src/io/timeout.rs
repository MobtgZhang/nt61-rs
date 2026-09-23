//! IRP Timeout and Cancellation
//!
//! Provides timeout tracking and automatic cancellation for IRPs.
//! This is critical for preventing hung I/O operations.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use super::Irp;
use crate::libs::ntdll::status::*;

struct TimeoutEntry {
    irp: *mut Irp,
    timeout_at: u64,
    fired: bool,
}

static TIMEOUT_TRACKER: Spinlock<Vec<TimeoutEntry>> = Spinlock::new(Vec::new());

static TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    TICK_COUNTER.store(0, Ordering::Release);
}

pub fn get_tick_count() -> u64 {
    TICK_COUNTER.load(Ordering::Acquire)
}

pub fn tick() {
    TICK_COUNTER.fetch_add(1, Ordering::Release);
    process_timeouts();
}

pub fn set_irp_timeout(irp: *mut Irp, timeout_ms: u32) {
    if irp.is_null() || timeout_ms == 0 {
        return;
    }

    let timeout_ticks = timeout_ms as u64;
    let timeout_at = get_tick_count() + timeout_ticks;

    let entry = TimeoutEntry {
        irp,
        timeout_at,
        fired: false,
    };

    let mut tracker = TIMEOUT_TRACKER.lock();
    tracker.push(entry);
}

pub fn cancel_irp_timeout(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }

    let mut tracker = TIMEOUT_TRACKER.lock();
    tracker.retain(|entry| entry.irp != irp);
}

fn process_timeouts() {
    let current_tick = get_tick_count();
    let mut tracker = TIMEOUT_TRACKER.lock();

    for entry in tracker.iter_mut() {
        if !entry.fired && entry.timeout_at <= current_tick {
            entry.fired = true;

            if !entry.irp.is_null() {
                super::cancel_irp(entry.irp);
            }
        }
    }

    tracker.retain(|entry| !entry.fired);
}

pub fn get_pending_timeout_count() -> usize {
    let tracker = TIMEOUT_TRACKER.lock();
    tracker.len()
}

pub fn clear_all_timeouts() {
    let mut tracker = TIMEOUT_TRACKER.lock();
    tracker.clear();
}

/// This can be used to ensure no I/O operation hangs indefinitely.
pub const DEFAULT_IO_TIMEOUT_MS: u32 = 30000; // 30 seconds

pub fn has_irp_timed_out(irp: *mut Irp) -> bool {
    if irp.is_null() {
        return false;
    }

    let tracker = TIMEOUT_TRACKER.lock();
    tracker.iter().any(|entry| entry.irp == irp && entry.fired)
}
