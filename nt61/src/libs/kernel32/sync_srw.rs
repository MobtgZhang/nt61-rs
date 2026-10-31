//! kernel32 — Slim Reader/Writer (SRW) Locks and Condition Variables
//!
//! Windows 7 lightweight synchronization primitives:
//! - SRW Locks: Lightweight reader/writer locks
//! - Condition Variables: Wait for conditions with automatic lock release
//!
//! SRW locks are more efficient than Critical Sections for read-heavy workloads.
//! Condition variables enable thread coordination patterns.
//!
//! References:
//!   * MSDN Library "Windows 7" — Synchronization Functions
//!   * Windows Internals 7th Ed. - Chapter 8

use super::types::{BOOL, FALSE, TRUE};
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
pub struct SRWLOCK {
    ptr: AtomicU64,
}

impl SRWLOCK {
    pub const fn new() -> Self {
        Self {
            ptr: AtomicU64::new(0),
        }
    }
}

impl Default for SRWLOCK {
    fn default() -> Self {
        Self::new()
    }
}

const SRW_LOCKED: u64 = 0x01;
pub const SRW_WAITING: u64 = 0x02;
pub const SRW_WAKING: u64 = 0x04;
const SRW_MULTIPLE_SHARED: u64 = 0x08;
const SRW_MASK: u64 = 0x0F;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn initialize_srwlock(srw_lock: *mut SRWLOCK) {
    if srw_lock.is_null() {
        return;
    }
    (*srw_lock).ptr.store(0, Ordering::Release);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn acquire_srwlock_exclusive(srw_lock: *mut SRWLOCK) {
    if srw_lock.is_null() {
        return;
    }

    let lock = &(*srw_lock).ptr;
    let current_thread = get_current_thread_id();

    if lock
        .compare_exchange(
            0,
            SRW_LOCKED | (current_thread << 4),
            Ordering::Acquire,
            Ordering::Relaxed,
        )
        .is_ok()
    {
        return;
    }

    loop {
        let state = lock.load(Ordering::Acquire);

        if (state & SRW_LOCKED) == 0 {
            if lock
                .compare_exchange(
                    state,
                    (state & !SRW_MASK) | SRW_LOCKED | (current_thread << 4),
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return;
            }
        } else {
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn try_acquire_srwlock_exclusive(srw_lock: *mut SRWLOCK) -> BOOL {
    if srw_lock.is_null() {
        return FALSE;
    }

    let lock = &(*srw_lock).ptr;
    let current_thread = get_current_thread_id();

    if lock
        .compare_exchange(
            0,
            SRW_LOCKED | (current_thread << 4),
            Ordering::Acquire,
            Ordering::Relaxed,
        )
        .is_ok()
    {
        TRUE
    } else {
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn release_srwlock_exclusive(srw_lock: *mut SRWLOCK) {
    if srw_lock.is_null() {
        return;
    }

    let lock = &(*srw_lock).ptr;

    let state = lock.load(Ordering::Acquire);
    let new_state = state & !SRW_LOCKED & !(0xFFFFFFFF_FFFFFFF0);

    lock.store(new_state, Ordering::Release);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn acquire_srwlock_shared(srw_lock: *mut SRWLOCK) {
    if srw_lock.is_null() {
        return;
    }

    let lock = &(*srw_lock).ptr;

    loop {
        let state = lock.load(Ordering::Acquire);

        if (state & SRW_LOCKED) != 0 {
            for _ in 0..100 {
                core::hint::spin_loop();
            }
            continue;
        }

        let reader_count = (state >> 4) as u32;
        let new_count = reader_count + 1;
        let new_state = (state & SRW_MASK) | ((new_count as u64) << 4) | SRW_MULTIPLE_SHARED;

        if lock
            .compare_exchange(state, new_state, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn try_acquire_srwlock_shared(srw_lock: *mut SRWLOCK) -> BOOL {
    if srw_lock.is_null() {
        return FALSE;
    }

    let lock = &(*srw_lock).ptr;
    let state = lock.load(Ordering::Acquire);

    if (state & SRW_LOCKED) != 0 {
        return FALSE;
    }

    let reader_count = (state >> 4) as u32;
    let new_count = reader_count + 1;
    let new_state = (state & SRW_MASK) | ((new_count as u64) << 4) | SRW_MULTIPLE_SHARED;

    if lock
        .compare_exchange(state, new_state, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        TRUE
    } else {
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn release_srwlock_shared(srw_lock: *mut SRWLOCK) {
    if srw_lock.is_null() {
        return;
    }

    let lock = &(*srw_lock).ptr;

    loop {
        let state = lock.load(Ordering::Acquire);
        let reader_count = (state >> 4) as u32;

        if reader_count == 0 {
            return;
        }

        let new_count = reader_count - 1;
        let new_state = if new_count == 0 {
            state & !SRW_MULTIPLE_SHARED & !(0xFFFFFFFF_FFFFFFF0)
        } else {
            (state & SRW_MASK) | ((new_count as u64) << 4)
        };

        if lock
            .compare_exchange(state, new_state, Ordering::Release, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

#[repr(C)]
pub struct CONDITION_VARIABLE {
    ptr: AtomicU64,
}

impl CONDITION_VARIABLE {
    pub const fn new() -> Self {
        Self {
            ptr: AtomicU64::new(0),
        }
    }
}

impl Default for CONDITION_VARIABLE {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone)]
struct WaiterNode {
    thread_id: u64,
    signaled: bool,
}

const MAX_CVS: usize = 64;
const MAX_WAITERS_PER_CV: usize = 16;

#[derive(Copy, Clone)]
struct CVWaiters {
    cv_addr: u64,
    waiters: [Option<WaiterNode>; MAX_WAITERS_PER_CV],
    count: usize,
}

impl CVWaiters {
    const fn new() -> Self {
        Self {
            cv_addr: 0,
            waiters: [None; MAX_WAITERS_PER_CV],
            count: 0,
        }
    }
}

static CV_WAITER_TABLE: Spinlock<[CVWaiters; MAX_CVS]> = Spinlock::new([CVWaiters::new(); MAX_CVS]);

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn initialize_condition_variable(
    condition_variable: *mut CONDITION_VARIABLE,
) {
    if condition_variable.is_null() {
        return;
    }
    (*condition_variable).ptr.store(0, Ordering::Release);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn sleep_condition_variable_cs(
    condition_variable: *mut CONDITION_VARIABLE,
    critical_section: *mut super::sync::CriticalSection,
    milliseconds: u32,
) -> BOOL {
    if condition_variable.is_null() || critical_section.is_null() {
        return FALSE;
    }

    let cv_addr = condition_variable as u64;
    let thread_id = get_current_thread_id();

    let slot_idx = (cv_addr as usize) % MAX_CVS;
    {
        let mut table = CV_WAITER_TABLE.lock();
        let slot = &mut table[slot_idx];

        if slot.cv_addr != cv_addr {
            slot.cv_addr = cv_addr;
            slot.count = 0;
        }

        if slot.count >= MAX_WAITERS_PER_CV {
            return FALSE;
        }

        slot.waiters[slot.count] = Some(WaiterNode {
            thread_id,
            signaled: false,
        });
        slot.count += 1;
    }

    super::sync::leave_critical_section(critical_section);

    let start = crate::ke::time::get_tick_count() as u64;
    let timeout_ticks = if milliseconds == 0xFFFFFFFF {
        u64::MAX
    } else {
        milliseconds as u64
    };

    let mut signaled = false;
    loop {
        {
            let table = CV_WAITER_TABLE.lock();
            let slot = &table[slot_idx];
            if slot.cv_addr == cv_addr {
                for node in slot.waiters.iter().take(slot.count).flatten() {
                    if node.thread_id == thread_id && node.signaled {
                        signaled = true;
                        break;
                    }
                }
            }
        }

        if signaled {
            break;
        }

        if milliseconds != 0xFFFFFFFF {
            let elapsed = crate::ke::time::get_tick_count() as u64 - start;
            if elapsed >= timeout_ticks {
                break;
            }
        }

        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    {
        let mut table = CV_WAITER_TABLE.lock();
        let slot = &mut table[slot_idx];
        if slot.cv_addr == cv_addr {
            let mut new_count = 0;
            for i in 0..slot.count {
                if let Some(node) = slot.waiters[i] {
                    if node.thread_id != thread_id {
                        slot.waiters[new_count] = Some(node);
                        new_count += 1;
                    }
                }
            }
            slot.count = new_count;
        }
    }

    super::sync::enter_critical_section(critical_section);

    if signaled {
        TRUE
    } else {
        super::error::set_last_error(1460); // ERROR_TIMEOUT
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn sleep_condition_variable_srw(
    condition_variable: *mut CONDITION_VARIABLE,
    srw_lock: *mut SRWLOCK,
    milliseconds: u32,
    flags: u32,
) -> BOOL {
    if condition_variable.is_null() || srw_lock.is_null() {
        return FALSE;
    }

    let cv_addr = condition_variable as u64;
    let thread_id = get_current_thread_id();
    let shared = (flags & 0x01) != 0; // CONDITION_VARIABLE_LOCKMODE_SHARED

    let slot_idx = (cv_addr as usize) % MAX_CVS;
    {
        let mut table = CV_WAITER_TABLE.lock();
        let slot = &mut table[slot_idx];

        if slot.cv_addr != cv_addr {
            slot.cv_addr = cv_addr;
            slot.count = 0;
        }

        if slot.count >= MAX_WAITERS_PER_CV {
            return FALSE;
        }

        slot.waiters[slot.count] = Some(WaiterNode {
            thread_id,
            signaled: false,
        });
        slot.count += 1;
    }

    if shared {
        release_srwlock_shared(srw_lock);
    } else {
        release_srwlock_exclusive(srw_lock);
    }

    let start = crate::ke::time::get_tick_count() as u64;
    let timeout_ticks = if milliseconds == 0xFFFFFFFF {
        u64::MAX
    } else {
        (milliseconds as u64) * 1000
    };

    let mut signaled = false;
    loop {
        {
            let table = CV_WAITER_TABLE.lock();
            let slot = &table[slot_idx];
            if slot.cv_addr == cv_addr {
                for node in slot.waiters.iter().take(slot.count).flatten() {
                    if node.thread_id == thread_id && node.signaled {
                        signaled = true;
                        break;
                    }
                }
            }
        }

        if signaled {
            break;
        }

        if milliseconds != 0xFFFFFFFF {
            let elapsed = crate::ke::time::get_tick_count() as u64 - start;
            if elapsed >= timeout_ticks {
                break;
            }
        }

        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    {
        let mut table = CV_WAITER_TABLE.lock();
        let slot = &mut table[slot_idx];
        if slot.cv_addr == cv_addr {
            let mut new_count = 0;
            for i in 0..slot.count {
                if let Some(node) = slot.waiters[i] {
                    if node.thread_id != thread_id {
                        slot.waiters[new_count] = Some(node);
                        new_count += 1;
                    }
                }
            }
            slot.count = new_count;
        }
    }

    if shared {
        acquire_srwlock_shared(srw_lock);
    } else {
        acquire_srwlock_exclusive(srw_lock);
    }

    if signaled {
        TRUE
    } else {
        super::error::set_last_error(1460);
        FALSE
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn wake_condition_variable(condition_variable: *mut CONDITION_VARIABLE) {
    if condition_variable.is_null() {
        return;
    }

    let cv_addr = condition_variable as u64;
    let slot_idx = (cv_addr as usize) % MAX_CVS;

    let mut table = CV_WAITER_TABLE.lock();
    let slot = &mut table[slot_idx];

    if slot.cv_addr != cv_addr || slot.count == 0 {
        return;
    }

    if let Some(node) = slot.waiters.iter_mut().take(slot.count).flatten().next() {
        node.signaled = true;
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn wake_all_condition_variable(condition_variable: *mut CONDITION_VARIABLE) {
    if condition_variable.is_null() {
        return;
    }

    let cv_addr = condition_variable as u64;
    let slot_idx = (cv_addr as usize) % MAX_CVS;

    let mut table = CV_WAITER_TABLE.lock();
    let slot = &mut table[slot_idx];

    if slot.cv_addr != cv_addr || slot.count == 0 {
        return;
    }

    for node in slot.waiters.iter_mut().take(slot.count).flatten() {
        node.signaled = true;
    }
}

fn get_current_thread_id() -> u64 {
    let thread = crate::arch::common::percpu::get_current_thread();
    if thread.is_null() {
        return 0;
    }
    unsafe { (*thread).client_id.unique_thread }
}
