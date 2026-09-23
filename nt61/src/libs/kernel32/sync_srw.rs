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

use super::types::{BOOL, TRUE, FALSE};
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};


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

const SRW_LOCKED: u64 = 0x01;
const SRW_WAITING: u64 = 0x02;
const SRW_WAKING: u64 = 0x04;
const SRW_MULTIPLE_SHARED: u64 = 0x08;
const SRW_MASK: u64 = 0x0F;


pub unsafe extern "C" fn InitializeSRWLock(srw_lock: *mut SRWLOCK) {
    if srw_lock.is_null() {
        return;
    }
    (*srw_lock).ptr.store(0, Ordering::Release);
}


pub unsafe extern "C" fn AcquireSRWLockExclusive(srw_lock: *mut SRWLOCK) {
    if srw_lock.is_null() {
        return;
    }

    let lock = &(*srw_lock).ptr;
    let current_thread = get_current_thread_id();

    if lock
        .compare_exchange(0, SRW_LOCKED | (current_thread << 4), Ordering::Acquire, Ordering::Relaxed)
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

pub unsafe extern "C" fn TryAcquireSRWLockExclusive(srw_lock: *mut SRWLOCK) -> BOOL {
    if srw_lock.is_null() {
        return FALSE;
    }

    let lock = &(*srw_lock).ptr;
    let current_thread = get_current_thread_id();

    if lock
        .compare_exchange(0, SRW_LOCKED | (current_thread << 4), Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        TRUE
    } else {
        FALSE
    }
}

pub unsafe extern "C" fn ReleaseSRWLockExclusive(srw_lock: *mut SRWLOCK) {
    if srw_lock.is_null() {
        return;
    }

    let lock = &(*srw_lock).ptr;

    let state = lock.load(Ordering::Acquire);
    let new_state = state & !SRW_LOCKED & !(0xFFFFFFFF_FFFFFFF0);

    lock.store(new_state, Ordering::Release);
}


pub unsafe extern "C" fn AcquireSRWLockShared(srw_lock: *mut SRWLOCK) {
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

pub unsafe extern "C" fn TryAcquireSRWLockShared(srw_lock: *mut SRWLOCK) -> BOOL {
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

pub unsafe extern "C" fn ReleaseSRWLockShared(srw_lock: *mut SRWLOCK) {
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

struct WaiterNode {
    thread_id: u64,
    signaled: bool,
}

const MAX_CVS: usize = 64;
const MAX_WAITERS_PER_CV: usize = 16;

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

static CV_WAITER_TABLE: Spinlock<[CVWaiters; MAX_CVS]> =
    Spinlock::new([CVWaiters::new(); MAX_CVS]);

pub unsafe extern "C" fn InitializeConditionVariable(condition_variable: *mut CONDITION_VARIABLE) {
    if condition_variable.is_null() {
        return;
    }
    (*condition_variable).ptr.store(0, Ordering::Release);
}

pub unsafe extern "C" fn SleepConditionVariableCS(
    condition_variable: *mut CONDITION_VARIABLE,
    critical_section: *mut super::sync::CRITICAL_SECTION,
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

    super::sync::LeaveCriticalSection(critical_section);

    let start = crate::ke::time::get_ticks();
    let timeout_ticks = if milliseconds == 0xFFFFFFFF {
        u64::MAX
    } else {
        (milliseconds as u64) * 1000 // Approximate
    };

    let mut signaled = false;
    loop {
        {
            let table = CV_WAITER_TABLE.lock();
            let slot = &table[slot_idx];
            if slot.cv_addr == cv_addr {
                for waiter in slot.waiters.iter().take(slot.count) {
                    if let Some(node) = waiter {
                        if node.thread_id == thread_id && node.signaled {
                            signaled = true;
                            break;
                        }
                    }
                }
            }
        }

        if signaled {
            break;
        }

        if milliseconds != 0xFFFFFFFF {
            let elapsed = crate::ke::time::get_ticks() - start;
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

    super::sync::EnterCriticalSection(critical_section);

    if signaled {
        TRUE
    } else {
        super::error::SetLastError(1460); // ERROR_TIMEOUT
        FALSE
    }
}

pub unsafe extern "C" fn SleepConditionVariableSRW(
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
        ReleaseSRWLockShared(srw_lock);
    } else {
        ReleaseSRWLockExclusive(srw_lock);
    }

    let start = crate::ke::time::get_ticks();
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
                for waiter in slot.waiters.iter().take(slot.count) {
                    if let Some(node) = waiter {
                        if node.thread_id == thread_id && node.signaled {
                            signaled = true;
                            break;
                        }
                    }
                }
            }
        }

        if signaled {
            break;
        }

        if milliseconds != 0xFFFFFFFF {
            let elapsed = crate::ke::time::get_ticks() - start;
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
        AcquireSRWLockShared(srw_lock);
    } else {
        AcquireSRWLockExclusive(srw_lock);
    }

    if signaled {
        TRUE
    } else {
        super::error::SetLastError(1460);
        FALSE
    }
}

pub unsafe extern "C" fn WakeConditionVariable(condition_variable: *mut CONDITION_VARIABLE) {
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

    for waiter in slot.waiters.iter_mut().take(slot.count) {
        if let Some(node) = waiter {
            node.signaled = true;
            break;
        }
    }
}

pub unsafe extern "C" fn WakeAllConditionVariable(condition_variable: *mut CONDITION_VARIABLE) {
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

    for waiter in slot.waiters.iter_mut().take(slot.count) {
        if let Some(node) = waiter {
            node.signaled = true;
        }
    }
}


fn get_current_thread_id() -> u64 {
    1
}
