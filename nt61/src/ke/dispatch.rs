//! IPI dispatch
//
//! x86_64 reserves vectors 0xE0..0xEF for inter-processor
//! interrupts (IPIs). NT 6.1's `KiIpiInterrupt` and
//! `KiIpiReady` handlers run on the target CPU and trigger
//! the scheduler. The bootstrap exposes a similar surface
//! area: a small set of fixed-vector handlers plus a
//! dynamically-allocated vector range.

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicU8, Ordering};

/// Fixed IPI vector assignments.
pub const IPI_RESCHEDULE: u8 = 0xE0;
pub const IPI_INTR_ENTER: u8 = 0xE1;
pub const IPI_INTR_EXIT: u8 = 0xE2;
pub const IPI_PANIC_STOP: u8 = 0xE3;
pub const IPI_DYNAMIC_BASE: u8 = 0xE4;
pub const IPI_DYNAMIC_END: u8 = 0xEF;

/// Per-vector IPI handler table for the dynamic range. The
/// static array is indexed by `vector - IPI_DYNAMIC_BASE`.
type IpiHandler = fn();
static mut IPI_HANDLERS: [Option<IpiHandler>; 12] = [None; 12];

/// Allocate a dynamic IPI vector in the 0xE4..=0xEF range.
/// Returns None if the table is full.
pub fn allocate_ipi_vector(handler: IpiHandler) -> Option<u8> {
    unsafe {
        for i in 0..IPI_HANDLERS.len() {
            if IPI_HANDLERS[i].is_none() {
                IPI_HANDLERS[i] = Some(handler);
                return Some(IPI_DYNAMIC_BASE + i as u8);
            }
        }
    }
    None
}

/// Free a previously-allocated IPI vector.
pub fn free_ipi_vector(vector: u8) {
    if vector < IPI_DYNAMIC_BASE || vector > IPI_DYNAMIC_END { return; }
    unsafe {
        let idx = (vector - IPI_DYNAMIC_BASE) as usize;
        IPI_HANDLERS[idx] = None;
    }
}

static PANIC_FLAG: AtomicU8 = AtomicU8::new(0);

/// Set the panic stop flag. Other CPUs that receive
/// `IPI_PANIC_STOP` will see this and halt.
pub fn set_panic_stop() {
    PANIC_FLAG.store(1, Ordering::SeqCst);
}

fn panic_stop_set() -> bool {
    PANIC_FLAG.load(Ordering::SeqCst) != 0
}

pub fn handle_ipi_reschedule() {
    // The bootstrap's scheduler doesn't have a separate IPI
    // trigger path; the timer tick already calls
    // `ke::scheduler::schedule` on the BSP. The IPI handler
    // still does the right thing (run the dispatcher) so that
    // when the scheduler is upgraded to an IPI-triggered
    // model the boot path is already in place.
    let _ = crate::ke::scheduler::schedule();
}

pub fn handle_ipi_intr_enter() {
    // The "interrupt enter" IPI is used by NT to escalate
    // IRQL on a remote CPU. The bootstrap runs everything at
    // IRQL 0; this is a no-op.
}

pub fn handle_ipi_intr_exit() {
    // The "interrupt exit" IPI is the counterpart; also a
    // no-op in the bootstrap.
}

pub fn handle_ipi_panic_stop() {
    set_panic_stop();
    // Spin until the BSP halts us. We can't take the
    // scheduler lock here because the BSP may be holding it
    // and we want to be polite. HLT is the polite idle.
    loop {
        if !panic_stop_set() { break; }
        crate::arch::halt();
    }
}

pub fn handle_ipi_dynamic(vector: u8) {
    if vector < IPI_DYNAMIC_BASE || vector > IPI_DYNAMIC_END { return; }
    let idx = (vector - IPI_DYNAMIC_BASE) as usize;
    let handler = unsafe { IPI_HANDLERS[idx] };
    if let Some(h) = handler {
        h();
    }
}

pub fn init() {
    crate::hal::serial::write_string("[ke.dispatch] enter\r\n");
    // No fixed-vector allocation; vectors are reserved by
    // the IDT (see `arch::x86_64::idt`).
    PANIC_FLAG.store(0, Ordering::SeqCst);
    // Allocate the per-CPU global wait list. We use a single
    // static list for the bootstrap; the real implementation
    // would have one per dispatcher object.
    unsafe {
        WAIT_LIST_HEAD.init();
    }
}

// ---------------------------------------------------------------------------
// Dispatcher wait / wake
// ---------------------------------------------------------------------------
//
// We model the dispatcher wait list as a global doubly-linked
// list of `WaitEntry` nodes, each pointing back at a
// `DispatcherHeader` and at the thread that's waiting on it.
// The list is checked from the timer tick; when an entry's
// object is signalled, the thread is moved back to the ready
// queue.

use crate::ke::sync::{DispatcherHeader, WaitResult};
use crate::ps::thread::Ethread;

const WAIT_LIST_MAX: usize = 128;
const WAIT_LIST_EXTRA: usize = 64;  // Extra slots when primary is full
const WAIT_LIST_TOTAL: usize = WAIT_LIST_MAX + WAIT_LIST_EXTRA;

#[repr(C)]
struct WaitEntry {
    header: DispatcherHeader,
    thread: *mut Ethread,
    object: *const DispatcherHeader,
    deadline_ticks: u64,
    in_use: bool,
}

static mut WAIT_ENTRIES: [WaitEntry; WAIT_LIST_MAX] = [const {
    WaitEntry {
        header: DispatcherHeader {
            type_: 0,
            signal_state: 0,
            size: 0,
            inserted: 0,
            spare: [0; 3],
            absolute: 0,
            co_started: 0,
            co_terminated: 0,
            inactive: 0,
            reserved: [0; 2],
        },
        thread: core::ptr::null_mut(),
        object: core::ptr::null(),
        deadline_ticks: 0,
        in_use: false,
    }
}; WAIT_LIST_MAX];

// Extra entries allocated dynamically when primary pool is exhausted
static mut WAIT_ENTRIES_EXTRA: [WaitEntry; WAIT_LIST_EXTRA] = [const {
    WaitEntry {
        header: DispatcherHeader {
            type_: 0,
            signal_state: 0,
            size: 0,
            inserted: 0,
            spare: [0; 3],
            absolute: 0,
            co_started: 0,
            co_terminated: 0,
            inactive: 0,
            reserved: [0; 2],
        },
        thread: core::ptr::null_mut(),
        object: core::ptr::null(),
        deadline_ticks: 0,
        in_use: false,
    }
}; WAIT_LIST_EXTRA];

// Track how many extra entries are currently allocated
static mut WAIT_EXTRA_USED: usize = 0;

static mut WAIT_LIST_HEAD: crate::ps::process::ListEntry = crate::ps::process::ListEntry {
    flink: core::ptr::null_mut(),
    blink: core::ptr::null_mut(),
};

/// Spinlock protecting the global wait list. This ensures thread-safe
/// access to the wait list from multiple CPUs in SMP environment.
static WAIT_LIST_LOCK: crate::ke::sync::Spinlock<()> = crate::ke::sync::Spinlock::new(());

/// Park the current thread on `object`'s wait list, with a
/// `timeout_ms` deadline (or `u32::MAX` for infinite).
pub fn wait_on(object: &DispatcherHeader, timeout_ms: u32) -> WaitResult {
    // Acquire the wait list lock for the duration of list operations.
    // Note: We release the lock before calling schedule() to avoid
    // potential deadlock with the scheduler's locks.
    let (_entry_ptr, _deadline) = {
        let _lock = WAIT_LIST_LOCK.lock();
        unsafe {
            let current = match crate::ke::scheduler::get_current_thread() {
                Some(t) => t as *mut Ethread,
                None => return WaitResult::Error,
            };
            // Find a free slot.
            let slot = match find_free_slot() {
                Some(s) => s,
                None => return WaitResult::Error, // out of wait entries
            };
            let entry = match get_wait_entry(slot) {
                Some(e) => e,
                None => return WaitResult::Error,
            };
            entry.thread = current;
            entry.object = object as *const DispatcherHeader;
            entry.deadline_ticks = if timeout_ms == u32::MAX {
                u64::MAX
            } else {
                crate::ke::time::get_tick_count() as u64 + timeout_ms as u64
            };
            entry.in_use = true;
            // Insert the thread's wait_list_entry at the tail of
            // the wait list (sentinel-style intrusive list).
            let head_ptr: *mut crate::ps::process::ListEntry = &mut WAIT_LIST_HEAD;
            let e_ptr: *mut crate::ps::process::ListEntry =
                &mut (*current).kthread.wait_list_entry;
            (*e_ptr).blink = (*head_ptr).blink;
            (*e_ptr).flink = head_ptr;
            (*(*head_ptr).blink).flink = e_ptr;
            (*head_ptr).blink = e_ptr;
            // Move the current thread to a Waiting state and yield.
            (*current).kthread.state = crate::ps::thread::KThreadState::Waiting;
            // Return the entry pointer and deadline for post-schedule check
            (e_ptr, entry.deadline_ticks)
        }
    }; // Lock released here before schedule()
    
    // Yield the CPU to the scheduler
    crate::ke::scheduler::schedule();
    
    // After schedule returns, check whether we were signalled or timed out
    if object.signal_state != 0 {
        WaitResult::Success
    } else {
        WaitResult::Timeout
    }
}

/// Wake up to `all` waiters on `object`. Walks the global
/// wait list, finds entries whose `object` matches, removes
/// them, and puts their threads back on the ready queue.
///
/// Also applies priority boost based on the dispatcher object type.
pub fn wake(object: &DispatcherHeader, all: bool) {
    let _lock = WAIT_LIST_LOCK.lock();
    unsafe {
        let head_ptr: *mut crate::ps::process::ListEntry = &mut WAIT_LIST_HEAD;
        let mut cur: *mut crate::ps::process::ListEntry = (*head_ptr).flink;
        let mut woken: u32 = 0;
        while !cur.is_null() && cur != head_ptr {
            let wait_entry_offset =
                core::mem::offset_of!(Ethread, kthread) +
                core::mem::offset_of!(crate::ps::thread::Kthread, wait_list_entry);
            let ethread = (cur as u64 - wait_entry_offset as u64) as *mut Ethread;
            let next: *mut crate::ps::process::ListEntry = (*cur).flink;
            let mut found = false;
            for i in 0..WAIT_LIST_MAX {
                if WAIT_ENTRIES[i].in_use && WAIT_ENTRIES[i].thread == ethread
                    && WAIT_ENTRIES[i].object == object as *const DispatcherHeader
                {
                    // Mark free, ready thread.
                    WAIT_ENTRIES[i].in_use = false;
                    (*ethread).kthread.state = crate::ps::thread::KThreadState::Ready;

                    // Determine boost type based on object type
                    let object_type = object.type_;
                    let boost_type = match object_type {
                        0 => crate::ke::scheduler::PriorityBoostType::EventSet,     // Event
                        1 => crate::ke::scheduler::PriorityBoostType::MutantRelease, // Mutex
                        2 => crate::ke::scheduler::PriorityBoostType::Special,     // Semaphore
                        5 => crate::ke::scheduler::PriorityBoostType::Special,     // Timer
                        _ => crate::ke::scheduler::PriorityBoostType::Special,
                    };

                    // Apply priority boost and get new priority
                    let new_priority = crate::ke::scheduler::ki_boost_thread(ethread, boost_type);
                    let priority = new_priority as u8;

                    crate::ke::scheduler::add_ready(ethread, priority);
                    woken += 1;
                    found = true;
                    if !all { return; }
                    break;
                }
            }
            // Unlink `cur` from the list. The list is a
            // circular doubly-linked list with `WAIT_LIST_HEAD`
            // as a sentinel; cur.flink and cur.blink are its
            // neighbours.
            if found {
                let flink = (*cur).flink;
                let blink = (*cur).blink;
                (*flink).blink = blink;
                (*blink).flink = flink;
                // The list entry itself no longer points
                // anywhere (the thread is leaving the wait
                // list). Reset to self to make the entry
                // re-usable on the next wait.
                (*cur).flink = cur;
                (*cur).blink = cur;
            }
            cur = next;
            if !all && woken > 0 { return; }
        }
    }
}

fn find_free_slot() -> Option<usize> {
    unsafe {
        // First, try to find a free slot in the primary pool
        for i in 0..WAIT_LIST_MAX {
            if !WAIT_ENTRIES[i].in_use {
                return Some(i);
            }
        }
        // Primary pool exhausted, try to allocate from the extra pool
        if WAIT_EXTRA_USED < WAIT_LIST_EXTRA {
            let slot = WAIT_LIST_MAX + WAIT_EXTRA_USED;
            WAIT_EXTRA_USED += 1;
            // // crate::kprintln!("[DISPATCH] find_free_slot: using extra slot {}, total extra used: {}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                              slot, WAIT_EXTRA_USED);
            return Some(slot);
        }
    }
    // Both pools exhausted
    // // crate::kprintln!("[DISPATCH] find_free_slot: all wait entries exhausted ({} + {})",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                      WAIT_LIST_MAX, WAIT_LIST_EXTRA);
    None
}

/// Get a reference to a wait entry by index.
/// Index 0..WAIT_LIST_MAX-1 is in primary pool, WAIT_LIST_MAX..WAIT_LIST_TOTAL-1 is in extra pool.
unsafe fn get_wait_entry(index: usize) -> Option<&'static mut WaitEntry> {
    if index < WAIT_LIST_MAX {
        Some(&mut WAIT_ENTRIES[index])
    } else if index < WAIT_LIST_TOTAL {
        Some(&mut WAIT_ENTRIES_EXTRA[index - WAIT_LIST_MAX])
    } else {
        None
    }
}

/// Called from the timer tick. Walks the wait list and wakes
/// any threads whose deadline has passed.
pub fn tick_wait_list() {
    let _lock = WAIT_LIST_LOCK.lock();
    unsafe {
        let now = crate::ke::time::get_tick_count() as u64;
        let head_ptr: *mut crate::ps::process::ListEntry = &mut WAIT_LIST_HEAD;
        let mut cur: *mut crate::ps::process::ListEntry = (*head_ptr).flink;
        while !cur.is_null() && cur != head_ptr {
            let wait_entry_offset =
                core::mem::offset_of!(Ethread, kthread) +
                core::mem::offset_of!(crate::ps::thread::Kthread, wait_list_entry);
            let ethread = (cur as u64 - wait_entry_offset as u64) as *mut Ethread;
            let next: *mut crate::ps::process::ListEntry = (*cur).flink;
            let mut found = false;

            // Search through both primary and extra wait entries
            for i in 0..WAIT_LIST_TOTAL {
                if let Some(entry) = get_wait_entry(i) {
                    if entry.in_use && entry.thread == ethread && entry.deadline_ticks <= now {
                        entry.in_use = false;
                        (*ethread).kthread.state = crate::ps::thread::KThreadState::Ready;

                        // Apply priority boost for timeout wake
                        let boost_type = crate::ke::scheduler::PriorityBoostType::Special;
                        let new_priority = crate::ke::scheduler::ki_boost_thread(ethread, boost_type);
                        let priority = new_priority as u8;

                        crate::ke::scheduler::add_ready(ethread, priority);
                        found = true;
                        break;
                    }
                }
            }
            if found {
                let flink = (*cur).flink;
                let blink = (*cur).blink;
                (*flink).blink = blink;
                (*blink).flink = flink;
                (*cur).flink = cur;
                (*cur).blink = cur;
            }
            cur = next;
        }
    }
}
