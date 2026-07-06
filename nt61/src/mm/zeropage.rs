//! Zero-page thread
//
//! NT 6.1 runs a low-priority system thread (`MiZeroPageThread`) that
//! idles in the background and pre-zeroes free pages. When the demand
//! zero fault path needs a page, it pops from the zeroed list. If
//! the zeroed list is empty, it pops a free page and zeros it
//! synchronously (slower but always correct).
//
//! The thread is woken by an event when free pages are available
//! or when the zeroed list drops below the target level.

#![allow(non_snake_case)]

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::mm::pfn;
use crate::mm::pte::pfn_to_phys;
use crate::ke::sync::{Event, EventType, DispatcherHeader, Spinlock};

/// Number of pages to zero per batch.
const ZEROS_PER_BATCH: u64 = 16;

/// Target number of pages to keep on the zeroed list as a buffer.
const ZEROED_TARGET: u64 = 32;

/// Zeroed list level (current count).
static ZEROED_LEVEL: AtomicU64 = AtomicU64::new(0);

/// Whether the zero-page thread should keep running.
static ZERO_THREAD_RUNNING: AtomicBool = AtomicBool::new(true);

/// Kernel event that signals the zero page thread to wake up and do work.
/// This event is signaled when:
/// - request_zeroed_pages() is called and more zeroed pages are needed
/// - The zeroed page count drops below ZEROED_TARGET
/// Uses a Spinlock to prevent the race between is_none() check and set.
static ZERO_PAGE_EVENT_STORAGE: Spinlock<Option<Event>> = Spinlock::new(None);

/// Statistics for zero page thread operation
static ZERO_REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
static ZERO_SUCCESS_COUNT: AtomicU64 = AtomicU64::new(0);
static ZERO_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);
static ZERO_PAGES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Thread-safe getter for the zero page event header pointer.
fn get_zero_event_ptr() -> &'static mut DispatcherHeader {
    let mut guard = ZERO_PAGE_EVENT_STORAGE.lock();
    if guard.is_none() {
        *guard = Some(Event::new(EventType::Notification));
    }
    // SAFETY: The Event is stored in a static Spinlock, so the
    // DispatcherHeader lives for the entire program lifetime. We
    // compute its address while holding the lock (so no data race
    // on the Option), then return the raw pointer. The caller uses
    // the pointer immediately and never stores the reference.
    let header_ptr = unsafe {
        let event = guard.as_mut().unwrap();
        let event_ptr = event as *mut Event as *mut u8;
        let header_offset = core::mem::offset_of!(Event, header);
        event_ptr.add(header_offset) as *mut DispatcherHeader
    };
    // SAFETY: header_ptr points into static storage that outlives
    // this function. The Spinlock guarantees exclusive access during
    // initialization; callers only read/write the header after the
    // Event is fully constructed.
    unsafe { &mut *header_ptr }
}

/// Push one page to the zeroed list. Called by `tick()` after we
/// finish zeroing.
pub fn insert_zeroed(pfn_no: u64) {
    let mut db = pfn::PFN_DB.lock();
    db.insert_zeroed(pfn_no);
    let level = ZEROED_LEVEL.fetch_add(1, Ordering::Relaxed) + 1;

    // Wake the zero page thread if we dropped below target
    // In a full implementation, this would signal an event
    if level < ZEROED_TARGET {
        // Request zero page thread to do more work
        request_zeroed_pages();
    }
}

/// Request more zeroed pages (called when demand-zero fault needs a page)
/// This signals the zero page thread to wake up and do more work
pub fn request_zeroed_pages() {
    let mut current_level = ZEROED_LEVEL.load(Ordering::Relaxed);

    // Check if we already have enough zeroed pages
    if current_level >= ZEROED_TARGET {
        return;
    }

    // Try to increase the target level atomically
    loop {
        match ZEROED_LEVEL.compare_exchange_weak(
            current_level,
            ZEROED_TARGET,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                // Successfully set target, signal the event to wake the zero page thread
                let event = get_zero_event_ptr();
                crate::ke::sync::wake(event, false);
                break;
            }
            Err(actual) => {
                current_level = actual;
                if current_level >= ZEROED_TARGET {
                    // Another thread already set enough, no need to signal
                    break;
                }
            }
        }
    }
}

/// Pop a zeroed page. Falls back to zeroing a free page in place.
pub fn get_zeroed_page() -> Option<u64> {
    let mut db = pfn::PFN_DB.lock();
    if let Some(p) = db.pop_zeroed() {
        ZEROED_LEVEL.fetch_sub(1, Ordering::Relaxed);
        db.allocate_pfn(p);
        return Some(p);
    }
    if let Some(p) = db.pop_free() {
        let va = pfn_to_phys(p) as *mut u8;
        unsafe { ptr::write_bytes(va, 0, 4096); }
        db.allocate_pfn(p);
        return Some(p);
    }
    None
}

/// Try to refill the zeroed list up to `ZEROED_TARGET`. Called from
/// the periodic balance tick. Returns the number of pages zeroed.
pub fn tick() -> u64 {
    let mut zeroed: u64 = 0;
    let mut db = pfn::PFN_DB.lock();
    let mut count = ZEROED_LEVEL.load(Ordering::Relaxed);
    for _ in 0..ZEROS_PER_BATCH {
        if count >= ZEROED_TARGET { break; }
        if let Some(p) = db.pop_free() {
            let va = pfn_to_phys(p) as *mut u8;
            unsafe { ptr::write_bytes(va, 0, 4096); }
            db.insert_zeroed(p);
            zeroed += 1;
            count += 1;
        } else {
            break;
        }
    }
    drop(db);
    ZEROED_LEVEL.store(count, Ordering::Relaxed);
    zeroed
}

/// MiZeroPageThread — the NT 6.1 zero page thread entry point.
///
/// This function runs as a real kernel-mode system thread. It
/// continuously refills the zeroed page list in the background,
/// waiting on events rather than busy polling.
///
/// Event-based synchronization:
/// 1. Waits on ZERO_PAGE_NEEDED_EVENT when idle
/// 2. When signaled, refills the zeroed list
/// 3. Returns to waiting when target is reached
///
/// The thread exits when `stop_zero_thread()` is called (during
/// system shutdown).
pub extern "C" fn mi_zero_page_thread_entry(_context: u64) {
    // [DISABLED] crate:: // // kprintln!("[MM] MiZeroPageThread started (event-based synchronization)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Get the event to wait on
    let event = get_zero_event_ptr();
    record_request();

    while ZERO_THREAD_RUNNING.load(Ordering::Relaxed) {
        // Check current level before waiting
        let level = ZEROED_LEVEL.load(Ordering::Relaxed);

        if level < ZEROED_TARGET {
            // Need more zeroed pages, do some work
            let zeroed = tick();

            if zeroed == 0 {
                // No free pages available to zero.
                // Wait for event signal with a reasonable timeout
                // so we can periodically check for shutdown.
                record_failure();
                let result = crate::ke::sync::wait_single(event, 2000);
                match result {
                    crate::ke::sync::WaitResult::Success => {
                        // Event was signaled, will loop to do work
                    }
                    crate::ke::sync::WaitResult::Timeout => {
                        // Timeout, will loop to check shutdown flag
                    }
                    _ => {}
                }
            } else {
                // Successfully zeroed some pages
                for _ in 0..zeroed {
                    record_success();
                }

                let new_level = level + zeroed;
                if new_level >= ZEROED_TARGET {
                    // Target reached, wait for event with longer timeout
                    let _ = crate::ke::sync::wait_single(event, 5000);
                }
                // else: Some progress made, loop back to check level
            }
        } else {
            // Target reached, sleep until event is signaled
            // The event will be set when more zeroed pages are needed
            record_request();
            let _ = crate::ke::sync::wait_single(event, 5000);
        }
    }
    // [DISABLED] crate:: // // kprintln!("[MM] MiZeroPageThread exiting")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] crate:: // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // // [DISABLED]         "[MM] Zero page stats: requests={}, success={}, fail={}, pages={}",
// // // [DISABLED]         ZERO_REQUEST_COUNT.load(Ordering::Relaxed),
// // // [DISABLED]         ZERO_SUCCESS_COUNT.load(Ordering::Relaxed),
// // // [DISABLED]         ZERO_FAIL_COUNT.load(Ordering::Relaxed),
// // // [DISABLED]         ZERO_PAGES_TOTAL.load(Ordering::Relaxed)
// // // [DISABLED]     );
    crate::ps::thread::ps_exit_system_thread(0);
}

/// Initialize the zero page thread synchronization primitives.
/// Creates the kernel event used for signaling the zero page thread.
pub fn init_events() {
    let mut guard = ZERO_PAGE_EVENT_STORAGE.lock();
    if guard.is_none() {
        *guard = Some(Event::new(EventType::Notification));
    }
    drop(guard);
    // [DISABLED] // // kprintln!("[MM] Zero page thread synchronization initialized")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Start the zero page thread as a system thread.
pub fn start_zero_page_thread() {
    // Initialize events first
    init_events();

    let entry_addr = mi_zero_page_thread_entry as *const () as u64;
    let result = crate::ps::thread::ps_create_system_thread(
        entry_addr,
        0, // no context
    );
    if result.success {
        // [DISABLED] crate:: // // kprintln!("[MM] MiZeroPageThread created (entry=0x{:016x}, event-based)",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // // [DISABLED]             entry_addr);
    } else {
        // [DISABLED] crate:: // // kprintln!("[MM] WARNING: MiZeroPageThread creation failed")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Stop the zero page thread (called during shutdown).
pub fn stop_zero_thread() {
    ZERO_THREAD_RUNNING.store(false, Ordering::SeqCst);
    // Wake the thread so it can exit cleanly
    let event = get_zero_event_ptr();
    crate::ke::sync::wake(event, false);
}

/// Get zero page thread statistics
/// Returns: (request_count, success_count, fail_count, pages_zeroed_total)
pub fn get_zero_stats() -> (u64, u64, u64, u64) {
    (
        ZERO_REQUEST_COUNT.load(Ordering::Relaxed),
        ZERO_SUCCESS_COUNT.load(Ordering::Relaxed),
        ZERO_FAIL_COUNT.load(Ordering::Relaxed),
        ZERO_PAGES_TOTAL.load(Ordering::Relaxed),
    )
}

/// Get the current zeroed page level
pub fn get_zeroed_level() -> u64 {
    ZEROED_LEVEL.load(Ordering::Relaxed)
}

/// Record a zero page request
fn record_request() {
    ZERO_REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Record a successful page zero
fn record_success() {
    ZERO_SUCCESS_COUNT.fetch_add(1, Ordering::Relaxed);
    ZERO_PAGES_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record a failed zero request
fn record_failure() {
    ZERO_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn init() {
    ZEROED_LEVEL.store(0, Ordering::SeqCst);
    ZERO_THREAD_RUNNING.store(true, Ordering::SeqCst);
}
