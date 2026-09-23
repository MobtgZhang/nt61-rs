//! Timer Management
//
//! Kernel timer support. The kernel maintains a global list of
//! "kernel timers" (KTIMER) that fire at an absolute deadline
//! expressed in 100-ns ticks (the system time). The smoke test
//! arms a few timers, advances the clock past their deadline, and
//! verifies they were signalled.
//
//! Like `dpc.rs`, the timer table is heap-allocated on first use
//! to avoid a page fault on the uninitialised gap between the
//! `.data` section and the next section in the PE/COFF image.
//! The pool allocator gives us a zeroed, writable page.

use crate::ke::sync::{DispatcherHeader, Spinlock};
use crate::ke::time;
use crate::mm::pool;

/// Maximum number of kernel timers we can track. 64 is plenty for
/// the bootstrap; the real kernel uses a hash table.
pub const MAX_TIMERS: usize = 64;
const TIMER_SIZE: usize = core::mem::size_of::<Ktimer>();

/// Kernel timer. Uses the standard NT dispatcher header so a
/// thread can `KeWaitForSingleObject` on it.
pub struct Ktimer {
    pub header: DispatcherHeader,
    /// Absolute deadline in 100ns intervals (system time units).
    /// A value of 0 means "not armed".
    pub due_time: u64,
    /// Optional period in 100ns intervals. 0 = one-shot, >0 =
    /// periodic with that period.
    pub period: u64,
    /// A tag we can use in the boot log.
    pub name: &'static str,
    /// True if the timer is currently on the active list.
    pub armed: bool,
}

impl Ktimer {
    pub const fn new(name: &'static str) -> Self {
        Self {
            header: DispatcherHeader::new(8), // Timer
            due_time: 0,
            period: 0,
            name,
            armed: false,
        }
    }

    /// Arm the timer to fire `ms` milliseconds from now.
    pub fn arm_ms(&mut self, ms: u32) {
        let st = time::get_system_time();
        self.due_time = st + (ms as u64) * time::HUNDRED_NS_PER_MS;
        self.armed = true;
    }

    /// Arm the timer at a specific system time.
    pub fn arm_at(&mut self, due: u64) {
        self.due_time = due;
        self.armed = true;
    }

    /// Cancel the timer.
    pub fn cancel(&mut self) {
        self.due_time = 0;
        self.armed = false;
    }

    /// Is the timer past its deadline?
    pub fn is_expired(&self) -> bool {
        self.armed && self.due_time <= time::get_system_time()
    }
}

/// Backing storage pointer for the timer table.
static TIMER_STORAGE: Spinlock<*mut Ktimer> = Spinlock::new(core::ptr::null_mut());

/// Get (or allocate on first call) the timer backing array.
fn timer_array() -> &'static mut [Ktimer; MAX_TIMERS] {
    crate::hal::serial::write_string("[ke.timer] ta:lock\r\n");
    let mut g = TIMER_STORAGE.lock();
    crate::hal::serial::write_string("[ke.timer] ta:locked\r\n");
    if g.is_null() {
        crate::hal::serial::write_string("[ke.timer] ta:alloc\r\n");
        let bytes = pool::allocate(
            pool::PoolType::NonPaged,
            MAX_TIMERS * TIMER_SIZE,
        ) as *mut Ktimer;
        crate::hal::serial::write_string("[ke.timer] ta:post-alloc\r\n");
        if bytes.is_null() {
            crate::hal::serial::write_string("[ke.timer] ta:fb\r\n");
            static mut FALLBACK: [Ktimer; MAX_TIMERS] = [const { Ktimer::new("<fb>") }; MAX_TIMERS];
            return unsafe { &mut *(&raw mut FALLBACK) };
        }
        unsafe {
            core::ptr::write_bytes(bytes as *mut u8, 0u8, MAX_TIMERS * TIMER_SIZE);
        }
        *g = bytes;
    }
    // SAFETY: pool alloc returned exactly MAX_TIMERS Ktimers, all zeroed.
    let arr_ptr = *g as *mut [Ktimer; MAX_TIMERS];
    unsafe { &mut *arr_ptr }
}

/// Allocate a timer slot. Returns the index.
fn alloc_slot() -> Option<usize> {
    let arr = timer_array();
    for i in 0..MAX_TIMERS {
        let slot = &arr[i];
        if !slot.armed && slot.due_time == 0 && slot.period == 0 {
            return Some(i);
        }
    }
    None
}

/// Initialize timer subsystem. We don't actually have any timers
/// in flight at boot; just print a status line.
pub fn init() {
    crate::hal::serial::write_string("[ke.timer] enter\r\n");
}

/// Number of spurious interrupts seen during timer init. Updated
/// from the IRQ0 handler so we can tell whether the PIT is firing
/// while we're inside `timer_array`.
pub static mut SPURIOUS_INTS: u32 = 0;

/// Create a named timer. The timer is not armed; call
/// `arm_ms` / `arm_at` on it before `tick()` will fire it.
pub fn create_timer(name: &'static str) -> Option<usize> {
    let idx = alloc_slot()?;
    let arr = timer_array();
    let kt = Ktimer::new(name);
    unsafe {
        let dst = (arr.as_mut_ptr() as *mut u8).add(idx * TIMER_SIZE);
        write_ktimer(dst, &kt);
    }
    Some(idx)
}

/// Field-by-field copy of a Ktimer into raw memory. We can't use
/// `core::ptr::write` here because the compiler lowers an
/// aggregate write to a SSE/memcpy sequence that uses *non-temporal*
/// stores; on this kernel's heap pages (which the VMM marked as
/// UC/MTRR-type) those instructions fault. Plain `u64` stores work
/// fine, so we decompose the struct by hand.
#[inline(never)]
unsafe fn write_ktimer(dst: *mut u8, kt: &Ktimer) {
    // DispatcherHeader: type_(u8) + signal_state(u8) + size(u16) +
    // inserted(u8) + spare([u8; 3]) = 8 bytes.
    let h = &kt.header;
    core::ptr::write(dst.add(0), h.type_);
    core::ptr::write(dst.add(1), h.signal_state);
    core::ptr::write(dst.add(2) as *mut u16, h.size);
    core::ptr::write(dst.add(4), h.inserted);
    core::ptr::write(dst.add(5) as *mut [u8; 3], h.spare);
    core::ptr::write(dst.add(8)  as *mut u64, kt.due_time);
    core::ptr::write(dst.add(16) as *mut u64, kt.period);
    core::ptr::write(dst.add(24) as *mut *const u8, kt.name.as_ptr());
    core::ptr::write(dst.add(32) as *mut usize, kt.name.len());
    core::ptr::write(dst.add(40) as *mut bool, kt.armed);
}

/// Arm a previously-created timer.
pub fn arm_timer(idx: usize, deadline_ticks: u64) -> bool {
    let arr = timer_array();
    if idx >= MAX_TIMERS {
        return false;
    }
    let t = &mut arr[idx];
    t.arm_at(deadline_ticks);
    true
}

/// Cancel a timer.
pub fn cancel_timer(idx: usize) -> bool {
    let arr = timer_array();
    if idx >= MAX_TIMERS {
        return false;
    }
    let t = &mut arr[idx];
    t.cancel();
    true
}

/// Run one tick of the timer subsystem. Walks the global timer
/// list and signals any timer whose deadline has passed. Returns
/// the number of timers that fired.
pub fn tick() -> usize {
    let mut fired = 0;
    let arr = timer_array();
    for i in 0..MAX_TIMERS {
        if arr[i].is_expired() {
            arr[i].header.signal_state = 1;
            arr[i].armed = false;
            if arr[i].period > 0 {
                arr[i].arm_at(arr[i].due_time + arr[i].period);
            }
            fired += 1;
        }
    }
    fired
}

/// Smoke test for the timer subsystem.
///
/// Arms a 1 ms timer, advances the system clock by 5 ms, ticks
/// the timer subsystem, and verifies the timer fired.
pub fn smoke_test() -> bool {
    // // kprintln!("    [TIMER SMOKE] enter")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    use crate::ke::time;
    let arr = timer_array();
    // // kprintln!("    [TIMER SMOKE] timer_array ok")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // Allocate a fresh slot.
    let idx = match create_timer("smoke") {
        Some(i) => i,
        None => {
            // // kprintln!("    [TIMER SMOKE FAIL] could not allocate timer")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    };
    // // kprintln!("    [TIMER SMOKE] timer allocated at idx={}", idx)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // Arm it 1 ms from now.
    arr[idx].arm_ms(1);
    // // kprintln!("    [TIMER SMOKE] timer armed, advancing ticks")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // Advance system time by 5 ms so the deadline is well past.
    time::advance_ticks(5);
    // // kprintln!("    [TIMER SMOKE] ticks advanced, ticking")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    let fired = tick();
    // // kprintln!("    [TIMER SMOKE] tick()={}", fired)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    if fired < 1 {
        // // kprintln!("    [TIMER SMOKE FAIL] tick()={} expected >= 1", fired)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    if arr[idx].header.signal_state == 0 {
        // // kprintln!("    [TIMER SMOKE FAIL] timer not signalled")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "    [TIMER SMOKE OK] armed+expired+signalled fired={}",
// //         fired
// //     );
    // Free the slot for subsequent tests (use field-by-field write
    // to avoid the SSE/non-temporal fault that the heap's UC memory
    // type would otherwise hit on a whole-struct copy).
    unsafe {
        let dst = (arr.as_mut_ptr() as *mut u8).add(idx * TIMER_SIZE);
        // DispatcherHeader -> 8 zero bytes
        core::ptr::write_bytes(dst, 0u8, 8);
        // due_time, period, name ptr, name len, armed
        core::ptr::write(dst.add(8)  as *mut u64, 0u64);
        core::ptr::write(dst.add(16) as *mut u64, 0u64);
        core::ptr::write(dst.add(24) as *mut *const u8, core::ptr::null());
        core::ptr::write(dst.add(32) as *mut usize, 0usize);
        core::ptr::write(dst.add(40) as *mut bool, false);
    }
    true
}
