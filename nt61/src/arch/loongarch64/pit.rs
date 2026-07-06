//! LoongArch 64 PIT (timer)
use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

static TIMER_BASE: AtomicU64 = AtomicU64::new(0);

pub fn init(base: u64) {
    TIMER_BASE.store(base, Ordering::Release);
}

pub fn set_compare(deadline: u64) {
    let b = TIMER_BASE.load(Ordering::Acquire);
    if b != 0 {
        unsafe { ptr::write_volatile((b + 0x40) as *mut u64, deadline); }
    }
}

pub fn read_count() -> u64 {
    let b = TIMER_BASE.load(Ordering::Acquire);
    if b == 0 { return 0; }
    unsafe { ptr::read_volatile(b as *const u64) }
}

/// Approximate busy-wait loop used by Phase-1 syscalls.
///
/// `intervals` is in 100-ns units (the NT `NtDelayExecution`
/// argument). We don't have a calibrated loop here, so we just spin
/// `intervals` times — callers should treat the result as
/// "definitely long enough, possibly much longer".
pub fn busy_wait_100ns(intervals: u64) {
    // 1 iteration ≈ a handful of cycles; 1000 iterations ≈ a few
    // microseconds on 3A6000. Scale accordingly.
    let iters = intervals.saturating_mul(10);
    for _ in 0..iters {
        core::hint::spin_loop();
    }
}

#[allow(dead_code)]
unsafe fn _keep() {
    let _ = asm!("nop");
}
