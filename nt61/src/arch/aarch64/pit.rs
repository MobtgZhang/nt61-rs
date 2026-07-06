//! aarch64 Generic Timer

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

static FREQ: AtomicU64 = AtomicU64::new(0);

pub fn timer_init() {
    unsafe {
        let f: u64;
        asm!("mrs {}, CNTFRQ_EL0", out(reg) f, options(nostack));
        FREQ.store(f, Ordering::Release);
    }
}

pub fn timer_freq() -> u64 {
    FREQ.load(Ordering::Acquire)
}

pub fn timer_count() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {}, CNTPCT_EL0", out(reg) v, options(nostack)); }
    v
}

/// Set the next timer compare value.
pub fn set_compare(deadline: u64) {
    unsafe {
        asm!("msr CNTP_CVAL_EL0, {}", in(reg) deadline, options(nostack));
        asm!("msr CNTP_CTL_EL0, {}", in(reg) 1u64, options(nostack));
    }
}

#[allow(dead_code)]
fn _keep() {
    let _ = ptr::null::<u8>();
}
