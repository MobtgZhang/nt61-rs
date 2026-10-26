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
        // Enable the physical timer (CNTP) for EL1 access.
        // CNTKCTL_EL1.EL1PCTEN = 1 — allow EL1 to access CNTPCT_EL0.
        let cntkctl: u64;
        asm!("mrs {}, CNTKCTL_EL1", out(reg) cntkctl, options(nostack));
        asm!("msr CNTKCTL_EL1, {}", in(reg) (cntkctl | 0x1), options(nostack));
    }
}

pub fn timer_freq() -> u64 {
    FREQ.load(Ordering::Acquire)
}

pub fn timer_count() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {}, CNTPCT_EL0", out(reg) v, options(nostack));
    }
    v
}

/// Set the next timer compare value.
pub fn set_compare(deadline: u64) {
    unsafe {
        asm!("msr CNTP_CVAL_EL0, {}", in(reg) deadline, options(nostack));
        // CNTP_CTL_EL0: bit 0 = Enable, bit 1 = INTR (generate IRQ).
        // Without bit 1 the timer fires but does not signal an
        // interrupt — the scheduler never gets ticked.
        asm!("msr CNTP_CTL_EL0, {}", in(reg) 0x3u64, options(nostack));
    }
}

fn _keep() {
    let _ = ptr::null::<u8>();
}
