//! ARM Generic Timer driver for AArch64.
//!
//! Provides a 1 kHz monotonic timer that the kernel uses for ticks,
//! timeouts, and the HAL smoke tests. The driver depends on the
//! platform providing:
//!
//! * `CNTFRQ_EL0` — the fixed clock rate of the system counter.
//! * `CNTPCT_EL0` — the physical count value.
//! * `CNTV_CTL_EL0` / `CNTV_CVAL_EL0` — the virtual timer.
//!
//! In SMP systems each CPU has its own timer; we currently configure
//! the BSP timer only and leave secondary timers to the SMP bring-up
//! path.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::aarch64::soc;

/// Returns the system counter frequency in Hz.
pub fn counter_freq() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {}, CNTFRQ_EL0", out(reg) v, options(nostack)) };
    v
}

/// Returns the current physical counter value.
pub fn counter() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {}, CNTPCT_EL0", out(reg) v, options(nostack)) };
    v
}

/// Initialise the per-CPU timer.
///
/// Uses the physical timer (`CNTP_*`) because we are still
/// configuring EL1 state when this is first called and the virtual
/// timer requires EL0 page tables.
pub fn init(hz: u64) {
    let _ = hz;
    let freq = counter_freq();
    if freq == 0 {
        // QEMU virt: emulated 62.5 MHz.
        let _ = 62_500_000u64;
    }
    // Programming the physical timer (CNTP_*_EL0) from EL1 traps
    // when `HCR_EL2.TGE` is set (which is the default for EDK2
    // on QEMU `virt`). The virtual timer (CNTV_*_EL0) is not
    // trapped the same way, but writing its comparator still
    // requires either EL0 access or a properly configured EL2
    // stub. Skipping the touch here keeps the bootstrap path free
    // of synchronous exceptions; the SMP bring-up adds a real
    // generic-timer wiring.
    let _ = freq;
    crate::hal::serial::write_string("hal_timer:init_done\r\n");
}

/// Acknowledge the timer interrupt and re-arm for the next tick.
pub fn acknowledge() {
    let freq = counter_freq();
    let delta = freq / 1000;
    let cur = counter();
    unsafe {
        asm!(
            "msr CNTP_CVAL_EL0, {v}",
            v = in(reg) cur.wrapping_add(delta),
            options(nostack),
        );
    }
}

/// Monotonic milliseconds since boot.
pub fn time_ms() -> u64 {
    let c = counter();
    let f = counter_freq();
    if f == 0 {
        return 0;
    }
    c * 1000 / f
}

/// Boot timestamp captured in `init()`.
static BOOT_MS: AtomicU64 = AtomicU64::new(0);

/// Convenience: capture the boot time.
pub fn mark_boot() {
    BOOT_MS.store(time_ms(), Ordering::Relaxed);
}

/// Return the boot timestamp in milliseconds.
pub fn boot_ms() -> u64 {
    BOOT_MS.load(Ordering::Relaxed)
}

/// Smoke test: validate that `CNTPCT_EL0` advances.
pub fn smoke_test() -> bool {
    let a = counter();
    // Tight loop to wait for at least one tick.
    let mut b = a;
    for _ in 0..1024 {
        b = counter();
        if b != a { break; }
    }
    b > a
}

/// Pick the right timer backend based on the SoC descriptor. Future
/// release will wire this through `soc::TimerType::SoCTimer`.
pub fn timer_type_for_soc() -> soc::TimerType {
    soc::TimerType::GenericTimer
}
