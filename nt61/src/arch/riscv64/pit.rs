//! RISC-V 64 SBI timer + CLINT mtimecmp

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

const CLINT_MTIMECMP: u64 = 0x2000_4000;
const CLINT_MTIME: u64 = 0x2000_BFF8;

static CLINT_BASE: AtomicU64 = AtomicU64::new(0);

pub fn init(base: u64) {
    CLINT_BASE.store(base, Ordering::Release);
}

pub fn set_next(ticks: u64) {
    let b = CLINT_BASE.load(Ordering::Acquire);
    if b != 0 {
        unsafe { core::ptr::write_volatile((b + CLINT_MTIMECMP) as *mut u64, ticks); }
    }
}

pub fn time() -> u64 {
    let b = CLINT_BASE.load(Ordering::Acquire);
    if b == 0 { return 0; }
    unsafe { core::ptr::read_volatile((b + CLINT_MTIME) as *const u64) }
}

/// SBI call: set timer.
pub fn sbi_set_timer(stime_value: u64) {
    unsafe {
        asm!(
            "mv a0, {v}",
            "li a7, 0",
            "li a6, 0",
            "ecall",
            v = in(reg) stime_value,
            options(nostack),
        );
    }
}

/// Busy-wait for the requested number of 100-ns ticks.
///
/// `count` is interpreted as NT's `NtDelayExecution` argument:
/// a relative or absolute duration in 100-ns units (signed 64-bit,
/// negative = relative). For Phase 1 we treat it as relative and
/// spin on the SBI / CLINT mtime counter. Resolution is coarse —
/// this is a placeholder used only by the syscall smoke test.
pub fn busy_wait_100ns(count: u64) {
    // Assume 10 MHz mtime — one tick every 100 ns. This matches
    // the legacy QEMU virt configuration.
    let start = time();
    let target = start.wrapping_add(count);
    while time() < target {
        core::hint::spin_loop();
    }
}
