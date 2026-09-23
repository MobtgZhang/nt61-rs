//! RISC-V64 Enhanced CLINT driver
//!
//! Core-Local Interruptor with:
//! - Timer management per hart
//! - Software interrupts (IPI)
//! - Time synchronization

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const CLINT_MAX_HARTS: usize = 64;
const CLINT_MSIP_STRIDE: u64 = 4;
const CLINT_MTIMECMP_STRIDE: u64 = 8;

static CLINT_BASE: AtomicU64 = AtomicU64::new(0);
static CLINT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TIMER_FREQUENCY: AtomicU64 = AtomicU64::new(10_000_000); // Default 10MHz

/// CLINT register offsets
mod offset {
    pub const MSIP_BASE: u64 = 0x0000;
    pub const MTIMECMP_BASE: u64 = 0x4000;
    pub const MTIME: u64 = 0xBFF8;
}

/// Initialize CLINT
pub fn init(base: u64) {
    CLINT_BASE.store(base, Ordering::Release);

    unsafe {
        // Clear all software interrupts
        for hart in 0..CLINT_MAX_HARTS {
            clear_msip(hart as u32);
        }

        // Set all timers to max (disabled)
        for hart in 0..CLINT_MAX_HARTS {
            set_mtimecmp(hart as u32, u64::MAX);
        }
    }

    CLINT_INITIALIZED.store(true, Ordering::Release);
}

/// Set timer frequency in Hz
pub fn set_frequency(freq_hz: u64) {
    TIMER_FREQUENCY.store(freq_hz, Ordering::Release);
}

/// Get timer frequency
pub fn get_frequency() -> u64 {
    TIMER_FREQUENCY.load(Ordering::Acquire)
}

/// Read current mtime value
pub fn read_mtime() -> u64 {
    let base = CLINT_BASE.load(Ordering::Acquire);
    if base == 0 {
        return 0;
    }

    unsafe {
        core::ptr::read_volatile((base + offset::MTIME) as *const u64)
    }
}

/// Set mtimecmp for specific hart
pub fn set_mtimecmp(hart: u32, value: u64) {
    let base = CLINT_BASE.load(Ordering::Acquire);
    if base == 0 || hart >= CLINT_MAX_HARTS as u32 {
        return;
    }

    unsafe {
        let addr = base + offset::MTIMECMP_BASE + (hart as u64) * CLINT_MTIMECMP_STRIDE;
        core::ptr::write_volatile(addr as *mut u64, value);
    }
}

/// Read mtimecmp for specific hart
pub fn read_mtimecmp(hart: u32) -> u64 {
    let base = CLINT_BASE.load(Ordering::Acquire);
    if base == 0 || hart >= CLINT_MAX_HARTS as u32 {
        return 0;
    }

    unsafe {
        let addr = base + offset::MTIMECMP_BASE + (hart as u64) * CLINT_MTIMECMP_STRIDE;
        core::ptr::read_volatile(addr as *const u64)
    }
}

/// Set software interrupt for hart (IPI)
pub fn raise_msip(hart: u32) {
    let base = CLINT_BASE.load(Ordering::Acquire);
    if base == 0 || hart >= CLINT_MAX_HARTS as u32 {
        return;
    }

    unsafe {
        let addr = base + offset::MSIP_BASE + (hart as u64) * CLINT_MSIP_STRIDE;
        core::ptr::write_volatile(addr as *mut u32, 1);
    }
}

/// Clear software interrupt for hart
pub fn clear_msip(hart: u32) {
    let base = CLINT_BASE.load(Ordering::Acquire);
    if base == 0 || hart >= CLINT_MAX_HARTS as u32 {
        return;
    }

    unsafe {
        let addr = base + offset::MSIP_BASE + (hart as u64) * CLINT_MSIP_STRIDE;
        core::ptr::write_volatile(addr as *mut u32, 0);
    }
}

/// Check if software interrupt is pending for hart
pub fn is_msip_pending(hart: u32) -> bool {
    let base = CLINT_BASE.load(Ordering::Acquire);
    if base == 0 || hart >= CLINT_MAX_HARTS as u32 {
        return false;
    }

    unsafe {
        let addr = base + offset::MSIP_BASE + (hart as u64) * CLINT_MSIP_STRIDE;
        core::ptr::read_volatile(addr as *const u32) != 0
    }
}

/// Schedule timer interrupt after delta ticks
pub fn schedule_timer_delta(hart: u32, delta: u64) {
    let current = read_mtime();
    set_mtimecmp(hart, current.wrapping_add(delta));
}

/// Schedule timer interrupt at absolute time
pub fn schedule_timer_absolute(hart: u32, target: u64) {
    set_mtimecmp(hart, target);
}

/// Schedule timer interrupt after microseconds
pub fn schedule_timer_us(hart: u32, microseconds: u64) {
    let freq = TIMER_FREQUENCY.load(Ordering::Acquire);
    let ticks = (microseconds * freq) / 1_000_000;
    schedule_timer_delta(hart, ticks);
}

/// Schedule timer interrupt after milliseconds
pub fn schedule_timer_ms(hart: u32, milliseconds: u64) {
    let freq = TIMER_FREQUENCY.load(Ordering::Acquire);
    let ticks = (milliseconds * freq) / 1_000;
    schedule_timer_delta(hart, ticks);
}

/// Disable timer for hart
pub fn disable_timer(hart: u32) {
    set_mtimecmp(hart, u64::MAX);
}

/// Check if timer is expired
pub fn is_timer_expired(hart: u32) -> bool {
    let current = read_mtime();
    let compare = read_mtimecmp(hart);
    current >= compare
}

/// Get time elapsed since boot in microseconds
pub fn get_uptime_us() -> u64 {
    let freq = TIMER_FREQUENCY.load(Ordering::Acquire);
    let ticks = read_mtime();
    (ticks * 1_000_000) / freq
}

/// Get time elapsed since boot in milliseconds
pub fn get_uptime_ms() -> u64 {
    let freq = TIMER_FREQUENCY.load(Ordering::Acquire);
    let ticks = read_mtime();
    (ticks * 1_000) / freq
}

/// Delay for microseconds (busy wait)
pub fn delay_us(microseconds: u64) {
    let freq = TIMER_FREQUENCY.load(Ordering::Acquire);
    let ticks = (microseconds * freq) / 1_000_000;
    let start = read_mtime();
    while read_mtime().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

/// Delay for milliseconds (busy wait)
pub fn delay_ms(milliseconds: u64) {
    delay_us(milliseconds * 1000);
}

/// Send IPI to hart
pub fn send_ipi(target_hart: u32) {
    raise_msip(target_hart);
}

/// Send IPI to all harts except sender
pub fn send_ipi_broadcast(sender_hart: u32, num_harts: u32) {
    for hart in 0..num_harts {
        if hart != sender_hart {
            send_ipi(hart);
        }
    }
}

/// Clear IPI for current hart
pub fn clear_ipi(hart: u32) {
    clear_msip(hart);
}

/// Check if CLINT is initialized
pub fn is_initialized() -> bool {
    CLINT_INITIALIZED.load(Ordering::Acquire)
}

/// Get base address
pub fn base() -> u64 {
    CLINT_BASE.load(Ordering::Acquire)
}
