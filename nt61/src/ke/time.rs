//! Time Management
//
//! System time and timers. The kernel tracks three time scales:
//
//!   * **Tick count** — the millisecond counter returned by
//!     `get_tick_count()`. This is the basis for most timer-queue
//!     math; the bootstrap increments it from the clock ISR.
//!   * **System time** — 100-ns intervals since 1601-01-01
//!     (the NT epoch). The HAL queries the RTC for the boot time
//!     and then the tick counter drives it forward.
//!   * **Interrupt time** — 100-ns intervals since boot, used by
//!     ISR-time code that needs a fast monotonic clock.
//
//! On x86_64 we prefer the HPET (`hal::x86_64::hpet::ticks()`)
//! and fall back to the TSC if the HPET is not present.

use core::sync::atomic::{AtomicU64, Ordering};


/// Tick frequency in Hz. The PIT/HAL is programmed to this rate.
pub const TICKS_PER_SECOND: u32 = 1000;
/// 100-ns intervals per millisecond. NT epoch math.
pub const HUNDRED_NS_PER_MS: u64 = 10_000;
/// Number of 100-ns intervals between 1601-01-01 and 1970-01-01.
pub const EPOCH_DIFF_100NS: u64 = 0x01B21DD2_13814000;
/// Number of milliseconds in one day (24*60*60*1000).
pub const MS_PER_DAY: u64 = 86_400_000;

/// Monotonic tick count in milliseconds. Boot is tick 0.
static SYSTEM_TIME: AtomicU64 = AtomicU64::new(0);
static INTERRUPT_TIME: AtomicU64 = AtomicU64::new(0);
/// Counter for the number of times `ke::time::advance_tick` was
/// called. Used by the smoke test to verify the timer ISR is
/// running.
static ADVANCE_COUNT: AtomicU64 = AtomicU64::new(0);
/// Source of time — chosen during `init()`.
static mut TIME_SOURCE: TimeSource = TimeSource::Stub;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    Stub,
    Tsc,
    Hpet,
    Pit,
}

/// Pick the best available time source. The HAL is the source of
/// truth on x86_64; we ask it for a HPET / PIT preference.
fn pick_time_source() -> TimeSource {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::hal::hpet::hpet_freq_hz() > 0 {
            return TimeSource::Hpet;
        }
        if crate::hal::pit::pit_freq_hz() > 0 {
            return TimeSource::Pit;
        }
    }
    TimeSource::Tsc
}

/// Initialize time subsystem.
pub fn init() {
    crate::hal::serial::write_string("[ke.time] enter\r\n");
    SYSTEM_TIME.store(0, Ordering::SeqCst);
    INTERRUPT_TIME.store(0, Ordering::SeqCst);
    ADVANCE_COUNT.store(0, Ordering::SeqCst);
    let source = pick_time_source();
    unsafe { TIME_SOURCE = source };
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
    // //         "    Time: source={:?} freq={}Hz ({}ms/tick)",
    // //         source, TICKS_PER_SECOND, 1000 / TICKS_PER_SECOND
    // //     );
    // // kprintln!("    Time: tick_count=0 system_time=0 interrupt_time=0")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Advance the time counters by one tick. Called from the clock
/// ISR; the smoke test can also drive it directly to verify the
/// math.
pub fn advance_tick() {
    let _ = SYSTEM_TIME.fetch_add(HUNDRED_NS_PER_MS, Ordering::Relaxed);
    let _ = INTERRUPT_TIME.fetch_add(HUNDRED_NS_PER_MS, Ordering::Relaxed);
    ADVANCE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Advance the time counters by `n` ticks. Used by the smoke test
/// to fast-forward without spinning.
pub fn advance_ticks(n: u64) {
    let delta = n * HUNDRED_NS_PER_MS;
    SYSTEM_TIME.fetch_add(delta, Ordering::Relaxed);
    INTERRUPT_TIME.fetch_add(delta, Ordering::Relaxed);
    ADVANCE_COUNT.fetch_add(n, Ordering::Relaxed);
}

/// Get current system time in 100ns intervals since 1601-01-01.
pub fn get_system_time() -> u64 {
    SYSTEM_TIME.load(Ordering::SeqCst)
}

/// Get current system time as a Unix timestamp (seconds since
/// 1970-01-01). On the bootstrap this is 0 because we never set
/// the wall clock; the real kernel reads the RTC.
pub fn get_unix_time() -> u64 {
    let st = get_system_time();
    if st < EPOCH_DIFF_100NS {
        0
    } else {
        (st - EPOCH_DIFF_100NS) / 10_000_000
    }
}

/// Get current interrupt time in 100ns intervals since boot.
pub fn get_interrupt_time() -> u64 {
    INTERRUPT_TIME.load(Ordering::SeqCst)
}

/// Get tick count (ms since boot).
pub fn get_tick_count() -> u32 {
    (SYSTEM_TIME.load(Ordering::SeqCst) / HUNDRED_NS_PER_MS) as u32
}

/// Time source chosen at init.
pub fn source() -> TimeSource {
    unsafe { TIME_SOURCE }
}

/// Number of times `advance_tick` has been called.
pub fn advance_count() -> u64 {
    ADVANCE_COUNT.load(Ordering::Relaxed)
}

/// Smoke test for the time subsystem.
///
/// Drives `advance_ticks` a few times and checks the math
/// (`get_tick_count`, `get_system_time`, `get_interrupt_time`).
pub fn smoke_test() -> bool {
    let before = get_tick_count();
    let adv_before = advance_count();
    let st_before = get_system_time();
    let it_before = get_interrupt_time();
    advance_ticks(7);
    let after = get_tick_count();
    let adv_after = advance_count();
    let st_after = get_system_time();
    let it_after = get_interrupt_time();

    if after != before + 7 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [TIME SMOKE FAIL] tick_count: {} -> {}",
// //             before, after
// //         );
        return false;
    }
    if adv_after != adv_before + 7 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [TIME SMOKE FAIL] advance_count: {} -> {}",
// //             adv_before, adv_after
// //         );
        return false;
    }
    if st_after != st_before + 7 * HUNDRED_NS_PER_MS {
        // // kprintln!("    [TIME SMOKE FAIL] system_time math")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    if it_after != it_before + 7 * HUNDRED_NS_PER_MS {
        // // kprintln!("    [TIME SMOKE FAIL] interrupt_time math")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "    [TIME SMOKE OK] tick_count={} system_time={}us interrupt_time={}us",
// //         after,
// //         st_after / 10,
// //         it_after / 10
// //     );
    true
}
