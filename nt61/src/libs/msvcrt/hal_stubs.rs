//! HAL (Hardware Abstraction Layer) Stubs for MSVCRT
//!
//! Stub implementations for hardware access needed by MSVCRT

/// Get RTC timestamp (Unix time)
pub fn read_rtc_timestamp() -> i64 {
    if let Some(t) = crate::hal::common::cmos::query_real_time_clock() {
        // Days from 1970-01-01 to the CMOS civil date, then to seconds.
        let days = days_from_civil(t.year as i64, t.month as i64, t.day as i64);
        let secs =
            days * 86_400 + (t.hour as i64) * 3_600 + (t.minute as i64) * 60 + t.second() as i64;
        secs
    } else {
        // Fall back to the monotonic counter scaled by a known
        // frequency; the caller treats this as "time since boot"
        // rather than wall-clock when the RTC is unavailable.
        let counter = crate::arch::common::counter::read_counter();
        let freq = crate::libs::msvcrt::hal_stubs::tsc_frequency();
        if freq == 0 { 0 } else { (counter / freq) as i64 }
    }
}

/// read Time Stamp Counter
pub fn rdtsc() -> u64 {
    crate::arch::common::counter::read_counter()
}

/// Get TSC frequency in Hz
pub fn tsc_frequency() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        crate::hal::x86_64::pit::tsc_frequency_hz()
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::arch::aarch64::pit::timer_freq()
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::arch::riscv64::pit::TIMER_TICKS_PER_MS * 1_000
    }
    #[cfg(target_arch = "loongarch64")]
    {
        // LoongArch constant timer runs at 100 MHz on QEMU virt.
        100_000_000
    }
}

/// Howard Hinnant's `days_from_civil` algorithm for the proleptic
/// Gregorian calendar. Converts (year, month, day) to a day count
/// since 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// sleep for milliseconds
pub fn sleep(milliseconds: u64) {
    // Busy wait loop (not ideal, but works for stub)
    let start = rdtsc();
    let freq = tsc_frequency();
    let cycles = (milliseconds * freq) / 1000;

    while rdtsc() - start < cycles {
        core::hint::spin_loop();
    }
}
