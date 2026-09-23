//! HAL (Hardware Abstraction Layer) Stubs for MSVCRT
//!
//! Stub implementations for hardware access needed by MSVCRT

/// Get RTC timestamp (Unix time)
pub fn read_rtc_timestamp() -> i64 {
    // Return a fixed timestamp: 2024-01-01 00:00:00 UTC
    1704067200
}

/// Read Time Stamp Counter
pub fn rdtsc() -> u64 {
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
}

/// Get TSC frequency in Hz
pub fn tsc_frequency() -> u64 {
    // Assume 2.4 GHz TSC frequency
    2_400_000_000
}

/// Sleep for milliseconds
pub fn sleep(milliseconds: u64) {
    // Busy wait loop (not ideal, but works for stub)
    let start = rdtsc();
    let freq = tsc_frequency();
    let cycles = (milliseconds * freq) / 1000;

    while rdtsc() - start < cycles {
        core::hint::spin_loop();
    }
}
