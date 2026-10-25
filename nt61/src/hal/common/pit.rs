//! Architecture-agnostic timer support.
//
//! This module provides a compatible interface to the platform timer.
//! On x86_64, it re-exports the PIT implementation.
//! On other platforms, it provides stub functions.

#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub use crate::hal::x86_64::pit::*;

#[cfg(target_arch = "aarch64")]
mod aarch64_timer {
    use crate::hal::aarch64::timer;

    pub fn get_ticks() -> u64 {
        timer::time_ms()
    }

    pub fn increment_ticks() {}

    pub fn get_system_time_ms() -> u64 {
        timer::time_ms()
    }

    pub fn get_system_time_us() -> u64 {
        timer::time_ms().saturating_mul(1000)
    }
}

#[cfg(target_arch = "aarch64")]
pub use aarch64_timer::*;

#[cfg(all(not(target_arch = "x86_64"), not(target_arch = "aarch64")))]
mod stub {
    /// Get the current tick count.
    pub fn get_ticks() -> u64 {
        0
    }

    /// Increment tick count.
    pub fn increment_ticks() {}

    /// Get system time in milliseconds since kernel boot.
    pub fn get_system_time_ms() -> u64 {
        0
    }

    /// Get system time in microseconds since kernel boot.
    pub fn get_system_time_us() -> u64 {
        0
    }
}

#[cfg(all(not(target_arch = "x86_64"), not(target_arch = "aarch64")))]
pub use stub::*;
