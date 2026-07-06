//! Architecture-agnostic timer support.
//
//! This module provides a compatible interface to the platform timer.
//! On x86_64, it re-exports the PIT implementation.
//! On other platforms, it provides stub functions.

#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub use crate::hal::x86_64::pit::*;

#[cfg(not(target_arch = "x86_64"))]
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

#[cfg(not(target_arch = "x86_64"))]
pub use stub::*;
