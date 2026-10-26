//! Common serial port interface.
//
//! Provides a unified serial port interface across all architectures.
//! Delegates to architecture-specific implementations.
//!
//! All UART writes share the global transmit lock below. SMP log
//! writers that each pushed their own bytes used to interleave at
//! byte granularity and produced unreadable logs (audit hal_rtl
//! P0-1). The lock is reentrant on the owning CPU so a fault handler
//! that logs while the same CPU already holds the lock cannot spin
//! against itself.

static UART_TX_LOCK: crate::hal::common::relock::ReentrantLock =
    crate::hal::common::relock::ReentrantLock::new();

/// Acquire the global UART transmit lock.
pub fn lock_uart_tx() -> crate::hal::common::relock::ReentrantGuard<'static> {
    UART_TX_LOCK.lock()
}

#[cfg(target_arch = "x86_64")]
pub use crate::hal::x86_64::serial::*;

#[cfg(target_arch = "aarch64")]
pub use crate::hal::aarch64::serial::*;

#[cfg(target_arch = "riscv64")]
pub use crate::hal::riscv64::serial::*;

#[cfg(target_arch = "loongarch64")]
pub use crate::hal::loongarch64::serial::*;
