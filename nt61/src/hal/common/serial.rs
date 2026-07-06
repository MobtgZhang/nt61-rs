//! Common serial port interface.
//
//! Provides a unified serial port interface across all architectures.
//! Delegates to architecture-specific implementations.

#[cfg(target_arch = "x86_64")]
pub use crate::hal::x86_64::serial::*;

#[cfg(target_arch = "aarch64")]
pub use crate::hal::aarch64::serial::*;

#[cfg(target_arch = "riscv64")]
pub use crate::hal::riscv64::serial::*;

#[cfg(target_arch = "loongarch64")]
pub use crate::hal::loongarch64::serial::*;
