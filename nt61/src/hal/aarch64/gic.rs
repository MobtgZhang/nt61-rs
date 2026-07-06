//! GIC driver re-export.
//!
//! Historically the AArch64 HAL exposed the GIC driver under
//! `hal::aarch64::apic`; a newer commit renamed it to `gic`. Both
//! are kept as public modules so existing callers continue to build.

pub use super::apic::*;
