//! Architecture-specific driver support.
//!
//! This module contains driver code that is specific to a particular
//! CPU architecture. Code that is portable across architectures lives
//! in the parent `drivers` module.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
