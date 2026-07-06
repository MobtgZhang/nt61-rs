//! Architecture-common trap frame abstraction.
//
//! This module provides a common `TrapFrame` and `KTrapFrame` struct
//! that abstracts over the architecture-specific interrupt/exception frame
//! structures.

#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::dispatch::TrapFrame;

#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::dispatch::KTrapFrame;

/// Placeholder TrapFrame for non-x86_64 architectures.
/// The actual implementation will depend on the architecture's
/// exception handling mechanism.
#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TrapFrame {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KTrapFrame {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}
