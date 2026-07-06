//! aarch64 HPET (aarch64 has no HPET — use the Generic Timer)
//! re-exported as `hpet` for symmetry.

pub use crate::arch::aarch64::pit as hpet;
