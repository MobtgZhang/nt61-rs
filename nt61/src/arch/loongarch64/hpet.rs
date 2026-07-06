//! LoongArch 64 HPET (no HPET, re-export the timer)

pub use crate::arch::loongarch64::pit as hpet;
