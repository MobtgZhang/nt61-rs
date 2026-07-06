//! RISC-V 64 HPET — no HPET on RISC-V; re-export the SBI timer

pub use crate::arch::riscv64::pit as hpet;
