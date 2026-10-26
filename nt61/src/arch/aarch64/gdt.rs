//! aarch64 GDT (CPU context)
use core::arch::asm;

#[derive(Clone, Copy, Default)]
pub struct CpuContext {
    pub sp_el0: u64,
    pub sp_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
}

pub fn init() {
    unsafe {
        // Do NOT zero SP_EL1. On AArch64, SP_EL1 is the EL1 stack
        // pointer; writing 0 would cause every exception taken from
        // EL0 (SPSR.SP=0 selects SP_EL0) or from EL1 to build its
        // frame at address 0, immediately triggering a recursive
        // data abort. Leave the current SP_EL1 untouched — it was
        // set by the bootloader or `smp::secondary_entry`. Zeroing
        // SPSR_EL1/ELR_EL1 is safe (no eret is performed here).
        let spsr: u64 = 0;
        asm!("msr SPSR_EL1, {}", in(reg) spsr, options(nostack));
        asm!("msr ELR_EL1, {}", in(reg) 0u64, options(nostack));
        asm!("msr SP_EL0, {}", in(reg) 0u64, options(nostack));
    }
}
