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
        let mut spsr: u64 = 0;
        asm!("msr SPSR_EL1, {}", in(reg) spsr, options(nostack));
        asm!("msr ELR_EL1, {}", in(reg) 0u64, options(nostack));
        asm!("msr SP_EL0, {}", in(reg) 0u64, options(nostack));
        asm!("msr SP_EL1, {}", in(reg) 0u64, options(nostack));
    }
}
