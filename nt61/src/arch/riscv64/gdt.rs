//! RISC-V 64 GDT (CPU context) — minimal placeholder

use core::arch::asm;

#[derive(Clone, Copy, Default)]
pub struct CpuContext {
    pub sepc: u64,
    pub sstatus: u64,
    pub sp: u64,
    pub tp: u64,
}

pub fn init() {
    unsafe {
        asm!("csrw sscratch, {}", in(reg) 0u64, options(nostack));
    }
}
