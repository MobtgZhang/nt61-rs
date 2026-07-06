//! LoongArch 64 GDT (CPU context)

use core::arch::asm;

#[derive(Clone, Copy, Default)]
pub struct CpuContext {
    pub era: u64,
    pub prmd: u64,
    pub crmd: u64,
    pub sp: u64,
}

pub fn init() {
    unsafe {
        asm!("csrwr {}, 0xc", in(reg) 0u64, options(nostack));
    }
}
