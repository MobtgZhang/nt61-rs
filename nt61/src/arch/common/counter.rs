//! Architecture-neutral monotonic hardware counter.

#[cfg(target_arch = "x86_64")]
pub fn read_counter() -> u64 {
    crate::arch::x86_64::percpu::read_tsc()
}

#[cfg(target_arch = "aarch64")]
pub fn read_counter() -> u64 {
    crate::arch::aarch64::pit::timer_count()
}

#[cfg(target_arch = "riscv64")]
pub fn read_counter() -> u64 {
    crate::arch::riscv64::pit::time()
}

#[cfg(target_arch = "loongarch64")]
pub fn read_counter() -> u64 {
    crate::arch::loongarch64::pit::read_count()
}
