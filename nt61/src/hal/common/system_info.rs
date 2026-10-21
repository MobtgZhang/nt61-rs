//! Architecture-neutral processor and memory descriptions.

use alloc::string::String;

pub struct MemoryInfo {
    pub total_kb: u64,
    pub available_kb: u64,
}

pub const fn architecture_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x64-based PC"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "ARM64-based PC"
    }
    #[cfg(target_arch = "loongarch64")]
    {
        "LoongArch64-based PC"
    }
    #[cfg(target_arch = "riscv64")]
    {
        "RISC-V 64-bit PC"
    }
    #[cfg(all(
        not(target_arch = "x86_64"),
        not(target_arch = "aarch64"),
        not(target_arch = "loongarch64"),
        not(target_arch = "riscv64")
    ))]
    {
        "Unknown Architecture"
    }
}

pub fn processor_count() -> u32 {
    crate::arch::common::smp::cpu_count().max(1)
}

#[cfg(target_arch = "x86_64")]
pub fn processor_brand(index: u32) -> String {
    if index == 0 {
        cpu_brand_string().unwrap_or_else(|| String::from("x64 Processor"))
    } else {
        String::from("x64 Processor")
    }
}

#[cfg(target_arch = "x86_64")]
fn cpu_brand_string() -> Option<String> {
    crate::arch::x86_64::cpu_brand::cpu_brand_string()
}

#[cfg(target_arch = "aarch64")]
pub fn processor_brand(_index: u32) -> String {
    String::from("ARM Cortex-A Series ~1000 Mhz")
}

#[cfg(target_arch = "loongarch64")]
pub fn processor_brand(_index: u32) -> String {
    String::from("LoongArch64 Processor")
}

#[cfg(target_arch = "riscv64")]
pub fn processor_brand(_index: u32) -> String {
    String::from("RISC-V RV64 Processor")
}

#[cfg(all(
    not(target_arch = "x86_64"),
    not(target_arch = "aarch64"),
    not(target_arch = "loongarch64"),
    not(target_arch = "riscv64")
))]
pub fn processor_brand(_index: u32) -> String {
    String::from("Unknown Processor")
}

#[cfg(target_arch = "x86_64")]
pub fn memory_info() -> Option<MemoryInfo> {
    None
}

#[cfg(not(target_arch = "x86_64"))]
pub fn memory_info() -> Option<MemoryInfo> {
    None
}
