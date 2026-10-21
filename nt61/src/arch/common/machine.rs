//! Architecture-neutral PE machine-type selection.

pub const fn current_pe_machine() -> u16 {
    #[cfg(target_arch = "x86_64")]
    {
        crate::loader::MachineType::AMD64 as u16
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::loader::MachineType::ARM64 as u16
    }
    #[cfg(target_arch = "loongarch64")]
    {
        crate::loader::MachineType::LOONGARCH64 as u16
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::loader::MachineType::RISCV64 as u16
    }
    #[cfg(all(
        not(target_arch = "x86_64"),
        not(target_arch = "aarch64"),
        not(target_arch = "loongarch64"),
        not(target_arch = "riscv64")
    ))]
    {
        0
    }
}
