//! Architecture-common SMP interface.
//
//! This module defines the `SmpArch` trait and `extern "Rust"` declarations
//! that allow architecture-specific SMP implementations to be called from
//! generic kernel code.

/// Trait for architecture-specific SMP operations.
///
/// Implement this trait for each supported architecture (aarch64, riscv64,
/// loongarch64) to provide CPU enumeration and boot operations.
pub trait SmpArch {
    /// Returns the number of available CPUs.
    fn cpu_count() -> u32;

    /// Boot secondary CPUs with the given PML4 PFN.
    ///
    /// # Safety
    /// The caller must ensure the page table is valid and identity-mapped.
    unsafe fn boot_secondary_cpus(pml4_pfn: u64);

    /// Returns the ID of the current CPU.
    fn get_current_cpu_id() -> u32;
}

// extern "Rust" declarations — each architecture provides these.
// The linker resolves them to the architecture-specific implementations.
//
// SAFETY: All functions in this block are inherently unsafe because they
// operate on raw page table PFNs and CPU state. Callers must ensure
// preconditions are met.
unsafe extern "Rust" {
    fn __smp_cpu_count() -> u32;
    unsafe fn __smp_boot_secondary(pml4_pfn: u64);
    fn __smp_get_current_cpu_id() -> u32;
}

/// Returns the number of available CPUs.
pub fn cpu_count() -> u32 {
    unsafe { __smp_cpu_count() }
}

/// Boot secondary CPUs with the given PML4 PFN.
///
/// # Safety
/// The caller must ensure the page table is valid and identity-mapped.
pub unsafe fn boot_secondary_cpus(pml4_pfn: u64) {
    __smp_boot_secondary(pml4_pfn);
}

/// Returns the ID of the current CPU.
pub fn get_current_cpu_id() -> u32 {
    // SAFETY: This is inherently unsafe because we're calling a function
    // imported from an unsafe extern block that accesses CPU-specific state.
    unsafe { __smp_get_current_cpu_id() }
}
