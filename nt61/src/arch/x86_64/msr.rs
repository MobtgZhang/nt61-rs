//! x86_64 Model-Specific Register (MSR) accessors.
//!
//! Provides read/write helpers for the x86_64 MSR family used by
//! the kernel: IA32_STAR, IA32_LSTAR, IA32_FMASK, IA32_GS_BASE,
//! IA32_KERNEL_GS_BASE, and others. On other architectures these
//! symbols don't exist.

/// Read an MSR by index.
///
/// # Safety
///
/// The caller must ensure that `msr` is a valid MSR for the current
/// CPU model and that reading it does not cause undefined behaviour
/// (e.g. reading a write-only MSR).
pub unsafe fn read_msr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nostack),
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// Write a value to an MSR by index.
///
/// # Safety
///
/// The caller must ensure that `msr` is a valid MSR for the current
/// CPU model and that writing to it does not cause undefined behaviour
/// (e.g. writing to a read-only MSR, or writing an illegal value).
pub unsafe fn write_msr(msr: u32, value: u64) {
    let lo = (value & 0xFFFF_FFFF) as u32;
    let hi = (value >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
        options(nostack),
    );
}
