//! Architecture policy for the boot manager.

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Probe a physical page by writing and reading a marker through
/// volatile memory. Returns the read-back byte so the caller can
/// reject firmware allocations that are not actually mapped.
///
/// SAFETY: `address` must point to mapped, writable memory.
pub unsafe fn probe_memory(address: u64) -> u8 {
    let pointer = address as *mut u8;
    pointer.write_volatile(0xAA);
    pointer.read_volatile()
}

/// Architecture-specific boot dispatch surface.
///
/// Callers may only use this facade; machine encodings and register
/// conventions belong in the per-architecture modules.
#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
pub mod current;

#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64.rs"]
pub mod current;

#[cfg(target_arch = "loongarch64")]
#[path = "loongarch64.rs"]
pub mod current;
