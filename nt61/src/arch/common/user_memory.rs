//! Architecture-neutral user-memory probing for syscall dispatch.

#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::cpu_flags::SmapGuard;

#[cfg(not(target_arch = "x86_64"))]
#[derive(Debug)]
pub struct SmapGuard;

#[cfg(not(target_arch = "x86_64"))]
impl SmapGuard {
    pub fn open() -> Self {
        Self
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Probe a NUL-terminated UTF-16 string before copying it into the kernel.
#[cfg(target_arch = "x86_64")]
pub unsafe fn probe_for_read_unicode_string(address: u64, max_chars: usize) -> Result<usize, i32> {
    crate::arch::x86_64::syscall_validation::probe_for_read_unicode_string(
        address as *const u16,
        max_chars,
    )
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn probe_for_read_unicode_string(
    _address: u64,
    _max_chars: usize,
) -> Result<usize, i32> {
    Err(crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION as i32)
}
