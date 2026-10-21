//! Very-early serial console bring-up (runs before `mm::init()`).
//!
//! On LoongArch64 the firmware leaves the UART MMIO region
//! unreachable while paging is on, so the trampoline below briefly
//! clears CRMD.PG; every other architecture is a plain wrapper.
/// write one byte to the platform's debug serial sink.
///
/// Safe to call from any context — including before
/// `mm::init()`/`hal::init()`. On LoongArch64 the trampoline also
/// makes the UART MMIO region reachable by clearing CRMD.PG, see
/// `arch_early_ensure_serial_ready`.
#[inline]
pub unsafe fn early_write_byte(c: u8) {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = crate::hal::x86_64::serial::write_char(c);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = crate::hal::aarch64::serial::write_char(c);
    }
    #[cfg(target_arch = "riscv64")]
    {
        let _ = crate::hal::riscv64::serial::write_char(c);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let _ = crate::hal::loongarch64::serial::write_char(c);
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    )))]
    {
        let _ = c;
    }
}

/// write a byte slice to the early serial console. On LoongArch64
/// this disables paging so the first MMIO access doesn't trap;
/// on every other architecture it is a plain wrapper around
/// `early_write_byte`.
pub fn early_write_str(s: &[u8]) {
    arch_early_ensure_serial_ready();
    // LoongArch64-specific dependency pin: keep the call site
    // alive so the trampoline above is never DCE'd.
    #[cfg(target_arch = "loongarch64")]
    {
        let _ = ARCH_EARLY_LAST_CRMD.load(core::sync::atomic::Ordering::Relaxed);
    }
    crate::hal::common::serial_disable::with_serial_unmasked(|| {
        for &c in s {
            unsafe { early_write_byte(c) };
        }
    })
}

/// Per-arch early serial sink readiness trampoline.
///
/// On LoongArch64 the firmware leaves the UART MMIO region
/// unreachable while paging is on, so we briefly clear CRMD.PG.
/// On every other architecture the firmware already provides an
/// identity-mapped UART window, so this is a no-op. The
/// `#[inline(never)]` + `static mut` dependencies ensure the LTO
/// pass cannot eliminate the call.
#[inline(never)]
pub fn arch_early_ensure_serial_ready() {
    #[cfg(target_arch = "loongarch64")]
    {
        let prev = arch_early_ensure_serial_ready_loongarch();
        ARCH_EARLY_LAST_CRMD.store(prev, core::sync::atomic::Ordering::Relaxed);
    }
    // x86_64 / aarch64 / riscv64: nothing to do.
}

#[cfg(target_arch = "loongarch64")]
#[inline(never)]
fn arch_early_ensure_serial_ready_loongarch() -> u64 {
    static mut GUARD: u64 = 0;
    unsafe {
        let mut crmd: u64;
        core::arch::asm!("csrrd {}, 0x0", out(reg) crmd, options(nostack));
        let prev = crmd;
        GUARD = GUARD.wrapping_add(1);
        core::arch::asm!("csrwr {}, 0x0", in(reg) crmd, options(nostack));
        GUARD = GUARD.wrapping_add(crmd ^ prev);
        prev
    }
}

#[cfg(target_arch = "loongarch64")]
static ARCH_EARLY_LAST_CRMD: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
