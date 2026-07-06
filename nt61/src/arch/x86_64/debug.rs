//! x86_64 debug register accessors.
//!
//! Provides read/write helpers for the x86_64 hardware debug registers
//! (DR0..DR7) and a small set of segment-register helpers (used to
//! reach user-mode TLS / TEB). On other architectures these symbols
//! don't exist; callers must gate their use with
//! `cfg(target_arch = "x86_64")`.
//!
//! The kernel's debug-exception handler uses these to inspect
//! breakpoint state after a `#DB` trap. They live in `arch::x86_64`
//! rather than `ke::exception` so that the exception-dispatch code
//! stays architecture-agnostic.

/// Read debug register DR6 (debug status).
#[inline]
pub fn read_dr6() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {}, dr6", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Read debug register DR7 (debug control).
#[inline]
pub fn read_dr7() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {}, dr7", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Write debug register DR7 (debug control).
#[inline]
pub fn write_dr7(value: u64) {
    unsafe {
        core::arch::asm!("mov dr7, {}", in(reg) value, options(nomem, nostack));
    }
}

/// Read an 8-byte value from the `gs` segment at `offset`.
///
/// The kernel sets the GS base to the user-mode TEB on every ring-3
/// entry, so `read_gs_offset(0x30)` yields the `NtCurrentTeb()`-style
/// self-pointer used by SEH to walk the user exception list.
#[inline]
pub fn read_gs_offset(offset: u64) -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[{}]",
            out(reg) value,
            in(reg) offset,
            options(nostack),
        );
    }
    value
}