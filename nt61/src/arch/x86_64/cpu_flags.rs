//! CR4 user-boundary protection bits (SMEP / SMAP)
//
//! SMEP (CR4 bit 9) faults if ring 0 executes code found in a ring 3
//! page. SMAP (CR4 bit 10) faults if ring 0 reads or writes a ring 3
//! page unless an explicit STAC/CLAC window is open.
//
//! Without these bits every user-pointer check in this kernel is a
//! software-only policy: a code path that forgets to probe silently
//! reads or writes user memory, and the damage is invisible. With them
//! a missed probe becomes a #PF that the exception dispatcher can act
//! on. They are the hardware half of the ring boundary that
//! `mm::user_copy` implements in software.
//
//! Both bits are optional. CPUID.(EAX=7,ECX=0):EBX reports SMEP in bit 7
//! and SMAP in bit 8, so the kernel probes before setting and records
//! what the CPU actually supports.

use core::sync::atomic::{AtomicBool, Ordering};

pub const CR4_SMEP_BIT: u64 = 1 << 9;
pub const CR4_SMAP_BIT: u64 = 1 << 10;

static SMEP_SUPPORTED: AtomicBool = AtomicBool::new(false);
static SMAP_SUPPORTED: AtomicBool = AtomicBool::new(false);
static SMEP_ENABLED: AtomicBool = AtomicBool::new(false);
static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);
static RDRAND_SUPPORTED: AtomicBool = AtomicBool::new(false);
static RDSEED_SUPPORTED: AtomicBool = AtomicBool::new(false);

pub fn read_cr4() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {0}, cr4", out(reg) value, options(nostack, nomem));
    }
    value
}

pub fn write_cr4(value: u64) {
    unsafe {
        core::arch::asm!("mov cr4, {0}", in(reg) value, options(nostack, nomem));
    }
}

// =============================================================================
// CR8 - Task Priority (AMD64 only)
// =============================================================================

/// read CR8 (Task Priority). On AMD64 the LAPIC task priority is exposed as
/// CR8; the low 4 bits hold the running priority level (0..15).
///
/// This is a privileged instruction: callers must only use it once the
/// interrupt controller is actually up (`hal::x86_64::apic::is_ready()`),
/// which is also what keeps unit tests running in userspace from faulting.
pub fn read_cr8() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {0}, cr8", out(reg) value, options(nostack, nomem));
    }
    value
}

/// write CR8 (Task Priority). Only the low 4 bits are architecturally used.
///
/// Privileged: same readiness precondition as `read_cr8`.
pub fn write_cr8(value: u64) {
    unsafe {
        core::arch::asm!("mov cr8, {0}", in(reg) value & 0xF, options(nostack, nomem));
    }
}

/// CPUID.(EAX=7,ECX=0):EBX — structured extended feature flags.
fn cpuid7_ebx() -> u32 {
    let ebx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx,
            options(nostack, nomem, preserves_flags)
        );
    }
    ebx
}

/// CPUID.(EAX=1):ECX — the RDRND flag lives here (bit 30), not in leaf 7.
fn cpuid1_ecx() -> u32 {
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "xor ecx, ecx",
            "cpuid",
            "mov {0:e}, ecx",
            "pop rbx",
            out(reg) ecx,
            options(nostack, nomem, preserves_flags)
        );
    }
    ecx
}

/// CPUID feature bits for the on-chip random number generators.
///
/// Per the Intel SDM: RDRAND is CPUID.(EAX=1):ECX[30], RDSEED is
/// CPUID.(EAX=7,ECX=0):EBX[30]. RDSEED is the stronger source — its
/// output is conditioned on hardware entropy rather than a PRNG — so it
/// is preferred for CSPRNG seeding.
///
/// The flags are only populated by `enable_user_boundary_protection()`
/// during boot. Before that they read false, which keeps unit tests
/// (running in ring 3 on a host kernel) from executing instructions the
/// host CPU may not implement.
pub const CPUID1_ECX_RDRND_BIT: u32 = 1 << 30;
pub const CPUID7_EBX_RDSEED_BIT: u32 = 1 << 30;

pub fn rdrand_supported() -> bool {
    RDRAND_SUPPORTED.load(Ordering::SeqCst)
}

pub fn rdseed_supported() -> bool {
    RDSEED_SUPPORTED.load(Ordering::SeqCst)
}

/// One RDSEED attempt. Returns `None` when the instruction is not
/// supported or the hardware reports no entropy available (RDSEED sets
/// CF on success and can fail; the SDM recommends retrying a bounded
/// number of times rather than treating a failure as fatal).
pub fn rdseed_u64() -> Option<u64> {
    if !RDSEED_SUPPORTED.load(Ordering::SeqCst) {
        return None;
    }
    for _ in 0..RDSEED_MAX_RETRIES {
        let value: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "rdseed {0}",
                "setc {1}",
                out(reg) value,
                out(reg_byte) ok,
                options(nostack, nomem, preserves_flags)
            );
        }
        if ok != 0 {
            return Some(value);
        }
    }
    None
}

/// One RDRAND attempt. Same CF-on-success convention as RDSEED.
pub fn rdrand_u64() -> Option<u64> {
    if !RDRAND_SUPPORTED.load(Ordering::SeqCst) {
        return None;
    }
    for _ in 0..RDSEED_MAX_RETRIES {
        let value: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {0}",
                "setc {1}",
                out(reg) value,
                out(reg_byte) ok,
                options(nostack, nomem, preserves_flags)
            );
        }
        if ok != 0 {
            return Some(value);
        }
    }
    None
}

const RDSEED_MAX_RETRIES: usize = 10;

/// Enable CR4.SMEP and CR4.SMAP on the current CPU.
///
/// Returns the mask of bits that are actually enabled. Bits the CPU does
/// not implement are left clear rather than written blindly: writing an
/// unsupported CR4 bit is undefined and can #GP during boot.
pub fn enable_user_boundary_protection() -> u64 {
    let ebx = cpuid7_ebx();
    SMEP_SUPPORTED.store((ebx & (1 << 7)) != 0, Ordering::SeqCst);
    SMAP_SUPPORTED.store((ebx & (1 << 8)) != 0, Ordering::SeqCst);
    RDSEED_SUPPORTED.store((ebx & CPUID7_EBX_RDSEED_BIT) != 0, Ordering::SeqCst);
    RDRAND_SUPPORTED.store((cpuid1_ecx() & CPUID1_ECX_RDRND_BIT) != 0, Ordering::SeqCst);

    let cr4 = read_cr4();
    let mut enabled = 0u64;
    if SMEP_SUPPORTED.load(Ordering::SeqCst) {
        enabled |= CR4_SMEP_BIT;
    }
    if SMAP_SUPPORTED.load(Ordering::SeqCst) {
        enabled |= CR4_SMAP_BIT;
    }
    if enabled != 0 {
        write_cr4(cr4 | enabled);
    }
    SMEP_ENABLED.store((enabled & CR4_SMEP_BIT) != 0, Ordering::SeqCst);
    SMAP_ENABLED.store((enabled & CR4_SMAP_BIT) != 0, Ordering::SeqCst);
    enabled
}

pub fn smep_enabled() -> bool {
    SMEP_ENABLED.load(Ordering::SeqCst)
}

pub fn smap_enabled() -> bool {
    SMAP_ENABLED.load(Ordering::SeqCst)
}

/// Open a SMAP window for the current CPU.
///
/// With CR4.SMAP set, kernel access to user pages is denied until STAC
/// runs. `mm::user_copy` probes the page tables first, then opens the
/// window for the duration of the copy and closes it with CLAC. Without
/// SMAP these are no-ops, so callers can use them unconditionally.
pub fn open_smap_window() {
    if !SMAP_ENABLED.load(Ordering::SeqCst) {
        return;
    }
    unsafe {
        core::arch::asm!("stac", options(nostack, nomem));
    }
}

/// close the SMAP window opened by `open_smap_window`.
pub fn close_smap_window() {
    if !SMAP_ENABLED.load(Ordering::SeqCst) {
        return;
    }
    unsafe {
        core::arch::asm!("clac", options(nostack, nomem));
    }
}

pub struct SmapGuard {
    active: bool,
}

impl SmapGuard {
    pub fn open() -> Self {
        let active = SMAP_ENABLED.load(Ordering::SeqCst);
        if active {
            unsafe {
                core::arch::asm!("stac", options(nostack, nomem));
            }
        }
        Self { active }
    }
}

impl Drop for SmapGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                core::arch::asm!("clac", options(nostack, nomem));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr4_bits_are_the_documented_positions() {
        assert_eq!(CR4_SMEP_BIT, 1 << 9);
        assert_eq!(CR4_SMAP_BIT, 1 << 10);
    }
}
