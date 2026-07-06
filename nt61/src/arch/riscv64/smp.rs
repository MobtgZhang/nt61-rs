//! RISC-V 64 SMP — SBI HSM HART_START.
//!
//! Implements the `extern "Rust"` functions required by
//! `arch::common::smp`:
//!
//! - `__smp_cpu_count()` — returns the CPU count (always 1 for
//!   the bootstrap; Phase 1 leaves SMP bring-up to the firmware).
//! - `__smp_boot_secondary()` — starts secondary harts via SBI
//!   HSM (Hart State Management).
//! - `__smp_get_current_cpu_id()` — reads `mhartid` CSR.
//!
//! Phase 1 calls `sbi::hsm_hart_start` for harts 1..N. Phase 2
//! will install a real trampoline and a per-hart `__smp_secondary`
//! entry point.

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

static CPU_COUNT: AtomicU32 = AtomicU32::new(1);

/// Return the cached CPU count.
pub fn cpu_count() -> u32 { CPU_COUNT.load(Ordering::Relaxed) }

/// SBI HSM hart_start (re-exported here for callers that already
/// imported from this module).
pub unsafe fn sbi_hsm_hart_start(hart_id: u64, start_addr: u64, opaque: u64) -> i64 {
    crate::arch::riscv64::sbi::hsm_hart_start(hart_id, start_addr, opaque).error
}

/// Read the running hart's id from the `mhartid` CSR.
pub fn current_hart_id() -> u32 {
    let id: u32;
    unsafe { asm!("csrr {}, mhartid", out(reg) id, options(nostack)); }
    id
}

/// Trampoline entry point for secondary harts.
///
/// The firmware (`OpenSBI` / Andes / etc.) jumps here after a
/// successful `HART_START`. Phase 1 spins; Phase 2 will switch to
/// the per-hart kernel stack and wait for a work item.
#[no_mangle]
pub unsafe extern "C" fn __smp_secondary_entry() -> ! {
    // Read our hart id and publish it via `tp` so the kernel can
    // find this hart's per-CPU area.
    let hart = current_hart_id();
    let base = crate::arch::riscv64::percpu_impl::per_cpu_base_for(hart);
    crate::arch::riscv64::csr::write_tp(base);
    // Spin until the BSP sends us an IPI with work. Phase 1 does
    // not implement the IPI mailbox protocol; secondary harts
    // simply park here.
    loop {
        core::arch::asm!("wfi", options(nostack));
    }
}

// ---------------------------------------------------------------------------
// extern "Rust" implementations required by arch::common::smp
// ---------------------------------------------------------------------------

/// Returns the number of available CPUs.
#[no_mangle]
pub extern "Rust" fn __smp_cpu_count() -> u32 {
    cpu_count()
}

/// Boot secondary CPUs with the given PML4 PFN (here interpreted
/// as the SATP root to install on each secondary hart).
///
/// Phase 1 implementation: probe `mhartid` to find the boot hart,
/// then issue `HART_START` for each secondary hart. The opaque
/// value is forwarded to [`__smp_secondary_entry`].
///
/// # Safety
///
/// `satp_root` must be a valid SATP value (Sv39/Sv48 mode bits
/// included) and the trampoline entry point must be executable.
#[no_mangle]
pub unsafe extern "Rust" fn __smp_boot_secondary(satp_root: u64) {
    let boot = current_hart_id();
    // Phase 1: assume a fixed 4-hart system unless we know
    // otherwise. The Phase 2 device-tree path will determine the
    // real hart count.
    let max = 4u32;
    for hart in 0..max {
        if hart == boot { continue; }
        // Trampoline address — the secondary entry. We use the
        // symbol exported above; SBI requires a physical address.
        let trampoline = __smp_secondary_entry as *const () as u64;
        let r = sbi_hsm_hart_start(hart as u64, trampoline, satp_root);
        if r == 0 {
            CPU_COUNT.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Returns the current hart ID from `mhartid` CSR.
#[no_mangle]
pub extern "Rust" fn __smp_get_current_cpu_id() -> u32 {
    current_hart_id()
}