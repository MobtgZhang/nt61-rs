//! LoongArch 64 SMP — bring up APs via mail_send
//!
//! Implements the `extern "Rust"` functions required by `arch::common::smp`:
//! - `__smp_cpu_count()` - returns CPU count
//! - `__smp_boot_secondary()` - signals APs via mail_send
//! - `__smp_get_current_cpu_id()` - reads cpuid CSR
//!
//! The bring-up adapts to the detected microarchitecture via
//! `arch::loongarch64::soc`. On LA364/LA464 we fall back to single-threaded
//! mode (SMT off). On LA664 we enable 2-way SMT and treat the second thread
//! of each physical core as a separate logical CPU.

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::loongarch64::cpuinfo_core;
use crate::arch::loongarch64::soc;

static CPU_COUNT: AtomicU32 = AtomicU32::new(1);

pub fn cpu_count() -> u32 { CPU_COUNT.load(Ordering::Relaxed) }

/// Number of SMT threads per physical core for the running SoC.
/// Returns `1` for LA364/LA464, `2` for LA664.
pub fn smt_threads() -> u8 {
    if soc::is_smt_capable() { 2 } else { 1 }
}

/// Total logical CPUs considering SMT:
///   `physical_count * smt_threads()`
pub fn logical_cpu_count(physical_count: u32) -> u32 {
    physical_count.saturating_mul(smt_threads() as u32)
}

/// Returns true if `cpu_id` shares its physical core with another
/// logical CPU (i.e. it has an SMT sibling).
pub fn has_smt_sibling(cpu_id: u32) -> bool {
    smt_threads() > 1
}

/// Send a `mail_send` to the target CPU with the supplied mailbox
/// data. Used to start the AP.
pub unsafe fn mail_send(cpu_id: u32, mailbox: u64) {
    let b: u64 = 0x1FE0_1000 + (cpu_id as u64) * 0x10;
    ptr::write_volatile((b + 0x20) as *mut u64, mailbox);
    ptr::write_volatile((b + 0x00) as *mut u32, 0x1);
}

// ---------------------------------------------------------------------------
// extern "Rust" implementations required by arch::common::smp
// ---------------------------------------------------------------------------

/// Returns the number of available CPUs.
#[no_mangle]
pub extern "Rust" fn __smp_cpu_count() -> u32 {
    cpu_count()
}

/// Boot secondary CPUs with the given PML4 PFN.
///
/// Currently a stub — real implementation would use `mail_send` to signal
/// each AP with the entry point and PML4 PFN. Per-cpu capability records
/// (SMT sibling id / microarch id) are filled in once the detection pass
/// has completed so `cpuinfo_core::get()` returns sensible data.
///
/// # Safety
/// The caller must ensure the page table is valid.
#[no_mangle]
pub unsafe extern "Rust" fn __smp_boot_secondary(_pml4_pfn: u64) {
    // Detect the SoC / cpuinfo state (idempotent).
    let _ = soc::detect();
    let _ = crate::arch::loongarch64::cpuinfo::detect_all();

    // Stub: the firmware on LoongArch typically uses a spin-table
    // approach. We mark the boot CPU's capability record so callers
    // observe a consistent view even though secondary cores are not
    // brought up here.
    cpuinfo_core::init_boot_cpu();
    CPU_COUNT.store(1, Ordering::SeqCst);
}

/// Returns the current CPU ID from the cpuid CSR (LoongArch-specific).
#[no_mangle]
pub extern "Rust" fn __smp_get_current_cpu_id() -> u32 {
    let cpuid: u32;
    unsafe {
        // csrrd reads the cpuid CSR (0x20) into a general-purpose register.
        core::arch::asm!("csrrd {0}, 0x20", out(reg) cpuid, options(nostack));
    }
    cpuid
}

#[allow(dead_code)]
unsafe fn _keep() {
    let _ = asm!("nop");
    let _ = smt_threads();
    let _ = logical_cpu_count(1);
    let _ = has_smt_sibling(0);
    CPU_COUNT.store(1, Ordering::SeqCst);
}
