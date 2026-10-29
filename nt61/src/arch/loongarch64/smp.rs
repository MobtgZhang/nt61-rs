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
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::loongarch64::cpuinfo_core;
use crate::arch::loongarch64::paging;
use crate::arch::loongarch64::soc;

static CPU_COUNT: AtomicU32 = AtomicU32::new(1);
static SECONDARY_ROOT_PFN: AtomicU32 = AtomicU32::new(0);

const MAX_AP_STACKS: usize = 64;
const AP_STACK_SIZE: usize = 64 * 1024;

#[no_mangle]
pub static AP_STACK_TOPS: [AtomicU64; MAX_AP_STACKS] = [const { AtomicU64::new(0) }; MAX_AP_STACKS];

core::arch::global_asm!(
    ".global __smp_secondary_entry",
    "__smp_secondary_entry:",
    "    csrrd $t0, 0x20",
    "    la.local $t1, AP_STACK_TOPS",
    "    slli.d $t2, $t0, 3",
    "    add.d $t1, $t1, $t2",
    "    ld.d $sp, $t1, 0",
    "    b secondary_entry",
);

pub fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Relaxed)
}

/// Update the cached logical CPU count after platform enumeration.
pub fn set_cpu_count(n: u32) {
    CPU_COUNT.store(n.max(1), Ordering::Release);
}

/// Number of SMT threads per physical core for the running SoC.
/// Returns `1` for LA364/LA464, `2` for LA664.
pub fn smt_threads() -> u8 {
    if soc::is_smt_capable() {
        2
    } else {
        1
    }
}

/// Total logical CPUs considering SMT:
///   `physical_count * smt_threads()`
pub fn logical_cpu_count(physical_count: u32) -> u32 {
    physical_count.saturating_mul(smt_threads() as u32)
}

/// Returns true if `cpu_id` shares its physical core with another
/// logical CPU (i.e. it has an SMT sibling).
pub fn has_smt_sibling(_cpu_id: u32) -> bool {
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
    SECONDARY_ROOT_PFN.store((_pml4_pfn & 0x000F_FFFF_FFFF) as u32, Ordering::Release);
    // Detect the SoC / cpuinfo state (idempotent).
    let _ = soc::detect();
    let _ = crate::arch::loongarch64::cpuinfo::detect_all();

    cpuinfo_core::init_boot_cpu();

    let count = cpu_count();
    crate::ke::scheduler::init_smp(count);

    // Pre-allocate the per-CPU state and a private bootstrap stack for
    // each AP. The assembly entry reads the stack top by CPU id.
    for cpu in 1..count as usize {
        if cpu >= MAX_AP_STACKS {
            set_cpu_count(cpu as u32);
            return;
        }
        let base = unsafe { crate::arch::loongarch64::percpu_impl::allocate(cpu as u32) };
        let stack =
            crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, AP_STACK_SIZE) as u64;
        if base == 0 || stack == 0 {
            set_cpu_count(cpu as u32);
            return;
        }
        let stack_top = stack + AP_STACK_SIZE as u64 - 16;
        unsafe {
            (base as *mut u64).add(1).write_volatile(stack_top);
            AP_STACK_TOPS[cpu].store(stack_top, Ordering::Release);
        }
    }

    let entry = secondary_entry as *const () as u64;
    for cpu in 1..count {
        unsafe { mail_send(cpu, entry) };
        CPU_COUNT.fetch_add(1, Ordering::SeqCst);
    }
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

/// Rust entry reached by the assembly trampoline after the per-CPU stack
/// has been selected.
#[no_mangle]
pub unsafe extern "C" fn secondary_entry() -> ! {
    let cpu = __smp_get_current_cpu_id();
    let base = crate::arch::loongarch64::percpu_impl::per_cpu_base_for(cpu);
    if base == 0 {
        loop {
            asm!("idle 0", options(nostack));
        }
    }

    crate::arch::loongarch64::percpu_impl::set_tp(base);

    let root_pfn = SECONDARY_ROOT_PFN.load(Ordering::Acquire) as u64;
    if root_pfn != 0 {
        unsafe { paging::load_page_root(root_pfn) };
    }

    crate::ke::scheduler::init_smp_this_cpu(cpu);
    crate::ke::scheduler::idle_loop()
}

unsafe fn _keep() {
    let _ = asm!("nop");
    let _ = smt_threads();
    let _ = logical_cpu_count(1);
    let _ = has_smt_sibling(0);
    CPU_COUNT.store(1, Ordering::SeqCst);
}
