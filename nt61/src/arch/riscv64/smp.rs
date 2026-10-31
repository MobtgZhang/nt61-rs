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

use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::riscv64::paging;
use crate::arch::riscv64::percpu_impl;
use crate::arch::riscv64::soc;

static CPU_COUNT: AtomicU32 = AtomicU32::new(1);
static SECONDARY_ROOT_PFN: AtomicU64 = AtomicU64::new(0);

extern "C" {
    fn __smp_secondary_entry();
}

const AP_STACK_SIZE: usize = 64 * 1024;

/// Return the cached CPU count.
pub fn cpu_count() -> u32 {
    let a = CPU_COUNT.load(Ordering::Relaxed);
    let b = soc::cpu_count() as u32;
    a.max(b).max(1)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// SBI HSM hart_start (re-exported here for callers that already
/// imported from this module).
pub unsafe fn sbi_hsm_hart_start(hart_id: u64, start_addr: u64, opaque: u64) -> i64 {
    crate::arch::riscv64::sbi::hsm_hart_start(hart_id, start_addr, opaque).error
}

/// Read the running hart's ID through SBI (S-mode safe).
pub fn current_hart_id() -> u32 {
    unsafe { crate::arch::riscv64::sbi::current_hartid() as u32 }
}

// Trampoline entry point for secondary harts.  The firmware jumps here
// after a successful `HART_START`; the Rust entry installs per-hart
// state before entering the scheduler.
global_asm!(
    ".align 4",
    ".global __smp_secondary_entry",
    "__smp_secondary_entry:",
    // Secondary harts start with an undefined stack pointer. Install
    // the trampoline stack before any Rust prologue can touch memory.
    "  mv sp, a1",
    "  tail __smp_secondary_entry_rust",
);

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn __smp_secondary_entry_rust(_hart: u64, _stack_top: u64) -> ! {
    // Publish this hart's per-CPU base in `tp`.
    crate::boot_debug_println!("[AP] entry");
    let hart = current_hart_id();
    let base = crate::arch::riscv64::percpu_impl::per_cpu_base_for(hart);
    if base == 0 {
        loop {
            core::arch::asm!("wfi", options(nostack));
        }
    }
    crate::arch::riscv64::csr::write_tp(base);

    // Install the same address space the BSP is already using.
    let root_pfn = SECONDARY_ROOT_PFN.load(Ordering::Acquire);
    if root_pfn != 0 {
        unsafe { paging::load_page_root(root_pfn) };
    }

    crate::ke::scheduler::init_smp_this_cpu(hart);
    crate::ke::scheduler::idle_loop()
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
    SECONDARY_ROOT_PFN.store(satp_root, Ordering::Release);
    crate::boot_debug_println!("[SMP] boot_secondary entered");
    let boot = current_hart_id();
    let max = cpu_count();
    crate::ke::scheduler::init_smp(max);

    for hart in 1..max as usize {
        let base = percpu_impl::per_cpu_base_for(hart as u32);
        let stack =
            crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, AP_STACK_SIZE) as u64;
        if base == 0 || stack == 0 {
            CPU_COUNT.store(hart as u32, Ordering::SeqCst);
            return;
        }
        let stack_top = stack + AP_STACK_SIZE as u64 - 16;
        unsafe {
            (base as *mut u64).add(1).write_volatile(stack_top);
        }
    }

    for hart in 0..max {
        if hart == boot {
            continue;
        }
        let trampoline = __smp_secondary_entry as *const () as u64;
        let stack_top = unsafe {
            (percpu_impl::per_cpu_base_for(hart) as *const u64)
                .add(1)
                .read_volatile()
        };
        crate::hal::serial::write_string_always(&alloc::format!(
            "[SMP] hart={} trampoline={:#x} stack={:#x}\r\n",
            hart,
            trampoline,
            stack_top
        ));
        let r = sbi_hsm_hart_start(hart as u64, trampoline, stack_top);
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
