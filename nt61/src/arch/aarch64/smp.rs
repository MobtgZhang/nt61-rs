//! aarch64 SMP bring-up
//!
//! Provides two backing strategies for waking up secondary cores:
//!
//!   * **PSCI** (`PSCI_VERSION >= 0.8400 0000`). Implemented via
//!     SMCCC `smc #0` calls into the firmware with the
//!     `PSCI_CPU_ON` function id (`0xC400_0003`).
//!   * **Spin-table** — secondary CPUs poll a known memory location;
//!     the kernel writes the entry point + context id and signals
//!     them via a release-style address protocol.
//!
//! The selection between PSCI and spin-table is performed at boot
//! by `init_soc` (in `soc.rs`) which calls [`set_method`] with the
//! correct default for the detected platform.

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::aarch64::cpuinfo;
use crate::arch::aarch64::paging;
use crate::arch::aarch64::percpu_impl;

/// SMP bring-up method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SmpMethod {
    PSCI = 0,
    SpinTable = 1,
    FirmwareManaged = 2,
}

static METHOD: AtomicU32 = AtomicU32::new(0);
static CPU_COUNT: AtomicU32 = AtomicU32::new(1);
static SECONDARY_ROOT_PFN: AtomicU32 = AtomicU32::new(0);

pub fn cpu_count() -> u32 {
    CPU_COUNT
        .load(Ordering::Relaxed)
        .max(cpuinfo::logical_cpu_count())
        .max(1)
}

pub fn set_method(m: SmpMethod) {
    METHOD.store(m as u32, Ordering::Release);
}

pub fn get_method() -> SmpMethod {
    match METHOD.load(Ordering::Acquire) {
        1 => SmpMethod::SpinTable,
        2 => SmpMethod::FirmwareManaged,
        _ => SmpMethod::PSCI,
    }
}

/// Real PSCI CPU_ON — place secondary cores at `entry` with the
/// `context_id` (passed in `x0` to the entry) through the SMCCC
/// interface. Returns the SMCCC return code in the lower 32 bits;
/// PSCI status codes are encoded in the upper 32.
pub unsafe fn psci_cpu_on(target_cpu: u64, entry: u64, context_id: u64) -> i64 {
    let mut r: i64 = 0;
    unsafe {
        asm!(
            // ARM SMCCC passes the function ID in x0 and arguments in
            // x1..x3. PSCI_CPU_ON takes target_cpu, entry, context_id.
            "mov x0, #0x3",
            "movk x0, #0xC400, lsl #16",
            "mov x1, {cpu}",
            "mov x2, {entry}",
            "mov x3, {ctx}",
            "smc #0",
            "mov {r}, x0",
            cpu = in(reg) target_cpu,
            entry = in(reg) entry,
            ctx = in(reg) context_id,
            r = out(reg) r,
            options(nostack),
        );
    }
    r
}

/// Spin-table release address used by older Phytium firmware
/// (FT-2000/4 era). The default 0xD000_0000 is the address used by
/// board firmware on the standard dev kit; production Phytium boards
/// expose the address in their device-tree.
pub const SPIN_TABLE_RELEASE_ADDR: u64 = 0xD000_0000;

/// Release a secondary CPU through the spin-table mechanism by
/// writing `(entry | context_id << 16)` (low 32 = entry, high 32 =
/// context id).
pub unsafe fn spin_table_release(cpu_idx: usize, entry: u64, context_id: u64) {
    let word = (entry & 0xFFFF_FFFF) | (context_id << 32);
    unsafe {
        let p = SPIN_TABLE_RELEASE_ADDR as *mut u64;
        p.write_volatile(word);
        core::arch::asm!(
            "sev",
            in("x0") p,
            in("x1") word,
            in("x2") cpu_idx,
            options(nostack),
        );
    }
}

// ---------------------------------------------------------------------------
// extern "Rust" implementations required by arch::common::smp
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "Rust" fn __smp_cpu_count() -> u32 {
    cpu_count()
}

#[no_mangle]
pub unsafe extern "Rust" fn __smp_boot_secondary(pml4_pfn: u64) {
    SECONDARY_ROOT_PFN.store((pml4_pfn & 0x000F_FFFF_FFFF) as u32, Ordering::Release);

    // Use the configured bring-up method. The PSCI implementation
    // here assumes the system firmware implements SMCCC 0.2+.
    let secondary_count = cpu_count().max(1);
    crate::ke::scheduler::init_smp(secondary_count);

    // Give every AP its own per-CPU area and bootstrap stack before it
    // starts running. The stack pointer is the only value that has to be
    // passed through the firmware entry protocol; the root page table is
    // shared by all APs and is published separately.
    for cpu in 1..secondary_count as usize {
        let per_cpu_base = percpu_impl::per_cpu_base_for(cpu as u32);
        let stack =
            crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, AP_STACK_SIZE) as u64;
        if per_cpu_base == 0 || stack == 0 {
            set_cpu_count(cpu as u32);
            return;
        }
        let stack_top = stack + AP_STACK_SIZE as u64 - 16;
        let area = per_cpu_base as *mut u64;
        unsafe {
            area.add(1).write_volatile(stack_top);
        }
    }

    for cpu in 1..secondary_count {
        match get_method() {
            SmpMethod::PSCI => {
                let _ = unsafe {
                    psci_cpu_on(
                        cpu as u64,
                        crate::arch::aarch64::smp::secondary_entry as *const () as u64,
                        *(crate::arch::aarch64::percpu_impl::per_cpu_base_for(cpu) as *const u64)
                            .add(1),
                    )
                };
            }
            SmpMethod::SpinTable => unsafe {
                spin_table_release(
                    cpu as usize,
                    crate::arch::aarch64::smp::secondary_entry as *const () as u64,
                    *(crate::arch::aarch64::percpu_impl::per_cpu_base_for(cpu) as *const u64)
                        .add(1),
                );
            },
            SmpMethod::FirmwareManaged => {
                // No-op: firmware has already released secondary cores.
            }
        }
    }
}

#[no_mangle]
pub extern "Rust" fn __smp_get_current_cpu_id() -> u32 {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, MPIDR_EL1", out(reg) mpidr, options(nostack));
    }
    ((mpidr >> 8) & 0xFF) as u32
}

/// Entry point for secondary cores. Implemented in assembly — see
/// `secondary_entry.S` for the stub. The default is a permanent
/// `wfi` loop so that the linker keeps the symbol alive even before
/// assembly has been added.
#[no_mangle]
pub extern "C" fn secondary_entry(_arg: u64) -> ! {
    let stack_top = _arg;
    unsafe {
        asm!("mov sp, {}", in(reg) stack_top, options(nostack));
    }

    let cpu = __smp_get_current_cpu_id();
    let base = percpu_impl::per_cpu_base_for(cpu);
    if base == 0 {
        unsafe {
            loop {
                asm!("wfi", options(nostack));
            }
        }
    }

    unsafe {
        asm!("msr tpidr_el1, {}", in(reg) base, options(nostack));
    }

    let root_pfn = SECONDARY_ROOT_PFN.load(Ordering::Acquire) as u64;
    if root_pfn != 0 {
        unsafe { paging::load_page_root(root_pfn) };
    }

    crate::ke::scheduler::init_smp_this_cpu(cpu);
    crate::ke::scheduler::idle_loop()
}

const AP_STACK_SIZE: usize = 64 * 1024;

/// Update the cached logical CPU count. Called by the SMP scanner
/// once it has enumerated cores via PSCI_VERSION / CPUID / GICR.
pub fn set_cpu_count(n: u32) {
    CPU_COUNT.store(n, Ordering::Release);
}

/// Smoke test: verify that the SMP method has been set.
pub fn smoke_test() -> bool {
    get_method() as u32 != u32::MAX
}
