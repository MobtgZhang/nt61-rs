//! aarch64 (ARMv8/ARMv9) Architecture Support
//!
//! All assembly is inline so we don't need a separate `.S` file. The
//! helpers here cover:
//!   * exception-vector bring-up (VBAR_EL1)
//!   * MAIR_EL1 / TCR_EL1 default values used by `paging::init`
//!   * a basic `eret` shim (only used in QEMU's EL1 build)
//!   * SoC detection helpers (KunPeng 920 / FT-2000+ / Rockchip RK
//!     series, see `soc.rs`)
//!   * CPU feature detection (AA64* registers, see `cpuinfo.rs`)

pub mod apic;
pub mod context;
pub mod context_switch;
pub mod cpuinfo;
pub mod exception;
pub mod framebuffer;
pub mod gdt;
pub mod hpet;
pub mod idt;
pub mod keyboard;
pub mod paging;
pub mod paging_impl;
pub mod percpu_impl;
pub mod pic;
pub mod pit;
pub mod serial;
pub mod smp;
pub mod soc;
pub mod syscall;
pub mod trap;
pub mod user_entry;

use core::arch::asm;

/// Per-CPU scratch area (TLS pointer). Each CPU gets one entry of
/// `MAX_CPUS` and we use this for the PRCB and the idle stack in a
/// real build. For the bootstrap we just store zero.
pub const MAX_CPUS: usize = 64;

/// Cache line size for aarch64 (typically 64 bytes).
pub const CACHE_LINE: usize = 64;

/// Page size.
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

/// Initialise aarch64 architecture state.
pub fn init() {
    unsafe {
        // NOTE: On QEMU virt + EDK2 the bootloader (OvmfPkg/ArmVirt)
        // already enabled the MMU with a set of identity-mapped
        // translation tables that expose the kernel image, the
        // stack, and the rest of RAM at their physical addresses.
        // We *must not* zero the bootloader-provided TTBRs or flip
        // `SCTLR_EL1.M` mid-stream — doing so unmaps the very code
        // we're running from, which manifests as an immediate
        // synchronous exception. Instead we leave the bootloader's
        // MMU configuration intact and only touch the registers
        // that don't risk unmapping live code:
        //   - `MAIR_EL1`: memory attribute encoding (read-only for
        //     us; the bootloader's tables already use sane attrs).
        //   - `VBAR_EL1`: vector base. Reset to 0; `idt::init`
        //     will install the actual vector table shortly.
        //   - `SCTLR_EL1.{WXN,I,C}`: tighten permissions on
        //     subsequently created mappings without enabling the
        //     MMU (the bootloader already did that).
        //   - `CPUECTLR`-equivalent CPU feature detection goes
        //     through `cpuinfo::init()`.
        //
        // Skipping the `msr ttbr0_el1, xzr` / `msr ttbr1_el1, xzr`
        // and `sctlr |= 1 << 0` writes that previous versions of
        // this function used to emit is what gets us out of the
        // "kernel faults before the first serial line is even
        // flushed" hole.

        // Set a known-good MAIR_EL1: device nGnRnE at Attr0,
        // normal non-cacheable at Attr1, writeback read/write at
        // Attr2, **writeback read/write at Attr3** as well.
        //
        // Attr3 must be "normal writeback": the EDK2 bootloader
        // leaves the firmware page tables in place at the kernel
        // half of the address space, and the firmware RAM
        // descriptors use MAIR index 3 for the heap region
        // (the region we hand to `mm::heap::init`). If we leave
        // Attr3 as 0x00 (strongly-ordered), writes to the heap
        // raise a synchronous data-abort (`Translation fault,
        // level 1` per QEMU's fault encoder, even though the
        // actual cause is the changed memory type). Setting Attr3
        // to 0xFF (writeback, matching the firmware's intent)
        // keeps the firmware's block descriptors consistent with
        // the active MAIR_EL1.
        crate::hal::serial::write_string("aarch64_init:mair\r\n");
        let mair: u64 = 0xFF440F_FF;
        asm!("msr mair_el1, {}", in(reg) mair);
        crate::hal::serial::write_string("aarch64_init:vbar\r\n");

        // VBAR_EL1 is installed by `idt::init()` (which forwards
        // to `exception::init()`); set it to zero here as a
        // default. Leaving the bootloader's vector base in place
        // would crash on the very first unexpected exception,
        // which is exactly what we are trying to diagnose.
        asm!("msr vbar_el1, {}", in(reg) 0u64);
        crate::hal::serial::write_string("aarch64_init:sctlr\r\n");

        // WXN/I/C are advisory bits. WXN enforces "execute never"
        // on writable pages; I and C enable the instruction and
        // data caches. They are no-ops if the bootloader set them
        // already and harmless if they weren't.
        let mut sctlr: u64;
        asm!("mrs {}, sctlr_el1", out(reg) sctlr);
        sctlr |= 1 << 19; // WXN
        sctlr |= 1 << 12; // I-cache
        sctlr |= 1 << 2;  // C-cache
        asm!("msr sctlr_el1, {}", in(reg) sctlr);
        crate::hal::serial::write_string("aarch64_init:isb\r\n");

        // Ensure all prior writes are observed before any
        // subsequent instruction fetch from the new state.
        asm!("isb", options(nostack));
        crate::hal::serial::write_string("aarch64_init:cpuinfo\r\n");

        // Initialise CPU feature detection so other subsystems
        // (HAL, scheduler, soc.rs) can query features early.
        super::aarch64::cpuinfo::init();
        crate::hal::serial::write_string("aarch64_init:done\r\n");
    }
}

/// Bring up secondary CPUs via PSCI (Power State Coordination
/// Interface) on QEMU virt. We use CPU_ON with the entry point
/// `arm64_secondary_entry`; in the bootstrap we just do nothing
/// because the bring-up is normally done by the firmware/bootloader
/// and the kernel only has to set up the per-CPU stacks.
pub fn init_secondary_cpu(_cpu_id: u32) {}

/// Number of CPUs we have detected.
pub fn get_cpu_count() -> u32 {
    let id: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) id, options(nostack));
    }
    // On QEMU virt the upper bits of MPIDR_EL1 are zero so the
    // `aff0` field is the only thing that matters; the actual count
    // is normally reported by firmware (ACPI / FDT / PSCI). For the
    // bootstrap we return the value cached by `cpuinfo::init()`.
    cpuinfo::logical_cpu_count().max(1)
}

// Re-export commonly used types (matches x86_64 re-exports in arch/x86_64/mod.rs)
// Note: PAGE_SIZE/PAGE_SHIFT are already defined at module level above.
pub use context::CpuContext;
pub use paging::{PageTableEntry, VirtAddr, PhysAddr};
pub use soc::{SocInfo, SocType};
