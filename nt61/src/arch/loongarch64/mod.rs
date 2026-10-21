//! LoongArch64 Architecture Support
//
//! LoongArch64 uses a CRMD (Current Mode) register for the interrupt
//! state, TLB-related instructions, and a 16-entry exception vector at
//! EBASE. For the bootstrap we just make sure the CPU is in a clean
//! kernel state and leave the exception vectors at the firmware default.

pub mod btl;
pub mod context;
pub mod context_switch;
pub mod cpuinfo;
pub mod cpuinfo_core;
pub mod exception_stack;
pub mod fpu;
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

/// Maximum CPUs supported.
pub const MAX_CPUS: usize = 64;

/// Cache line size.
pub const CACHE_LINE: usize = 64;

/// Page size.
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

/// Page-walk geometry: five levels of nine bits each over a 4 KiB
/// page. The walk covers VA[56:0] with the root table indexed by
/// VA[56:48] and the leaf PTE indexed by VA[20:12], matching the
/// tables built by `paging::leaf_pte_for`.
const PW_PT_BASE: u64 = 12; // leaf index VA[20:12]
const PW_PT_WIDTH: u64 = 9;
const PW_DIR1_BASE: u64 = 21; // L3 index VA[29:21] -> leaf table
const PW_DIR2_BASE: u64 = 30; // L2 index VA[38:30] -> L3
const PW_DIR3_BASE: u64 = 39; // L1 index VA[47:39] -> L2
const PW_DIR4_BASE: u64 = 48; // root index VA[56:48] -> L1
const PW_DIR_WIDTH: u64 = 9;

/// Configure the page-walk CSRs (PWCL/PWCH/STLBPS) for the kernel's
/// five-level page table.
///
/// The refill sequence (`lddir 4`, `lddir 3`, `lddir 2`, `lddir 1`,
/// `ldpte`) reads DIR4..DIR1 for the table hops and PTBASE/PTWIDTH for
/// the leaf index; DIR numbering follows the Linux convention where
/// DIR1 is the level closest to the PTE. STLBPS selects 4 KiB software
/// TLB pages.
///
/// This must run before `CRMD.PG` is enabled: the first instruction
/// fetch with PG=1 immediately takes a TLB refill, and the refill
/// handler walks these CSRs.
pub fn init_page_walk() {
    unsafe {
        let pwcl: u64 = PW_PT_BASE
            | (PW_PT_WIDTH << 5)
            | (PW_DIR1_BASE << 10)
            | (PW_DIR_WIDTH << 15)
            | (PW_DIR2_BASE << 20)
            | (PW_DIR_WIDTH << 25);
        let pwch: u64 =
            PW_DIR3_BASE | (PW_DIR_WIDTH << 6) | (PW_DIR4_BASE << 12) | (PW_DIR_WIDTH << 18);
        asm!("csrwr {}, 0x1C", in(reg) pwcl, options(nostack));
        asm!("csrwr {}, 0x1D", in(reg) pwch, options(nostack));

        // STLBPS = 0 selects 4 KiB software TLB pages (16 KiB is the
        // reset default and would mismatch the 4 KiB page tables).
        asm!("csrwr {}, 0x1E", in(reg) 0u64, options(nostack));

        // Publish DMW0 before the first mapped-mode instruction
        // executes. The UART and later platform MMIO use this window;
        // early boot keeps physical addresses because DMW only applies
        // when CRMD.PG is enabled.
        let dmw0 = paging::CSR_DMW0_INIT;
        asm!("csrwr {}, 0x180", in(reg) dmw0, options(nostack));
    }
}

/// Initialise LoongArch64 architecture state.
pub fn init() {
    // Paging is intentionally left in the state the firmware
    // (or our early `arch_early_ensure_serial_ready` helper)
    // left it in. The kernel starts with `PG = 0` so that
    // every supervisor load/store addresses the underlying
    // physical memory 1:1 — this avoids relying on the
    // firmware's `PGDH` page table (which on QEMU/EDK2 only
    // covers the kernel-image range above 0x80000000 and does
    // NOT include the LS7A UART at 0x1FE0_01E0, triggering
    // an "Address error exception" on the first serial
    // write). Once the kernel builds its own page table
    // (`mm::paging::init` → `arch::paging::load_page_root`)
    // the new root is loaded and `PG` is flipped back on
    // together, so the user-mode portion of the address
    // space can be entered normally.
    init_page_walk();
}

/// Bring up secondary CPUs (LoongArch uses the mail-box or
/// firmware-mediated bring-up; the kernel itself does not start
/// secondary cores on the bootstrap).
pub fn init_secondary_cpu(_cpu_id: u32) {}

/// Get the current number of CPUs.
pub fn get_cpu_count() -> u32 {
    1
}

// Re-export commonly used types (matches x86_64 re-exports in arch/x86_64/mod.rs)
pub use context::CpuContext;
pub use paging::{PageTableEntry, PhysAddr, VirtAddr};

pub mod apic;
pub mod cache;
pub mod interrupt;
pub mod ssdt;
pub mod tlb;
