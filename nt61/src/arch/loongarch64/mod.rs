//! LoongArch64 Architecture Support
//
//! LoongArch64 uses a CRMD (Current Mode) register for the interrupt
//! state, TLB-related instructions, and a 16-entry exception vector at
//! EBASE. For the bootstrap we just make sure the CPU is in a clean
//! kernel state and leave the exception vectors at the firmware default.

pub mod context;
pub mod context_switch;
pub mod btl;
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

/// Initialise LoongArch64 architecture state.
pub fn init() {
    unsafe {
        // Paging is intentionally left in the state the firmware
        // (or our early `arch_early_ensure_serial_ready` helper)
        // left it in. The kernel starts with `PG = 0` so that
        // every supervisor load/store addresses the underlying
        // physical memory 1:1 — this avoids relying on the
        // firmware's `PGDH` page table (which on QEMU/EDK2 only
        // covers the kernel-image range above 0x80000000 and does
        // NOT include the LS7A UART at 0x1FE0_0000, triggering
        // an "Address error exception" on the first serial
        // write). Once the kernel builds its own page table
        // (`mm::paging::init` → `arch::paging::load_page_root`)
        // the new root is loaded and `PG` is flipped back on
        // together, so the user-mode portion of the address
        // space can be entered normally.

        // Configure the page-walk format. We use the LoongArch64
        // default (4-level page table) by setting PWCL/PWCH from
        // the canonical values in the architecture manual. These
        // match what Linux uses for a 48-bit VA configuration.
        let pwcl: u64 = (0x0C << 30) | (0x0C << 24) | (0x0C << 18) | (0x0C << 12) | (0x04 << 6) | 0x04;
        let pwch: u64 = (0x0C << 6) | 0x0C;
        asm!("csrwr {}, 0x1C", in(reg) pwcl);
        asm!("csrwr {}, 0x1D", in(reg) pwch);

        // Configure STLB page size and the page-fault exception
        // entry. PAGE_SIZE for the page-walker is 16 KiB by default
        // on LoongArch; we override it to 4 KiB (the same as the
        // rest of the kernel) by writing the page-size override to
        // the STLBPS register.
        asm!("csrwr {}, 0x1E", in(reg) 0u64);
    }
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
pub use paging::{PageTableEntry, VirtAddr, PhysAddr};
