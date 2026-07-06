//! RISC-V 64 Architecture Support
//!
//! Covers RV64IMAC and friends. We use the `sstatus` / `sie` / `stvec`
//! CSRs for interrupt control. The `scause` / `sepc` / `stval` CSRs
//! are handled by [`trap`].
//!
//! The init sequence is:
//!
//! ```text
//! soc::detect_soc()   ─► mvendorid/marchid/mimpid → SocInfo
//! cpuinfo::init_cpuinfo() ─► misa → IsaExtensions
//! idt::init()         ─► install stvec handler
//! trap::init()        ─► install Rust-side dispatch glue
//! context_switch::init() ─► (no-op for Phase 0)
//! ```

pub mod apic;
#[cfg(feature = "btl")]
pub mod btl;
pub mod clint;
pub mod context;
pub mod context_switch;
pub mod cpuinfo;
pub mod csr;
pub mod framebuffer;
pub mod fpu;
pub mod gdt;
pub mod hpet;
pub mod idt;
pub mod keyboard;
pub mod paging;
pub mod paging_impl;
pub mod percpu_impl;
pub mod pic;
pub mod pit;
pub mod plic;
pub mod sbi;
pub mod serial;
pub mod smp;
pub mod soc;
pub mod sv48;
pub mod syscall;
pub mod trap;
pub mod user_entry;

use core::arch::asm;

/// Maximum CPUs supported (SMP bring-up is out of scope for the
/// bootstrap; the boot CPU is CPU 0).
pub const MAX_CPUS: usize = 64;

/// Cache line size.
pub const CACHE_LINE: usize = 64;

/// Page size.
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

/// Initialise RISC-V 64 architecture state.
///
/// The order is significant: SoC identification first (so other
/// subsystems can query [`soc::current_soc`]), then CPU feature
/// detection (so [`cpuinfo::features_mask`] is valid), then the
/// exception vector (so any subsequent code path is protected),
/// then trap glue, then the rest of the platform.
pub fn init() {
    // Phase 0.1: detect SoC. Idempotent; cheap.
    soc::init_soc();
    // Phase 0.2: parse `misa` and cache ISA features.
    cpuinfo::init_cpuinfo();
    // Phase 0.3: install the trap vector before anything else
    // touches `sret` / `ecall`.
    idt::init();
    // Phase 0.4: Rust-side trap dispatcher (currently a stub —
    // see [`trap::init`]).
    trap::init();

    // Phase 5: bring the BTL online (only when the feature flag is
    // set). The BTL is enabled on first guest thread start, not at
    // boot time — calling `init()` here is cheap and idempotent.
    #[cfg(feature = "btl")]
    btl::init();

    unsafe {
        // Set up a default satp. For the bootstrap we leave it at
        // MODE=Bare (no translation) until paging::init installs a
        // real mode. We do this explicitly because the firmware
        // may have left satp in any state.
        asm!("csrw satp, {}", in(reg) 0u64);

        // Enable the supervisor timer and external interrupts at
        // the `sie` level. The `sstatus.SIE` global enable is left
        // off (handled by `enable_interrupts`).
        asm!("csrs sie, {}", in(reg) (1u64 << 5) | (1u64 << 9));

        // Memory fence - ordering between PMP setup and any
        // subsequent memory access.
        asm!("fence rw, rw", options(nostack));
    }
}

/// Bring up secondary CPUs. RISC-V uses SBI HSM (Hart State
/// Management) extension to start secondary harts; in the bootstrap
/// we do nothing because the firmware has already started the boot
/// hart and we treat this as a single-CPU system until the SMP
/// trampoline is wired up.
pub fn init_secondary_cpu(_cpu_id: u32) {}

/// Get the current number of CPUs.
pub fn get_cpu_count() -> u32 {
    soc::cpu_count() as u32
}

// Re-export commonly used types (matches x86_64 / aarch64 / loongarch64
// re-exports in their respective `arch/*/mod.rs`).
pub use context::CpuContext;
pub use context_switch::{ContextFrame, swap_context};
pub use cpuinfo::{IsaExtensions, PerHartCpuInfo};
pub use paging::{PageTableEntry, PhysAddr, VirtAddr};
pub use soc::{SocInfo, SocType};
pub use trap::{TrapFrame, TrapKind};