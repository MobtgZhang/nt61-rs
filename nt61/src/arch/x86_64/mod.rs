//! x86_64 Architecture Support
//
//! x86_64-specific implementations for the NT6.1 kernel
//
//! # Architecture vs HAL
//
//! The `arch/` module provides early boot infrastructure:
//! - GDT, IDT, TSS, paging, context switch (Phase 0)
//! - Syscall entry points and per-CPU areas
//
//! Device drivers live in `hal::x86_64::` and `drivers/`. Do NOT
//! add device driver modules here — use `crate::hal::x86_64::*`
//! for hardware access after boot.

pub mod context;
pub mod context_switch;
pub mod cpu_flags;
pub mod debug;
pub mod dispatch;
pub mod fpu;
pub mod gdt;
pub mod idt;
pub mod idt_stubs;
pub mod ntoskrnl_handoff;
pub mod paging;
pub mod paging_impl;
pub mod percpu_impl;
pub mod smp;
pub mod syscall;
pub mod syscall_handlers_validated;
pub mod syscall_numbers;
pub mod syscall_validation;
pub mod tss;
pub mod user_entry;

// Re-export commonly used types
pub use context::{CpuContext, ThreadContext};
pub use paging::{PageTableEntry, PhysAddr, VirtAddr, PAGE_SHIFT, PAGE_SIZE};

pub mod boot_anim;
pub mod dynamic_paging;
pub mod idt_header;
pub mod ipi;
pub mod msr;
pub mod percpu;
pub mod syscall_nums;
