//! aarch64-style "PIC" compatibility shim — on RISC-V the PLIC
//! plays this role.
//!
//! This module re-exports the PLIC's enable / acknowledge
//! primitives under a more familiar interface (matching the
//! aarch64 port).

pub use crate::arch::riscv64::apic::{
    handle_irq as pic_handle_irq,
    dispatch_irq as pic_dispatch_irq,
    send_ipi,
};

/// Enable an SPI on the controller. On RISC-V this maps to a PLIC
/// `enable(irq, priority)` call.
pub fn pic_enable_irq(irq: u32) {
    crate::arch::riscv64::plic::enable(irq, 1);
}

pub fn pic_eoi_irq(_irq: u32) {
    // EOI is handled per-IRQ in dispatch_irq().
}

/// Initialise the PLIC via the `apic` shim. Phase 1 entry point
/// used by `ke::interrupt::init` and similar.
///
/// `base` is the PLIC base address; if 0 we fall back to the
/// QEMU virt default (`0xC00_0000`).
pub fn init(base: u64) {
    crate::arch::riscv64::apic::init_with_base(base);
}