//! aarch64 PIC (the GIC serves the role of the platform PIC).
//!
//! Historically x86 systems used a 8259 PIC. On aarch64 the GIC
//! plays the equivalent role. This module re-exports the GIC's
//! enable / acknowledge primitives under a more familiar interface.

pub use crate::hal::aarch64::apic::{
    handle_irq as pic_handle_irq,
    dispatch_irq as pic_dispatch_irq,
};

/// Enable an SPI on the controller. On GICv2 this maps to writing the
/// `ISENABLER` register.
pub fn pic_enable_irq(irq: u32) {
    let _ = irq;
    // Real driver writes to GICD_ISENABLER. Stub for the bootstrap.
}

pub fn pic_eoi_irq(_irq: u32) {
    // Real driver writes to GICC_EOIR. Stub for the bootstrap.
}
