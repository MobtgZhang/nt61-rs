//! PLIC-backed "APIC" compatibility shim for RISC-V 64.
//!
//! On RISC-V the PLIC plays the role of the platform PIC (the
//! role x86 assigns to the 8259 / IO-APIC and aarch64 assigns to
//! the GIC). This module re-exports PLIC primitives under an
//! `apic::*` namespace so the kernel's arch-agnostic interrupt
//! code can call a uniform API.
//!
//! Phase 1 wires the PLIC at the QEMU virt base (`0xC00_0000`) and
//! pre-enables a small set of common IRQs (UART, virtio) so the
//! serial console can fire interrupts. Phase 2 will extend this to
//! device-tree-driven discovery.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::riscv64::plic;

/// Cached hart id used by [`handle_irq`] and friends.
static CURRENT_HART: AtomicU32 = AtomicU32::new(0);

/// Initialise the PLIC for the boot hart with the QEMU virt
/// default base (`0xC00_0000`).
pub fn init() {
    init_with_base(0xC00_0000);
}

/// Initialise the PLIC with an explicit base address.
pub fn init_with_base(base: u64) {
    let real = if base == 0 { 0xC00_0000 } else { base };
    plic::init(real);
    // Threshold = 0 — accept everything enabled above priority 0.
    plic::set_threshold(0, 1, 0); // hart 0, S-mode context
    // Pre-enable the typical QEMU virt IRQs.
    //   1 = virtio device 0 (block, net, ...)
    //   10 = UART16550 (used by `serial.rs`)
    // These can be re-tuned by the platform driver later.
    plic::enable(10, 7); // UART16550 priority 7
    plic::enable(1, 1);  // virtio priority 1
}

/// Handle a pending external interrupt on the current hart.
///
/// Returns the IRQ number claimed (or 0 if none).
pub fn handle_irq() -> u32 {
    let hart = crate::arch::riscv64::smp::current_hart_id();
    CURRENT_HART.store(hart, Ordering::Relaxed);
    plic::claim(hart, 1)
}

/// Dispatch the claimed IRQ to the registered device handler.
pub fn dispatch_irq(irq: u32) {
    if irq == plic::PLIC_NO_INTERRUPT {
        return;
    }
    // Phase 1: route the UART to the serial handler. Phase 2 will
    // dispatch against a registered vector table.
    if irq == 10 {
        crate::arch::riscv64::serial::handle_rx();
    }
    // EOI regardless.
    let hart = CURRENT_HART.load(Ordering::Relaxed);
    plic::complete(hart, 1, irq);
}

/// Send an IPI to a target hart.
///
/// On RISC-V this is implemented as a CLINT MSIP write rather
/// than a PLIC operation, because the PLIC only handles external
/// (peripheral) interrupts.
pub fn send_ipi(hart_id: u32, _irq: u32) {
    crate::arch::riscv64::clint::raise_msip(hart_id);
}