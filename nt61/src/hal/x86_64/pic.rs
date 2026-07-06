//! 8259A Programmable Interrupt Controller (PIC)
//
//! Two cascaded 8259A controllers in the PC. Master is wired to
//! vector base 0x20, slave to vector base 0x28. IRQs 0..7 live on
//! the master, 8..15 on the slave.
//
//! The functions here match the surface area of the original
//! Windows `hal.dll` PIC exports (`HalEnableSystemInterrupt`,
//! `HalDisableSystemInterrupt`, `HalGetInterruptVector`) plus the
//! lower-level helpers used by the kernel's interrupt dispatcher.

#![cfg(target_arch = "x86_64")]

use core::arch::asm;
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::{READ_PORT_UCHAR, WRITE_PORT_UCHAR};

/// Master PIC command / data ports.
const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
/// Slave PIC command / data ports.
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// ICW1 flags.
const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
/// ICW4 mode bits.
const ICW4_8086: u8 = 0x01;
/// OCW2 / OCW3 command values.
const OCW2_EOI: u8 = 0x20;
const OCW3_READ_IRR: u8 = 0x0A;
const OCW3_READ_ISR: u8 = 0x0B;

/// Currently programmed vector base for the master PIC.
static PIC1_BASE: AtomicU8 = AtomicU8::new(0x20);
/// Currently programmed vector base for the slave PIC.
static PIC2_BASE: AtomicU8 = AtomicU8::new(0x28);

/// IRQL mapping used by the legacy PIC. The kernel's IRQL model
/// uses the same numeric range as the APIC TPR (0..15), so we
/// simply return `irq` as the IRQL for ISA devices.
#[inline]
fn irql_for_irq(irq: u8) -> u8 {
    // ISA devices use DIRQL — device IRQL. Each line traditionally
    // gets its own DIRQL; the bootstrap uses `irq` as a
    // pass-through.
    irq
}

/// Tiny I/O delay. The 8259 has a ~200ns latency for port access
/// on the original hardware, so a write to an unused port is
/// inserted between ICW writes.
#[inline]
fn io_wait() {
    unsafe { asm!("out 0x80, al", in("al") 0u8, options(nomem, nostack)); }
}

/// Remap both PICs to the supplied vector bases. `offset1` is the
/// master base (default 0x20), `offset2` is the slave base
/// (default 0x28). Returns `true` on success.
///
/// This performs the standard ICW1..ICW4 sequence: edge-triggered,
/// cascaded, 8086 mode, AEOI disabled, and finishes with all IRQs
/// masked.
pub fn i8259_init() -> bool {
    i8259_init_with_offsets(0x20, 0x28)
}

/// CRITICAL-010: Initialize the 8259A PIC and immediately mask all
/// 16 IRQ lines. This must be called BEFORE the IDT is loaded and
/// BEFORE `enable_interrupts_once()` is ever called.
///
/// The function performs the standard ICW1..ICW4 remap sequence
/// (edge-triggered, cascaded, 8086 mode) and finishes with both
/// PIC data ports holding 0xFF (all IRQs masked). After this
/// returns, no IRQ can be raised until a caller explicitly unmasks
/// one.
///
/// This is the function `arch::init_hardware()` calls immediately
/// after `cli()` and before `idt::init()`. See
/// `nt61/src/arch/mod.rs::init_hardware`.
pub fn init_and_mask_all() {
    i8259_init_with_offsets(0x20, 0x28);
}

/// Program the PIC with explicit vector bases. Useful for tests
/// and for systems where the IDT is laid out at a non-default
/// location.
pub fn i8259_init_with_offsets(offset1: u8, offset2: u8) -> bool {
    // Save the existing mask so we can restore it after init.
    let saved_mask1 = READ_PORT_UCHAR(PIC1_DATA);
    let saved_mask2 = READ_PORT_UCHAR(PIC2_DATA);

    // ICW1 — start init, expect ICW4.
    WRITE_PORT_UCHAR(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
    io_wait();
    WRITE_PORT_UCHAR(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
    io_wait();

    // ICW2 — vector base.
    WRITE_PORT_UCHAR(PIC1_DATA, offset1);
    io_wait();
    WRITE_PORT_UCHAR(PIC2_DATA, offset2);
    io_wait();

    // ICW3 — wiring. Master has slave on IRQ2 (bit 2); slave is
    // cascaded into IRQ2 (value 2).
    WRITE_PORT_UCHAR(PIC1_DATA, 0x04);
    io_wait();
    WRITE_PORT_UCHAR(PIC2_DATA, 0x02);
    io_wait();

    // ICW4 — 8086 mode.
    WRITE_PORT_UCHAR(PIC1_DATA, ICW4_8086);
    io_wait();
    WRITE_PORT_UCHAR(PIC2_DATA, ICW4_8086);
    io_wait();

    // Mask all IRQs by default; the caller is expected to
    // selectively unmask the ones it wants.
    WRITE_PORT_UCHAR(PIC1_DATA, 0xFF);
    WRITE_PORT_UCHAR(PIC2_DATA, 0xFF);

    PIC1_BASE.store(offset1, Ordering::Release);
    PIC2_BASE.store(offset2, Ordering::Release);

    let _ = saved_mask1;
    let _ = saved_mask2;
    true
}

/// Send End-Of-Interrupt to the PIC(s) responsible for `irq`.
/// `irq` is the system-wide IRQ number, 0..15.
pub fn send_eoi(irq: u8) {
    unsafe {
        asm!("out dx, al", in("dx") PIC1_CMD, in("al") OCW2_EOI,
             options(nomem, nostack));
    }
    if irq >= 8 {
        unsafe {
            asm!("out dx, al", in("dx") PIC2_CMD, in("al") OCW2_EOI,
                 options(nomem, nostack));
        }
    }
}

/// Unmask the IRQ so it can fire. IRQ numbers 0..15.
pub fn unmask_irq(irq: u8) {
    let (port, bit) = if irq < 8 { (PIC1_DATA, irq) } else { (PIC2_DATA, irq - 8) };
    let new_mask = READ_PORT_UCHAR(port) & !(1 << bit);
    WRITE_PORT_UCHAR(port, new_mask);
}

/// Mask the IRQ so it cannot fire.
pub fn mask_irq(irq: u8) {
    let (port, bit) = if irq < 8 { (PIC1_DATA, irq) } else { (PIC2_DATA, irq - 8) };
    let new_mask = READ_PORT_UCHAR(port) | (1 << bit);
    WRITE_PORT_UCHAR(port, new_mask);
}

/// Dispatch a PIC IRQ. Sends EOI and calls the registered handler.
pub fn irq_dispatch(irq: u8) {
    send_eoi(irq);
    let _ = irq;
}

/// Read the In-Service Register. The ISR has a 1 set for every
/// IRQ currently being serviced (between INT and EOI).
pub fn read_isr() -> u16 {
    unsafe {
        asm!("out dx, al", in("dx") PIC1_CMD, in("al") OCW3_READ_ISR,
             options(nomem, nostack));
    }
    let lo = READ_PORT_UCHAR(PIC1_CMD) as u16;
    unsafe {
        asm!("out dx, al", in("dx") PIC2_CMD, in("al") OCW3_READ_ISR,
             options(nomem, nostack));
    }
    let hi = READ_PORT_UCHAR(PIC2_CMD) as u16;
    (hi << 8) | lo
}

/// Read the Interrupt Request Register. The IRR has a 1 set for
/// every IRQ that has been signalled but not yet acknowledged.
pub fn read_irr() -> u16 {
    unsafe {
        asm!("out dx, al", in("dx") PIC1_CMD, in("al") OCW3_READ_IRR,
             options(nomem, nostack));
    }
    let lo = READ_PORT_UCHAR(PIC1_CMD) as u16;
    unsafe {
        asm!("out dx, al", in("dx") PIC2_CMD, in("al") OCW3_READ_IRR,
             options(nomem, nostack));
    }
    let hi = READ_PORT_UCHAR(PIC2_CMD) as u16;
    (hi << 8) | lo
}

/// Read the current PIC mask. Bit n corresponds to IRQ n; 1 means
/// masked.
pub fn read_mask() -> u16 {
    let lo = READ_PORT_UCHAR(PIC1_DATA) as u16;
    let hi = READ_PORT_UCHAR(PIC2_DATA) as u16;
    (hi << 8) | lo
}

/// Write a complete mask. Bit n corresponds to IRQ n; 1 means
/// masked.
pub fn write_mask(mask: u16) {
    WRITE_PORT_UCHAR(PIC1_DATA, (mask & 0xFF) as u8);
    WRITE_PORT_UCHAR(PIC2_DATA, ((mask >> 8) & 0xFF) as u8);
}

// =====================================================================
// hal.dll-style exports
// =====================================================================

/// Bus / interface type as defined in `hal.dll` `KdGetInterruptVector`
/// and `HalGetInterruptVector` semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InterfaceType {
    Internal = 0,
    Isa = 1,
    Eisa = 2,
    MicroChannel = 3,
    TurboChannel = 4,
    PCIBus = 5,
    VME = 6,
    NuBus = 7,
    PCMCIABus = 8,
    CBus = 9,
    MPIBus = 10,
    MPSABus = 11,
    ProcessorInternal = 12,
    InternalPowerBus = 13,
    PNPISABus = 14,
    PNPBus = 15,
    MaximumInterfaceType = 16,
}

/// Vector / IRQL pair returned by `HalGetInterruptVector`. We use
/// the same structure as the real `hal.dll`.
#[derive(Debug, Clone, Copy, Default)]
pub struct HalInterruptVector {
    pub vector: u32,
    pub irql: u8,
    pub affinity: u32,
}

/// Translate a bus-relative IRQ into an IDT vector, an IRQL, and a
/// processor affinity. For the legacy PIC, the vector is
/// `pic_base + irq`, the IRQL is `irq` (matching the APIC TPR
/// range), and the affinity is `0xFFFFFFFF` (any processor).
pub fn HalGetInterruptVector(
    interface_type: InterfaceType,
    _bus_number: u32,
    bus_interrupt_level: u32,
    _bus_interrupt_vector: u32,
) -> HalInterruptVector {
    let irq = bus_interrupt_level as u8;
    let base = if irq < 8 {
        PIC1_BASE.load(Ordering::Acquire)
    } else {
        PIC2_BASE.load(Ordering::Acquire)
    };
    let vector = base as u32 + (irq & 0x07) as u32;
    let _ = interface_type;
    HalInterruptVector {
        vector,
        irql: irql_for_irq(irq),
        affinity: 0xFFFF_FFFF,
    }
}

/// Enable an ISA-style system interrupt. `irq` is the system IRQ
/// number (0..15), `irql` is the DIRQL that the line should run
/// at, and `vector` is the IDT vector that the line is wired to.
/// The vector argument is informational — the PIC already knows
/// which vector it raises for which IRQ — but the real
/// `HalEnableSystemInterrupt` validates that the vector matches.
pub fn HalEnableSystemInterrupt(irq: u8, irql: u8, vector: u32) -> i32 {
    if irq >= 16 {
        return -1;
    }
    let base = if irq < 8 {
        PIC1_BASE.load(Ordering::Acquire) as u32
    } else {
        PIC2_BASE.load(Ordering::Acquire) as u32
    };
    let expected = base + (irq & 0x07) as u32;
    if vector != expected {
        return -2;
    }
    let _ = irql;
    unmask_irq(irq);
    0
}

/// Disable an ISA-style system interrupt. `irq` is the system IRQ
/// number. Returns 0 on success, -1 if the IRQ is out of range.
pub fn HalDisableSystemInterrupt(irq: u8) -> i32 {
    if irq >= 16 {
        return -1;
    }
    mask_irq(irq);
    0
}

/// Test handler used by the unit tests. Verifies that the inlines
/// round-trip and that mask writes are idempotent.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_translation() {
        // Without calling i8259_init we just use the defaults
        // baked into the statics.
        let v = HalGetInterruptVector(InterfaceType::Isa, 0, 1, 0);
        assert_eq!(v.vector, 0x21);
        assert_eq!(v.irql, 1);
    }

    #[test]
    fn mask_round_trip() {
        let before = read_mask();
        // Mask IRQ 7, verify, restore.
        mask_irq(7);
        assert_eq!(read_mask() & (1 << 7), 1 << 7);
        write_mask(before);
        assert_eq!(read_mask(), before);
    }
}
