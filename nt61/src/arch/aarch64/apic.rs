//! aarch64 GICv2 driver

use core::arch::asm;
use core::ptr;

/// GIC distributor registers
const GICD_CTLR: u32 = 0x000;
const GICD_ISENABLER: u32 = 0x100;
const GICD_IPRIORITYR: u32 = 0x400;
const GICD_ITARGETSR: u32 = 0x800;

/// GIC CPU interface registers
const GICC_CTLR: u32 = 0x000;
const GICC_PMR: u32 = 0x004;
const GICC_EOIR: u32 = 0x010;
const GICC_IAR: u32 = 0x00C;

static mut GICD_BASE: u64 = 0;
static mut GICC_BASE: u64 = 0;

fn gicd_reg(off: u32) -> u32 {
    let b = unsafe { GICD_BASE };
    if b == 0 { return 0; }
    unsafe { ptr::read_volatile((b + off as u64) as *const u32) }
}
fn gicd_write(off: u32, val: u32) {
    let b = unsafe { GICD_BASE };
    if b == 0 { return; }
    unsafe { ptr::write_volatile((b + off as u64) as *mut u32, val); }
}
fn gicc_reg(off: u32) -> u32 {
    let b = unsafe { GICC_BASE };
    if b == 0 { return 0; }
    unsafe { ptr::read_volatile((b + off as u64) as *const u32) }
}
fn gicc_write(off: u32, val: u32) {
    let b = unsafe { GICC_BASE };
    if b == 0 { return; }
    unsafe { ptr::write_volatile((b + off as u64) as *mut u32, val); }
}

/// Initialise the GIC distributor and CPU interface. `gicd_base`
/// and `gicc_base` are the physical addresses of the registers.
pub fn init(gicd_base: u64, gicc_base: u64) {
    unsafe {
        GICD_BASE = gicd_base;
        GICC_BASE = gicc_base;
        gicd_write(GICD_CTLR, 1); // enable distributor
        gicc_write(GICC_CTLR, 1); // enable CPU interface
        gicc_write(GICC_PMR, 0xFF); // accept all priorities
        gicc_write(GICC_EOIR, 1023);
        // Enable SGIs (0..15) and PPIs (16..31).
        for i in 0..32u32 {
            gicd_write(GICD_ISENABLER + 4 * (i / 32), 1u32 << (i % 32));
        }
    }
}

pub fn enable_irq(irq: u32) {
    gicd_write(GICD_ISENABLER + 4 * (irq / 32), 1u32 << (irq % 32));
    gicd_write(GICD_IPRIORITYR + 4 * (irq / 4), 0xA0u32 << (8 * (irq % 4)));
    gicd_write(GICD_ITARGETSR + 4 * (irq / 4), 0x01u32 << (8 * (irq % 4)));
}

pub fn eoi_irq(irq: u32) {
    gicc_write(GICC_EOIR, irq);
}

pub fn ack_irq() -> u32 {
    gicc_reg(GICC_IAR) & 0x3FF
}

#[allow(dead_code)]
fn _keep() {
    let _ = unsafe { asm!("nop") };
}
