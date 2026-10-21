//! LoongArch 64 PIC (Platform I/O Controller)

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

static PIC_BASE: AtomicU64 = AtomicU64::new(0);

/// QEMU virt routes the PL011 UART through EXTIOI line 2.
const EXTIOI_UART_IRQ: u32 = 2;

pub fn init(base: u64) {
    let mapped_base = if crate::arch::loongarch64::paging::paging_enabled() {
        crate::arch::loongarch64::paging::mmio_virt(base)
    } else {
        base
    };
    PIC_BASE.store(mapped_base, Ordering::Release);
    enable_irq(EXTIOI_UART_IRQ);
}

pub fn enable_irq(irq: u32) {
    let b = PIC_BASE.load(Ordering::Acquire);
    if b == 0 {
        return;
    }
    let reg = (irq / 32) as u64;
    unsafe {
        let v = ptr::read_volatile((b + 0x200 + reg * 4) as *const u32);
        ptr::write_volatile((b + 0x200 + reg * 4) as *mut u32, v | (1 << (irq % 32)));
    }
}

pub fn irq_status() -> u32 {
    let b = PIC_BASE.load(Ordering::Acquire);
    if b == 0 {
        return 0;
    }
    unsafe { ptr::read_volatile((b + 0x3A0) as *const u32) }
}

pub fn ack(irq: u32) {
    let b = PIC_BASE.load(Ordering::Acquire);
    if b == 0 {
        return;
    }
    let reg = (irq / 32) as u64;
    unsafe {
        let v = ptr::read_volatile((b + 0x280 + reg * 4) as *const u32);
        ptr::write_volatile((b + 0x280 + reg * 4) as *mut u32, v | (1 << (irq % 32)));
    }
}

/// Clear the per-core EXTIOI line without clearing the global device ISR.
pub fn core_ack(irq: u32) {
    let b = PIC_BASE.load(Ordering::Acquire);
    if b == 0 {
        return;
    }
    let reg = (irq / 32) as u64;
    unsafe {
        let address = b + 0x400 + reg * 4;
        let value = ptr::read_volatile(address as *const u32);
        ptr::write_volatile(address as *mut u32, value | (1 << (irq % 32)));
    }
}

unsafe fn _keep() {
    let _ = asm!("nop");
}
