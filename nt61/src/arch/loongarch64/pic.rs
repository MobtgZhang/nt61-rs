//! LoongArch 64 PIC (Platform I/O Controller)

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

static PIC_BASE: AtomicU64 = AtomicU64::new(0);

pub fn init(base: u64) {
    PIC_BASE.store(base, Ordering::Release);
}

pub fn enable_irq(irq: u32) {
    let b = PIC_BASE.load(Ordering::Acquire);
    if b == 0 { return; }
    let reg = (irq / 32) as u64;
    unsafe {
        let v = ptr::read_volatile((b + 0x200 + reg * 4) as *const u32);
        ptr::write_volatile((b + 0x200 + reg * 4) as *mut u32, v | (1 << (irq % 32)));
    }
}

pub fn irq_status() -> u32 {
    let b = PIC_BASE.load(Ordering::Acquire);
    if b == 0 { return 0; }
    unsafe { ptr::read_volatile((b + 0x3A0) as *const u32) }
}

pub fn ack(irq: u32) {
    let b = PIC_BASE.load(Ordering::Acquire);
    if b == 0 { return; }
    let reg = (irq / 32) as u64;
    unsafe {
        let v = ptr::read_volatile((b + 0x280 + reg * 4) as *const u32);
        ptr::write_volatile((b + 0x280 + reg * 4) as *mut u32, v | (1 << (irq % 32)));
    }
}

#[allow(dead_code)]
unsafe fn _keep() {
    let _ = asm!("nop");
}
