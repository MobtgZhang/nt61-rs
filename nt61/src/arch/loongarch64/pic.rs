//! LoongArch 64 PIC (Platform I/O Controller)

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

static PIC_BASE: AtomicU64 = AtomicU64::new(0);

/// QEMU virt routes the PL011 UART through EXTIOI line 2.
const EXTIOI_UART_IRQ: u32 = 2;

pub fn init(base: u64) {
    crate::arch::boot::early_write_str(b"[PIC_ENTER]\r\n");
    crate::arch::loongarch64::interrupt::init(base);
    PIC_BASE.store(
        crate::arch::loongarch64::interrupt::base(),
        Ordering::Release,
    );
    enable_irq(EXTIOI_UART_IRQ);
}

pub fn enable_irq(irq: u32) {
    crate::arch::loongarch64::interrupt::enable_irq(irq);
}

pub fn irq_status() -> u32 {
    let b = PIC_BASE.load(Ordering::Acquire);
    if b == 0 {
        return 0;
    }
    let irq = crate::arch::loongarch64::interrupt::handle_irq(0);
    irq.unwrap_or(u32::MAX)
}

pub fn ack(irq: u32) {
    crate::arch::loongarch64::interrupt::eoi(irq);
}

/// Clear the per-core EXTIOI line without clearing the global device ISR.
pub fn core_ack(irq: u32) {
    crate::arch::loongarch64::interrupt::eoi(irq);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn _keep() {
    let _ = asm!("nop");
}
