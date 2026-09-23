//! LoongArch64 Enhanced Interrupt Controller
//!
//! Comprehensive interrupt handling with:
//! - EXTIOI (Extended I/O Interrupt Controller)
//! - IPI (Inter-Processor Interrupts)
//! - Timer interrupts
//! - Priority management

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const MAX_IRQS: usize = 256;
const MAX_CPUS: usize = 64;

static EXTIOI_BASE: AtomicU64 = AtomicU64::new(0x1FE0_1000);
static EXTIOI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// EXTIOI register offsets
mod extioi {
    pub const NODETYPE: u64 = 0x000;
    pub const ENABLE: u64 = 0x020;
    pub const BOUNCE: u64 = 0x060;
    pub const ISR: u64 = 0x0A0;
    pub const COREISR: u64 = 0x100;
    pub const COREMAP: u64 = 0x200;
    pub const ROUTE: u64 = 0x300;
}

/// Initialize EXTIOI interrupt controller
pub fn init(base: u64) {
    EXTIOI_BASE.store(base, Ordering::Release);

    unsafe {
        // Disable all interrupts initially
        for i in 0..(MAX_IRQS / 32) {
            let enable_addr = base + extioi::ENABLE + (i as u64) * 4;
            core::ptr::write_volatile(enable_addr as *mut u32, 0);
        }

        // Route all interrupts to CPU 0 by default
        for i in 0..MAX_IRQS {
            set_route(i as u32, 0);
        }

        // Clear pending interrupts
        for i in 0..(MAX_IRQS / 32) {
            let isr_addr = base + extioi::ISR + (i as u64) * 4;
            let pending = core::ptr::read_volatile(isr_addr as *const u32);
            core::ptr::write_volatile(isr_addr as *mut u32, pending);
        }
    }

    EXTIOI_INITIALIZED.store(true, Ordering::Release);
}

/// Enable interrupt
pub fn enable_irq(irq: u32) {
    if irq >= MAX_IRQS as u32 {
        return;
    }

    let base = EXTIOI_BASE.load(Ordering::Acquire);
    let word_idx = irq / 32;
    let bit_idx = irq % 32;

    unsafe {
        let enable_addr = base + extioi::ENABLE + (word_idx as u64) * 4;
        let mut val = core::ptr::read_volatile(enable_addr as *const u32);
        val |= 1 << bit_idx;
        core::ptr::write_volatile(enable_addr as *mut u32, val);
    }
}

/// Disable interrupt
pub fn disable_irq(irq: u32) {
    if irq >= MAX_IRQS as u32 {
        return;
    }

    let base = EXTIOI_BASE.load(Ordering::Acquire);
    let word_idx = irq / 32;
    let bit_idx = irq % 32;

    unsafe {
        let enable_addr = base + extioi::ENABLE + (word_idx as u64) * 4;
        let mut val = core::ptr::read_volatile(enable_addr as *const u32);
        val &= !(1 << bit_idx);
        core::ptr::write_volatile(enable_addr as *mut u32, val);
    }
}

/// Set interrupt routing (which CPU handles the interrupt)
pub fn set_route(irq: u32, cpu: u32) {
    if irq >= MAX_IRQS as u32 || cpu >= MAX_CPUS as u32 {
        return;
    }

    let base = EXTIOI_BASE.load(Ordering::Acquire);
    let byte_idx = irq;

    unsafe {
        let route_addr = (base + extioi::ROUTE + byte_idx as u64) as *mut u8;
        core::ptr::write_volatile(route_addr, cpu as u8);
    }
}

/// Get interrupt routing
pub fn get_route(irq: u32) -> u32 {
    if irq >= MAX_IRQS as u32 {
        return 0;
    }

    let base = EXTIOI_BASE.load(Ordering::Acquire);
    let byte_idx = irq;

    unsafe {
        let route_addr = (base + extioi::ROUTE + byte_idx as u64) as *const u8;
        core::ptr::read_volatile(route_addr) as u32
    }
}

/// Check if interrupt is pending
pub fn is_pending(irq: u32) -> bool {
    if irq >= MAX_IRQS as u32 {
        return false;
    }

    let base = EXTIOI_BASE.load(Ordering::Acquire);
    let word_idx = irq / 32;
    let bit_idx = irq % 32;

    unsafe {
        let isr_addr = base + extioi::ISR + (word_idx as u64) * 4;
        let val = core::ptr::read_volatile(isr_addr as *const u32);
        (val & (1 << bit_idx)) != 0
    }
}

/// Clear pending interrupt
pub fn clear_pending(irq: u32) {
    if irq >= MAX_IRQS as u32 {
        return;
    }

    let base = EXTIOI_BASE.load(Ordering::Acquire);
    let word_idx = irq / 32;
    let bit_idx = irq % 32;

    unsafe {
        let isr_addr = base + extioi::ISR + (word_idx as u64) * 4;
        core::ptr::write_volatile(isr_addr as *mut u32, 1 << bit_idx);
    }
}

/// Get pending interrupts for CPU
pub fn get_pending_for_cpu(cpu: u32) -> u32 {
    if cpu >= MAX_CPUS as u32 {
        return 0;
    }

    let base = EXTIOI_BASE.load(Ordering::Acquire);

    unsafe {
        let coreisr_addr = base + extioi::COREISR + (cpu as u64) * 4;
        core::ptr::read_volatile(coreisr_addr as *const u32)
    }
}

/// Send IPI to CPU using mailbox
pub fn send_ipi(target_cpu: u32) {
    if target_cpu >= MAX_CPUS as u32 {
        return;
    }

    // LoongArch IPI is sent via IOCSR (I/O CSR space)
    unsafe {
        // IOCSR_IPI_SEND register
        core::arch::asm!(
            "iocsrwr.w {val}, {reg}",
            val = in(reg) 1u32,
            reg = in(reg) 0x1040 + target_cpu * 4,
            options(nostack)
        );
    }
}

/// Clear IPI for current CPU
pub fn clear_ipi() {
    unsafe {
        // IOCSR_IPI_CLEAR register
        core::arch::asm!(
            "iocsrwr.w {val}, {reg}",
            val = in(reg) 1u32,
            reg = in(reg) 0x1060,
            options(nostack)
        );
    }
}

/// Check if IPI is pending for current CPU
pub fn is_ipi_pending() -> bool {
    unsafe {
        let val: u32;
        core::arch::asm!(
            "iocsrrd.w {val}, {reg}",
            val = out(reg) val,
            reg = in(reg) 0x1020,
            options(nostack)
        );
        val != 0
    }
}

/// Handle interrupt - returns IRQ number or None
pub fn handle_irq(cpu: u32) -> Option<u32> {
    let pending = get_pending_for_cpu(cpu);

    if pending == 0 {
        return None;
    }

    // Find first set bit
    let irq = pending.trailing_zeros();

    if irq < 32 {
        Some(irq)
    } else {
        None
    }
}

/// Acknowledge interrupt (clear pending)
pub fn eoi(irq: u32) {
    clear_pending(irq);
}

/// Check if initialized
pub fn is_initialized() -> bool {
    EXTIOI_INITIALIZED.load(Ordering::Acquire)
}

/// Get base address
pub fn base() -> u64 {
    EXTIOI_BASE.load(Ordering::Acquire)
}
