//! LoongArch64 Enhanced Interrupt Controller
//!
//! Comprehensive interrupt handling with:
//! - EXTIOI (Extended I/O Interrupt Controller)
//! - IPI (Inter-Processor Interrupts)
//! - Timer interrupts
//! - Priority management

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const MAX_IRQS: usize = 256;
const MAX_CPUS: usize = 64;

const EXTIOI_IOCSR_BASE: u64 = 0x1400;
static EXTIOI_BASE: AtomicU64 = AtomicU64::new(EXTIOI_IOCSR_BASE);
static EXTIOI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// EXTIOI register offsets
mod extioi {
    pub const ENABLE: u64 = 0x200;
    pub const ISR: u64 = 0x300;
    pub const COREISR: u64 = 0x400;
    pub const COREMAP: u64 = 0x800;
}

unsafe fn read_u32(address: u64) -> u32 {
    let value: u32;
    asm!(
        "iocsrrd.w {value}, {address}",
        value = out(reg) value,
        address = in(reg) address,
        options(nostack)
    );
    value
}

unsafe fn write_u32(address: u64, value: u32) {
    asm!(
        "iocsrwr.w {value}, {address}",
        value = in(reg) value,
        address = in(reg) address,
        options(nostack)
    );
}

/// Initialize EXTIOI interrupt controller
pub fn init(_base: u64) {
    crate::arch::loongarch64::paging::vector_page_check("pic_init");
    let _ = crate::arch::loongarch64::paging::ensure_vector_page_mapped();
    EXTIOI_BASE.store(EXTIOI_IOCSR_BASE, Ordering::Release);
    crate::arch::boot::early_write_str(b"[LA64] ext_enter\r\n");

    unsafe {
        // Disable all interrupts initially
        for i in 0..(MAX_IRQS / 32) {
            write_u32(EXTIOI_IOCSR_BASE + extioi::ENABLE + (i as u64) * 4, 0);
        }
        crate::arch::boot::early_write_str(b"[LA64] ext_disable\r\n");

        // Route all interrupts to CPU 0 by default
        for i in 0..MAX_IRQS {
            set_route(i as u32, 0);
        }
        crate::arch::boot::early_write_str(b"[LA64] ext_route\r\n");
    }

    EXTIOI_INITIALIZED.store(true, Ordering::Release);
    crate::arch::boot::early_write_str(b"[LA64] ext_done\r\n");
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
        let mut val = read_u32(base + extioi::ENABLE + (word_idx as u64) * 4);
        val |= 1 << bit_idx;
        write_u32(base + extioi::ENABLE + (word_idx as u64) * 4, val);
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
        let mut val = read_u32(base + extioi::ENABLE + (word_idx as u64) * 4);
        val &= !(1 << bit_idx);
        write_u32(base + extioi::ENABLE + (word_idx as u64) * 4, val);
    }
}

/// Set interrupt routing (which CPU handles the interrupt)
pub fn set_route(irq: u32, cpu: u32) {
    if irq >= MAX_IRQS as u32 || cpu >= MAX_CPUS as u32 {
        return;
    }

    let base = EXTIOI_BASE.load(Ordering::Acquire);
    unsafe {
        let route_addr = base + extioi::COREMAP + ((irq / 4) as u64) * 4;
        let shift = (irq % 4) * 8;
        let val = read_u32(route_addr);
        let masked = val & !(0xff << shift);
        write_u32(route_addr, masked | ((cpu as u32 & 0xff) << shift));
    }
}

/// Get interrupt routing
pub fn get_route(irq: u32) -> u32 {
    if irq >= MAX_IRQS as u32 {
        return 0;
    }

    let base = EXTIOI_BASE.load(Ordering::Acquire);
    unsafe {
        let route_addr = base + extioi::COREMAP + ((irq / 4) as u64) * 4;
        let shift = (irq % 4) * 8;
        (read_u32(route_addr) >> shift) & 0xff
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
        let val = read_u32(base + extioi::ISR + (word_idx as u64) * 4);
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
        write_u32(base + extioi::COREISR + (word_idx as u64) * 4, 1 << bit_idx);
    }
}

/// Get pending interrupts for CPU
pub fn get_pending_for_cpu(cpu: u32) -> u32 {
    if cpu >= MAX_CPUS as u32 {
        return 0;
    }

    let base = EXTIOI_BASE.load(Ordering::Acquire);

    unsafe { read_u32(base + extioi::COREISR + (cpu as u64) * 4) }
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

/// handle interrupt - returns IRQ number or None
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
