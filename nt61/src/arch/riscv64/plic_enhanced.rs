//! RISC-V64 Enhanced PLIC driver
//!
//! Extended Platform-Level Interrupt Controller with:
//! - Multi-hart support
//! - Priority management
//! - Interrupt routing
//! - Edge/level configuration

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const PLIC_NUM_SOURCES: usize = 128;
const PLIC_NUM_PRIORITIES: usize = 7;

static PLIC_BASE: AtomicU64 = AtomicU64::new(0);
static PLIC_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// PLIC register offsets
mod offset {
    pub const PRIORITY_BASE: u64 = 0x0000_0000;
    pub const PENDING_BASE: u64 = 0x0000_1000;
    pub const ENABLE_BASE: u64 = 0x0000_2000;
    pub const ENABLE_STRIDE: u64 = 0x80;
    pub const CONTEXT_BASE: u64 = 0x0020_0000;
    pub const CONTEXT_STRIDE: u64 = 0x1000;
    pub const THRESHOLD_OFFSET: u64 = 0x000;
    pub const CLAIM_COMPLETE_OFFSET: u64 = 0x004;
}

/// Initialize PLIC with enhanced features
pub fn init(base: u64) {
    PLIC_BASE.store(base, Ordering::Release);

    unsafe {
        // Disable all interrupts initially
        for context in 0..8 {
            for word in 0..(PLIC_NUM_SOURCES / 32) {
                let enable_addr = base + offset::ENABLE_BASE
                    + context * offset::ENABLE_STRIDE
                    + (word as u64) * 4;
                core::ptr::write_volatile(enable_addr as *mut u32, 0);
            }

            // Set threshold to 0 (accept all priorities)
            let threshold_addr = base + offset::CONTEXT_BASE
                + context * offset::CONTEXT_STRIDE
                + offset::THRESHOLD_OFFSET;
            core::ptr::write_volatile(threshold_addr as *mut u32, 0);
        }

        // Set all priorities to default (1)
        for irq in 1..PLIC_NUM_SOURCES {
            let prio_addr = base + offset::PRIORITY_BASE + (irq as u64) * 4;
            core::ptr::write_volatile(prio_addr as *mut u32, 1);
        }
    }

    PLIC_INITIALIZED.store(true, Ordering::Release);
}

/// Enable interrupt for specific hart
pub fn enable_irq(irq: u32, hart: u32) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 || irq >= PLIC_NUM_SOURCES as u32 {
        return;
    }

    let context = hart * 2 + 1; // S-mode context
    let word_idx = irq / 32;
    let bit_idx = irq % 32;

    unsafe {
        let enable_addr = base + offset::ENABLE_BASE
            + (context as u64) * offset::ENABLE_STRIDE
            + (word_idx as u64) * 4;
        let mut val = core::ptr::read_volatile(enable_addr as *const u32);
        val |= 1 << bit_idx;
        core::ptr::write_volatile(enable_addr as *mut u32, val);
    }
}

/// Disable interrupt for specific hart
pub fn disable_irq(irq: u32, hart: u32) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 || irq >= PLIC_NUM_SOURCES as u32 {
        return;
    }

    let context = hart * 2 + 1;
    let word_idx = irq / 32;
    let bit_idx = irq % 32;

    unsafe {
        let enable_addr = base + offset::ENABLE_BASE
            + (context as u64) * offset::ENABLE_STRIDE
            + (word_idx as u64) * 4;
        let mut val = core::ptr::read_volatile(enable_addr as *const u32);
        val &= !(1 << bit_idx);
        core::ptr::write_volatile(enable_addr as *mut u32, val);
    }
}

/// Set interrupt priority (1-7, 0 = disabled)
pub fn set_priority(irq: u32, priority: u8) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 || irq >= PLIC_NUM_SOURCES as u32 {
        return;
    }

    let prio = priority.min(PLIC_NUM_PRIORITIES as u8);
    unsafe {
        let prio_addr = base + offset::PRIORITY_BASE + (irq as u64) * 4;
        core::ptr::write_volatile(prio_addr as *mut u32, prio as u32);
    }
}

/// Get interrupt priority
pub fn get_priority(irq: u32) -> u8 {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 || irq >= PLIC_NUM_SOURCES as u32 {
        return 0;
    }

    unsafe {
        let prio_addr = base + offset::PRIORITY_BASE + (irq as u64) * 4;
        core::ptr::read_volatile(prio_addr as *const u32) as u8
    }
}

/// Set priority threshold for hart
pub fn set_threshold(hart: u32, threshold: u8) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }

    let context = hart * 2 + 1;
    unsafe {
        let threshold_addr = base + offset::CONTEXT_BASE
            + (context as u64) * offset::CONTEXT_STRIDE
            + offset::THRESHOLD_OFFSET;
        core::ptr::write_volatile(threshold_addr as *mut u32, threshold as u32);
    }
}

/// Claim interrupt for hart
pub fn claim(hart: u32) -> u32 {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 {
        return 0;
    }

    let context = hart * 2 + 1;
    unsafe {
        let claim_addr = base + offset::CONTEXT_BASE
            + (context as u64) * offset::CONTEXT_STRIDE
            + offset::CLAIM_COMPLETE_OFFSET;
        core::ptr::read_volatile(claim_addr as *const u32)
    }
}

/// Complete interrupt for hart
pub fn complete(hart: u32, irq: u32) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }

    let context = hart * 2 + 1;
    unsafe {
        let complete_addr = base + offset::CONTEXT_BASE
            + (context as u64) * offset::CONTEXT_STRIDE
            + offset::CLAIM_COMPLETE_OFFSET;
        core::ptr::write_volatile(complete_addr as *mut u32, irq);
    }
}

/// Check if interrupt is pending
pub fn is_pending(irq: u32) -> bool {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 || irq >= PLIC_NUM_SOURCES as u32 {
        return false;
    }

    let word_idx = irq / 32;
    let bit_idx = irq % 32;

    unsafe {
        let pending_addr = base + offset::PENDING_BASE + (word_idx as u64) * 4;
        let val = core::ptr::read_volatile(pending_addr as *const u32);
        (val & (1 << bit_idx)) != 0
    }
}

/// Enable interrupt for all harts
pub fn enable_for_all_harts(irq: u32, num_harts: u32) {
    for hart in 0..num_harts {
        enable_irq(irq, hart);
    }
}

/// Configure interrupt (priority and enable)
pub fn configure(irq: u32, hart: u32, priority: u8) {
    set_priority(irq, priority);
    enable_irq(irq, hart);
}

/// Check if PLIC is initialized
pub fn is_initialized() -> bool {
    PLIC_INITIALIZED.load(Ordering::Acquire)
}

/// Get base address
pub fn base() -> u64 {
    PLIC_BASE.load(Ordering::Acquire)
}
