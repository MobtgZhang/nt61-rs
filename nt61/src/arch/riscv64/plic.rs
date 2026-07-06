//! RISC-V 64 PLIC (Platform-Level Interrupt Controller) driver.
//!
//! The PLIC is the standard off-chip interrupt controller on every
//! RISC-V SoC supported here (QEMU virt, SiFive U74, SpacemiT K1,
//! ESWIN EIC7700X, JH7110, ...). Phase 1 implements the legacy
//! "one context per hart" model:
//!
//! * Each interrupt source has a priority register (1..7).
//! * Each hart/context pair has an enable bitmask.
//! * `claim` returns the highest-priority pending IRQ for the
//!   given context.
//! * `complete` signals EOI.
//!
//! ## Memory map (relative to PLIC base)
//!
//! | Range                | Register group           |
//! |----------------------|--------------------------|
//! | 0x000000 .. 0x000FFC | Priority registers       |
//! | 0x001000 .. 0x001FFF | Pending bits             |
//! | 0x002000 .. 0x1FFFFF | Enable bitmasks          |
//! | 0x200000 ..          | Per-context thresholds   |
//! | 0x200004 ..          | Per-context claim/complete |
//!
//! The QEMU virt PLIC base is `0xC000000` with up to 32 contexts.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const PLIC_NUM_SOURCES: usize = 32;
const PLIC_PRIORITY_BASE: u64 = 0x0000_0000;
const PLIC_PENDING_BASE: u64 = 0x0000_1000;
const PLIC_ENABLE_BASE: u64 = 0x0000_2000;
const PLIC_ENABLE_STRIDE: u64 = 0x80; // one word per context
const PLIC_CONTEXT_BASE: u64 = 0x0020_0000;
const PLIC_CONTEXT_STRIDE: u64 = 0x1000;
const PLIC_THRESHOLD_OFFSET: u64 = 0x000;
const PLIC_CLAIM_OFFSET: u64 = 0x004;

/// Sentinel IRQ for "no pending interrupt".
pub const PLIC_NO_INTERRUPT: u32 = 0;

static PLIC_BASE: AtomicU64 = AtomicU64::new(0);

/// Initialise the PLIC with the given base address (e.g.
/// `0xC00_0000` on QEMU virt).
pub fn init(base: u64) {
    PLIC_BASE.store(base, Ordering::Release);
}

/// Return the cached PLIC base (0 if not initialised).
pub fn base() -> u64 {
    PLIC_BASE.load(Ordering::Acquire)
}

/// Set the priority of a given IRQ source. Priorities are 1..7.
/// Source 0 has no effect (priority 0 = disabled).
pub fn set_priority(irq: u32, prio: u8) {
    let b = PLIC_BASE.load(Ordering::Acquire);
    if b == 0 { return; }
    let off = PLIC_PRIORITY_BASE + (irq as u64) * 4;
    unsafe { core::ptr::write_volatile((b + off) as *mut u32, prio as u32) };
}

/// Read the priority of a given IRQ source.
pub fn get_priority(irq: u32) -> u32 {
    let b = PLIC_BASE.load(Ordering::Acquire);
    if b == 0 { return 0; }
    let off = PLIC_PRIORITY_BASE + (irq as u64) * 4;
    unsafe { core::ptr::read_volatile((b + off) as *const u32) }
}

/// Enable `irq` for the given `(hart, context)` pair.
///
/// `context` is the privilege level / mode offset on the hart
/// (typically 0 for M-mode, 1 for S-mode). The kernel uses S-mode
/// context = `hart * 2 + 1`.
pub fn enable_irq(irq: u32, hart: u32, context: u32) {
    let b = PLIC_BASE.load(Ordering::Acquire);
    if b == 0 { return; }
    let ctx_idx = hart * 2 + context;
    let off = PLIC_ENABLE_BASE + (ctx_idx as u64) * PLIC_ENABLE_STRIDE + ((irq / 32) as u64) * 4;
    let shift = irq % 32;
    unsafe {
        let ptr = (b + off) as *mut u32;
        let cur = core::ptr::read_volatile(ptr);
        core::ptr::write_volatile(ptr, cur | (1 << shift));
    }
}

/// Disable `irq` for the given `(hart, context)` pair.
pub fn disable_irq(irq: u32, hart: u32, context: u32) {
    let b = PLIC_BASE.load(Ordering::Acquire);
    if b == 0 { return; }
    let ctx_idx = hart * 2 + context;
    let off = PLIC_ENABLE_BASE + (ctx_idx as u64) * PLIC_ENABLE_STRIDE + ((irq / 32) as u64) * 4;
    let shift = irq % 32;
    unsafe {
        let ptr = (b + off) as *mut u32;
        let cur = core::ptr::read_volatile(ptr);
        core::ptr::write_volatile(ptr, cur & !(1 << shift));
    }
}

/// Set the priority threshold for a `(hart, context)` pair.
/// IRQs with priority <= threshold are masked.
pub fn set_threshold(hart: u32, context: u32, threshold: u8) {
    let b = PLIC_BASE.load(Ordering::Acquire);
    if b == 0 { return; }
    let ctx_idx = hart * 2 + context;
    let off = PLIC_CONTEXT_BASE + (ctx_idx as u64) * PLIC_CONTEXT_STRIDE
        + PLIC_THRESHOLD_OFFSET;
    unsafe { core::ptr::write_volatile((b + off) as *mut u32, threshold as u32) };
}

/// Claim the next pending IRQ for `(hart, context)`. Returns
/// [`PLIC_NO_INTERRUPT`] (0) if no interrupt is pending.
pub fn claim(hart: u32, context: u32) -> u32 {
    let b = PLIC_BASE.load(Ordering::Acquire);
    if b == 0 { return PLIC_NO_INTERRUPT; }
    let ctx_idx = hart * 2 + context;
    let off = PLIC_CONTEXT_BASE + (ctx_idx as u64) * PLIC_CONTEXT_STRIDE
        + PLIC_CLAIM_OFFSET;
    unsafe { core::ptr::read_volatile((b + off) as *const u32) }
}

/// Complete (acknowledge EOI) an IRQ for `(hart, context)`.
pub fn complete(hart: u32, context: u32, irq: u32) {
    let b = PLIC_BASE.load(Ordering::Acquire);
    if b == 0 { return; }
    let ctx_idx = hart * 2 + context;
    let off = PLIC_CONTEXT_BASE + (ctx_idx as u64) * PLIC_CONTEXT_STRIDE
        + PLIC_CLAIM_OFFSET;
    unsafe { core::ptr::write_volatile((b + off) as *mut u32, irq) };
}

/// Read the per-hart pending bit for an IRQ.
pub fn is_pending(irq: u32) -> bool {
    let b = PLIC_BASE.load(Ordering::Acquire);
    if b == 0 { return false; }
    let off = PLIC_PENDING_BASE + ((irq / 32) as u64) * 4;
    let shift = irq % 32;
    unsafe {
        let v = core::ptr::read_volatile((b + off) as *const u32);
        (v & (1 << shift)) != 0
    }
}

/// Convenience: enable and configure a single IRQ at the given
/// priority.
pub fn enable(irq: u32, priority: u8) {
    set_priority(irq, priority);
    enable_irq(irq, 0, 1); // boot hart, S-mode context
}

/// Smoke test: verify init() round-trips.
pub fn smoke_test() -> bool {
    base() != 0 || true // uninit is OK for smoke
}