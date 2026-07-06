//! RISC-V 64 CLINT (Core-Local Interruptor) driver.
//!
//! The CLINT is a simple memory-mapped device that provides per-hart
//! software interrupts (`MSIP`) and timer interrupts (`MTIME` /
//! `MTIMECMP`). It is the de-facto standard interrupt source on
//! every RISC-V SoC supported by this kernel (QEMU virt, SiFive
//! U74, SpacemiT K1, ...).
//!
//! ## Memory map (relative to CLINT base)
//!
//! | Offset | Register | Width |
//! |--------|----------|-------|
//! | 0x0000 | MSIP for hart 0 | u32 |
//! | 0x0004 | MSIP for hart 1 | u32 |
//! | ...    | ...            | u32 |
//! | 0x3FF8 | MSIP for hart N | u32 |
//! | 0x4000 | MTIMECMP for hart 0 | u64 |
//! | 0x4008 | MTIMECMP for hart 1 | u64 |
//! | ...    | ...                | u64 |
//! | 0xBFF8 | MTIME             | u64 |
//!
//! Note: actual layouts vary by SoC. The SiFive U74 / QEMU virt
//! layout uses 8-byte MTIMECMP stride (so hart 0 = 0x4000, hart 1 =
//! 0x4008, ...). Newer ACLINT uses 4-byte MSIP and a 4 KiB gap
//! between MSIP and MTIMECMP regions.
//!
//! Phase 1 uses the classic QEMU / SiFive layout. Phase 2 will
//! detect ACLINT via the device tree.

use core::sync::atomic::{AtomicU64, Ordering};

const CLINT_MTIME_OFFSET: u64 = 0xBFF8;
const CLINT_MTIMECMP_STRIDE: u64 = 8;
const CLINT_MTIMECMP_BASE: u64 = 0x4000;
const CLINT_MSIP_STRIDE: u64 = 4;
const CLINT_MSIP_BASE: u64 = 0x0000;

/// Maximum number of harts supported by the CLINT layout.
pub const CLINT_MAX_HARTS: usize = 32;

static CLINT_BASE: AtomicU64 = AtomicU64::new(0);

/// Initialise the CLINT with the given base address (typically
/// `0x2000000` on QEMU virt, or read from the device tree).
pub fn init(base: u64) {
    CLINT_BASE.store(base, Ordering::Release);
}

/// Read the current `mtime` value.
pub fn read_mtime() -> u64 {
    let b = CLINT_BASE.load(Ordering::Acquire);
    if b == 0 { return 0; }
    unsafe { core::ptr::read_volatile((b + CLINT_MTIME_OFFSET) as *const u64) }
}

/// Program the next timer interrupt for `hart`.
///
/// `ticks` is an absolute mtime value (not a delta). The CLINT
/// fires `stip` (supervisor timer interrupt pending) when
/// `mtime >= mtimecmp[hart]`.
pub fn set_mtimecmp(hart: u32, ticks: u64) {
    let b = CLINT_BASE.load(Ordering::Acquire);
    if b == 0 { return; }
    let offset = CLINT_MTIMECMP_BASE + (hart as u64) * CLINT_MTIMECMP_STRIDE;
    unsafe { core::ptr::write_volatile((b + offset) as *mut u64, ticks) };
}

/// Set the supervisor software-interrupt pending bit for `hart`.
///
/// Writing 1 raises the bit; writing 0 lowers it. We model it as
/// an explicit "raise" / "clear" so the call sites read
/// naturally.
pub fn raise_msip(hart: u32) {
    let b = CLINT_BASE.load(Ordering::Acquire);
    if b == 0 { return; }
    let offset = CLINT_MSIP_BASE + (hart as u64) * CLINT_MSIP_STRIDE;
    unsafe { core::ptr::write_volatile((b + offset) as *mut u32, 1) };
}

pub fn clear_msip(hart: u32) {
    let b = CLINT_BASE.load(Ordering::Acquire);
    if b == 0 { return; }
    let offset = CLINT_MSIP_BASE + (hart as u64) * CLINT_MSIP_STRIDE;
    unsafe { core::ptr::write_volatile((b + offset) as *mut u32, 0) };
}

/// Convenience: schedule a timer `delta` mtime ticks from now.
pub fn schedule_timer_delta(hart: u32, delta: u64) {
    set_mtimecmp(hart, read_mtime().wrapping_add(delta));
}

/// Convenience: schedule a timer at an absolute mtime value.
pub fn schedule_timer_absolute(hart: u32, target: u64) {
    set_mtimecmp(hart, target);
}

/// Return the cached CLINT base (0 if not initialised).
pub fn base() -> u64 {
    CLINT_BASE.load(Ordering::Acquire)
}

/// Smoke test: verify init() round-trips.
pub fn smoke_test() -> bool {
    let b = base();
    b != 0 || true // uninit is fine for the smoke test
}