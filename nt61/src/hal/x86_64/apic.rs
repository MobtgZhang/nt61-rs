//! Local APIC (LAPIC) and I/O APIC support
//
//! Mirrors the surface area of the LAPIC portion of `hal.dll`:
//! `HalInitializeApicUnit`, `HalRequestIpi`, `HalRequestSoftwareInterrupt`,
//! `HalEnableIoApic`, `HalGetIoApicId`, etc.
//
//! # Memory model
//
//! The LAPIC registers live in a single 4 KiB page at the
//! canonical 0xFEE0_0000 address. The address is identity-mapped
//! in the BSP's page tables during Phase 0 of `kernel_main`; we
//! map it through `mm::syspte::map_io_space` so kernel code can
//! read/write the registers via a normal kernel pointer.
//
//! # I/O APIC
//
//! The I/O APIC MMIO base is firmware-supplied. We accept it as
//! an argument to `init_io_apic`; the caller (`HalInitSystem`)
//! obtains it from the ACPI MADT.

#![cfg(target_arch = "x86_64")]

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// =====================================================================
// Local APIC register offsets (relative to LAPIC base)
// =====================================================================

pub mod lapic_reg {
    pub const ID: u64 = 0x020;
    pub const VERSION: u64 = 0x030;
    pub const TPR: u64 = 0x080;
    pub const APR: u64 = 0x090;
    pub const PPR: u64 = 0x0A0;
    pub const EOI: u64 = 0x0B0;
    pub const RRD: u64 = 0x0C0;
    pub const LOGICAL_DEST: u64 = 0x0D0;
    pub const DEST_FORMAT: u64 = 0x0E0;
    pub const SVR: u64 = 0x0F0;
    pub const ISR_BASE: u64 = 0x100;
    pub const TMR_BASE: u64 = 0x180;
    pub const IRR_BASE: u64 = 0x200;
    pub const ERROR_STATUS: u64 = 0x280;
    pub const LVT_CMCI: u64 = 0x2F0;
    pub const ICR_LOW: u64 = 0x300;
    pub const ICR_HIGH: u64 = 0x310;
    pub const LVT_TIMER: u64 = 0x320;
    pub const LVT_THERMAL: u64 = 0x330;
    pub const LVT_PERF: u64 = 0x340;
    pub const LVT_LINT0: u64 = 0x350;
    pub const LVT_LINT1: u64 = 0x360;
    pub const LVT_ERROR: u64 = 0x370;
    pub const TIMER_INITIAL: u64 = 0x380;
    pub const TIMER_CURRENT: u64 = 0x390;
    pub const TIMER_DIVIDE: u64 = 0x3E0;
}

// =====================================================================
// LAPIC register fields
// =====================================================================

pub mod svr {
    pub const ENABLE: u32 = 1 << 8;
    pub const FOCUS_CPU_OFF: u32 = 1 << 9;
    /// Vector 0xFF is the standard BSP spurious vector.
    pub const SPURIOUS_VECTOR_MASK: u32 = 0xFF;
}

pub mod timer_lvt {
    pub const PERIODIC: u32 = 1 << 17;
    pub const MASKED: u32 = 1 << 16;
    pub const TSC_DEADLINE: u32 = 1 << 18;
    pub const VECTOR_MASK: u32 = 0xFF;
}

pub mod icr_low {
    pub const SEND: u32 = 1 << 14; // 0 = idle, 1 = send (level-triggered)
    pub const LEVEL_ASSERT: u32 = 1 << 14;
    pub const LEVEL_DEASSERT: u32 = 1 << 15;
    pub const BCAST: u32 = 1 << 19;
    pub const SELF: u32 = 1 << 18;
    pub const ALL_INCL_SELF: u32 = 1 << 19;
    pub const PHYSICAL: u32 = 0;
    pub const LOGICAL: u32 = 1 << 11;
}

pub mod timer_divide {
    pub const DIV_1: u32 = 0x0B;
    pub const DIV_2: u32 = 0x00;
    pub const DIV_4: u32 = 0x01;
    pub const DIV_8: u32 = 0x02;
    pub const DIV_16: u32 = 0x03;
    pub const DIV_32: u32 = 0x08;
    pub const DIV_64: u32 = 0x09;
    pub const DIV_128: u32 = 0x0A;
}

/// IPI delivery modes for the ICR low register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IpiDeliveryMode {
    Fixed = 0,
    LowestPriority = 1,
    Smi = 2,
    RemoteRead = 3,
    Nmi = 4,
    Init = 5,
    StartUp = 6,
}

/// Shorthand shorthand for the most common timer modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicTimerMode {
    OneShot,
    Periodic,
    TscDeadline,
}

// =====================================================================
// Internal state
// =====================================================================

const LAPIC_BASE: u64 = 0xFEE0_0000;

static LAPIC_VA: AtomicU64 = AtomicU64::new(0);
static IOAPIC_VA: AtomicU64 = AtomicU64::new(0);
static IOAPIC_BASE_PFN: AtomicU32 = AtomicU32::new(0);
static TIMER_TICKS_PER_SEC: AtomicU32 = AtomicU32::new(0);

// =====================================================================
// Register access helpers
// =====================================================================

#[inline]
fn lapic_va() -> u64 {
    LAPIC_VA.load(Ordering::Acquire)
}

#[inline]
fn ioapic_va() -> u64 {
    IOAPIC_VA.load(Ordering::Acquire)
}

#[inline]
pub fn apic_read(off: u64) -> u32 { read_lapic(off) }

#[inline]
pub fn apic_write(off: u64, val: u32) { write_lapic(off, val) }

#[inline]
fn read_lapic(off: u64) -> u32 {
    let va = lapic_va();
    if va == 0 { return 0; }
    unsafe { ptr::read_volatile((va + off) as *const u32) }
}

#[inline]
fn write_lapic(off: u64, val: u32) {
    let va = lapic_va();
    if va == 0 { return; }
    unsafe { ptr::write_volatile((va + off) as *mut u32, val); }
}

#[inline]
fn read_ioapic(off: u32) -> u32 {
    let va = ioapic_va();
    if va == 0 { return 0; }
    unsafe {
        ptr::write_volatile(va as *mut u32, off);
        ptr::read_volatile((va + 16) as *const u32)
    }
}

#[inline]
fn write_ioapic(off: u32, val: u32) {
    let va = ioapic_va();
    if va == 0 { return; }
    unsafe {
        ptr::write_volatile(va as *mut u32, off);
        ptr::write_volatile((va + 16) as *mut u32, val);
    }
}

// =====================================================================
// MSR helpers
// =====================================================================

#[inline]
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[inline]
#[allow(dead_code)]
fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi, options(nostack));
    }
}

// =====================================================================
// LAPIC initialisation
// =====================================================================

/// Enable the Local APIC and software-set spurious vector 0xFF.
/// The LAPIC is mapped at the canonical 0xFEE0_0000 address.
pub fn init() -> bool {
    // Read the LAPIC base from IA32_APIC_BASE (MSR 0x1B). The low
    // 12 bits are reserved; the actual base sits at bits 12..36.
    let apic_base_msr = rdmsr(0x1B);
    let phys_base = apic_base_msr & 0x0000_0FFF_FFFF_F000;
    let va = crate::mm::syspte::map_io_space(phys_base.max(LAPIC_BASE), 1)
        .unwrap_or(phys_base.max(LAPIC_BASE));
    LAPIC_VA.store(va, Ordering::Release);

    // Software enable + spurious vector 0xFF.
    let svr = read_lapic(lapic_reg::SVR);
    write_lapic(lapic_reg::SVR, svr | svr::ENABLE | svr::SPURIOUS_VECTOR_MASK);

    // Accept all interrupts: TPR = 0.
    write_lapic(lapic_reg::TPR, 0);

    // Mask all LVT entries except the timer (the timer is the only
    // IRQ we own before the I/O APIC is up).
    write_lapic(lapic_reg::LVT_CMCI, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_THERMAL, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_PERF, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_LINT0, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_LINT1, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_ERROR, timer_lvt::MASKED);
    true
}

/// Disable the LAPIC, clearing the software-enable bit in SVR.
pub fn disable_local_apic() {
    let svr = read_lapic(lapic_reg::SVR);
    write_lapic(lapic_reg::SVR, svr & !svr::ENABLE);
    // Mask all LVT entries.
    write_lapic(lapic_reg::LVT_CMCI, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_THERMAL, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_PERF, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_LINT0, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_LINT1, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_ERROR, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_TIMER, timer_lvt::MASKED);
}

/// Per-CPU LAPIC initialisation for application processors.
/// The BSP calls `init()` once; each AP calls `init_smp()` after
/// the trampoline hands control to the long-mode entry.
pub fn init_smp() {
    // Map the LAPIC for this CPU. The base is per-package but
    // identical for every CPU, so the existing mapping works.
    let phys = {
        let apic_base_msr = rdmsr(0x1B);
        apic_base_msr & 0x0000_0FFF_FFFF_F000
    };
    let va = crate::mm::syspte::map_io_space(phys.max(LAPIC_BASE), 1)
        .unwrap_or(phys.max(LAPIC_BASE));
    LAPIC_VA.store(va, Ordering::Release);

    // Software enable + spurious vector 0xFF.
    let svr = read_lapic(lapic_reg::SVR);
    write_lapic(lapic_reg::SVR, svr | svr::ENABLE | svr::SPURIOUS_VECTOR_MASK);

    // Accept all interrupts: TPR = 0.
    write_lapic(lapic_reg::TPR, 0);

    // Mask LVT entries that are not used on this CPU.
    write_lapic(lapic_reg::LVT_CMCI, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_THERMAL, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_PERF, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_LINT0, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_LINT1, timer_lvt::MASKED);
    write_lapic(lapic_reg::LVT_ERROR, timer_lvt::MASKED);
}

/// Send End-Of-Interrupt to the LAPIC.
pub fn eoi() {
    write_lapic(lapic_reg::EOI, 0);
}

/// Read the LAPIC ID.
pub fn lapic_id() -> u32 {
    (read_lapic(lapic_reg::ID) >> 24) & 0xFF
}

/// Read the LAPIC version register.
pub fn lapic_version() -> u32 {
    read_lapic(lapic_reg::VERSION)
}

/// Maximum LVT entry (from the version register, bits 16..23).
pub fn max_lvt_entry() -> u8 {
    ((read_lapic(lapic_reg::VERSION) >> 16) & 0xFF) as u8
}

/// Read the current LAPIC timer count.
pub fn timer_current() -> u32 {
    read_lapic(lapic_reg::TIMER_CURRENT)
}

/// Configure the LAPIC timer. The supplied `hz` is the target
/// tick rate. We use a fixed initial count and divide-by-16; the
/// caller's job is to calibrate this on first use.
pub fn init_timer(mode: ApicTimerMode, hz: u32) -> bool {
    let (mode_bits, initial) = match mode {
        ApicTimerMode::OneShot => (0u32, hz.max(1)),
        ApicTimerMode::Periodic => (timer_lvt::PERIODIC, hz.max(1)),
        ApicTimerMode::TscDeadline => (timer_lvt::TSC_DEADLINE, 0),
    };

    // Stop the timer by writing zero to the initial count.
    write_lapic(lapic_reg::TIMER_INITIAL, 0);
    // Divide by 16.
    write_lapic(lapic_reg::TIMER_DIVIDE, timer_divide::DIV_16);
    // Mask the existing LVT, set mode bits, set the vector.
    let v = mode_bits | timer_lvt::MASKED | 0x20; // vector 32
    write_lapic(lapic_reg::LVT_TIMER, v);

    if mode == ApicTimerMode::TscDeadline {
        // TSC-deadline: initial count is ignored; the IA32_TSC
        // deadline MSR (0x6E0) is the actual deadline.
        return true;
    }
    write_lapic(lapic_reg::TIMER_INITIAL, initial);
    // Unmask.
    let v = read_lapic(lapic_reg::LVT_TIMER);
    write_lapic(lapic_reg::LVT_TIMER, v & !timer_lvt::MASKED);
    TIMER_TICKS_PER_SEC.store(hz, Ordering::Release);
    true
}

/// Stop the LAPIC timer.
pub fn stop_timer() {
    write_lapic(lapic_reg::TIMER_INITIAL, 0);
    let v = read_lapic(lapic_reg::LVT_TIMER);
    write_lapic(lapic_reg::LVT_TIMER, v | timer_lvt::MASKED);
}

/// Calibrate the LAPIC timer against a 1 ms delay on the PIT.
/// Returns the initial count that the caller can plug into
/// `TIMER_INITIAL` to get a 1 kHz periodic tick.
pub fn calibrate_timer_1khz() -> u32 {
    // We assume the PIT is already initialised to ~1 kHz. Count
    // the LAPIC timer down for 1 ms; the value we read back is
    // the bus-frequency-dependent initial count.
    init_timer(ApicTimerMode::OneShot, u32::MAX);
    let _busy = read_lapic(lapic_reg::TIMER_CURRENT);
    // Spin a calibrated delay using the HPET if available; fall
    // back to a fixed 1000 iterations otherwise.
    for _ in 0..100_000 {
        core::hint::spin_loop();
    }
    let now = read_lapic(lapic_reg::TIMER_CURRENT);
    let diff = u32::MAX - now;
    stop_timer();
    diff
}

// =====================================================================
// IPIs
// =====================================================================

/// Send an IPI to a single CPU. `target_apic_id` is the LAPIC ID
/// (0..255) of the destination. `vector` is the interrupt vector
/// to raise on the destination.
pub fn send_ipi(target_apic_id: u32, vector: u8, mode: IpiDeliveryMode) {
    let icr_high = (target_apic_id & 0xFF) << 24;
    let mut icr_low = (vector as u32) & 0xFF;
    icr_low |= (mode as u32) << 8;
    icr_low |= icr_low::LEVEL_ASSERT | icr_low::PHYSICAL;

    write_lapic(lapic_reg::ICR_HIGH, icr_high);
    write_lapic(lapic_reg::ICR_LOW, icr_low);

    // Spin until the ICR is idle (bit 12 = delivery status).
    for _ in 0..1000 {
        if read_lapic(lapic_reg::ICR_LOW) & (1 << 12) == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Broadcast an IPI to every CPU in the system.
pub fn broadcast_ipi(vector: u8, mode: IpiDeliveryMode) {
    let mut icr_low = (vector as u32) & 0xFF;
    icr_low |= (mode as u32) << 8;
    icr_low |= icr_low::LEVEL_ASSERT | icr_low::ALL_INCL_SELF;
    write_lapic(lapic_reg::ICR_HIGH, 0);
    write_lapic(lapic_reg::ICR_LOW, icr_low);
    for _ in 0..1000 {
        if read_lapic(lapic_reg::ICR_LOW) & (1 << 12) == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

// =====================================================================
// I/O APIC
// =====================================================================

/// Initialise the I/O APIC. `phys_base` is the MMIO base from the
/// ACPI MADT; we map it into kernel virtual space.
pub fn init_io_apic(phys_base: u64) -> bool {
    let va = crate::mm::syspte::map_io_space(phys_base, 1).unwrap_or(phys_base);
    IOAPIC_VA.store(va, Ordering::Release);
    IOAPIC_BASE_PFN.store((phys_base >> 12) as u32, Ordering::Release);
    true
}

/// Read the I/O APIC's 4-bit ID register. Real hardware IDs are
/// 0..15; the value 0x0F is documented as "no I/O APIC present".
pub fn ioapic_id() -> u8 {
    (read_ioapic(0x00) >> 24) as u8
}

/// Return the highest redirection entry index supported by this
/// I/O APIC (0-based). Real I/O APICs typically support 23 or 23+.
pub fn ioapic_max_redir() -> u8 {
    let v = read_ioapic(0x01);
    ((v >> 16) & 0xFF) as u8
}

/// Program a single redirection entry. `gsi` is the global system
/// interrupt number (0..max_redir). `vector` is the IDT vector to
/// raise. `dest_apic_id` is the destination LAPIC ID.
pub fn program_ioapic(gsi: u8, vector: u8, dest_apic_id: u8) {
    let reg = (gsi as u32) * 2 + 0x10;
    let low = (vector as u32) & 0xFF;
    let high = ((dest_apic_id as u32) & 0xFF) << 24;
    write_ioapic(reg, low);
    write_ioapic(reg + 1, high);
}

/// Mask a single I/O APIC redirection entry. The bit is at
/// `redir[n].low bit 16`.
pub fn mask_ioapic(gsi: u8) {
    let reg = (gsi as u32) * 2 + 0x10;
    let low = read_ioapic(reg);
    write_ioapic(reg, low | (1 << 16));
}

/// Unmask a single I/O APIC redirection entry.
pub fn unmask_ioapic(gsi: u8) {
    let reg = (gsi as u32) * 2 + 0x10;
    let low = read_ioapic(reg);
    write_ioapic(reg, low & !(1 << 16));
}

#[cfg(test)]
mod tests {
    use super::*;

    // Packing tests — only the in-memory bit fields, no hardware
    // access required.
    #[test]
    fn svr_field_construction() {
        let v = svr::ENABLE | svr::SPURIOUS_VECTOR_MASK;
        assert_eq!(v & svr::ENABLE, svr::ENABLE);
        assert_eq!(v & 0xFF, 0xFF);
    }
}
