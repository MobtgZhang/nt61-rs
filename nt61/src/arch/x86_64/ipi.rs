//! Inter-Processor Interrupts (IPI)
//
//! IPIs are used for CPU-to-CPU communication in SMP systems:
//! - Reschedule requests
//! - TLB shootdown
//! - Function calls
//! - CPU stop/halt
//
//! IPI vectors are allocated in the high range (0xF0-0xFF) to avoid
//! conflicts with hardware IRQs.

use core::arch::asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::hal::x86_64::apic::{apic_write, apic_read, lapic_reg};

/// IPI vector assignments
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpiVector {
    Reschedule = 0xF0,  // Request reschedule on target CPU
    TlbFlush = 0xF1,    // Flush TLB on target CPU
    FunctionCall = 0xF2, // Execute a function on target CPU
    Stop = 0xF3,        // Stop/halt target CPU
}

impl IpiVector {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0xF0 => Some(IpiVector::Reschedule),
            0xF1 => Some(IpiVector::TlbFlush),
            0xF2 => Some(IpiVector::FunctionCall),
            0xF3 => Some(IpiVector::Stop),
            _ => None,
        }
    }
}

/// IPI delivery mode
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum IpiDeliveryMode {
    Fixed = 0,       // Normal interrupt
    LowestPriority = 1,
    Smi = 2,
    Nmi = 4,
    Init = 5,
    StartUp = 6,
}

/// IPI destination shorthand

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum IpiDestination {
    NoShorthand = 0,      // Use destination field
    Self_ = 1,            // Send to self
    AllIncludingSelf = 2, // Broadcast to all CPUs
    AllExcludingSelf = 3, // Broadcast to all except self
}

/// IPI statistics
static IPI_SENT: AtomicU64 = AtomicU64::new(0);
static IPI_RECEIVED: AtomicU64 = AtomicU64::new(0);
static IPI_RESCHEDULE_COUNT: AtomicU64 = AtomicU64::new(0);
static IPI_TLB_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);

/// Send an IPI to a specific CPU (by APIC ID)
pub fn send_ipi(target_apic_id: u32, vector: IpiVector) {
    send_ipi_raw(target_apic_id, vector.as_u8() as u32, IpiDeliveryMode::Fixed);
    IPI_SENT.fetch_add(1, Ordering::Relaxed);
}

/// Send IPI with custom delivery mode
pub fn send_ipi_raw(target_apic_id: u32, vector: u32, delivery_mode: IpiDeliveryMode) {
    // Wait for any pending IPI to complete
    // Bit 12 of ICR_LOW is the delivery status bit
    let mut timeout = 10000;
    while timeout > 0 {
        let icr_low = apic_read(lapic_reg::ICR_LOW);
        if (icr_low & (1 << 12)) == 0 {
            break;
        }
        timeout -= 1;
        unsafe { asm!("pause", options(nostack, preserves_flags)); }
    }

    if timeout == 0 {
        // Timeout waiting for IPI completion
        return;
    }

    // Write destination APIC ID to ICR high (bits 56-63)
    apic_write(lapic_reg::ICR_HIGH, (target_apic_id & 0xFF) << 24);

    // Write vector and delivery mode to ICR low
    // Bits 0-7: Vector
    // Bits 8-10: Delivery Mode
    // Bit 11: Destination Mode (0=physical, 1=logical)
    // Bit 12: Delivery Status (read-only)
    // Bit 13: Reserved
    // Bit 14: Level (1=assert, 0=de-assert)
    // Bit 15: Trigger Mode (0=edge, 1=level)
    // Bits 18-19: Destination Shorthand
    let icr_low = vector
        | ((delivery_mode as u32) << 8)
        | (1 << 14); // Assert level

    apic_write(lapic_reg::ICR_LOW, icr_low);
}

/// Broadcast an IPI to all CPUs except self
pub fn broadcast_ipi(vector: IpiVector) {
    broadcast_ipi_raw(vector.as_u8() as u32, IpiDeliveryMode::Fixed);
    IPI_SENT.fetch_add(1, Ordering::Relaxed);
}

/// Broadcast IPI with custom delivery mode
pub fn broadcast_ipi_raw(vector: u32, delivery_mode: IpiDeliveryMode) {
    // Wait for any pending IPI to complete
    let mut timeout = 10000;
    while timeout > 0 {
        let icr_low = apic_read(lapic_reg::ICR_LOW);
        if (icr_low & (1 << 12)) == 0 {
            break;
        }
        timeout -= 1;
        unsafe { asm!("pause", options(nostack, preserves_flags)); }
    }

    if timeout == 0 {
        return;
    }

    // Use destination shorthand: all excluding self (bits 18-19 = 11)
    let icr_low = vector
        | ((delivery_mode as u32) << 8)
        | (1 << 14)  // Assert level
        | ((IpiDestination::AllExcludingSelf as u32) << 18);

    apic_write(lapic_reg::ICR_LOW, icr_low);
}

/// Send a reschedule IPI to a specific CPU
pub fn send_reschedule_ipi(target_apic_id: u32) {
    send_ipi(target_apic_id, IpiVector::Reschedule);
}

/// Broadcast reschedule IPI to all CPUs
pub fn broadcast_reschedule_ipi() {
    broadcast_ipi(IpiVector::Reschedule);
}

/// Send a TLB flush IPI to a specific CPU
pub fn send_tlb_flush_ipi(target_apic_id: u32) {
    send_ipi(target_apic_id, IpiVector::TlbFlush);
    IPI_TLB_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Broadcast TLB flush IPI to all CPUs
pub fn broadcast_tlb_flush_ipi() {
    broadcast_ipi(IpiVector::TlbFlush);
    IPI_TLB_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Handle reschedule IPI
pub fn handle_reschedule_ipi() {
    IPI_RECEIVED.fetch_add(1, Ordering::Relaxed);
    IPI_RESCHEDULE_COUNT.fetch_add(1, Ordering::Relaxed);

    // Mark that this CPU needs to reschedule
    if let Some(percpu) = crate::arch::x86_64::percpu::PerCpuData::try_current() {
        percpu.set_need_reschedule();
        percpu.ipi_count += 1;
    }

    // Send EOI to acknowledge the interrupt
    unsafe { apic_eoi(); }
}

/// Handle TLB flush IPI
pub fn handle_tlb_flush_ipi() {
    IPI_RECEIVED.fetch_add(1, Ordering::Relaxed);

    // Flush TLB by reloading CR3
    unsafe {
        asm!(
            "mov {0}, cr3",
            "mov cr3, {0}",
            out(reg) _,
            options(nostack, preserves_flags)
        );
    }

    if let Some(percpu) = crate::arch::x86_64::percpu::PerCpuData::try_current() {
        percpu.tlb_flushes += 1;
        percpu.ipi_count += 1;
    }

    // Send EOI
    unsafe { apic_eoi(); }
}

/// Handle function call IPI
pub fn handle_function_call_ipi() {
    IPI_RECEIVED.fetch_add(1, Ordering::Relaxed);

    // TODO: Implement function call mechanism
    // This would involve a queue of function pointers and arguments
    // that each CPU can execute when it receives this IPI

    if let Some(percpu) = crate::arch::x86_64::percpu::PerCpuData::try_current() {
        percpu.ipi_count += 1;
    }

    // Send EOI
    unsafe { apic_eoi(); }
}

/// Handle stop IPI
pub fn handle_stop_ipi() {
    IPI_RECEIVED.fetch_add(1, Ordering::Relaxed);

    // Disable interrupts and halt
    unsafe {
        asm!(
            "cli",
            "2:",
            "hlt",
            "jmp 2b",
            options(noreturn)
        );
    }
}

/// Send End-Of-Interrupt to the local APIC
#[inline]
pub unsafe fn apic_eoi() {
    apic_write(lapic_reg::EOI, 0);
}

/// Get IPI statistics
pub fn get_ipi_stats() -> IpiStats {
    IpiStats {
        sent: IPI_SENT.load(Ordering::Relaxed),
        received: IPI_RECEIVED.load(Ordering::Relaxed),
        reschedule_count: IPI_RESCHEDULE_COUNT.load(Ordering::Relaxed),
        tlb_flush_count: IPI_TLB_FLUSH_COUNT.load(Ordering::Relaxed),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IpiStats {
    pub sent: u64,
    pub received: u64,
    pub reschedule_count: u64,
    pub tlb_flush_count: u64,
}

/// Initialize IPI subsystem
pub fn init() {
    // IPI vectors will be registered in IDT during idt::init()
    // Nothing to do here for now
}

/// Flush TLB on all CPUs (including self)
pub fn flush_tlb_all() {
    // Flush local TLB
    unsafe {
        asm!(
            "mov {0}, cr3",
            "mov cr3, {0}",
            out(reg) _,
            options(nostack, preserves_flags)
        );
    }

    // Send TLB flush IPI to all other CPUs
    broadcast_tlb_flush_ipi();

    // Wait a bit for other CPUs to process the IPI
    // This is a simple spin; a more sophisticated implementation
    // would use acknowledgments
    for _ in 0..1000 {
        unsafe { asm!("pause", options(nostack, preserves_flags)); }
    }
}

/// Flush TLB for a specific virtual address on all CPUs
pub fn flush_tlb_page(vaddr: u64) {
    // Flush local TLB entry
    unsafe {
        asm!(
            "invlpg [{}]",
            in(reg) vaddr,
            options(nostack, preserves_flags)
        );
    }

    // For simplicity, send full TLB flush to other CPUs
    // A more sophisticated implementation would send the address
    broadcast_tlb_flush_ipi();
}
