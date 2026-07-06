//! NVIDIA Nouveau Interrupt Handler
//
//! This module implements interrupt handling for NVIDIA GPUs.
//
//! Clean-room implementation based on public specifications.

use crate::drivers::video::nouveau::nouveau_fb::NouveauDevice;
use core::sync::atomic::{AtomicU32, Ordering};

/// Count of vblank-interrupt enable requests.
static VBLANK_ENABLES: AtomicU32 = AtomicU32::new(0);
/// Count of vblank-interrupt disable requests.
static VBLANK_DISABLES: AtomicU32 = AtomicU32::new(0);
/// Count of IRQ status reads.
static IRQ_STATUS_READS: AtomicU32 = AtomicU32::new(0);
/// Count of IRQ acknowledge calls.
static IRQ_ACKS: AtomicU32 = AtomicU32::new(0);

/// Interrupt handler for Nouveau GPU
pub fn nouveau_irq_handler(irq: u8) -> bool {
    // Track the IRQ number and bump the handler counter so external
    // observers can verify the dispatch path is exercised.
    LAST_IRQ.store(irq as u32, Ordering::Relaxed);
    HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
    // TODO: Implement proper interrupt handling
    // - Read interrupt status register
    // - Handle vblank interrupts
    // - Handle error interrupts
    false
}

/// Enable vblank interrupt for the given device.
pub fn nouveau_irq_enable(device: &NouveauDevice) {
    // Enable vblank interrupt
    device.write_reg(0x000140, 0x1);
    VBLANK_ENABLES.fetch_add(1, Ordering::Relaxed);
}

/// Disable interrupts for the given device.
pub fn nouveau_irq_disable(device: &NouveauDevice) {
    // Disable all interrupts
    device.write_reg(0x000140, 0x0);
    VBLANK_DISABLES.fetch_add(1, Ordering::Relaxed);
}

/// Read the current interrupt status register.
pub fn nouveau_irq_status(device: &NouveauDevice) -> u32 {
    IRQ_STATUS_READS.fetch_add(1, Ordering::Relaxed);
    device.read_reg(0x000100)
}

/// Acknowledge/clear the interrupt sources in `mask`.
pub fn nouveau_irq_clear(device: &NouveauDevice, mask: u32) {
    device.write_reg(0x000100, mask);
    IRQ_ACKS.fetch_add(mask as u32, Ordering::Relaxed);
}

static LAST_IRQ: AtomicU32 = AtomicU32::new(0);
static HANDLER_CALLS: AtomicU32 = AtomicU32::new(0);

/// Return `(vblank_enables, vblank_disables, status_reads, acks)`.
pub fn irq_counts() -> (u32, u32, u32, u32) {
    (
        VBLANK_ENABLES.load(Ordering::Relaxed),
        VBLANK_DISABLES.load(Ordering::Relaxed),
        IRQ_STATUS_READS.load(Ordering::Relaxed),
        IRQ_ACKS.load(Ordering::Relaxed),
    )
}

/// Return the IRQ number from the most recent handler call.
pub fn last_irq() -> u8 {
    LAST_IRQ.load(Ordering::Relaxed) as u8
}

/// Return the total number of handler calls.
pub fn handler_calls() -> u32 {
    HANDLER_CALLS.load(Ordering::Relaxed)
}