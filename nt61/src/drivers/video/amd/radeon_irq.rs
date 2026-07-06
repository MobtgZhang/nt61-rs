//! AMD Radeon Interrupt Handling
//
//! Implements interrupt handling for vblank and other events

use crate::drivers::video::amd::radeon_reg::*;

/// Interrupt handler
pub struct RadeonIrqHandler {
    /// MMIO base
    mmio_base: u64,
    /// VBlank callback
    vblank_callback: Option<fn(u32)>,
}

impl RadeonIrqHandler {
    /// Create new handler
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            vblank_callback: None,
        }
    }

    /// Read register
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write register
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.mmio_base + offset as u64) as *mut u32,
                value,
            )
        }
    }

    /// Register vblank callback
    pub fn register_vblank(&mut self, callback: fn(u32)) {
        self.vblank_callback = Some(callback);
    }

    /// Handle interrupt
    pub fn handle_irq(&mut self) -> bool {
        let status = self.read_reg(RBBM_INT_STATUS);
        if status == 0 {
            return false;
        }

        if status & RBBM_INT_VBLANK != 0 {
            if let Some(cb) = self.vblank_callback {
                cb(0);
            }
        }

        // Clear interrupts
        self.write_reg(RBBM_INT_STATUS, status);

        true
    }

    /// Enable vblank interrupt
    pub fn enable_vblank(&self) {
        let mask = self.read_reg(RBBM_INT_MASK);
        self.write_reg(RBBM_INT_MASK, mask | RBBM_INT_VBLANK);
    }

    /// Disable vblank interrupt
    pub fn disable_vblank(&self) {
        let mask = self.read_reg(RBBM_INT_MASK);
        self.write_reg(RBBM_INT_MASK, mask & !RBBM_INT_VBLANK);
    }
}
