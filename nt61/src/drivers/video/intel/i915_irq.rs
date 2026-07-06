//! Intel i915 Interrupt Handling
//
//! Implements interrupt handling for vblank and other display events

use crate::drivers::video::intel::i915_reg::*;

/// Interrupt status
#[derive(Debug, Clone, Copy)]
pub struct InterruptStatus {
    /// VBlank A pending
    pub vblank_a: bool,
    /// VBlank B pending
    pub vblank_b: bool,
    /// Flip complete A pending
    pub flip_a: bool,
    /// Flip complete B pending
    pub flip_b: bool,
    /// Error pending
    pub error: bool,
}

impl Default for InterruptStatus {
    fn default() -> Self {
        Self {
            vblank_a: false,
            vblank_b: false,
            flip_a: false,
            flip_b: false,
            error: false,
        }
    }
}

/// i915 interrupt handler
pub struct I915IrqHandler {
    /// MMIO base
    mmio_base: u64,
    /// VBlank callback
    vblank_callback: Option<fn(u32)>,
    /// Flip callback
    flip_callback: Option<fn(u32)>,
}

impl I915IrqHandler {
    /// Create new handler
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            vblank_callback: None,
            flip_callback: None,
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

    /// Register flip callback
    pub fn register_flip(&mut self, callback: fn(u32)) {
        self.flip_callback = Some(callback);
    }

    /// Handle interrupt
    pub fn handle_irq(&mut self) -> bool {
        let iir = self.read_reg(DEIIR_RENDER);
        if iir == 0 {
            return false;
        }

        // Process VBlank A
        if iir & DEIIR_PIPEA_VBLANK != 0 {
            if let Some(cb) = self.vblank_callback {
                cb(0);
            }
        }

        // Process VBlank B
        if iir & DEIIR_PIPEB_VBLANK != 0 {
            if let Some(cb) = self.vblank_callback {
                cb(1);
            }
        }

        // Process flip complete A
        if iir & DEIIR_PIPEA_FLIP_DONE != 0 {
            if let Some(cb) = self.flip_callback {
                cb(0);
            }
        }

        // Clear interrupts
        self.write_reg(DEIIR_RENDER, iir);

        true
    }

    /// Enable vblank interrupt
    pub fn enable_vblank(&self, pipe: u32) {
        let current = self.read_reg(DEIER);
        let mask = match pipe {
            0 => DEIER_VBLANK,
            1 => DEIER_VBLANK << 1,
            _ => 0,
        };
        self.write_reg(DEIER, current | mask);
    }

    /// Disable vblank interrupt
    pub fn disable_vblank(&self, pipe: u32) {
        let current = self.read_reg(DEIER);
        let mask = match pipe {
            0 => DEIER_VBLANK,
            1 => DEIER_VBLANK << 1,
            _ => 0,
        };
        self.write_reg(DEIER, current & !mask);
    }

    /// Get interrupt status
    pub fn get_status(&self) -> InterruptStatus {
        let iir = self.read_reg(DEIIR_RENDER);

        InterruptStatus {
            vblank_a: iir & DEIIR_PIPEA_VBLANK != 0,
            vblank_b: iir & DEIIR_PIPEB_VBLANK != 0,
            flip_a: iir & DEIIR_PIPEA_FLIP_DONE != 0,
            flip_b: iir & DEIIR_PIPEA_FLIP_DONE != 0,
            error: false,
        }
    }
}
