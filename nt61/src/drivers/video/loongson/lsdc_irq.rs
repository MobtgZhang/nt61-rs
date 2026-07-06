//! Loongson Display Controller Interrupt Handling
//
//! Implements interrupt handling for vblank and error interrupts

use crate::drivers::video::loongson::lsdc_reg::*;

/// Interrupt types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsDcInterrupt {
    /// Vertical blank (Pipeline A)
    VBlankA,
    /// Vertical blank (Pipeline B)
    VBlankB,
    /// Horizontal blank (Pipeline A)
    HBlankA,
    /// Horizontal blank (Pipeline B)
    HBlankB,
    /// FIFO underflow
    FifoUnderflow,
    /// Register update
    RegUpdate,
    /// Line flag
    LineFlag,
}

impl LsDcInterrupt {
    /// Get interrupt mask bit
    pub fn mask_bit(&self) -> u32 {
        match self {
            LsDcInterrupt::VBlankA => INT_VBLANK_A,
            LsDcInterrupt::VBlankB => INT_VBLANK_B,
            LsDcInterrupt::HBlankA => INT_HBLANK_A,
            LsDcInterrupt::HBlankB => INT_HBLANK_B,
            LsDcInterrupt::FifoUnderflow => INT_FIFO_UNDERFLOW,
            LsDcInterrupt::RegUpdate => INT_REG_UPDATE,
            LsDcInterrupt::LineFlag => INT_LINE_FLAG,
        }
    }
}

/// Interrupt handler callback
pub type InterruptCallback = fn(LsDcInterrupt);

/// Loongson DC interrupt handler
pub struct LsDcIrqHandler {
    /// DC base address
    dc_base: u64,
    /// Registered callbacks
    callbacks: [Option<InterruptCallback>; 7],
    /// Current interrupt status
    status: u32,
}

impl LsDcIrqHandler {
    /// Create a new interrupt handler
    pub fn new(dc_base: u64) -> Self {
        Self {
            dc_base,
            callbacks: [None, None, None, None, None, None, None],
            status: 0,
        }
    }

    /// Read a register
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.dc_base + offset as u64) as *const u32) }
    }

    /// Write a register
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.dc_base + offset as u64) as *mut u32,
                value,
            )
        }
    }

    /// Register an interrupt callback
    pub fn register_callback(&mut self, irq: LsDcInterrupt, callback: InterruptCallback) {
        let idx = irq_to_index(irq);
        if idx < self.callbacks.len() {
            self.callbacks[idx] = Some(callback);
        }
    }

    /// Unregister an interrupt callback
    pub fn unregister_callback(&mut self, irq: LsDcInterrupt) {
        let idx = irq_to_index(irq);
        if idx < self.callbacks.len() {
            self.callbacks[idx] = None;
        }
    }

    /// Handle an interrupt
    ///
    /// Returns true if an interrupt was handled.
    pub fn handle_irq(&mut self) -> bool {
        // Read interrupt status
        let status = self.read_reg(DC_INT);
        if status == 0 {
            return false;
        }

        self.status = status;

        // Process each interrupt type
        if status & INT_VBLANK_A != 0 {
            self.invoke_callback(LsDcInterrupt::VBlankA);
        }
        if status & INT_VBLANK_B != 0 {
            self.invoke_callback(LsDcInterrupt::VBlankB);
        }
        if status & INT_HBLANK_A != 0 {
            self.invoke_callback(LsDcInterrupt::HBlankA);
        }
        if status & INT_HBLANK_B != 0 {
            self.invoke_callback(LsDcInterrupt::HBlankB);
        }
        if status & INT_FIFO_UNDERFLOW != 0 {
            self.invoke_callback(LsDcInterrupt::FifoUnderflow);
        }
        if status & INT_REG_UPDATE != 0 {
            self.invoke_callback(LsDcInterrupt::RegUpdate);
        }
        if status & INT_LINE_FLAG != 0 {
            self.invoke_callback(LsDcInterrupt::LineFlag);
        }

        // Clear interrupt flags
        self.write_reg(DC_INT, status);

        true
    }

    /// Invoke callback for an interrupt
    fn invoke_callback(&mut self, irq: LsDcInterrupt) {
        let idx = irq_to_index(irq);
        if idx < self.callbacks.len() {
            if let Some(callback) = self.callbacks[idx] {
                callback(irq);
            }
        }
    }

    /// Enable an interrupt
    pub fn enable_irq(&self, irq: LsDcInterrupt) {
        let mask = irq.mask_bit();
        let current = self.read_reg(DC_INT_MASK);
        self.write_reg(DC_INT_MASK, current | mask);
    }

    /// Disable an interrupt
    pub fn disable_irq(&self, irq: LsDcInterrupt) {
        let mask = irq.mask_bit();
        let current = self.read_reg(DC_INT_MASK);
        self.write_reg(DC_INT_MASK, current & !mask);
    }

    /// Enable all interrupts
    pub fn enable_all(&self) {
        let mask = INT_VBLANK_A
            | INT_VBLANK_B
            | INT_HBLANK_A
            | INT_HBLANK_B
            | INT_FIFO_UNDERFLOW
            | INT_REG_UPDATE
            | INT_LINE_FLAG;
        self.write_reg(DC_INT_MASK, mask);
    }

    /// Disable all interrupts
    pub fn disable_all(&self) {
        self.write_reg(DC_INT_MASK, 0);
    }

    /// Get current interrupt status
    pub fn get_status(&self) -> u32 {
        self.read_reg(DC_INT)
    }

    /// Get current interrupt mask
    pub fn get_mask(&self) -> u32 {
        self.read_reg(DC_INT_MASK)
    }

    /// Check if a specific interrupt is pending
    pub fn is_pending(&self, irq: LsDcInterrupt) -> bool {
        let status = self.get_status();
        status & irq.mask_bit() != 0
    }

    /// Wait for vblank on a head
    pub fn wait_vblank(&self, head: u32, timeout_ms: u32) -> Result<(), &'static str> {
        let mask = match head {
            0 => INT_VBLANK_A,
            1 => INT_VBLANK_B,
            _ => return Err("Invalid head"),
        };

        let max_iterations = timeout_ms * 1000;
        let mut iterations = 0;

        while iterations < max_iterations {
            let status = self.get_status();
            if status & mask != 0 {
                // Clear the interrupt
                self.write_reg(DC_INT, mask);
                return Ok(());
            }
            iterations += 1;
        }

        Err("Timeout waiting for vblank")
    }
}

/// Convert interrupt to index
fn irq_to_index(irq: LsDcInterrupt) -> usize {
    match irq {
        LsDcInterrupt::VBlankA => 0,
        LsDcInterrupt::VBlankB => 1,
        LsDcInterrupt::HBlankA => 2,
        LsDcInterrupt::HBlankB => 3,
        LsDcInterrupt::FifoUnderflow => 4,
        LsDcInterrupt::RegUpdate => 5,
        LsDcInterrupt::LineFlag => 6,
    }
}

/// Convert index to interrupt
fn index_to_irq(idx: usize) -> LsDcInterrupt {
    match idx {
        0 => LsDcInterrupt::VBlankA,
        1 => LsDcInterrupt::VBlankB,
        2 => LsDcInterrupt::HBlankA,
        3 => LsDcInterrupt::HBlankB,
        4 => LsDcInterrupt::FifoUnderflow,
        5 => LsDcInterrupt::RegUpdate,
        6 => LsDcInterrupt::LineFlag,
        _ => LsDcInterrupt::VBlankA,
    }
}
