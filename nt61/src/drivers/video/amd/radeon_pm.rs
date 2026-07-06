//! AMD Radeon Power Management
//
//! Implements power management for AMD Radeon graphics

use crate::drivers::video::amd::radeon_reg::*;

/// Power state
#[derive(Debug, Clone, Copy)]
pub enum PowerState {
    /// D0: Fully on
    D0,
    /// D1: Light sleep
    D1,
    /// D2: Deep sleep
    D2,
    /// D3: Hot standby
    D3,
}

/// Power management
pub struct RadeonPowerManager {
    /// MMIO base
    mmio_base: u64,
    /// Current state
    current_state: PowerState,
}

impl RadeonPowerManager {
    /// Create new power manager
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            current_state: PowerState::D0,
        }
    }

    /// Read register
    #[inline]
    pub fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write register
    #[inline]
    pub fn write_reg(&self, offset: u32, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.mmio_base + offset as u64) as *mut u32,
                value,
            )
        }
    }

    /// Get current power state
    pub fn get_power_state(&self) -> PowerState {
        self.current_state
    }

    /// Set power state
    pub fn set_power_state(&mut self, state: PowerState) {
        match state {
            PowerState::D0 => self.power_up(),
            PowerState::D3 => self.power_down(),
            _ => {}
        }
        self.current_state = state;
    }

    /// Power up (D0)
    fn power_up(&mut self) {
        // Enable clocks
        let status = self.read_reg(CG_STATUS);
        let _ = status;
    }

    /// Power down (D3)
    fn power_down(&mut self) {
        // Disable clocks
        let _ = self.read_reg(CG_STATUS);
    }
}
