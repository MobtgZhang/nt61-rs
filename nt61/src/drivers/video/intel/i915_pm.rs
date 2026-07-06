//! Intel i915 Power Management
//
//! Implements power management for Intel integrated graphics

use crate::drivers::video::intel::i915_reg::*;

/// Power well state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerWellState {
    /// Power well is on
    On,
    /// Power well is off (request only)
    RequestOnly,
    /// Unknown
    Unknown,
}

/// Power management for i915
pub struct I915PowerManager {
    /// MMIO base
    mmio_base: u64,
    /// Current power well state
    power_well_state: PowerWellState,
}

impl I915PowerManager {
    /// Create new power manager
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            power_well_state: PowerWellState::Unknown,
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

    /// Get power well state
    pub fn get_power_well_state(&mut self) -> PowerWellState {
        let status = self.read_reg(HSW_PWR_WELL_B_STATUS);

        if status & HSW_PWR_WELL_STATE_POWER_ON != 0 {
            self.power_well_state = PowerWellState::On;
        } else if status & HSW_PWR_WELL_STATE_REQ_ONLY != 0 {
            self.power_well_state = PowerWellState::RequestOnly;
        } else {
            self.power_well_state = PowerWellState::Unknown;
        }

        self.power_well_state
    }

    /// Request power well
    pub fn request_power_well(&mut self) -> bool {
        // Request power well
        self.write_reg(HSW_PWR_WELL_B_REQUEST, HSW_PWR_WELL_ENABLE);

        // Wait for power on
        for _ in 0..10000 {
            let status = self.read_reg(HSW_PWR_WELL_B_STATUS);
            if status & HSW_PWR_WELL_STATE_POWER_ON != 0 {
                self.power_well_state = PowerWellState::On;
                return true;
            }
        }

        false
    }

    /// Release power well
    pub fn release_power_well(&mut self) {
        self.write_reg(HSW_PWR_WELL_B_REQUEST, 0);
        self.power_well_state = PowerWellState::RequestOnly;
    }

    /// Check if power well is on
    pub fn is_power_well_on(&mut self) -> bool {
        self.get_power_well_state() == PowerWellState::On
    }
}
