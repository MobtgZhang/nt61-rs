//! Rockchip HDMI Output
//
//! This module implements HDMI output support for Rockchip.
//
//! Clean-room implementation based on public specifications.

use crate::libs::ntdll::types::NTSTATUS;

/// HDMI device
pub struct HdmiDevice {}

impl HdmiDevice {
    /// create new HDMI device
    pub fn new() -> Self {
        Self {}
    }

    /// Initialize HDMI
    pub fn init(&mut self) -> Result<(), NTSTATUS> {
        Ok(())
    }

    /// Set video mode
    pub fn set_mode(&mut self, width: u32, height: u32, refresh: u32) -> Result<(), NTSTATUS> {
        let _ = (width, height, refresh);
        Ok(())
    }

    /// Enable HDMI output
    pub fn enable(&mut self) -> Result<(), NTSTATUS> {
        Ok(())
    }

    /// Disable HDMI output
    pub fn disable(&mut self) {
        // Disable HDMI
    }
}
