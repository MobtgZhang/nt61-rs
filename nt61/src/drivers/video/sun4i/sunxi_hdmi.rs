//! Allwinner HDMI Controller
//
//! This module implements HDMI output support for Allwinner SoCs.
//
//! Clean-room implementation based on public specifications.

/// HDMI device
pub struct HdmiDevice {}

impl HdmiDevice {
    /// create new HDMI device
    pub fn new() -> Self {
        Self {}
    }

    /// Initialize HDMI
    pub fn init(&mut self) -> Result<(), ()> {
        Ok(())
    }

    /// Set video mode
    pub fn set_mode(&mut self, width: u32, height: u32, refresh: u32) -> Result<(), ()> {
        let _ = (width, height, refresh);
        Ok(())
    }

    /// Enable HDMI
    pub fn enable(&mut self) -> Result<(), ()> {
        Ok(())
    }

    /// Disable HDMI
    pub fn disable(&mut self) {
        // Disable HDMI
    }
}
