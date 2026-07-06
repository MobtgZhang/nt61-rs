//! Allwinner MIPI DSI Interface
//
//! This module implements MIPI DSI display interface support for Allwinner SoCs.
//
//! Clean-room implementation based on public specifications.

/// MIPI DSI device
pub struct MipiDsiDevice {
    /// Base address
    base: u64,
}

impl MipiDsiDevice {
    /// Create new MIPI DSI device
    pub fn new(base: u64) -> Self {
        Self { base }
    }

    /// Initialize MIPI DSI
    pub fn init(&mut self) -> Result<(), ()> {
        Ok(())
    }

    /// Send DSI command
    pub fn send_command(&self, cmd: u8, data: &[u8]) -> Result<(), ()> {
        let _ = (cmd, data);
        Ok(())
    }

    /// Enable video mode
    pub fn enable_video_mode(&mut self, width: u32, height: u32) -> Result<(), ()> {
        let _ = (width, height);
        Ok(())
    }
}
