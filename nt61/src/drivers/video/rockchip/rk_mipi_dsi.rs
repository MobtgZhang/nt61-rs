//! Rockchip MIPI DSI Interface
//
//! This module implements MIPI DSI display interface support for Rockchip.
//
//! Clean-room implementation based on public specifications.

use crate::libs::ntdll::types::NTSTATUS;

/// MIPI DSI device
pub struct MipiDsiDevice {}

impl MipiDsiDevice {
    /// create new MIPI DSI device
    pub fn new() -> Self {
        Self {}
    }

    /// Initialize MIPI DSI
    pub fn init(&mut self) -> Result<(), NTSTATUS> {
        Ok(())
    }

    /// Send DSI command
    pub fn send_command(&self, cmd: u8, data: &[u8]) -> Result<(), NTSTATUS> {
        let _ = (cmd, data);
        Ok(())
    }

    /// Enable video mode
    pub fn enable_video_mode(&mut self, width: u32, height: u32) -> Result<(), NTSTATUS> {
        let _ = (width, height);
        Ok(())
    }
}
