//! Adreno A3xx Register Definitions
//
//! This module defines registers for Adreno 3xx GPUs.
//
//! Clean-room implementation based on public specifications.

/// A3xx RBBM registers
pub const A3XX_RBBM_OFFSET: u32 = 0x00000;
pub const A3XX_RBBM_STATUS: u32 = 0x00004;
pub const A3XX_RBBM_SOFT_RESET: u32 = 0x00110;

/// A3xx display registers
pub const A3XX_DISPLAY_OFFSET: u32 = 0x20000;
pub const A3XX_RBBM_FRAMEBUFFER_ADDR: u32 = 0x20000;
pub const A3XX_RBBM_FRAMEBUFFER_PITCH: u32 = 0x20004;
