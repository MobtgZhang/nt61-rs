//! Adreno A4xx Register Definitions
//
//! This module defines registers for Adreno 4xx GPUs.
//
//! Clean-room implementation based on public specifications.

/// A4xx RBBM registers
pub const A4XX_RBBM_OFFSET: u32 = 0x00000;
pub const A4XX_RBBM_STATUS: u32 = 0x00004;
pub const A4XX_RBBM_SOFT_RESET: u32 = 0x00110;

/// A4xx display registers
pub const A4XX_DISPLAY_OFFSET: u32 = 0x20000;
pub const A4XX_RBBM_FRAMEBUFFER_ADDR: u32 = 0x20000;
pub const A4XX_RBBM_FRAMEBUFFER_PITCH: u32 = 0x20004;
