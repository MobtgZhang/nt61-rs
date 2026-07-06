//! Adreno A5xx Register Definitions
//
//! This module defines registers for Adreno 5xx GPUs.
//
//! Clean-room implementation based on public specifications.

/// A5xx RBBM registers
pub const A5XX_RBBM_OFFSET: u32 = 0x00000;
pub const A5XX_RBBM_STATUS: u32 = 0x00004;
pub const A5XX_RBBM_SOFT_RESET: u32 = 0x00110;

/// A5xx display registers
pub const A5XX_DISPLAY_OFFSET: u32 = 0x20000;
pub const A5XX_RBBM_FRAMEBUFFER_ADDR: u32 = 0x20000;
pub const A5XX_RBBM_FRAMEBUFFER_PITCH: u32 = 0x20004;

/// A5xx GMU registers
pub const A5XX_GMU_OFFSET: u32 = 0x50000;
pub const A5XX_GMU_STATUS: u32 = 0x50004;
pub const A5XX_GMU_PWR: u32 = 0x50008;
