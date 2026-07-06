//! ARM Mali-400 GPU Register Definitions
//
//! This module defines registers for ARM Mali-400 GPU found in various Allwinner SoCs.
//
//! Clean-room implementation based on public specifications.

/// Mali-400 base address
pub const MALI400_BASE: u64 = 0x0;

/// Mali GP (Graphics Processor) registers
pub const MALI400_GP_CTRL: u32 = 0x0000;
pub const MALI400_GP_STATUS: u32 = 0x0004;
pub const MALI400_GP_CMD: u32 = 0x0008;

/// Mali PP (Pixel Processor) registers
pub const MALI400_PP_CTRL: u32 = 0x1000;
pub const MALI400_PP_STATUS: u32 = 0x1004;
pub const MALI400_PP_CMD: u32 = 0x1008;

/// Mali L2 cache registers
pub const MALI400_L2_CTRL: u32 = 0x2000;
pub const MALI400_L2_STATUS: u32 = 0x2004;

/// Control values
pub const MALI400_GP_SOFT_RESET: u32 = 1 << 0;
pub const MALI400_PP_SOFT_RESET: u32 = 1 << 0;
pub const MALI400_ENABLE: u32 = 1 << 0;
