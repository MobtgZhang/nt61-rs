//! ARM Mali-450 GPU Register Definitions
//
//! This module defines registers for ARM Mali-450 GPU found in various Allwinner SoCs.
//
//! Clean-room implementation based on public specifications.

/// Mali-450 base address
pub const MALI450_BASE: u64 = 0x0;

/// Mali GP (Graphics Processor) registers
pub const MALI450_GP_CTRL: u32 = 0x0000;
pub const MALI450_GP_STATUS: u32 = 0x0004;
pub const MALI450_GP_CMD: u32 = 0x0008;

/// Mali PP (Pixel Processor) registers
pub const MALI450_PP0_CTRL: u32 = 0x1000;
pub const MALI450_PP1_CTRL: u32 = 0x1800;
pub const MALI450_PP_STATUS: u32 = 0x1004;
pub const MALI450_PP_CMD: u32 = 0x1008;

/// Mali L2 cache registers
pub const MALI450_L2_CTRL: u32 = 0x2000;
pub const MALI450_L2_STATUS: u32 = 0x2004;

/// Control values
pub const MALI450_GP_SOFT_RESET: u32 = 1 << 0;
pub const MALI450_PP_SOFT_RESET: u32 = 1 << 0;
pub const MALI450_ENABLE: u32 = 1 << 0;
