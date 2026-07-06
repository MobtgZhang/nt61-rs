//! ARM Mali-T700 GPU Register Definitions
//
//! This module defines registers for ARM Mali-T700 GPU (T720/T760/T820)
//! found in various Allwinner SoCs.
//
//! Clean-room implementation based on public specifications.

/// Mali-T700 base address
pub const MALIT7_BASE: u64 = 0x0;

/// Mali GP (Graphics Processor) registers
pub const MALIT7_GP_CTRL: u32 = 0x0000;
pub const MALIT7_GP_STATUS: u32 = 0x0004;
pub const MALIT7_GP_CMD: u32 = 0x0008;

/// Mali PP (Pixel Processor) registers
pub const MALIT7_PP0_CTRL: u32 = 0x1000;
pub const MALIT7_PP0_STATUS: u32 = 0x1004;
pub const MALIT7_PP0_CMD: u32 = 0x1008;
pub const MALIT7_PP1_CTRL: u32 = 0x1800;
pub const MALIT7_PP1_STATUS: u32 = 0x1804;
pub const MALIT7_PP1_CMD: u32 = 0x1808;

/// Mali L2 cache registers
pub const MALIT7_L20_CTRL: u32 = 0x2000;
pub const MALIT7_L21_CTRL: u32 = 0x2800;
pub const MALIT7_L2_STATUS: u32 = 0x2004;

/// Control values
pub const MALIT7_GP_SOFT_RESET: u32 = 1 << 0;
pub const MALIT7_PP_SOFT_RESET: u32 = 1 << 0;
pub const MALIT7_ENABLE: u32 = 1 << 0;
