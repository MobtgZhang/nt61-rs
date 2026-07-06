//! Qualcomm Adreno Register Definitions
//
//! This module defines the MMIO register layout for Qualcomm Adreno GPUs.
//
//! Reference: Freedreno project, Linux adreno driver
//
//! Clean-room implementation based on public specifications.

use super::pci_ids::AdrenoGeneration;

// =====================================================================
// Common Registers
// =====================================================================

/// RBBM (Register Bus Bridge Module) registers
pub const RBBM_OFFSET: u32 = 0x00000;

/// RBBM Status Register
pub const RBBM_STATUS: u32 = 0x00004;
/// RBBM Status 2 Register
pub const RBBM_STATUS2: u32 = 0x00008;
/// RBBM Status 3 Register
pub const RBBM_STATUS3: u32 = 0x0000C;

/// RBBM Control Register
pub const RBBM_CONTROL: u32 = 0x00100;
/// RBBM AHB Control Register
pub const RBBM_AHB_CTL0: u32 = 0x00104;
/// RBBM AHB Control Register 2
pub const RBBM_AHB_CTL1: u32 = 0x00108;

/// RBBM Software Reset Register
pub const RBBM_SOFT_RESET: u32 = 0x00110;

/// RBBM Interrupt Status Register
pub const RBBM_INT_0_STATUS: u32 = 0x00120;
/// RBBM Interrupt Clear Register
pub const RBBM_INT_0_CLEAR: u32 = 0x00128;
/// RBBM Interrupt Mask Register
pub const RBBM_INT_0_MASK: u32 = 0x00130;
/// RBBM Interrupt Enable Register
pub const RBBM_INT_0_EN: u32 = 0x00138;

/// RBBM status flags
pub const RBBM_STATUS_GPU_IDLE: u32 = 1 << 0;
pub const RBBM_STATUS_RBBM_IDLE: u32 = 1 << 1;
pub const RBBM_STATUS_MC_IDLE: u32 = 1 << 2;
pub const RBBM_STATUS_PFP_IDLE: u32 = 1 << 3;
pub const RBBM_STATUS_CP_IDLE: u32 = 1 << 4;

// =====================================================================
// CP (Command Processor) Registers
// =====================================================================

/// CP registers
pub const CP_OFFSET: u32 = 0x10000;

/// CP Status Register
pub const CP_STATUS: u32 = 0x10034;
/// CP Crash Dump Registers
pub const CP_CRASH_DUMP: u32 = 0x10100;

// =====================================================================
// Display Registers
// =====================================================================

/// Display registers
pub const DISPLAY_OFFSET: u32 = 0x20000;

/// Framebuffer Address Register
pub const DISPLAY_FB_ADDR: u32 = 0x20000;
/// Framebuffer Pitch Register
pub const DISPLAY_FB_PITCH: u32 = 0x20004;
/// Framebuffer Size Register
pub const DISPLAY_FB_SIZE: u32 = 0x20008;

/// Display status
pub const DISPLAY_STATUS: u32 = 0x2000C;

// =====================================================================
// GMU (Graphics Management Unit) Registers
// =====================================================================

/// GMU registers
pub const GMU_OFFSET: u32 = 0x50000;

/// GMU Control Register
pub const GMU_CGC: u32 = 0x50000;
/// GMU Status Register
pub const GMU_STATUS: u32 = 0x50004;
/// GMU Power Control Register
pub const GMU_PWR: u32 = 0x50008;

/// GMU status flags
pub const GMU_STATUS_IDLE: u32 = 1 << 0;
pub const GMU_STATUS_ON: u32 = 1 << 1;

// =====================================================================
// Helper Functions
// =====================================================================

/// Get register base for generation
pub fn get_reg_base(gen: AdrenoGeneration) -> u64 {
    match gen {
        AdrenoGeneration::A3XX => 0x00100000,
        AdrenoGeneration::A4XX => 0x00200000,
        AdrenoGeneration::A5XX => 0x00300000,
        AdrenoGeneration::A6XX => 0x00500000,
        _ => 0x00100000,
    }
}

/// Check if GPU is idle
pub fn is_gpu_idle(status: u32) -> bool {
    (status & RBBM_STATUS_GPU_IDLE) != 0
}

/// Check if GMU is idle
pub fn is_gmu_idle(status: u32) -> bool {
    (status & GMU_STATUS_IDLE) != 0
}

/// Calculate framebuffer stride
pub fn calculate_stride(width: u32, bpp: u32) -> u32 {
    ((width * bpp / 8) + 127) & !127u32
}
