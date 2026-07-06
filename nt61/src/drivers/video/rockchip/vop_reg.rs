//! Rockchip VOP (Video Output Processor) Register Definitions
//
//! This module defines the MMIO register layout for the Rockchip VOP
//! display controller found in various Rockchip SoCs.
//
//! Reference: Rockchip TRM, Linux rockchip display driver
//
//! Clean-room implementation based on public specifications.

use super::pci_ids::RockchipSoc;

// =====================================================================
// VOP Core Registers
// =====================================================================

/// VOP Control Register
pub const VOP_CTRL: u32 = 0x0000;
/// VOP Status Register
pub const VOP_STATUS: u32 = 0x0004;
/// VOP Version Register
pub const VOP_VERSION: u32 = 0x0008;

/// VOP Control flags
pub const VOP_CTRL_ENABLE: u32 = 1 << 0;
pub const VOP_CTRL_START: u32 = 1 << 1;
pub const VOP_CTRL_DONE: u32 = 1 << 2;

// =====================================================================
// Framebuffer Configuration
// =====================================================================

/// Framebuffer 0 Address Register
pub const VOP_FB0_ADDR: u32 = 0x0100;
/// Framebuffer 0 Stride Register
pub const VOP_FB0_STRIDE: u32 = 0x0104;
/// Framebuffer 0 Format Register
pub const VOP_FB0_FORMAT: u32 = 0x0108;
/// Framebuffer 0 Size Register
pub const VOP_FB0_SIZE: u32 = 0x010C;

/// Framebuffer 1 Address Register
pub const VOP_FB1_ADDR: u32 = 0x0110;
/// Framebuffer 1 Stride Register
pub const VOP_FB1_STRIDE: u32 = 0x0114;
/// Framebuffer 1 Format Register
pub const VOP_FB1_FORMAT: u32 = 0x0118;
/// Framebuffer 1 Size Register
pub const VOP_FB1_SIZE: u32 = 0x011C;

/// Framebuffer format values
pub const VOP_FORMAT_RGBA8888: u32 = 0x00;
pub const VOP_FORMAT_BGRA8888: u32 = 0x01;
pub const VOP_FORMAT_RGB888: u32 = 0x02;
pub const VOP_FORMAT_RGB565: u32 = 0x03;
pub const VOP_FORMAT_YUV420: u32 = 0x10;
pub const VOP_FORMAT_YUV422: u32 = 0x11;

// =====================================================================
// Window/Plane Configuration
// =====================================================================

/// Window 0 Control Register
pub const VOP_WIN0_CTRL: u32 = 0x0200;
/// Window 0 Address Register
pub const VOP_WIN0_ADDR: u32 = 0x0204;
/// Window 0 Stride Register
pub const VOP_WIN0_STRIDE: u32 = 0x0208;
/// Window 0 Size Register
pub const VOP_WIN0_SIZE: u32 = 0x0210;
/// Window 0 Position Register
pub const VOP_WIN0_POS: u32 = 0x0214;
/// Window 0 Format Register
pub const VOP_WIN0_FORMAT: u32 = 0x0218;

/// Window 1 Control Register
pub const VOP_WIN1_CTRL: u32 = 0x0300;
/// Window 1 Address Register
pub const VOP_WIN1_ADDR: u32 = 0x0304;
/// Window 1 Stride Register
pub const VOP_WIN1_STRIDE: u32 = 0x0308;
/// Window 1 Size Register
pub const VOP_WIN1_SIZE: u32 = 0x0310;
/// Window 1 Position Register
pub const VOP_WIN1_POS: u32 = 0x0314;
/// Window 1 Format Register
pub const VOP_WIN1_FORMAT: u32 = 0x0318;

/// Window control flags
pub const VOP_WIN_CTRL_ENABLE: u32 = 1 << 0;
pub const VOP_WIN_CTRL_FORMAT_SHIFT: u32 = 8;
pub const VOP_WIN_CTRL_ALPHA_EN: u32 = 1 << 24;
pub const VOP_WIN_CTRL_ALPHA_MODE: u32 = 1 << 25;

// =====================================================================
// CRT Controller (CRTC)
// =====================================================================

/// CRTC Control Register
pub const VOP_CRTC_CTRL: u32 = 0x0300;
/// CRTC Horizontal Total Register
pub const VOP_CRTC_H_TOTAL: u32 = 0x0310;
/// CRTC Horizontal Active Register
pub const VOP_CRTC_H_ACT: u32 = 0x0314;
/// CRTC Horizontal Sync Start Register
pub const VOP_CRTC_H_SYNC: u32 = 0x0318;
/// CRTC Horizontal Sync End Register
pub const VOP_CRTC_H_END: u32 = 0x031C;
/// CRTC Vertical Total Register
pub const VOP_CRTC_V_TOTAL: u32 = 0x0320;
/// CRTC Vertical Active Register
pub const VOP_CRTC_V_ACT: u32 = 0x0324;
/// CRTC Vertical Sync Start Register
pub const VOP_CRTC_V_SYNC: u32 = 0x0328;
/// CRTC Vertical Sync End Register
pub const VOP_CRTC_V_END: u32 = 0x032C;
/// CRTC Border Color Register
pub const VOP_CRTC_BORDER: u32 = 0x0330;

/// CRTC control flags
pub const VOP_CRTC_CTRL_ENABLE: u32 = 1 << 0;
pub const VOP_CRTC_CTRL_HSYNC_POS: u32 = 1 << 4;
pub const VOP_CRTC_CTRL_VSYNC_POS: u32 = 1 << 5;
pub const VOP_CRTC_CTRL_INTERLACE: u32 = 1 << 6;

// =====================================================================
// Interrupt Registers
// =====================================================================

/// Interrupt Status Register
pub const VOP_INT_STATUS: u32 = 0x0400;
/// Interrupt Clear Register
pub const VOP_INT_CLEAR: u32 = 0x0404;
/// Interrupt Mask Register
pub const VOP_INT_MASK: u32 = 0x0408;
/// Interrupt Enable Register
pub const VOP_INT_EN: u32 = 0x040C;

/// Interrupt flags
pub const VOP_INT_VBLANK: u32 = 1 << 0;
pub const VOP_INT_FIFO_EMPTY: u32 = 1 << 1;
pub const VOP_INT_FIFO_FULL: u32 = 1 << 2;
pub const VOP_INT_LINE_FLAG: u32 = 1 << 3;

// =====================================================================
// Alpha Blending
// =====================================================================

/// Alpha Control Register
pub const VOP_ALPHA_CTRL: u32 = 0x0500;
/// Alpha Value Register
pub const VOP_ALPHA_VALUE: u32 = 0x0504;

/// Alpha control flags
pub const VOP_ALPHA_CTRL_ENABLE: u32 = 1 << 0;
pub const VOP_ALPHA_CTRL_MODE: u32 = 1 << 1;

// =====================================================================
// Color Key
// =====================================================================

/// Color Key Control Register
pub const VOP_COLOR_KEY_CTRL: u32 = 0x0600;
/// Color Key Value Register
pub const VOP_COLOR_KEY_VALUE: u32 = 0x0604;
/// Color Key Mask Register
pub const VOP_COLOR_KEY_MASK: u32 = 0x0608;

/// Color key control flags
pub const VOP_COLOR_KEY_CTRL_ENABLE: u32 = 1 << 0;
pub const VOP_COLOR_KEY_CTRL_DIR: u32 = 1 << 1;

// =====================================================================
// Gamma Correction
// =====================================================================

/// Gamma Control Register
pub const VOP_GAMMA_CTRL: u32 = 0x0700;
/// Gamma LUT Address Register
pub const VOP_GAMMA_LUT_ADDR: u32 = 0x0704;
/// Gamma LUT Data Register
pub const VOP_GAMMA_LUT_DATA: u32 = 0x0708;

// =====================================================================
// Helper Functions
// =====================================================================

/// Get VOP base offset for SoC
pub fn get_vop_base(soc: RockchipSoc) -> u64 {
    match soc {
        RockchipSoc::RK3066 | RockchipSoc::RK3288 => 0x00A0_0000,
        RockchipSoc::RK3399 => 0x00B0_0000,
        RockchipSoc::RK3566 | RockchipSoc::RK3568 | RockchipSoc::RK3588 => 0x00C0_0000,
        _ => 0x00A0_0000,
    }
}

/// Get maximum width for SoC
pub fn get_max_width(soc: RockchipSoc) -> u32 {
    match soc {
        RockchipSoc::RK3066 | RockchipSoc::RK3288 => 1920,
        RockchipSoc::RK3399 => 2560,
        RockchipSoc::RK3566 | RockchipSoc::RK3568 => 3840,
        RockchipSoc::RK3588 => 4096,
        _ => 1920,
    }
}

/// Get maximum height for SoC
pub fn get_max_height(soc: RockchipSoc) -> u32 {
    match soc {
        RockchipSoc::RK3066 | RockchipSoc::RK3288 => 1080,
        RockchipSoc::RK3399 => 1600,
        RockchipSoc::RK3566 | RockchipSoc::RK3568 => 2160,
        RockchipSoc::RK3588 => 2304,
        _ => 1080,
    }
}

/// Calculate CRTC timing
pub fn calculate_crtc_timing(width: u32, height: u32, refresh: u32) -> CrtcTiming {
    let h_total = width + 120;
    let h_sync_start = width + 20;
    let h_sync_end = width + 40;
    let h_blank_start = width;
    let h_blank_end = h_total;

    let v_total = height + 30;
    let v_sync_start = height + 5;
    let v_sync_end = height + 10;
    let v_blank_start = height;
    let v_blank_end = v_total;

    CrtcTiming {
        h_total,
        h_blank_start,
        h_blank_end,
        h_sync_start,
        h_sync_end,
        v_total,
        v_blank_start,
        v_blank_end,
        v_sync_start,
        v_sync_end,
    }
}

/// CRT timing parameters
#[derive(Debug, Clone, Copy)]
pub struct CrtcTiming {
    pub h_total: u32,
    pub h_blank_start: u32,
    pub h_blank_end: u32,
    pub h_sync_start: u32,
    pub h_sync_end: u32,
    pub v_total: u32,
    pub v_blank_start: u32,
    pub v_blank_end: u32,
    pub v_sync_start: u32,
    pub v_sync_end: u32,
}

impl CrtcTiming {
    /// Encode horizontal total register
    pub fn h_total_reg(&self) -> u32 {
        (self.h_total << 16) | self.h_blank_start
    }

    /// Encode horizontal sync register
    pub fn h_sync_reg(&self) -> u32 {
        (self.h_sync_end << 16) | self.h_sync_start
    }

    /// Encode vertical total register
    pub fn v_total_reg(&self) -> u32 {
        (self.v_total << 16) | self.v_blank_start
    }

    /// Encode vertical sync register
    pub fn v_sync_reg(&self) -> u32 {
        (self.v_sync_end << 16) | self.v_sync_start
    }
}
