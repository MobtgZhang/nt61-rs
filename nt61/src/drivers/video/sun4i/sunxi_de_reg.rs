//! Allwinner DEBE (Display Engine Backend) Register Definitions
//
//! This module defines the MMIO register layout for the Allwinner DEBE
//! display engine backend found in various Allwinner SoCs.
//
//! Reference: Linux sun4i display driver
//
//! Clean-room implementation based on public specifications.

use super::pci_ids::SunxiSoc;

// =====================================================================
// DEBE Core Registers
// =====================================================================

/// DEBE Control Register
pub const DEBE_CTRL: u32 = 0x0000;
/// DEBE Status Register
pub const DEBE_STATUS: u32 = 0x0004;
/// DEBE Mode Register
pub const DEBE_MODE: u32 = 0x0008;

/// DEBE Control flags
pub const DEBE_CTRL_ENABLE: u32 = 1 << 0;
pub const DEBE_CTRL_START: u32 = 1 << 1;
pub const DEBE_CTRL_MODE_PRIMARY: u32 = 0 << 2;
pub const DEBE_CTRL_MODE_OVERLAY: u32 = 1 << 2;

// =====================================================================
// Framebuffer Configuration
// =====================================================================

/// Framebuffer 0 Address Register
pub const DEBE_FB0_ADDR: u32 = 0x0100;
/// Framebuffer 0 Stride Register
pub const DEBE_FB0_STRIDE: u32 = 0x0104;
/// Framebuffer 0 Size Register
pub const DEBE_FB0_SIZE: u32 = 0x0108;
/// Framebuffer 0 Format Register
pub const DEBE_FB0_FORMAT: u32 = 0x010C;

/// Framebuffer 1 Address Register
pub const DEBE_FB1_ADDR: u32 = 0x0110;
/// Framebuffer 1 Stride Register
pub const DEBE_FB1_STRIDE: u32 = 0x0114;
/// Framebuffer 1 Size Register
pub const DEBE_FB1_SIZE: u32 = 0x0118;
/// Framebuffer 1 Format Register
pub const DEBE_FB1_FORMAT: u32 = 0x011C;

/// Framebuffer format values
pub const DEBE_FORMAT_ARGB8888: u32 = 0x00;
pub const DEBE_FORMAT_RGBA8888: u32 = 0x01;
pub const DEBE_FORMAT_RGB888: u32 = 0x02;
pub const DEBE_FORMAT_RGB565: u32 = 0x03;
pub const DEBE_FORMAT_ARGB1555: u32 = 0x04;
pub const DEBE_FORMAT_ARGB4444: u32 = 0x05;

// =====================================================================
// Layer Configuration
// =====================================================================

/// Layer 0 Control Register
pub const DEBE_LAYER0_CTRL: u32 = 0x0200;
/// Layer 0 Address Register
pub const DEBE_LAYER0_ADDR: u32 = 0x0204;
/// Layer 0 Stride Register
pub const DEBE_LAYER0_STRIDE: u32 = 0x0208;
/// Layer 0 Size Register
pub const DEBE_LAYER0_SIZE: u32 = 0x020C;
/// Layer 0 Position Register
pub const DEBE_LAYER0_POS: u32 = 0x0210;
/// Layer 0 Format Register
pub const DEBE_LAYER0_FORMAT: u32 = 0x0214;

/// Layer 1 Control Register
pub const DEBE_LAYER1_CTRL: u32 = 0x0300;
/// Layer 1 Address Register
pub const DEBE_LAYER1_ADDR: u32 = 0x0304;
/// Layer 1 Stride Register
pub const DEBE_LAYER1_STRIDE: u32 = 0x0308;
/// Layer 1 Size Register
pub const DEBE_LAYER1_SIZE: u32 = 0x030C;
/// Layer 1 Position Register
pub const DEBE_LAYER1_POS: u32 = 0x0310;
/// Layer 1 Format Register
pub const DEBE_LAYER1_FORMAT: u32 = 0x0314;

/// Layer control flags
pub const DEBE_LAYER_ENABLE: u32 = 1 << 0;
pub const DEBE_LAYER_KEY_EN: u32 = 1 << 1;
pub const DEBE_LAYER_ALPHA_EN: u32 = 1 << 2;
pub const DEBE_LAYER_FORMAT_SHIFT: u32 = 4;

// =====================================================================
// Color Key and Blending
// =====================================================================

/// Color Key Control Register
pub const DEBE_COLOR_KEY_CTRL: u32 = 0x0400;
/// Color Key Value Register
pub const DEBE_COLOR_KEY_VALUE: u32 = 0x0404;
/// Color Key Mask Register
pub const DEBE_COLOR_KEY_MASK: u32 = 0x0408;

/// Blending Mode Register
pub const DEBE_BLEND_MODE: u32 = 0x040C;

/// Blending control flags
pub const DEBE_BLEND_PIXEL_ALPHA: u32 = 1 << 0;
pub const DEBE_BLEND_CONST_ALPHA: u32 = 1 << 1;
pub const DEBE_BLEND_SRC_OVER: u32 = 1 << 4;

// =====================================================================
// Interrupt Registers
// =====================================================================

/// Interrupt Register
pub const DEBE_INT: u32 = 0x0500;
/// Interrupt Enable Register
pub const DEBE_INT_ENABLE: u32 = 0x0504;
/// Interrupt Status Register
pub const DEBE_INT_STATUS: u32 = 0x0508;

/// Interrupt flags
pub const DEBE_INT_VBLANK: u32 = 1 << 0;
pub const DEBE_INT_FIFO_EMPTY: u32 = 1 << 1;
pub const DEBE_INT_FIFO_FULL: u32 = 1 << 2;
pub const DEBE_INT_LINE_FLAG: u32 = 1 << 3;

// =====================================================================
// TCON (Timing Controller) Registers
// =====================================================================

/// TCON Control Register
pub const TCON_CTRL: u32 = 0x0000;
/// TCON Status Register
pub const TCON_STATUS: u32 = 0x0004;

/// TCON Horizontal Total Register
pub const TCON_HTOTAL: u32 = 0x0010;
/// TCON Horizontal Sync Register
pub const TCON_HSYNC: u32 = 0x0014;
/// TCON Horizontal Back Porch Register
pub const TCON_HBP: u32 = 0x0018;
/// TCON Horizontal Front Porch Register
pub const TCON_HFP: u32 = 0x001C;

/// TCON Vertical Total Register
pub const TCON_VTOTAL: u32 = 0x0020;
/// TCON Vertical Sync Register
pub const TCON_VSYNC: u32 = 0x0024;
/// TCON Vertical Back Porch Register
pub const TCON_VBP: u32 = 0x0028;
/// TCON Vertical Front Porch Register
pub const TCON_VFP: u32 = 0x002C;

/// TCON Active Width Register
pub const TCON_ACT_WIDTH: u32 = 0x0030;
/// TCON Active Height Register
pub const TCON_ACT_HEIGHT: u32 = 0x0034;

/// TCON Clock Control Register
pub const TCON_CLK_CTRL: u32 = 0x0040;
/// TCON Interrupt Register
pub const TCON_INT: u32 = 0x0060;
/// TCON Interrupt Enable Register
pub const TCON_INT_ENABLE: u32 = 0x0064;

/// TCON control flags
pub const TCON_CTRL_ENABLE: u32 = 1 << 0;
pub const TCON_CTRL_CLK_ENABLE: u32 = 1 << 31;

// =====================================================================
// Helper Functions
// =====================================================================

/// Get DEBE base offset for SoC
pub fn get_debe_base(soc: SunxiSoc) -> u64 {
    match soc {
        SunxiSoc::A10 | SunxiSoc::A13 | SunxiSoc::A20 | SunxiSoc::A33 => 0x01E0_0000,
        SunxiSoc::A31 | SunxiSoc::A64 => 0x01E0_0000,
        SunxiSoc::H3 | SunxiSoc::H5 => 0x01E0_0000,
        SunxiSoc::H6 | SunxiSoc::H616 => 0x0540_0000,
        SunxiSoc::D1 | SunxiSoc::F133 => 0x0650_0000,
        _ => 0x01E0_0000,
    }
}

/// Get TCON base offset for SoC
pub fn get_tcon_base(soc: SunxiSoc) -> u64 {
    match soc {
        SunxiSoc::A10 | SunxiSoc::A13 | SunxiSoc::A20 | SunxiSoc::A33 => 0x01C0_0000,
        SunxiSoc::A31 | SunxiSoc::A64 => 0x01C0_0000,
        SunxiSoc::H3 | SunxiSoc::H5 => 0x01C0_0000,
        SunxiSoc::H6 | SunxiSoc::H616 => 0x0550_0000,
        SunxiSoc::D1 | SunxiSoc::F133 => 0x0660_0000,
        _ => 0x01C0_0000,
    }
}

/// Get maximum resolution for SoC
pub fn get_max_resolution(soc: SunxiSoc) -> (u32, u32) {
    match soc {
        SunxiSoc::A10 | SunxiSoc::A13 | SunxiSoc::A20 => (1920, 1080),
        SunxiSoc::A33 => (1280, 800),
        SunxiSoc::A64 => (2560, 1600),
        SunxiSoc::H3 | SunxiSoc::H5 => (2560, 1600),
        SunxiSoc::H6 | SunxiSoc::H616 => (4096, 2160),
        SunxiSoc::D1 | SunxiSoc::F133 => (1920, 1080),
        _ => (1920, 1080),
    }
}
