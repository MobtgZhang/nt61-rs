//! Glenfly GT-10C0 Graphics Registers
//
//! This module defines the MMIO register layout for the Glenfly GT-10C0
//! graphics adapter used in KX-6000G processors.
//
//! The GT-10C0 is a discrete/integrated graphics chip with
//! improved performance over the ZX-Chrome 9 integrated graphics.
//
//! Reference: Glenfly documentation, Linux drivers
//
//! Clean-room implementation based on public specifications.

use super::pci_ids::DisplayFormat;

// =====================================================================
// Register Base Address
// =====================================================================

/// Glenfly Display Controller MMIO base offset
pub const GLENFLY_DC_BASE: u32 = 0x0000;

// =====================================================================
// Display Controller Core Registers (0x0000 - 0x00FF)
// =====================================================================

/// Display Controller Control Register
pub const GLENFLY_DC_CTRL: u32 = 0x0000;
/// Display Controller Status Register
pub const GLENFLY_DC_STATUS: u32 = 0x0004;
/// Display Controller Interrupt Register
pub const GLENFLY_DC_INT: u32 = 0x0008;
/// Display Controller Interrupt Mask Register
pub const GLENFLY_DC_INT_MASK: u32 = 0x000C;
/// Display Controller Version Register
pub const GLENFLY_DC_VERSION: u32 = 0x0010;
/// Display Controller Revision Register
pub const GLENFLY_DC_REVISION: u32 = 0x0014;
/// Display Controller Feature Register
pub const GLENFLY_DC_FEATURE: u32 = 0x0018;
/// Display Controller Capability Register
pub const GLENFLY_DC_CAPS: u32 = 0x001C;

/// Control register flags
pub const GLENFLY_DC_CTRL_ENABLE: u32 = 1 << 0;
pub const GLENFLY_DC_CTRL_RUN: u32 = 1 << 1;
pub const GLENFLY_DC_CTRL_RESET: u32 = 1 << 2;
pub const GLENFLY_DC_CTRL_VBLANK_INT: u32 = 1 << 3;
pub const GLENFLY_DC_CTRL_REG_UPDATE: u32 = 1 << 4;
pub const GLENFLY_DC_CTRL_TE_FREEZE: u32 = 1 << 5;

/// Status register flags
pub const GLENFLY_DC_STATUS_ENABLE: u32 = 1 << 0;
pub const GLENFLY_DC_STATUS_RUN: u32 = 1 << 1;
pub const GLENFLY_DC_STATUS_VBLANK: u32 = 1 << 2;
pub const GLENFLY_DC_STATUS_ERROR: u32 = 1 << 3;
pub const GLENFLY_DC_STATUS_REG_UPDATE: u32 = 1 << 4;
pub const GLENFLY_DC_STATUS_PIPE_A_ON: u32 = 1 << 8;
pub const GLENFLY_DC_STATUS_PIPE_B_ON: u32 = 1 << 9;

/// Interrupt flags
pub const GLENFLY_DC_INT_VBLANK_A: u32 = 1 << 0;
pub const GLENFLY_DC_INT_VBLANK_B: u32 = 1 << 1;
pub const GLENFLY_DC_INT_FIFO_UNDERFLOW: u32 = 1 << 8;
pub const GLENFLY_DC_INT_FIFO_OVERFLOW: u32 = 1 << 9;
pub const GLENFLY_DC_INT_REG_UPDATE: u32 = 1 << 16;
pub const GLENFLY_DC_INT_PAGE_FAULT: u32 = 1 << 20;
pub const GLENFLY_DC_INT_2D_COMPLETE: u32 = 1 << 24;
pub const GLENFLY_DC_INT_3D_COMPLETE: u32 = 1 << 25;

// =====================================================================
// Framebuffer Configuration (0x0100 - 0x01FF)
// =====================================================================

/// Framebuffer Physical Address Register (64-bit)
pub const GLENFLY_FB_ADDR: u32 = 0x0100;
/// Framebuffer Physical Address High Register
pub const GLENFLY_FB_ADDR_HIGH: u32 = 0x0104;
/// Framebuffer Stride Register
pub const GLENFLY_FB_STRIDE: u32 = 0x0108;
/// Framebuffer Size Register
pub const GLENFLY_FB_SIZE: u32 = 0x010C;
/// Framebuffer Format Register
pub const GLENFLY_FB_FORMAT: u32 = 0x0110;
/// Framebuffer Color Key Register
pub const GLENFLY_FB_COLOR_KEY: u32 = 0x0114;
/// Framebuffer Color Key Mask Register
pub const GLENFLY_FB_COLOR_KEY_MASK: u32 = 0x0118;
/// Framebuffer Gamma Register
pub const GLENFLY_FB_GAMMA: u32 = 0x011C;

/// Framebuffer format flags
pub const GLENFLY_FB_FORMAT_BGRA8888: u32 = 0x00;
pub const GLENFLY_FB_FORMAT_RGBA8888: u32 = 0x01;
pub const GLENFLY_FB_FORMAT_RGB565: u32 = 0x02;
pub const GLENFLY_FB_FORMAT_RGB888: u32 = 0x03;
pub const GLENFLY_FB_FORMAT_ARGB1555: u32 = 0x04;
pub const GLENFLY_FB_FORMAT_ARGB4444: u32 = 0x05;
pub const GLENFLY_FB_FORMAT_YUV422: u32 = 0x10;
pub const GLENFLY_FB_FORMAT_YUV420: u32 = 0x11;
pub const GLENFLY_FB_FORMAT_NV12: u32 = 0x12;

// =====================================================================
// CRT Controller A Registers (0x0200 - 0x02FF)
// =====================================================================

/// CRT Controller A Control Register
pub const GLENFLY_CRTC_A_CTRL: u32 = 0x0200;
/// CRT Controller A Configuration Register
pub const GLENFLY_CRTC_A_CONFIG: u32 = 0x0204;
/// CRT Controller A Horizontal Total Register
pub const GLENFLY_CRTC_A_H_TOTAL: u32 = 0x0210;
/// CRT Controller A Horizontal Blank Register
pub const GLENFLY_CRTC_A_H_BLANK: u32 = 0x0214;
/// CRT Controller A Horizontal Sync Register
pub const GLENFLY_CRTC_A_H_SYNC: u32 = 0x0218;
/// CRT Controller A Horizontal Sync End Register
pub const GLENFLY_CRTC_A_H_SYNC_END: u32 = 0x021C;
/// CRT Controller A Vertical Total Register
pub const GLENFLY_CRTC_A_V_TOTAL: u32 = 0x0220;
/// CRT Controller A Vertical Blank Register
pub const GLENFLY_CRTC_A_V_BLANK: u32 = 0x0224;
/// CRT Controller A Vertical Sync Register
pub const GLENFLY_CRTC_A_V_SYNC: u32 = 0x0228;
/// CRT Controller A Vertical Sync End Register
pub const GLENFLY_CRTC_A_V_SYNC_END: u32 = 0x022C;
/// CRT Controller A Display Address Register
pub const GLENFLY_CRTC_A_ADDR: u32 = 0x0230;
/// CRT Controller A Display Address Offset Register
pub const GLENFLY_CRTC_A_ADDR_OFFSET: u32 = 0x0234;
/// CRT Controller A Border Color Register
pub const GLENFLY_CRTC_A_BORDER_COLOR: u32 = 0x0238;

/// CRT Controller A control flags
pub const GLENFLY_CRTC_A_CTRL_ENABLE: u32 = 1 << 0;
pub const GLENFLY_CRTC_A_CTRL_8BPP: u32 = 0 << 2;
pub const GLENFLY_CRTC_A_CTRL_16BPP: u32 = 1 << 2;
pub const GLENFLY_CRTC_A_CTRL_24BPP: u32 = 2 << 2;
pub const GLENFLY_CRTC_A_CTRL_32BPP: u32 = 3 << 2;
pub const GLENFLY_CRTC_A_CTRL_HSYNC_POS: u32 = 1 << 6;
pub const GLENFLY_CRTC_A_CTRL_VSYNC_POS: u32 = 1 << 7;
pub const GLENFLY_CRTC_A_CTRL_INTERLACE: u32 = 1 << 8;
pub const GLENFLY_CRTC_A_CTRL_DOUBLE_SCAN: u32 = 1 << 9;

// =====================================================================
// CRT Controller B Registers (0x0300 - 0x03FF)
// =====================================================================

/// CRT Controller B Control Register
pub const GLENFLY_CRTC_B_CTRL: u32 = 0x0300;
/// CRT Controller B Configuration Register
pub const GLENFLY_CRTC_B_CONFIG: u32 = 0x0304;
/// CRT Controller B Horizontal Total Register
pub const GLENFLY_CRTC_B_H_TOTAL: u32 = 0x0310;
/// CRT Controller B Horizontal Blank Register
pub const GLENFLY_CRTC_B_H_BLANK: u32 = 0x0314;
/// CRT Controller B Horizontal Sync Register
pub const GLENFLY_CRTC_B_H_SYNC: u32 = 0x0318;
/// CRT Controller B Horizontal Sync End Register
pub const GLENFLY_CRTC_B_H_SYNC_END: u32 = 0x031C;
/// CRT Controller B Vertical Total Register
pub const GLENFLY_CRTC_B_V_TOTAL: u32 = 0x0320;
/// CRT Controller B Vertical Blank Register
pub const GLENFLY_CRTC_B_V_BLANK: u32 = 0x0324;
/// CRT Controller B Vertical Sync Register
pub const GLENFLY_CRTC_B_V_SYNC: u32 = 0x0328;
/// CRT Controller B Vertical Sync End Register
pub const GLENFLY_CRTC_B_V_SYNC_END: u32 = 0x032C;
/// CRT Controller B Display Address Register
pub const GLENFLY_CRTC_B_ADDR: u32 = 0x0330;
/// CRT Controller B Display Address Offset Register
pub const GLENFLY_CRTC_B_ADDR_OFFSET: u32 = 0x0334;
/// CRT Controller B Border Color Register
pub const GLENFLY_CRTC_B_BORDER_COLOR: u32 = 0x0338;

// =====================================================================
// Primary Plane Registers (0x0400 - 0x04FF)
// =====================================================================

/// Primary Plane Control Register
pub const GLENFLY_PLANE_PRIMARY_CTRL: u32 = 0x0400;
/// Primary Plane Address Register (64-bit)
pub const GLENFLY_PLANE_PRIMARY_ADDR: u32 = 0x0404;
/// Primary Plane Address High Register
pub const GLENFLY_PLANE_PRIMARY_ADDR_HIGH: u32 = 0x0408;
/// Primary Plane Stride Register
pub const GLENFLY_PLANE_PRIMARY_STRIDE: u32 = 0x040C;
/// Primary Plane Size Register
pub const GLENFLY_PLANE_PRIMARY_SIZE: u32 = 0x0410;
/// Primary Plane Position Register
pub const GLENFLY_PLANE_PRIMARY_POS: u32 = 0x0414;
/// Primary Plane Format Register
pub const GLENFLY_PLANE_PRIMARY_FORMAT: u32 = 0x0418;
/// Primary Plane Color Key Register
pub const GLENFLY_PLANE_PRIMARY_COLOR_KEY: u32 = 0x041C;

/// Primary plane control flags
pub const GLENFLY_PLANE_CTRL_ENABLE: u32 = 1 << 0;
pub const GLENFLY_PLANE_CTRL_KEY_EN: u32 = 1 << 1;
pub const GLENFLY_PLANE_CTRL_ALPHA_EN: u32 = 1 << 2;
pub const GLENFLY_PLANE_CTRL_CONST_ALPHA: u32 = 1 << 3;
pub const GLENFLY_PLANE_CTRL_FORMAT_SHIFT: u32 = 4;
pub const GLENFLY_PLANE_CTRL_SCALE_EN: u32 = 1 << 16;

// =====================================================================
// Overlay Plane Registers (0x0500 - 0x05FF)
// =====================================================================

/// Overlay Plane Control Register
pub const GLENFLY_PLANE_OVERLAY_CTRL: u32 = 0x0500;
/// Overlay Plane Address Y Register
pub const GLENFLY_PLANE_OVERLAY_ADDR_Y: u32 = 0x0504;
/// Overlay Plane Address Y High Register
pub const GLENFLY_PLANE_OVERLAY_ADDR_Y_HIGH: u32 = 0x0508;
/// Overlay Plane Address UV Register
pub const GLENFLY_PLANE_OVERLAY_ADDR_UV: u32 = 0x050C;
/// Overlay Plane Address UV High Register
pub const GLENFLY_PLANE_OVERLAY_ADDR_UV_HIGH: u32 = 0x0510;
/// Overlay Plane Stride Register
pub const GLENFLY_PLANE_OVERLAY_STRIDE: u32 = 0x0514;
/// Overlay Plane UV Stride Register
pub const GLENFLY_PLANE_OVERLAY_STRIDE_UV: u32 = 0x0518;
/// Overlay Plane Size Register
pub const GLENFLY_PLANE_OVERLAY_SIZE: u32 = 0x051C;
/// Overlay Plane Position Register
pub const GLENFLY_PLANE_OVERLAY_POS: u32 = 0x0520;
/// Overlay Plane Format Register
pub const GLENFLY_PLANE_OVERLAY_FORMAT: u32 = 0x0524;

/// Overlay plane control flags
pub const GLENFLY_OVERLAY_CTRL_ENABLE: u32 = 1 << 0;
pub const GLENFLY_OVERLAY_CTRL_COLOR_KEY: u32 = 1 << 1;
pub const GLENFLY_OVERLAY_CTRL_ALPHA: u32 = 1 << 2;
pub const GLENFLY_OVERLAY_CTRL_YUV2RGB: u32 = 1 << 8;
pub const GLENFLY_OVERLAY_CTRL_BILINEAR: u32 = 1 << 12;

// =====================================================================
// Hardware Cursor Registers (0x0600 - 0x06FF)
// =====================================================================

/// Hardware Cursor Control Register
pub const GLENFLY_CURSOR_CTRL: u32 = 0x0600;
/// Hardware Cursor Palette 0
pub const GLENFLY_CURSOR_PALETTE0: u32 = 0x0604;
/// Hardware Cursor Palette 1
pub const GLENFLY_CURSOR_PALETTE1: u32 = 0x0608;
/// Hardware Cursor Palette 2
pub const GLENFLY_CURSOR_PALETTE2: u32 = 0x060C;
/// Hardware Cursor Palette 3
pub const GLENFLY_CURSOR_PALETTE3: u32 = 0x0610;
/// Hardware Cursor Address Register
pub const GLENFLY_CURSOR_ADDR: u32 = 0x0614;
/// Hardware Cursor Address High Register
pub const GLENFLY_CURSOR_ADDR_HIGH: u32 = 0x0618;
/// Hardware Cursor Position Register
pub const GLENFLY_CURSOR_POS: u32 = 0x061C;
/// Hardware Cursor Hotspot Register
pub const GLENFLY_CURSOR_HOTSPOT: u32 = 0x0620;

/// Cursor control flags
pub const GLENFLY_CURSOR_CTRL_ENABLE: u32 = 1 << 0;
pub const GLENFLY_CURSOR_CTRL_64X64: u32 = 0 << 2;
pub const GLENFLY_CURSOR_CTRL_32X32: u32 = 1 << 2;
pub const GLENFLY_CURSOR_CTRL_256_COLOR: u32 = 0 << 4;
pub const GLENFLY_CURSOR_CTRL_XOR: u32 = 1 << 4;
pub const GLENFLY_CURSOR_CTRL_32BPP: u32 = 2 << 4;

// =====================================================================
// 2D Engine Registers (0x0700 - 0x07FF)
// =====================================================================

/// 2D Engine Control Register
pub const GLENFLY_2D_CTRL: u32 = 0x0700;
/// 2D Engine Status Register
pub const GLENFLY_2D_STATUS: u32 = 0x0704;
/// 2D Engine Source Address Register
pub const GLENFLY_2D_SRC_ADDR: u32 = 0x0710;
/// 2D Engine Source Pitch Register
pub const GLENFLY_2D_SRC_PITCH: u32 = 0x0714;
/// 2D Engine Destination Address Register
pub const GLENFLY_2D_DST_ADDR: u32 = 0x0720;
/// 2D Engine Destination Pitch Register
pub const GLENFLY_2D_DST_PITCH: u32 = 0x0724;
/// 2D Engine ROP Register
pub const GLENFLY_2D_ROP: u32 = 0x0730;
/// 2D Engine Pattern Address Register
pub const GLENFLY_2D_PATTERN_ADDR: u32 = 0x0740;
/// 2D Engine Pattern Control Register
pub const GLENFLY_2D_PATTERN_CTRL: u32 = 0x0744;
/// 2D Engine Clip Rectangle Register
pub const GLENFLY_2D_CLIP: u32 = 0x0750;

/// 2D engine control flags
pub const GLENFLY_2D_CTRL_START: u32 = 1 << 0;
pub const GLENFLY_2D_CTRL_RESET: u32 = 1 << 1;
pub const GLENFLY_2D_CTRL_SOURCE_FILL: u32 = 1 << 4;
pub const GLENFLY_2D_CTRL_BLIT: u32 = 1 << 5;
pub const GLENFLY_2D_CTRL_STRETCH: u32 = 1 << 6;

/// 2D engine status flags
pub const GLENFLY_2D_STATUS_BUSY: u32 = 1 << 0;
pub const GLENFLY_2D_STATUS_COMPLETE: u32 = 1 << 1;

// =====================================================================
// DirectX / 3D Engine Registers (0x0800 - 0x0FFF)
// =====================================================================

/// 3D Engine Control Register
pub const GLENFLY_3D_CTRL: u32 = 0x0800;
/// 3D Engine Status Register
pub const GLENFLY_3D_STATUS: u32 = 0x0804;
/// 3D Engine Vertex Buffer Address Register
pub const GLENFLY_3D_VERTEX_BUF: u32 = 0x0810;
/// 3D Engine Index Buffer Address Register
pub const GLENFLY_3D_INDEX_BUF: u32 = 0x0820;
/// 3D Engine Texture Address Register 0
pub const GLENFLY_3D_TEX_ADDR0: u32 = 0x0830;
/// 3D Engine Texture Pitch Register 0
pub const GLENFLY_3D_TEX_PITCH0: u32 = 0x0834;
/// 3D Engine Render Target Register
pub const GLENFLY_3D_RENDER_TARGET: u32 = 0x0840;

/// DirectX capability registers
pub const GLENFLY_DX_VERSION: u32 = 0x0900;
pub const GLENFLY_DX_CAPS: u32 = 0x0904;
pub const GLENFLY_DX_FEATURE_LEVEL: u32 = 0x0908;

/// DirectX version flags
pub const GLENFLY_DX_VERSION_DX9: u32 = 0x0900_0000;
pub const GLENFLY_DX_VERSION_DX10: u32 = 0x0A00_0000;
pub const GLENFLY_DX_VERSION_DX11: u32 = 0x0B00_0000;
pub const GLENFLY_DX_VERSION_DX11_1: u32 = 0x0B01_0000;

/// DirectX capability flags
pub const GLENFLY_DX_CAPS_2D: u32 = 1 << 0;
pub const GLENFLY_DX_CAPS_3D: u32 = 1 << 1;
pub const GLENFLY_DX_CAPS_VIDEO_DECODE: u32 = 1 << 2;
pub const GLENFLY_DX_CAPS_COMPUTE: u32 = 1 << 3;

// =====================================================================
// Power Management Registers (0x1000 - 0x10FF)
// =====================================================================

/// Power Management Control Register
pub const GLENFLY_PM_CTRL: u32 = 0x1000;
/// Power Management Status Register
pub const GLENFLY_PM_STATUS: u32 = 0x1004;
/// Power Management Target Register
pub const GLENFLY_PM_TARGET: u32 = 0x1008;
/// Power Management D-State Register
pub const GLENFLY_PM_DSTATE: u32 = 0x100C;

/// Power states
pub const GLENFLY_PM_STATE_D0: u32 = 0x00;
pub const GLENFLY_PM_STATE_D1: u32 = 0x01;
pub const GLENFLY_PM_STATE_D2: u32 = 0x02;
pub const GLENFLY_PM_STATE_D3: u32 = 0x03;

/// Power control flags
pub const GLENFLY_PM_CTRL_AUTO: u32 = 1 << 0;
pub const GLENFLY_PM_CTRL_CLOCK_GATE: u32 = 1 << 1;
pub const GLENFLY_PM_CTRL_POWER_OFF: u32 = 1 << 2;
pub const GLENFLY_PM_CTRL_RENDER_OFF: u32 = 1 << 3;
pub const GLENFLY_PM_CTRL_DISPLAY_OFF: u32 = 1 << 4;
pub const GLENFLY_PM_CTRL_3D_OFF: u32 = 1 << 5;
pub const GLENFLY_PM_CTRL_2D_OFF: u32 = 1 << 6;

// =====================================================================
// Clock and PLL Registers (0x1100 - 0x11FF)
// =====================================================================

/// Clock Control Register
pub const GLENFLY_CLK_CTRL: u32 = 0x1100;
/// Clock Status Register
pub const GLENFLY_CLK_STATUS: u32 = 0x1104;
/// Display PLL Control Register
pub const GLENFLY_PLL_DISP_CTRL: u32 = 0x1110;
/// Display PLL Status Register
pub const GLENFLY_PLL_DISP_STATUS: u32 = 0x1114;
/// Display PLL Divisor Register
pub const GLENFLY_PLL_DISP_DIV: u32 = 0x1118;
/// Core PLL Control Register
pub const GLENFLY_PLL_CORE_CTRL: u32 = 0x1120;
/// Memory PLL Control Register
pub const GLENFLY_PLL_MEM_CTRL: u32 = 0x1130;

/// Clock control flags
pub const GLENFLY_CLK_CTRL_PLL_ENABLE: u32 = 1 << 0;
pub const GLENFLY_CLK_CTRL_DC_CLOCK_ENABLE: u32 = 1 << 8;
pub const GLENFLY_CLK_CTRL_DISPLAY_CLOCK_ENABLE: u32 = 1 << 9;
pub const GLENFLY_CLK_CTRL_2D_CLOCK_ENABLE: u32 = 1 << 10;
pub const GLENFLY_CLK_CTRL_3D_CLOCK_ENABLE: u32 = 1 << 11;
pub const GLENFLY_CLK_CTRL_VP_CLOCK_ENABLE: u32 = 1 << 12;

// =====================================================================
// Helper Functions
// =====================================================================

/// Convert DisplayFormat to Glenfly framebuffer format
pub fn format_to_glenfly_format(format: DisplayFormat) -> u32 {
    match format {
        DisplayFormat::Bgra8888 => GLENFLY_FB_FORMAT_BGRA8888,
        DisplayFormat::Argb8888 => GLENFLY_FB_FORMAT_RGBA8888,
        DisplayFormat::Rgb565 => GLENFLY_FB_FORMAT_RGB565,
        DisplayFormat::Rgb888 => GLENFLY_FB_FORMAT_RGB888,
    }
}

/// Calculate CRT timing parameters for Glenfly
pub fn calculate_crtc_timing(width: u32, height: u32, _refresh: u32) -> GlenflyCrtcTiming {
    let h_total = width + 160;
    let h_sync_start = width + 48;
    let h_sync_end = width + 112;
    let h_blank_start = width;
    let h_blank_end = h_total;

    let v_total = height + 30;
    let v_sync_start = height + 10;
    let v_sync_end = height + 12;
    let v_blank_start = height;
    let v_blank_end = v_total;

    GlenflyCrtcTiming {
        h_total,
        h_sync_start,
        h_sync_end,
        h_blank_start,
        h_blank_end,
        v_total,
        v_sync_start,
        v_sync_end,
        v_blank_start,
        v_blank_end,
    }
}

/// Glenfly CRT timing parameters
#[derive(Debug, Clone, Copy)]
pub struct GlenflyCrtcTiming {
    pub h_total: u32,
    pub h_sync_start: u32,
    pub h_sync_end: u32,
    pub h_blank_start: u32,
    pub h_blank_end: u32,
    pub v_total: u32,
    pub v_sync_start: u32,
    pub v_sync_end: u32,
    pub v_blank_start: u32,
    pub v_blank_end: u32,
}

impl GlenflyCrtcTiming {
    /// Encode horizontal total register value
    pub fn h_total_reg(&self) -> u32 {
        (self.h_total << 16) | self.h_blank_start
    }

    /// Encode horizontal blank register value
    pub fn h_blank_reg(&self) -> u32 {
        (self.h_blank_end << 16) | self.h_blank_start
    }

    /// Encode horizontal sync register value
    pub fn h_sync_reg(&self) -> u32 {
        (self.h_sync_end << 16) | self.h_sync_start
    }

    /// Encode vertical total register value
    pub fn v_total_reg(&self) -> u32 {
        (self.v_total << 16) | self.v_blank_start
    }

    /// Encode vertical blank register value
    pub fn v_blank_reg(&self) -> u32 {
        (self.v_blank_end << 16) | self.v_blank_start
    }

    /// Encode vertical sync register value
    pub fn v_sync_reg(&self) -> u32 {
        (self.v_sync_end << 16) | self.v_sync_start
    }
}
