//! Zhaoxin ZX-E / KX-6000 Display Controller Registers
//
//! This module defines the MMIO register layout for the ZX-E display
//! controller used in KX-6000 and KX-6000G processors.
//
//! The ZX-E DC is an enhanced version of ZX-D with improved features:
//! - Better 3D acceleration
//! - DirectX 11.1 support
//! - Enhanced video capabilities
//
//! Reference: S3 Chrome documentation, Linux zhaoxin driver
//
//! Clean-room implementation based on public specifications.

use super::pci_ids::{DisplayFormat, ZhaoxinVariant};

// =====================================================================
// Register Base Address
// =====================================================================

/// ZX-E Display Controller MMIO base offset (BAR0)
pub const ZX_E_DC_BASE: u32 = 0x0000;

// =====================================================================
// Display Controller Core Registers (0x0000 - 0x00FF)
// =====================================================================

/// Display Controller Control Register
pub const ZX_E_DC_CTRL: u32 = 0x0000;
/// Display Controller Status Register
pub const ZX_E_DC_STATUS: u32 = 0x0004;
/// Display Controller Interrupt Register
pub const ZX_E_DC_INT: u32 = 0x0008;
/// Display Controller Interrupt Mask Register
pub const ZX_E_DC_INT_MASK: u32 = 0x000C;
/// Display Controller Version Register
pub const ZX_E_DC_VERSION: u32 = 0x0010;
/// Display Controller Revision Register
pub const ZX_E_DC_REVISION: u32 = 0x0014;
/// Display Controller Feature Register
pub const ZX_E_DC_FEATURE: u32 = 0x0018;

/// Control register flags (enhanced)
pub const ZX_E_DC_CTRL_ENABLE: u32 = 1 << 0;        // DC enable
pub const ZX_E_DC_CTRL_RUN: u32 = 1 << 1;          // DC running
pub const ZX_E_DC_CTRL_RESET: u32 = 1 << 2;        // DC reset
pub const ZX_E_DC_CTRL_VBLANK_INT: u32 = 1 << 3;   // V-blank interrupt enable
pub const ZX_E_DC_CTRL_REG_UPDATE: u32 = 1 << 4;    // Register update
pub const ZX_E_DC_CTRL_TE_FREEZE: u32 = 1 << 5;    // TE freeze (for sync)

/// Status register flags (enhanced)
pub const ZX_E_DC_STATUS_ENABLE: u32 = 1 << 0;     // DC enabled
pub const ZX_E_DC_STATUS_RUN: u32 = 1 << 1;        // DC running
pub const ZX_E_DC_STATUS_VBLANK: u32 = 1 << 2;     // V-blank active
pub const ZX_E_DC_STATUS_ERROR: u32 = 1 << 3;      // Error occurred
pub const ZX_E_DC_STATUS_REG_UPDATE: u32 = 1 << 4; // Register update pending
pub const ZX_E_DC_STATUS_PIPE_A_ON: u32 = 1 << 8;  // Pipe A active
pub const ZX_E_DC_STATUS_PIPE_B_ON: u32 = 1 << 9;  // Pipe B active

/// Interrupt flags (enhanced)
pub const ZX_E_DC_INT_VBLANK_A: u32 = 1 << 0;      // Pipeline A v-blank
pub const ZX_E_DC_INT_VBLANK_B: u32 = 1 << 1;      // Pipeline B v-blank
pub const ZX_E_DC_INT_FIFO_UNDERFLOW: u32 = 1 << 8; // FIFO underflow
pub const ZX_E_DC_INT_FIFO_OVERFLOW: u32 = 1 << 9;  // FIFO overflow
pub const ZX_E_DC_INT_REG_UPDATE: u32 = 1 << 16;    // Register update
pub const ZX_E_DC_INT_PAGE_FAULT: u32 = 1 << 20;    // Page fault

// =====================================================================
// Framebuffer Configuration (0x0100 - 0x01FF) - Enhanced
// =====================================================================

/// Framebuffer Physical Address Register (64-bit)
pub const ZX_E_FB_ADDR: u32 = 0x0100;
/// Framebuffer Physical Address High Register
pub const ZX_E_FB_ADDR_HIGH: u32 = 0x0104;
/// Framebuffer Stride (bytes per line) Register
pub const ZX_E_FB_STRIDE: u32 = 0x0108;
/// Framebuffer Size Register
pub const ZX_E_FB_SIZE: u32 = 0x010C;
/// Framebuffer Format Register
pub const ZX_E_FB_FORMAT: u32 = 0x0110;
/// Framebuffer Color Key Register
pub const ZX_E_FB_COLOR_KEY: u32 = 0x0114;
/// Framebuffer Color Key Mask Register
pub const ZX_E_FB_COLOR_KEY_MASK: u32 = 0x0118;
/// Framebuffer Gamma Correction Register
pub const ZX_E_FB_GAMMA: u32 = 0x011C;

/// Framebuffer format flags (enhanced)
pub const ZX_E_FB_FORMAT_BGRA8888: u32 = 0x00;   // BGRA 8888
pub const ZX_E_FB_FORMAT_RGBA8888: u32 = 0x01;   // RGBA 8888
pub const ZX_E_FB_FORMAT_RGB565: u32 = 0x02;      // RGB 565
pub const ZX_E_FB_FORMAT_RGB888: u32 = 0x03;      // RGB 888
pub const ZX_E_FB_FORMAT_ARGB1555: u32 = 0x04;    // ARGB 1555
pub const ZX_E_FB_FORMAT_ARGB4444: u32 = 0x05;    // ARGB 4444
pub const ZX_E_FB_FORMAT_YUV422: u32 = 0x10;      // YUV 4:2:2
pub const ZX_E_FB_FORMAT_YUV420: u32 = 0x11;      // YUV 4:2:0

// =====================================================================
// CRT Controller A Registers (0x0200 - 0x02FF) - Enhanced
// =====================================================================

/// CRT Controller A Control Register
pub const ZX_E_CRTC_A_CTRL: u32 = 0x0200;
/// CRT Controller A Configuration Register
pub const ZX_E_CRTC_A_CONFIG: u32 = 0x0204;
/// CRT Controller A Horizontal Total Register
pub const ZX_E_CRTC_A_H_TOTAL: u32 = 0x0210;
/// CRT Controller A Horizontal Blank Start/End Register
pub const ZX_E_CRTC_A_H_BLANK: u32 = 0x0214;
/// CRT Controller A Horizontal Sync Start Register
pub const ZX_E_CRTC_A_H_SYNC: u32 = 0x0218;
/// CRT Controller A Horizontal Sync End Register
pub const ZX_E_CRTC_A_H_SYNC_END: u32 = 0x021C;
/// CRT Controller A Vertical Total Register
pub const ZX_E_CRTC_A_V_TOTAL: u32 = 0x0220;
/// CRT Controller A Vertical Blank Start/End Register
pub const ZX_E_CRTC_A_V_BLANK: u32 = 0x0224;
/// CRT Controller A Vertical Sync Start Register
pub const ZX_E_CRTC_A_V_SYNC: u32 = 0x0228;
/// CRT Controller A Vertical Sync End Register
pub const ZX_E_CRTC_A_V_SYNC_END: u32 = 0x022C;
/// CRT Controller A Display Address Start Register
pub const ZX_E_CRTC_A_ADDR: u32 = 0x0230;
/// CRT Controller A Display Address Offset Register
pub const ZX_E_CRTC_A_ADDR_OFFSET: u32 = 0x0234;
/// CRT Controller A Border Color Register
pub const ZX_E_CRTC_A_BORDER_COLOR: u32 = 0x0238;

/// CRT Controller A control flags
pub const ZX_E_CRTC_A_CTRL_ENABLE: u32 = 1 << 0;      // CRT enable
pub const ZX_E_CRTC_A_CTRL_8BPP: u32 = 0 << 2;        // 8 bits per pixel
pub const ZX_E_CRTC_A_CTRL_16BPP: u32 = 1 << 2;       // 16 bits per pixel
pub const ZX_E_CRTC_A_CTRL_24BPP: u32 = 2 << 2;         // 24 bits per pixel
pub const ZX_E_CRTC_A_CTRL_32BPP: u32 = 3 << 2;         // 32 bits per pixel
pub const ZX_E_CRTC_A_CTRL_HSYNC_POS: u32 = 1 << 6;     // H-sync positive
pub const ZX_E_CRTC_A_CTRL_VSYNC_POS: u32 = 1 << 7;    // V-sync positive
pub const ZX_E_CRTC_A_CTRL_INTERLACE: u32 = 1 << 8;    // Interlaced mode
pub const ZX_E_CRTC_A_CTRL_DOUBLE_SCAN: u32 = 1 << 9;  // Double scan

// =====================================================================
// CRT Controller B Registers (0x0300 - 0x03FF)
// =====================================================================

/// CRT Controller B Control Register
pub const ZX_E_CRTC_B_CTRL: u32 = 0x0300;
/// CRT Controller B Configuration Register
pub const ZX_E_CRTC_B_CONFIG: u32 = 0x0304;
/// CRT Controller B Horizontal Total Register
pub const ZX_E_CRTC_B_H_TOTAL: u32 = 0x0310;
/// CRT Controller B Horizontal Blank Start/End Register
pub const ZX_E_CRTC_B_H_BLANK: u32 = 0x0314;
/// CRT Controller B Horizontal Sync Start Register
pub const ZX_E_CRTC_B_H_SYNC: u32 = 0x0318;
/// CRT Controller B Horizontal Sync End Register
pub const ZX_E_CRTC_B_H_SYNC_END: u32 = 0x031C;
/// CRT Controller B Vertical Total Register
pub const ZX_E_CRTC_B_V_TOTAL: u32 = 0x0320;
/// CRT Controller B Vertical Blank Start/End Register
pub const ZX_E_CRTC_B_V_BLANK: u32 = 0x0324;
/// CRT Controller B Vertical Sync Start Register
pub const ZX_E_CRTC_B_V_SYNC: u32 = 0x0328;
/// CRT Controller B Vertical Sync End Register
pub const ZX_E_CRTC_B_V_SYNC_END: u32 = 0x032C;
/// CRT Controller B Display Address Start Register
pub const ZX_E_CRTC_B_ADDR: u32 = 0x0330;
/// CRT Controller B Display Address Offset Register
pub const ZX_E_CRTC_B_ADDR_OFFSET: u32 = 0x0334;
/// CRT Controller B Border Color Register
pub const ZX_E_CRTC_B_BORDER_COLOR: u32 = 0x0338;

/// CRT Controller B control flags (same as A)
pub const ZX_E_CRTC_B_CTRL_ENABLE: u32 = ZX_E_CRTC_A_CTRL_ENABLE;
pub const ZX_E_CRTC_B_CTRL_8BPP: u32 = ZX_E_CRTC_A_CTRL_8BPP;
pub const ZX_E_CRTC_B_CTRL_16BPP: u32 = ZX_E_CRTC_A_CTRL_16BPP;
pub const ZX_E_CRTC_B_CTRL_24BPP: u32 = ZX_E_CRTC_A_CTRL_24BPP;
pub const ZX_E_CRTC_B_CTRL_32BPP: u32 = ZX_E_CRTC_A_CTRL_32BPP;
pub const ZX_E_CRTC_B_CTRL_HSYNC_POS: u32 = ZX_E_CRTC_A_CTRL_HSYNC_POS;
pub const ZX_E_CRTC_B_CTRL_VSYNC_POS: u32 = ZX_E_CRTC_A_CTRL_VSYNC_POS;

// =====================================================================
// Primary Plane Registers (0x0400 - 0x04FF) - Enhanced
// =====================================================================

/// Primary Plane Control Register
pub const ZX_E_PLANE_PRIMARY_CTRL: u32 = 0x0400;
/// Primary Plane Address Register (64-bit)
pub const ZX_E_PLANE_PRIMARY_ADDR: u32 = 0x0404;
/// Primary Plane Address High Register
pub const ZX_E_PLANE_PRIMARY_ADDR_HIGH: u32 = 0x0408;
/// Primary Plane Stride Register
pub const ZX_E_PLANE_PRIMARY_STRIDE: u32 = 0x040C;
/// Primary Plane Size Register
pub const ZX_E_PLANE_PRIMARY_SIZE: u32 = 0x0410;
/// Primary Plane Position Register
pub const ZX_E_PLANE_PRIMARY_POS: u32 = 0x0414;
/// Primary Plane Format Register
pub const ZX_E_PLANE_PRIMARY_FORMAT: u32 = 0x0418;
/// Primary Plane Color Key Register
pub const ZX_E_PLANE_PRIMARY_COLOR_KEY: u32 = 0x041C;
/// Primary Plane Gamma Register
pub const ZX_E_PLANE_PRIMARY_GAMMA: u32 = 0x0420;

/// Primary plane control flags
pub const ZX_E_PLANE_CTRL_ENABLE: u32 = 1 << 0;        // Plane enable
pub const ZX_E_PLANE_CTRL_KEY_EN: u32 = 1 << 1;         // Color key enable
pub const ZX_E_PLANE_CTRL_ALPHA_EN: u32 = 1 << 2;       // Alpha blend enable
pub const ZX_E_PLANE_CTRL_CONST_ALPHA: u32 = 1 << 3;    // Constant alpha
pub const ZX_E_PLANE_CTRL_FORMAT_SHIFT: u32 = 4;          // Format field shift
pub const ZX_E_PLANE_CTRL_SCALE_EN: u32 = 1 << 16;      // Scaling enable
pub const ZX_E_PLANE_CTRL_DEINTERLACE: u32 = 1 << 17;   // Deinterlace

// =====================================================================
// Overlay Plane Registers (0x0500 - 0x05FF) - Enhanced
// =====================================================================

/// Overlay Plane Control Register
pub const ZX_E_PLANE_OVERLAY_CTRL: u32 = 0x0500;
/// Overlay Plane Address Y Register (64-bit)
pub const ZX_E_PLANE_OVERLAY_ADDR_Y: u32 = 0x0504;
/// Overlay Plane Address Y High Register
pub const ZX_E_PLANE_OVERLAY_ADDR_Y_HIGH: u32 = 0x0508;
/// Overlay Plane Address UV Register
pub const ZX_E_PLANE_OVERLAY_ADDR_UV: u32 = 0x050C;
/// Overlay Plane Address UV High Register
pub const ZX_E_PLANE_OVERLAY_ADDR_UV_HIGH: u32 = 0x0510;
/// Overlay Plane Stride Register
pub const ZX_E_PLANE_OVERLAY_STRIDE: u32 = 0x0514;
/// Overlay Plane UV Stride Register
pub const ZX_E_PLANE_OVERLAY_STRIDE_UV: u32 = 0x0518;
/// Overlay Plane Size Register
pub const ZX_E_PLANE_OVERLAY_SIZE: u32 = 0x051C;
/// Overlay Plane Position Register
pub const ZX_E_PLANE_OVERLAY_POS: u32 = 0x0520;
/// Overlay Plane Format Register
pub const ZX_E_PLANE_OVERLAY_FORMAT: u32 = 0x0524;
/// Overlay Plane Color Key Register
pub const ZX_E_PLANE_OVERLAY_COLOR_KEY: u32 = 0x0528;

/// Overlay plane control flags
pub const ZX_E_OVERLAY_CTRL_ENABLE: u32 = 1 << 0;
pub const ZX_E_OVERLAY_CTRL_COLOR_KEY: u32 = 1 << 1;
pub const ZX_E_OVERLAY_CTRL_ALPHA: u32 = 1 << 2;
pub const ZX_E_OVERLAY_CTRL_CONST_ALPHA: u32 = 1 << 3;
pub const ZX_E_OVERLAY_CTRL_YUV2RGB: u32 = 1 << 8;
pub const ZX_E_OVERLAY_CTRL_BILINEAR: u32 = 1 << 12;
pub const ZX_E_OVERLAY_CTRL_DEINTERLACE: u32 = 1 << 16;

// =====================================================================
// Hardware Cursor Registers (0x0600 - 0x06FF) - Enhanced
// =====================================================================

/// Hardware Cursor Control Register
pub const ZX_E_CURSOR_CTRL: u32 = 0x0600;
/// Hardware Cursor Palette Register 0
pub const ZX_E_CURSOR_PALETTE0: u32 = 0x0604;
/// Hardware Cursor Palette Register 1
pub const ZX_E_CURSOR_PALETTE1: u32 = 0x0608;
/// Hardware Cursor Palette Register 2
pub const ZX_E_CURSOR_PALETTE2: u32 = 0x060C;
/// Hardware Cursor Palette Register 3
pub const ZX_E_CURSOR_PALETTE3: u32 = 0x0610;
/// Hardware Cursor Address Register
pub const ZX_E_CURSOR_ADDR: u32 = 0x0614;
/// Hardware Cursor Address High Register
pub const ZX_E_CURSOR_ADDR_HIGH: u32 = 0x0618;
/// Hardware Cursor Position Register
pub const ZX_E_CURSOR_POS: u32 = 0x061C;
/// Hardware Cursor Hotspot Register
pub const ZX_E_CURSOR_HOTSPOT: u32 = 0x0620;

/// Cursor control flags
pub const ZX_E_CURSOR_CTRL_ENABLE: u32 = 1 << 0;
pub const ZX_E_CURSOR_CTRL_64X64: u32 = 0 << 2;
pub const ZX_E_CURSOR_CTRL_32X32: u32 = 1 << 2;
pub const ZX_E_CURSOR_CTRL_16X16: u32 = 2 << 2;
pub const ZX_E_CURSOR_CTRL_256_COLOR: u32 = 0 << 4;
pub const ZX_E_CURSOR_CTRL_XOR: u32 = 1 << 4;
pub const ZX_E_CURSOR_CTRL_32BPP: u32 = 2 << 4;
pub const ZX_E_CURSOR_CTRL_HOTSPOT_EN: u32 = 1 << 8;

// =====================================================================
// DirectX 11.1 Capability Registers (0x1000 - 0x10FF)
// =====================================================================

/// DirectX Version Register
pub const ZX_E_DX_VERSION: u32 = 0x1000;
/// DirectX Capability Register
pub const ZX_E_DX_CAPS: u32 = 0x1004;
/// DirectX Max Texture Size Register
pub const ZX_E_DX_MAX_TEXTURE: u32 = 0x1008;
/// DirectX Max Render Targets Register
pub const ZX_E_DX_MAX_RENDER_TARGETS: u32 = 0x100C;
/// DirectX Feature Level Register
pub const ZX_E_DX_FEATURE_LEVEL: u32 = 0x1010;
/// DirectX Device ID Register
pub const ZX_E_DX_DEVICE_ID: u32 = 0x1014;

/// DirectX version flags
pub const ZX_E_DX_VERSION_DX9: u32 = 0x0900_0000;
pub const ZX_E_DX_VERSION_DX10: u32 = 0x0A00_0000;
pub const ZX_E_DX_VERSION_DX11: u32 = 0x0B00_0000;
pub const ZX_E_DX_VERSION_DX11_1: u32 = 0x0B01_0000;

/// DirectX feature levels
pub const ZX_E_DX_FL_9_1: u32 = 0x9100;
pub const ZX_E_DX_FL_9_2: u32 = 0x9200;
pub const ZX_E_DX_FL_9_3: u32 = 0x9300;
pub const ZX_E_DX_FL_10_0: u32 = 0xA000;
pub const ZX_E_DX_FL_10_1: u32 = 0xA100;
pub const ZX_E_DX_FL_11_0: u32 = 0xB000;
pub const ZX_E_DX_FL_11_1: u32 = 0xB100;

/// DirectX capability flags
pub const ZX_E_DX_CAPS_2D: u32 = 1 << 0;
pub const ZX_E_DX_CAPS_3D: u32 = 1 << 1;
pub const ZX_E_DX_CAPS_VIDEO_DECODE: u32 = 1 << 2;
pub const ZX_E_DX_CAPS_VIDEO_ENCODE: u32 = 1 << 3;
pub const ZX_E_DX_CAPS_COMPUTE: u32 = 1 << 4;
pub const ZX_E_DX_CAPS_TESSELLATION: u32 = 1 << 5;

// =====================================================================
// Video Processor Registers (0x1100 - 0x11FF)
// =====================================================================

/// Video Processor Control Register
pub const ZX_E_VP_CTRL: u32 = 0x1100;
/// Video Processor Status Register
pub const ZX_E_VP_STATUS: u32 = 0x1104;
/// Video Processor Source Address Register
pub const ZX_E_VP_SRC_ADDR: u32 = 0x1108;
/// Video Processor Destination Address Register
pub const ZX_E_VP_DST_ADDR: u32 = 0x110C;
/// Video Processor Size Register
pub const ZX_E_VP_SIZE: u32 = 0x1110;

/// Video processor control flags
pub const ZX_E_VP_CTRL_ENABLE: u32 = 1 << 0;
pub const ZX_E_VP_CTRL_DEINTERLACE: u32 = 1 << 1;
pub const ZX_E_VP_CTRL_DENOISE: u32 = 1 << 2;
pub const ZX_E_VP_CTRL_SHARPNESS: u32 = 1 << 3;
pub const ZX_E_VP_CTRL_COLOR_ADJUST: u32 = 1 << 4;

// =====================================================================
// Power Management Registers (0x1200 - 0x12FF)
// =====================================================================

/// Power Management Control Register
pub const ZX_E_PM_CTRL: u32 = 0x1200;
/// Power Management Status Register
pub const ZX_E_PM_STATUS: u32 = 0x1204;
/// Power Management Target Register
pub const ZX_E_PM_TARGET: u32 = 0x1208;
/// Power Management D-State Register
pub const ZX_E_PM_DSTATE: u32 = 0x120C;

/// Power states
pub const ZX_E_PM_STATE_D0: u32 = 0x00;
pub const ZX_E_PM_STATE_D1: u32 = 0x01;
pub const ZX_E_PM_STATE_D2: u32 = 0x02;
pub const ZX_E_PM_STATE_D3: u32 = 0x03;

/// Power control flags
pub const ZX_E_PM_CTRL_AUTO: u32 = 1 << 0;
pub const ZX_E_PM_CTRL_CLOCK_GATE: u32 = 1 << 1;
pub const ZX_E_PM_CTRL_POWER_OFF: u32 = 1 << 2;
pub const ZX_E_PM_CTRL_RENDER_OFF: u32 = 1 << 3;
pub const ZX_E_PM_CTRL_DISPLAY_OFF: u32 = 1 << 4;

// =====================================================================
// Clock and PLL Registers (0x1300 - 0x13FF)
// =====================================================================

/// Clock Control Register
pub const ZX_E_CLK_CTRL: u32 = 0x1300;
/// Clock Status Register
pub const ZX_E_CLK_STATUS: u32 = 0x1304;
/// Display PLL Control Register
pub const ZX_E_PLL_DISP_CTRL: u32 = 0x1310;
/// Display PLL Status Register
pub const ZX_E_PLL_DISP_STATUS: u32 = 0x1314;
/// Display PLL Divisor Register
pub const ZX_E_PLL_DISP_DIV: u32 = 0x1318;

/// Clock control flags
pub const ZX_E_CLK_CTRL_PLL_ENABLE: u32 = 1 << 0;
pub const ZX_E_CLK_CTRL_DC_CLOCK_ENABLE: u32 = 1 << 8;
pub const ZX_E_CLK_CTRL_DISPLAY_CLOCK_ENABLE: u32 = 1 << 9;
pub const ZX_E_CLK_CTRL_VP_CLOCK_ENABLE: u32 = 1 << 10;
pub const ZX_E_CLK_CTRL_2D_CLOCK_ENABLE: u32 = 1 << 11;
pub const ZX_E_CLK_CTRL_3D_CLOCK_ENABLE: u32 = 1 << 12;

// =====================================================================
// Helper Functions
// =====================================================================

/// Convert DisplayFormat to ZX-E framebuffer format
pub fn format_to_zxe_format(format: DisplayFormat) -> u32 {
    match format {
        DisplayFormat::Bgra8888 => ZX_E_FB_FORMAT_BGRA8888,
        DisplayFormat::Argb8888 => ZX_E_FB_FORMAT_RGBA8888,
        DisplayFormat::Rgb565 => ZX_E_FB_FORMAT_RGB565,
        DisplayFormat::Rgb888 => ZX_E_FB_FORMAT_RGB888,
    }
}

/// Calculate enhanced CRT timing parameters for ZX-E
pub fn calculate_crtc_timing_enhanced(width: u32, height: u32, _refresh: u32) -> EnhancedCrtcTiming {
    // Standard timing with overscan for ZX-E
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

    EnhancedCrtcTiming {
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

/// Enhanced CRT timing parameters
#[derive(Debug, Clone, Copy)]
pub struct EnhancedCrtcTiming {
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

impl EnhancedCrtcTiming {
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

// =====================================================================
// Register Access Helper
// =====================================================================

/// ZX-E register definitions for use in driver code
pub mod regs {
    use super::*;

    /// All ZX-E DC registers with their offsets
    pub struct ZxERegisters;

    impl ZxERegisters {
        /// DC core registers
        pub const DC_CTRL: u32 = ZX_E_DC_CTRL;
        pub const DC_STATUS: u32 = ZX_E_DC_STATUS;
        pub const DC_INT: u32 = ZX_E_DC_INT;
        pub const DC_INT_MASK: u32 = ZX_E_DC_INT_MASK;
        pub const DC_VERSION: u32 = ZX_E_DC_VERSION;
        pub const DC_FEATURE: u32 = ZX_E_DC_FEATURE;

        /// Framebuffer registers
        pub const FB_ADDR: u32 = ZX_E_FB_ADDR;
        pub const FB_ADDR_HIGH: u32 = ZX_E_FB_ADDR_HIGH;
        pub const FB_STRIDE: u32 = ZX_E_FB_STRIDE;
        pub const FB_SIZE: u32 = ZX_E_FB_SIZE;
        pub const FB_FORMAT: u32 = ZX_E_FB_FORMAT;

        /// CRT controller A
        pub const CRTC_A_CTRL: u32 = ZX_E_CRTC_A_CTRL;
        pub const CRTC_A_CONFIG: u32 = ZX_E_CRTC_A_CONFIG;
        pub const CRTC_A_H_TOTAL: u32 = ZX_E_CRTC_A_H_TOTAL;
        pub const CRTC_A_H_BLANK: u32 = ZX_E_CRTC_A_H_BLANK;
        pub const CRTC_A_H_SYNC: u32 = ZX_E_CRTC_A_H_SYNC;
        pub const CRTC_A_V_TOTAL: u32 = ZX_E_CRTC_A_V_TOTAL;
        pub const CRTC_A_V_BLANK: u32 = ZX_E_CRTC_A_V_BLANK;
        pub const CRTC_A_V_SYNC: u32 = ZX_E_CRTC_A_V_SYNC;
        pub const CRTC_A_ADDR: u32 = ZX_E_CRTC_A_ADDR;
        pub const CRTC_A_ADDR_OFFSET: u32 = ZX_E_CRTC_A_ADDR_OFFSET;

        /// CRT controller B
        pub const CRTC_B_CTRL: u32 = ZX_E_CRTC_B_CTRL;
        pub const CRTC_B_CONFIG: u32 = ZX_E_CRTC_B_CONFIG;
        pub const CRTC_B_H_TOTAL: u32 = ZX_E_CRTC_B_H_TOTAL;
        pub const CRTC_B_H_BLANK: u32 = ZX_E_CRTC_B_H_BLANK;
        pub const CRTC_B_H_SYNC: u32 = ZX_E_CRTC_B_H_SYNC;
        pub const CRTC_B_V_TOTAL: u32 = ZX_E_CRTC_B_V_TOTAL;
        pub const CRTC_B_V_BLANK: u32 = ZX_E_CRTC_B_V_BLANK;
        pub const CRTC_B_V_SYNC: u32 = ZX_E_CRTC_B_V_SYNC;
        pub const CRTC_B_ADDR: u32 = ZX_E_CRTC_B_ADDR;
        pub const CRTC_B_ADDR_OFFSET: u32 = ZX_E_CRTC_B_ADDR_OFFSET;

        /// Primary plane
        pub const PLANE_PRIMARY_CTRL: u32 = ZX_E_PLANE_PRIMARY_CTRL;
        pub const PLANE_PRIMARY_ADDR: u32 = ZX_E_PLANE_PRIMARY_ADDR;
        pub const PLANE_PRIMARY_ADDR_HIGH: u32 = ZX_E_PLANE_PRIMARY_ADDR_HIGH;
        pub const PLANE_PRIMARY_STRIDE: u32 = ZX_E_PLANE_PRIMARY_STRIDE;
        pub const PLANE_PRIMARY_SIZE: u32 = ZX_E_PLANE_PRIMARY_SIZE;
        pub const PLANE_PRIMARY_FORMAT: u32 = ZX_E_PLANE_PRIMARY_FORMAT;

        /// Overlay plane
        pub const PLANE_OVERLAY_CTRL: u32 = ZX_E_PLANE_OVERLAY_CTRL;
        pub const PLANE_OVERLAY_ADDR_Y: u32 = ZX_E_PLANE_OVERLAY_ADDR_Y;
        pub const PLANE_OVERLAY_STRIDE: u32 = ZX_E_PLANE_OVERLAY_STRIDE;
        pub const PLANE_OVERLAY_SIZE: u32 = ZX_E_PLANE_OVERLAY_SIZE;
        pub const PLANE_OVERLAY_FORMAT: u32 = ZX_E_PLANE_OVERLAY_FORMAT;

        /// Hardware cursor
        pub const CURSOR_CTRL: u32 = ZX_E_CURSOR_CTRL;
        pub const CURSOR_ADDR: u32 = ZX_E_CURSOR_ADDR;
        pub const CURSOR_POS: u32 = ZX_E_CURSOR_POS;

        /// DirectX registers
        pub const DX_VERSION: u32 = ZX_E_DX_VERSION;
        pub const DX_CAPS: u32 = ZX_E_DX_CAPS;
        pub const DX_FEATURE_LEVEL: u32 = ZX_E_DX_FEATURE_LEVEL;

        /// Power management
        pub const PM_CTRL: u32 = ZX_E_PM_CTRL;
        pub const PM_STATUS: u32 = ZX_E_PM_STATUS;

        /// Clock control
        pub const CLK_CTRL: u32 = ZX_E_CLK_CTRL;
        pub const PLL_DISP_CTRL: u32 = ZX_E_PLL_DISP_CTRL;
    }
}
