//! Zhaoxin ZX-D Display Controller Registers
//
//! This module defines the MMIO register layout for the ZX-D display
//! controller used in KX-5000/KX-6000 processors.
//
//! The ZX-D DC is based on S3 Graphics Chrome architecture.
//
//! Reference: S3 Chrome documentation, Linux zhaoxin driver
//
//! Clean-room implementation based on public specifications.

use super::pci_ids::{DisplayFormat, ZhaoxinVariant};

// =====================================================================
// Register Base Address
// =====================================================================

/// ZX-D Display Controller MMIO base offset (BAR0)
pub const ZX_DC_BASE: u32 = 0x0000;

// =====================================================================
// Display Controller Core Registers (0x0000 - 0x00FF)
// =====================================================================

/// Display Controller Control Register
pub const ZX_DC_CTRL: u32 = 0x0000;
/// Display Controller Status Register
pub const ZX_DC_STATUS: u32 = 0x0004;
/// Display Controller Interrupt Register
pub const ZX_DC_INT: u32 = 0x0008;
/// Display Controller Interrupt Mask Register
pub const ZX_DC_INT_MASK: u32 = 0x000C;
/// Display Controller Version Register
pub const ZX_DC_VERSION: u32 = 0x0010;
/// Display Controller Revision Register
pub const ZX_DC_REVISION: u32 = 0x0014;

/// Control register flags
pub const ZX_DC_CTRL_ENABLE: u32 = 1 << 0;      // DC enable
pub const ZX_DC_CTRL_RUN: u32 = 1 << 1;        // DC running
pub const ZX_DC_CTRL_RESET: u32 = 1 << 2;     // DC reset
pub const ZX_DC_CTRL_VBLANK_INT: u32 = 1 << 3; // V-blank interrupt enable

/// Status register flags
pub const ZX_DC_STATUS_ENABLE: u32 = 1 << 0;  // DC enabled
pub const ZX_DC_STATUS_RUN: u32 = 1 << 1;     // DC running
pub const ZX_DC_STATUS_VBLANK: u32 = 1 << 2;  // V-blank active
pub const ZX_DC_STATUS_ERROR: u32 = 1 << 3;   // Error occurred

/// Interrupt flags
pub const ZX_DC_INT_VBLANK_A: u32 = 1 << 0;   // Pipeline A v-blank
pub const ZX_DC_INT_VBLANK_B: u32 = 1 << 1;   // Pipeline B v-blank
pub const ZX_DC_INT_FIFO_UNDERFLOW: u32 = 1 << 8;  // FIFO underflow
pub const ZX_DC_INT_REG_UPDATE: u32 = 1 << 16;    // Register update

// =====================================================================
// Framebuffer Configuration (0x0100 - 0x01FF)
// =====================================================================

/// Framebuffer Physical Address Register
pub const ZX_FB_ADDR: u32 = 0x0100;
/// Framebuffer Stride (bytes per line) Register
pub const ZX_FB_STRIDE: u32 = 0x0104;
/// Framebuffer Size Register
pub const ZX_FB_SIZE: u32 = 0x0108;
/// Framebuffer Format Register
pub const ZX_FB_FORMAT: u32 = 0x010C;
/// Framebuffer Color Key Register
pub const ZX_FB_COLOR_KEY: u32 = 0x0110;
/// Framebuffer Color Key Mask Register
pub const ZX_FB_COLOR_KEY_MASK: u32 = 0x0114;

/// Framebuffer format flags
pub const ZX_FB_FORMAT_BGRA8888: u32 = 0x00;   // BGRA 8888
pub const ZX_FB_FORMAT_RGBA8888: u32 = 0x01;   // RGBA 8888
pub const ZX_FB_FORMAT_RGB565: u32 = 0x02;     // RGB 565
pub const ZX_FB_FORMAT_RGB888: u32 = 0x03;     // RGB 888
pub const ZX_FB_FORMAT_ARGB1555: u32 = 0x04;   // ARGB 1555
pub const ZX_FB_FORMAT_ARGB4444: u32 = 0x05;   // ARGB 4444

// =====================================================================
// CRT Controller A Registers (0x0200 - 0x02FF)
// =====================================================================

/// CRT Controller A Control Register
pub const ZX_CRTC_A_CTRL: u32 = 0x0200;
/// CRT Controller A Horizontal Total Register
pub const ZX_CRTC_A_H_TOTAL: u32 = 0x0210;
/// CRT Controller A Horizontal Blank Start Register
pub const ZX_CRTC_A_H_BLANK: u32 = 0x0214;
/// CRT Controller A Horizontal Sync Start Register
pub const ZX_CRTC_A_H_SYNC: u32 = 0x0218;
/// CRT Controller A Horizontal Sync End Register
pub const ZX_CRTC_A_H_SYNC_END: u32 = 0x021C;
/// CRT Controller A Vertical Total Register
pub const ZX_CRTC_A_V_TOTAL: u32 = 0x0220;
/// CRT Controller A Vertical Blank Start Register
pub const ZX_CRTC_A_V_BLANK: u32 = 0x0224;
/// CRT Controller A Vertical Sync Start Register
pub const ZX_CRTC_A_V_SYNC: u32 = 0x0228;
/// CRT Controller A Vertical Sync End Register
pub const ZX_CRTC_A_V_SYNC_END: u32 = 0x022C;
/// CRT Controller A Display Address Start Register
pub const ZX_CRTC_A_ADDR: u32 = 0x0230;
/// CRT Controller A Display Address Offset Register
pub const ZX_CRTC_A_ADDR_OFFSET: u32 = 0x0234;

/// CRT Controller A control flags
pub const ZX_CRTC_A_CTRL_ENABLE: u32 = 1 << 0;      // CRT enable
pub const ZX_CRTC_A_CTRL_8BPP: u32 = 0 << 2;        // 8 bits per pixel
pub const ZX_CRTC_A_CTRL_16BPP: u32 = 1 << 2;       // 16 bits per pixel
pub const ZX_CRTC_A_CTRL_24BPP: u32 = 2 << 2;        // 24 bits per pixel
pub const ZX_CRTC_A_CTRL_32BPP: u32 = 3 << 2;        // 32 bits per pixel
pub const ZX_CRTC_A_CTRL_HSYNC_POS: u32 = 1 << 6;    // H-sync positive
pub const ZX_CRTC_A_CTRL_VSYNC_POS: u32 = 1 << 7;   // V-sync positive
pub const ZX_CRTC_A_CTRL_INTERLACE: u32 = 1 << 8;    // Interlaced mode

// =====================================================================
// CRT Controller B Registers (0x0300 - 0x03FF)
// =====================================================================

/// CRT Controller B Control Register
pub const ZX_CRTC_B_CTRL: u32 = 0x0300;
/// CRT Controller B Horizontal Total Register
pub const ZX_CRTC_B_H_TOTAL: u32 = 0x0310;
/// CRT Controller B Horizontal Blank Start Register
pub const ZX_CRTC_B_H_BLANK: u32 = 0x0314;
/// CRT Controller B Horizontal Sync Start Register
pub const ZX_CRTC_B_H_SYNC: u32 = 0x0318;
/// CRT Controller B Horizontal Sync End Register
pub const ZX_CRTC_B_H_SYNC_END: u32 = 0x031C;
/// CRT Controller B Vertical Total Register
pub const ZX_CRTC_B_V_TOTAL: u32 = 0x0320;
/// CRT Controller B Vertical Blank Start Register
pub const ZX_CRTC_B_V_BLANK: u32 = 0x0324;
/// CRT Controller B Vertical Sync Start Register
pub const ZX_CRTC_B_V_SYNC: u32 = 0x0328;
/// CRT Controller B Vertical Sync End Register
pub const ZX_CRTC_B_V_SYNC_END: u32 = 0x032C;
/// CRT Controller B Display Address Start Register
pub const ZX_CRTC_B_ADDR: u32 = 0x0330;
/// CRT Controller B Display Address Offset Register
pub const ZX_CRTC_B_ADDR_OFFSET: u32 = 0x0334;

/// CRT Controller B control flags (same as A)
pub const ZX_CRTC_B_CTRL_ENABLE: u32 = ZX_CRTC_A_CTRL_ENABLE;
pub const ZX_CRTC_B_CTRL_8BPP: u32 = ZX_CRTC_A_CTRL_8BPP;
pub const ZX_CRTC_B_CTRL_16BPP: u32 = ZX_CRTC_A_CTRL_16BPP;
pub const ZX_CRTC_B_CTRL_24BPP: u32 = ZX_CRTC_A_CTRL_24BPP;
pub const ZX_CRTC_B_CTRL_32BPP: u32 = ZX_CRTC_A_CTRL_32BPP;
pub const ZX_CRTC_B_CTRL_HSYNC_POS: u32 = ZX_CRTC_A_CTRL_HSYNC_POS;
pub const ZX_CRTC_B_CTRL_VSYNC_POS: u32 = ZX_CRTC_A_CTRL_VSYNC_POS;

// =====================================================================
// Primary Plane Registers (0x0400 - 0x04FF)
// =====================================================================

/// Primary Plane Control Register
pub const ZX_PLANE_PRIMARY_CTRL: u32 = 0x0400;
/// Primary Plane Address Register
pub const ZX_PLANE_PRIMARY_ADDR: u32 = 0x0404;
/// Primary Plane Stride Register
pub const ZX_PLANE_PRIMARY_STRIDE: u32 = 0x0408;
/// Primary Plane Size Register
pub const ZX_PLANE_PRIMARY_SIZE: u32 = 0x040C;
/// Primary Plane Position Register
pub const ZX_PLANE_PRIMARY_POS: u32 = 0x0410;
/// Primary Plane Format Register
pub const ZX_PLANE_PRIMARY_FORMAT: u32 = 0x0414;

/// Primary plane control flags
pub const ZX_PLANE_CTRL_ENABLE: u32 = 1 << 0;       // Plane enable
pub const ZX_PLANE_CTRL_KEY_EN: u32 = 1 << 1;        // Color key enable
pub const ZX_PLANE_CTRL_ALPHA_EN: u32 = 1 << 2;      // Alpha blend enable
pub const ZX_PLANE_CTRL_FORMAT_SHIFT: u32 = 4;        // Format field shift

// =====================================================================
// Overlay Plane Registers (0x0500 - 0x05FF)
// =====================================================================

/// Overlay Plane Control Register
pub const ZX_PLANE_OVERLAY_CTRL: u32 = 0x0500;
/// Overlay Plane Address Register
pub const ZX_PLANE_OVERLAY_ADDR: u32 = 0x0504;
/// Overlay Plane Stride Register
pub const ZX_PLANE_OVERLAY_STRIDE: u32 = 0x0508;
/// Overlay Plane Size Register
pub const ZX_PLANE_OVERLAY_SIZE: u32 = 0x050C;
/// Overlay Plane Position Register
pub const ZX_PLANE_OVERLAY_POS: u32 = 0x0510;
/// Overlay Plane Format Register
pub const ZX_PLANE_OVERLAY_FORMAT: u32 = 0x0514;

/// Overlay plane control flags
pub const ZX_OVERLAY_CTRL_ENABLE: u32 = 1 << 0;
pub const ZX_OVERLAY_CTRL_COLOR_KEY: u32 = 1 << 1;
pub const ZX_OVERLAY_CTRL_ALPHA: u32 = 1 << 2;
pub const ZX_OVERLAY_CTRL_YUV2RGB: u32 = 1 << 8; // YUV to RGB conversion

// =====================================================================
// Hardware Cursor Registers (0x0600 - 0x06FF)
// =====================================================================

/// Hardware Cursor Control Register
pub const ZX_CURSOR_CTRL: u32 = 0x0600;
/// Hardware Cursor Address Register
pub const ZX_CURSOR_ADDR: u32 = 0x0604;
/// Hardware Cursor Position Register
pub const ZX_CURSOR_POS: u32 = 0x0608;
/// Hardware Cursor Hotspot Register
pub const ZX_CURSOR_HOTSPOT: u32 = 0x060C;
/// Hardware Cursor Background Color Register
pub const ZX_CURSOR_BG_COLOR: u32 = 0x0610;
/// Hardware Cursor Foreground Color Register
pub const ZX_CURSOR_FG_COLOR: u32 = 0x0614;

/// Cursor control flags
pub const ZX_CURSOR_CTRL_ENABLE: u32 = 1 << 0;      // Cursor enable
pub const ZX_CURSOR_CTRL_64X64: u32 = 0 << 2;        // 64x64 cursor
pub const ZX_CURSOR_CTRL_32X32: u32 = 1 << 2;        // 32x32 cursor
pub const ZX_CURSOR_CTRL_16X16: u32 = 2 << 2;        // 16x16 cursor
pub const ZX_CURSOR_CTRL_256_COLOR: u32 = 0 << 4;     // 256-color cursor
pub const ZX_CURSOR_CTRL_XOR: u32 = 1 << 4;          // XOR cursor
pub const ZX_CURSOR_CTRL_32BPP: u32 = 2 << 4;        // 32-bit cursor

// =====================================================================
// DirectX 11.1 Capability Registers (0x1000 - 0x10FF)
// =====================================================================

/// DirectX Version Register
pub const ZX_DX_VERSION: u32 = 0x1000;
/// DirectX Capability Register
pub const ZX_DX_CAPS: u32 = 0x1004;
/// DirectX Max Texture Size Register
pub const ZX_DX_MAX_TEXTURE: u32 = 0x1008;
/// DirectX Max Render Targets Register
pub const ZX_DX_MAX_RENDER_TARGETS: u32 = 0x100C;

/// DirectX version flags
pub const ZX_DX_VERSION_DX9: u32 = 0x0900_0000;
pub const ZX_DX_VERSION_DX10: u32 = 0x0A00_0000;
pub const ZX_DX_VERSION_DX11: u32 = 0x0B00_0000;
pub const ZX_DX_VERSION_DX11_1: u32 = 0x0B01_0000;

/// DirectX capability flags
pub const ZX_DX_CAPS_2D: u32 = 1 << 0;
pub const ZX_DX_CAPS_3D: u32 = 1 << 1;
pub const ZX_DX_CAPS_VIDEO_DECODE: u32 = 1 << 2;
pub const ZX_DX_CAPS_COMPUTE: u32 = 1 << 3;

// =====================================================================
// Power Management Registers (0x1100 - 0x11FF)
// =====================================================================

/// Power Management Control Register
pub const ZX_PM_CTRL: u32 = 0x1100;
/// Power Management Status Register
pub const ZX_PM_STATUS: u32 = 0x1104;
/// Power Management Target Register
pub const ZX_PM_TARGET: u32 = 0x1108;

/// Power states
pub const ZX_PM_STATE_D0: u32 = 0x00;  // Fully on
pub const ZX_PM_STATE_D1: u32 = 0x01;  // Low power
pub const ZX_PM_STATE_D2: u32 = 0x02;  // Standby
pub const ZX_PM_STATE_D3: u32 = 0x03;  // Hot standby

/// Power control flags
pub const ZX_PM_CTRL_AUTO: u32 = 1 << 0;   // Auto power management
pub const ZX_PM_CTRL_CLOCK_GATE: u32 = 1 << 1;  // Clock gating
pub const ZX_PM_CTRL_POWER_OFF: u32 = 1 << 2;   // Power off clock domains

// =====================================================================
// GPIO and Clock Registers (0x1200 - 0x12FF)
// =====================================================================

/// Clock Control Register
pub const ZX_CLK_CTRL: u32 = 0x1200;
/// Clock Status Register
pub const ZX_CLK_STATUS: u32 = 0x1204;
/// PLL Control Register
pub const ZX_PLL_CTRL: u32 = 0x1210;
/// PLL Status Register
pub const ZX_PLL_STATUS: u32 = 0x1214;

/// Clock control flags
pub const ZX_CLK_CTRL_PLL_ENABLE: u32 = 1 << 0;
pub const ZX_CLK_CTRL_DC_CLOCK_ENABLE: u32 = 1 << 8;
pub const ZX_CLK_CTRL_DISPLAY_CLOCK_ENABLE: u32 = 1 << 9;

// =====================================================================
// Helper Functions
// =====================================================================

/// Convert DisplayFormat to ZX framebuffer format
pub fn format_to_zx_format(format: DisplayFormat) -> u32 {
    match format {
        DisplayFormat::Bgra8888 => ZX_FB_FORMAT_BGRA8888,
        DisplayFormat::Argb8888 => ZX_FB_FORMAT_RGBA8888,
        DisplayFormat::Rgb565 => ZX_FB_FORMAT_RGB565,
        DisplayFormat::Rgb888 => ZX_FB_FORMAT_RGB888,
    }
}

/// Calculate CRT timing parameters
pub fn calculate_crtc_timing(width: u32, height: u32, _refresh: u32) -> CrtcTiming {
    // Standard VGA-like timing with overscan
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

    CrtcTiming {
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

/// CRT timing parameters
#[derive(Debug, Clone, Copy)]
pub struct CrtcTiming {
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

impl CrtcTiming {
    /// Encode horizontal total register value
    pub fn h_total_reg(&self) -> u32 {
        (self.h_total << 16) | self.h_blank_start
    }

    /// Encode horizontal sync register value
    pub fn h_sync_reg(&self) -> u32 {
        (self.h_sync_end << 16) | self.h_sync_start
    }

    /// Encode vertical total register value
    pub fn v_total_reg(&self) -> u32 {
        (self.v_total << 16) | self.v_blank_start
    }

    /// Encode vertical sync register value
    pub fn v_sync_reg(&self) -> u32 {
        (self.v_sync_end << 16) | self.v_sync_start
    }
}

// =====================================================================
// Register Access Macros
// =====================================================================

/// Calculate register offset within DC MMIO space
#[macro_export]
macro_rules! zx_reg_offset {
    ($name:ident) => {
        $name as u64
    };
}

/// ZX-D register definitions for use in driver code
pub mod regs {
    use super::*;

    /// All ZX-D DC registers with their offsets
    pub struct ZxDRgisters;

    impl ZxDRgisters {
        /// DC core registers
        pub const DC_CTRL: u32 = ZX_DC_CTRL;
        pub const DC_STATUS: u32 = ZX_DC_STATUS;
        pub const DC_INT: u32 = ZX_DC_INT;
        pub const DC_INT_MASK: u32 = ZX_DC_INT_MASK;
        pub const DC_VERSION: u32 = ZX_DC_VERSION;

        /// Framebuffer registers
        pub const FB_ADDR: u32 = ZX_FB_ADDR;
        pub const FB_STRIDE: u32 = ZX_FB_STRIDE;
        pub const FB_SIZE: u32 = ZX_FB_SIZE;
        pub const FB_FORMAT: u32 = ZX_FB_FORMAT;

        /// CRT controller A
        pub const CRTC_A_CTRL: u32 = ZX_CRTC_A_CTRL;
        pub const CRTC_A_H_TOTAL: u32 = ZX_CRTC_A_H_TOTAL;
        pub const CRTC_A_H_SYNC: u32 = ZX_CRTC_A_H_SYNC;
        pub const CRTC_A_V_TOTAL: u32 = ZX_CRTC_A_V_TOTAL;
        pub const CRTC_A_V_SYNC: u32 = ZX_CRTC_A_V_SYNC;
        pub const CRTC_A_ADDR: u32 = ZX_CRTC_A_ADDR;

        /// CRT controller B
        pub const CRTC_B_CTRL: u32 = ZX_CRTC_B_CTRL;
        pub const CRTC_B_H_TOTAL: u32 = ZX_CRTC_B_H_TOTAL;
        pub const CRTC_B_H_SYNC: u32 = ZX_CRTC_B_H_SYNC;
        pub const CRTC_B_V_TOTAL: u32 = ZX_CRTC_B_V_TOTAL;
        pub const CRTC_B_V_SYNC: u32 = ZX_CRTC_B_V_SYNC;
        pub const CRTC_B_ADDR: u32 = ZX_CRTC_B_ADDR;

        /// Primary plane
        pub const PLANE_PRIMARY_CTRL: u32 = ZX_PLANE_PRIMARY_CTRL;
        pub const PLANE_PRIMARY_ADDR: u32 = ZX_PLANE_PRIMARY_ADDR;
        pub const PLANE_PRIMARY_STRIDE: u32 = ZX_PLANE_PRIMARY_STRIDE;
        pub const PLANE_PRIMARY_SIZE: u32 = ZX_PLANE_PRIMARY_SIZE;

        /// Hardware cursor
        pub const CURSOR_CTRL: u32 = ZX_CURSOR_CTRL;
        pub const CURSOR_ADDR: u32 = ZX_CURSOR_ADDR;
        pub const CURSOR_POS: u32 = ZX_CURSOR_POS;

        /// Power management
        pub const PM_CTRL: u32 = ZX_PM_CTRL;
        pub const PM_STATUS: u32 = ZX_PM_STATUS;

        /// Clock control
        pub const CLK_CTRL: u32 = ZX_CLK_CTRL;
    }
}
