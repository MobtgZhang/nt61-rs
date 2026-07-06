//! Loongson Display Controller (LS7A/DC) Register Definitions
//
//! This module contains the register definitions for Loongson's
//! integrated display controller. These registers are accessed via
//! MMIO from BAR0.
//
//! Reference: Loongson 3A5000 technical reference manual

// =====================================================================
// Controller Base Registers (0x0000-0x00FF)
// =====================================================================

/// DC Control Register
///
/// Bit 0: DC enable
/// Bit 1: DC reset
/// Bit 8: Load CRTC configuration
pub const DC_CTRL: u32 = 0x0000;

/// DC control: Enable DC
pub const DC_CTRL_ENABLE: u32 = 1 << 0;

/// DC control: Reset DC
pub const DC_CTRL_RESET: u32 = 1 << 1;

/// DC control: Load CRTC configuration
pub const DC_CTRL_LD_CRTC: u32 = 1 << 8;

/// DC Status Register
///
/// Bit 0: CRTC A active
/// Bit 1: CRTC B active
/// Bit 4: Sync status
pub const DC_STATUS: u32 = 0x0004;

/// DC status: CRTC A active
pub const DC_STATUS_CRTC_A_ACTIVE: u32 = 1 << 0;

/// DC status: CRTC B active
pub const DC_STATUS_CRTC_B_ACTIVE: u32 = 1 << 1;

/// DC status: Sync detected
pub const DC_STATUS_SYNC: u32 = 1 << 4;

/// DC Interrupt Register
pub const DC_INT: u32 = 0x0008;

/// DC Interrupt Mask Register
pub const DC_INT_MASK: u32 = 0x000C;

/// DC Version Register
///
/// Bits 0-15: Chip version
/// Bits 16-23: Revision
pub const DC_VERSION: u32 = 0x0010;

// =====================================================================
// Framebuffer Configuration Registers (0x0100-0x01FF)
// =====================================================================

/// Framebuffer Address Register
pub const FB_ADDR: u32 = 0x0100;

/// Framebuffer Stride Register (bytes per row)
pub const FB_STRIDE: u32 = 0x0104;

/// Framebuffer Size Register
pub const FB_SIZE: u32 = 0x0108;

/// Framebuffer Format Register
pub const FB_FORMAT: u32 = 0x010C;

/// Framebuffer format: BGRA 8:8:8:8
pub const FB_FORMAT_BGRA8888: u32 = 0x00;

/// Framebuffer format: RGBA 8:8:8:8
pub const FB_FORMAT_RGBA8888: u32 = 0x01;

/// Framebuffer format: RGB 5:6:5
pub const FB_FORMAT_RGB565: u32 = 0x02;

/// Framebuffer format: XRGB 8:8:8:8
pub const FB_FORMAT_XRGB8888: u32 = 0x03;

// =====================================================================
// CRT Controller A (Pipeline A) Registers (0x0200-0x02FF)
// =====================================================================

/// CRTC A Control Register
pub const CRTC_A_CTRL: u32 = 0x0200;

/// CRTC control: Enable
pub const CRTC_ENABLE: u32 = 1 << 0;

/// CRTC control: Double scan
pub const CRTC_DOUBLE_SCAN: u32 = 1 << 1;

/// CRTC control: Interlaced
pub const CRTC_INTERLACE: u32 = 1 << 2;

/// CRTC control: Composite sync
pub const CRTC_CSYNC: u32 = 1 << 3;

/// CRTC control: Pixel doubling
pub const CRTC_PIXEL_DOUBLE: u32 = 1 << 4;

/// CRTC control: Line doubling
pub const CRTC_LINE_DOUBLE: u32 = 1 << 5;

/// CRTC A Horizontal Timing Register
///
/// [31:16] H total
/// [15:8] H sync end
/// [7:0] H sync start
pub const CRTC_A_TIMING_H: u32 = 0x0210;

/// CRTC A Vertical Timing Register
///
/// [31:16] V total
/// [15:8] V sync end
/// [7:0] V sync start
pub const CRTC_A_TIMING_V: u32 = 0x0214;

/// CRTC A Sync Signal Register
pub const CRTC_A_SYNC: u32 = 0x0218;

/// CRTC sync: HS positive
pub const CRTC_SYNC_HS_POS: u32 = 0;

/// CRTC sync: HS negative
pub const CRTC_SYNC_HS_NEG: u32 = 1 << 0;

/// CRTC sync: VS positive
pub const CRTC_SYNC_VS_POS: u32 = 0;

/// CRTC sync: VS negative
pub const CRTC_SYNC_VS_NEG: u32 = 1 << 1;

/// CRTC A Polarity Register
pub const CRTC_A_POLARITY: u32 = 0x021C;

/// H polarity: Active high
pub const CRTC_HPOLARITY_HIGH: u32 = 1 << 0;

/// H polarity: Active low
pub const CRTC_HPOLARITY_LOW: u32 = 0;

/// V polarity: Active high
pub const CRTC_VPOLARITY_HIGH: u32 = 1 << 1;

/// V polarity: Active low
pub const CRTC_VPOLARITY_LOW: u32 = 0;

/// CRTC A Framebuffer Address Register
pub const CRTC_A_ADDR: u32 = 0x0220;

/// CRTC A Current Scanline Register
pub const CRTC_A_LINE: u32 = 0x0230;

// =====================================================================
// CRT Controller B (Pipeline B) Registers (0x0300-0x03FF)
// =====================================================================

/// CRTC B Control Register
pub const CRTC_B_CTRL: u32 = 0x0300;

/// CRTC B Horizontal Timing Register
pub const CRTC_B_TIMING_H: u32 = 0x0310;

/// CRTC B Vertical Timing Register
pub const CRTC_B_TIMING_V: u32 = 0x0314;

/// CRTC B Sync Signal Register
pub const CRTC_B_SYNC: u32 = 0x0318;

/// CRTC B Polarity Register
pub const CRTC_B_POLARITY: u32 = 0x031C;

/// CRTC B Framebuffer Address Register
pub const CRTC_B_ADDR: u32 = 0x0320;

/// CRTC B Current Scanline Register
pub const CRTC_B_LINE: u32 = 0x0330;

// =====================================================================
// Plane/Layer Registers (0x0400-0x05FF)
// =====================================================================

/// Primary Plane Control Register
pub const PLANE_PRIMARY_CTRL: u32 = 0x0400;

/// Plane control: Enable
pub const PLANE_ENABLE: u32 = 1 << 0;

/// Plane control: Format mask
pub const PLANE_FORMAT_MASK: u32 = 0xF << 8;

/// Plane control: BGRA format
pub const PLANE_FORMAT_BGRA: u32 = 0x0 << 8;

/// Plane control: RGBA format
pub const PLANE_FORMAT_RGBA: u32 = 0x1 << 8;

/// Plane control: RGB565 format
pub const PLANE_FORMAT_RGB565: u32 = 0x2 << 8;

/// Primary Plane Address Register
pub const PLANE_PRIMARY_ADDR: u32 = 0x0404;

/// Primary Plane Stride Register
pub const PLANE_PRIMARY_STRIDE: u32 = 0x0408;

/// Primary Plane Size Register
///
/// [31:16] Height
/// [15:0] Width
pub const PLANE_PRIMARY_SIZE: u32 = 0x040C;

/// Primary Plane Position Register
pub const PLANE_PRIMARY_POS: u32 = 0x0410;

/// Cursor Plane Control Register
pub const PLANE_CURSOR_CTRL: u32 = 0x0500;

/// Cursor control: Enable
pub const CURSOR_ENABLE: u32 = 1 << 0;

/// Cursor control: Format 2BPP
pub const CURSOR_FORMAT_2BPP: u32 = 0 << 4;

/// Cursor control: Format 8BPP
pub const CURSOR_FORMAT_8BPP: u32 = 1 << 4;

/// Cursor control: Format 32BPP
pub const CURSOR_FORMAT_32BPP: u32 = 2 << 4;

/// Cursor control: Size 32x32
pub const CURSOR_SIZE_32: u32 = 0 << 8;

/// Cursor control: Size 64x64
pub const CURSOR_SIZE_64: u32 = 1 << 8;

/// Cursor Plane Address Register
pub const PLANE_CURSOR_ADDR: u32 = 0x0504;

/// Cursor Plane Position Register
///
/// [31:16] Y position
/// [15:0] X position
pub const PLANE_CURSOR_POS: u32 = 0x0508;

// =====================================================================
// Interrupt Status Bits (for DC_INT register)
// =====================================================================

/// Interrupt: VBlank A
pub const INT_VBLANK_A: u32 = 1 << 0;

/// Interrupt: VBlank B
pub const INT_VBLANK_B: u32 = 1 << 1;

/// Interrupt: HBlank A
pub const INT_HBLANK_A: u32 = 1 << 2;

/// Interrupt: HBlank B
pub const INT_HBLANK_B: u32 = 1 << 3;

/// Interrupt: FIFO underflow
pub const INT_FIFO_UNDERFLOW: u32 = 1 << 8;

/// Interrupt: Register update
pub const INT_REG_UPDATE: u32 = 1 << 16;

/// Interrupt: Line flag
pub const INT_LINE_FLAG: u32 = 1 << 17;

// =====================================================================
// Clock Configuration
// =====================================================================

/// Clock Enable Register
pub const CLK_ENABLE: u32 = 0x0600;

/// Clock enable: DC clock
pub const CLK_DC_ENABLE: u32 = 1 << 0;

/// Clock enable: Pipeline A clock
pub const CLK_PIPEA_ENABLE: u32 = 1 << 1;

/// Clock enable: Pipeline B clock
pub const CLK_PIPEB_ENABLE: u32 = 1 << 2;

// =====================================================================
// Common Display Timings
// =====================================================================

/// Standard 640x480 @ 60Hz
pub const TIMING_640X480_60: [(u32, u32, u32, u32, u32, u32, u32, u32); 4] = [
    (800, 656, 752, 800, 525, 490, 492, 525), // H: total, sync_start, sync_end, total; V: total, sync_start, sync_end, total
];

/// Standard 800x600 @ 60Hz
pub const TIMING_800X600_60: [(u32, u32, u32, u32, u32, u32, u32, u32); 4] = [
    (1056, 840, 968, 1056, 628, 601, 605, 628),
];

/// Standard 1024x768 @ 60Hz
pub const TIMING_1024X768_60: [(u32, u32, u32, u32, u32, u32, u32, u32); 4] = [
    (1344, 1024, 1072, 1344, 806, 771, 777, 806),
];

/// Standard 1280x720 @ 60Hz
pub const TIMING_1280X720_60: [(u32, u32, u32, u32, u32, u32, u32, u32); 4] = [
    (1650, 1280, 1390, 1650, 750, 725, 730, 750),
];

/// Standard 1920x1080 @ 60Hz
pub const TIMING_1920X1080_60: [(u32, u32, u32, u32, u32, u32, u32, u32); 4] = [
    (2200, 1920, 2008, 2200, 1125, 1084, 1089, 1125),
];
