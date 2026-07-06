//! Intel i915 Register Definitions
//
//! This module contains the register definitions for Intel integrated
//! graphics (i915 and later). Registers are accessed via MMIO from BAR0.
//
//! Reference: Intel Graphics Programmer's Reference Manuals (PRMs)

use crate::drivers::video::core::gpu_common::PixelFormat;

// =====================================================================
// Power Management Registers
// =====================================================================

/// Power Well Control Register (Haswell+)
pub const HSW_PWR_WELL_B_REQUEST: u32 = 0x45400;

/// Power Well Status Register (Haswell+)
pub const HSW_PWR_WELL_B_STATUS: u32 = 0x45404;

/// Power well state: power on
pub const HSW_PWR_WELL_STATE_POWER_ON: u32 = 1 << 0;

/// Power well state: request only
pub const HSW_PWR_WELL_STATE_REQ_ONLY: u32 = 1 << 1;

/// Power well enable
pub const HSW_PWR_WELL_ENABLE: u32 = 1 << 0;

// =====================================================================
// Display Control Registers
// =====================================================================

/// CPU VGA Control Register
pub const CPU_VGACNTRL: u32 = 0x4100;

/// CPU VGA control: disable VGA
pub const CPU_VGACNTRL_DISABLE: u32 = 1 << 31;

// =====================================================================
// Display A Control (PIPEA)
// =====================================================================

/// Display A Control Register
pub const PIPEA_DSPCNTR: u32 = 0x70180;

/// Display A Status Register
pub const PIPEA_DSPSURFACE: u32 = 0x70184;

/// Display A Stride Register
pub const PIPEA_DSPSURFACE_STRIDE: u32 = 0x70188;

/// Display A Offset Register
pub const PIPEA_DSPAOFFSET: u32 = 0x701A4;

/// Display A Size Register
pub const PIPEA_DSPASIZE: u32 = 0x70170;

/// Display A Position Register
pub const PIPEA_DSPAPOS: u32 = 0x70174;

/// Display A Base Address Register
pub const PIPEA_DSPABASE: u32 = 0x7017C;

/// Display A Stride Register (alias)
pub const PIPEA_DSPASTRIDE: u32 = 0x70188;

/// Display enable
pub const DISPLAY_ENABLE: u32 = 1 << 31;

/// Pixel format mask
pub const DISPLAY_FORMAT_MASK: u32 = 0xFF << 20;

/// Display format: XRGB 8:8:8:8
pub const DISPLAY_FORMAT_XRGB8888: u32 = 0 << 20;

/// Display format: RGB 5:6:5
pub const DISPLAY_FORMAT_RGB565: u32 = 4 << 20;

// =====================================================================
// Display B Control (PIPEB)
// =====================================================================

/// Display B Control Register
pub const PIPEB_DSPCNTR: u32 = 0x71180;

/// Display B Status Register
pub const PIPEB_DSPSURFACE: u32 = 0x71184;

/// Display B Stride Register
pub const PIPEB_DSPSURFACE_STRIDE: u32 = 0x71188;

// =====================================================================
// Display C Control (PIPEC)
// =====================================================================

/// Display C Control Register
pub const PIPEC_DSPCNTR: u32 = 0x72180;

/// Display C Status Register
pub const PIPEC_DSPSURFACE: u32 = 0x72184;

// =====================================================================
// Pipe Configuration Registers
// =====================================================================

/// Pipe A Configuration Register
pub const PIPEA_CONF: u32 = 0x70008;

/// Pipe B Configuration Register
pub const PIPEB_CONF: u32 = 0x71008;

/// Pipe C Configuration Register
pub const PIPEC_CONF: u32 = 0x72008;

/// Pipe configuration: enable
pub const PIPEA_CONF_ENABLE: u32 = 1 << 0;

// =====================================================================
// Pipe Timing Registers (PIPEA)
// =====================================================================

/// Pipe A Horizontal Total Register
pub const PIPEA_H_TOTAL: u32 = 0x70000;

/// Pipe A Horizontal Blank Start/End Register
pub const PIPEA_H_BLANK: u32 = 0x70004;

/// Pipe A Horizontal Sync Start/End Register
pub const PIPEA_H_SYNC: u32 = 0x70008;

/// Pipe A Vertical Total Register
pub const PIPEA_V_TOTAL: u32 = 0x7000C;

/// Pipe A Vertical Blank Start/End Register
pub const PIPEA_V_BLANK: u32 = 0x70010;

/// Pipe A Vertical Sync Start/End Register
pub const PIPEA_V_SYNC: u32 = 0x70014;

/// Pipe A Pipe Configuration Register
pub const PIPEA_PIPE_SCONF: u32 = 0x70020;

// =====================================================================
// Pipe Timing Registers (PIPEB)
// =====================================================================

/// Pipe B Horizontal Total Register
pub const PIPEB_H_TOTAL: u32 = 0x71000;

/// Pipe B Vertical Total Register
pub const PIPEB_V_TOTAL: u32 = 0x7100C;

// =====================================================================
// Interrupt Registers
// =====================================================================

/// Master Interrupt Control Register
pub const GEN6_MASTER_IRQ: u32 = 0x44200;

/// Display Interrupt Enable Register
pub const DEIIR: u32 = 0x44004;

/// Display Interrupt Mask Register
pub const DEIMR: u32 = 0x44008;

/// Display Interrupt Identity Register
pub const DEIIR_RENDER: u32 = 0x44064;

/// Display Interrupt Enable Register
pub const DEIER: u32 = 0x4406C;

/// VBLANK interrupt enable
pub const DEIER_VBLANK: u32 = 1 << 17;

/// Pipe A VBLANK status
pub const DEIIR_PIPEA_VBLANK: u32 = 1 << 0;

/// Pipe B VBLANK status
pub const DEIIR_PIPEB_VBLANK: u32 = 1 << 1;

/// Flip complete status
pub const DEIIR_PIPEA_FLIP_DONE: u32 = 1 << 5;

// =====================================================================
// Power PCODE Mailbox
// =====================================================================

/// Power PCODE mailbox register
pub const GEN6_PCODE_MAILBOX: u32 = 0x138124;

/// PCODE status
pub const GEN6_PCODE_STATUS: u32 = 0x13812C;

// =====================================================================
// Memory Management
// =====================================================================

/// GTT (Graphics Translation Table) base
pub const GTT_BASE: u32 = 0x208000;

/// PTE (Page Table Entry) size
pub const PTE_SIZE: u32 = 8;

// =====================================================================
// Framebuffer Compression (FBC)
// =====================================================================

/// FBC Control Register
pub const FBC_CONTROL: u32 = 0x212000;

/// FBC Status Register
pub const FBC_STATUS: u32 = 0x212004;

/// FBC enable
pub const FBC_ENABLE: u32 = 1 << 31;

/// FBC compressing
pub const FBC_COMPRESSING: u32 = 1 << 0;

// =====================================================================
// Sprite Plane Registers (PIPEA)
// =====================================================================

/// Sprite A Control Register
pub const SPRITEA_CTL: u32 = 0x72180;

/// Sprite A Position Register
pub const SPRITEA_POS: u32 = 0x721A8;

/// Sprite A Size Register
pub const SPRITEA_SIZE: u32 = 0x721A4;

/// Sprite enable
pub const SPRITEA_ENABLE: u32 = 1 << 31;

// =====================================================================
// Cursor Registers
// =====================================================================

/// Cursor A Control Register
pub const CURACNTR: u32 = 0x70080;

/// Cursor A Position Register
pub const CURAPOS: u32 = 0x70084;

/// Cursor A Base Address Register
pub const CURABASE: u32 = 0x70088;

/// Cursor B Control Register
pub const CURBCNTR: u32 = 0x71080;

/// Cursor B Position Register
pub const CURBPOS: u32 = 0x71084;

/// Cursor B Base Address Register
pub const CURBBASE: u32 = 0x71088;

/// Cursor enable
pub const CURSOR_ENABLE: u32 = 1 << 0;

/// Cursor format: ARGB 8:8:8:8
pub const CURSOR_FORMAT_ARGB8888: u32 = 0 << 5;

/// Cursor format: RGB 5:6:5
pub const CURSOR_FORMAT_RGB565: u32 = 4 << 5;

/// Cursor size: 64x64
pub const CURSOR_SIZE_64: u32 = 2 << 24;

/// Cursor size: 256x256
pub const CURSOR_SIZE_256: u32 = 3 << 24;

// =====================================================================
// Panel Fitting
// =====================================================================

/// Pipe A PF Control Register
pub const PIPEA_PF_CTL: u32 = 0x70240;

/// Pipe A PF Status Register
pub const PIPEA_PF_STATUS: u32 = 0x70244;

/// PF enable
pub const PIPEA_PF_ENABLE: u32 = 1 << 31;

/// PF auto-ratio
pub const PIPEA_PF_AUTO_RATIO: u32 = 1 << 0;

// =====================================================================
// Port Registers
// =====================================================================

/// Digital Port A Status
pub const DPA_AUX_CTL: u32 = 0x64000;

/// Digital Port B Status
pub const DPB_AUX_CTL: u32 = 0x64100;

/// Digital Port C Status
pub const DPC_AUX_CTL: u32 = 0x64200;

/// Digital Port D Status
pub const DPD_AUX_CTL: u32 = 0x64300;

// =====================================================================
// Display Port Compliance
// =====================================================================

/// DP A link training pattern
pub const DP_A_TRAINING_PATTERN: u32 = 0x64040;

/// DP B link training pattern
pub const DP_B_TRAINING_PATTERN: u32 = 0x64140;

// =====================================================================
// Helper Functions
// =====================================================================

/// Calculate stride from width
pub fn calc_stride(width: u32, bpp: u32) -> u32 {
    let bytes_per_row = (width * bpp / 8) + 63;
    bytes_per_row & !63
}

/// Get format register value
pub fn pixel_format_to_reg(format: PixelFormat) -> u32 {
    match format {
        PixelFormat::Bgra8888 | PixelFormat::Bgrx8888 => DISPLAY_FORMAT_XRGB8888,
        PixelFormat::Bgr565 => DISPLAY_FORMAT_RGB565,
        _ => DISPLAY_FORMAT_XRGB8888,
    }
}
