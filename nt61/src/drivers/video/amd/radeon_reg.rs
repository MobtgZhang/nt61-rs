//! AMD Radeon Register Definitions
//
//! This module contains the register definitions for AMD Radeon graphics
//! (R600 and later). Registers are accessed via MMIO from BAR0.
//
//! Reference: AMD GPU programmer manuals and Linux radeon driver

// =====================================================================
// Configuration Registers
// =====================================================================

/// Config control
pub const R_0000_CONFIG_CNTL: u32 = 0x0000;

/// Config control start
pub const R_0002_CONFIG_CNTL_START: u32 = 0x0002;

// =====================================================================
// RBBM (Raster Backend Manager)
// =====================================================================

/// RBBM soft reset
pub const R_0003_RBBM_SOFT_RESET: u32 = 0x0003;

/// RBBM clock cntl index
pub const R_0004_RBBM_CLOCK_CNTL_INDEX: u32 = 0x0004;

/// RBBM clock cntl data
pub const R_0005_RBBM_CLOCK_CNTL_DATA: u32 = 0x0005;

/// RBBM num instances
pub const R_0006_RBBM_NUM_INSTANCES: u32 = 0x0006;

/// RBBM SE cntl
pub const R_0007_RBBM_SE_CNTL: u32 = 0x0007;

/// RBBM cntl
pub const R_0008_RBBM_CNTL: u32 = 0x0008;

/// Soft reset: CP
pub const RBBM_SOFT_RESET_CP: u32 = 1 << 0;

/// Soft reset: HDP
pub const RBBM_SOFT_RESET_HDP: u32 = 1 << 1;

/// Soft reset: RB
pub const RBBM_SOFT_RESET_RB: u32 = 1 << 2;

/// Soft reset: DC
pub const RBBM_SOFT_RESET_DC: u32 = 1 << 3;

/// Soft reset: HI
pub const RBBM_SOFT_RESET_HI: u32 = 1 << 4;

// =====================================================================
// Display Controller - AVIVO
// =====================================================================

/// D1 CRT control
pub const AVIVO_D1CRTC_CONTROL: u32 = 0x1A00;

/// D2 CRT control
pub const AVIVO_D2CRTC_CONTROL: u32 = 0x1B00;

/// CRT enable
pub const AVIVO_CRTC_ENABLE: u32 = 1 << 0;

/// CRT disable
pub const AVIVO_CRTC_DISABLE: u32 = 0;

/// D1 CRT h total
pub const AVIVO_D1CRTC_H_TOTAL: u32 = 0x1A04;

/// D1 CRT h blank start/end
pub const AVIVO_D1CRTC_H_BLANK_START_END: u32 = 0x1A08;

/// D1 CRT h sync a
pub const AVIVO_D1CRTC_H_SYNC_A: u32 = 0x1A0C;

/// D1 CRT h sync a cntl
pub const AVIVO_D1CRTC_H_SYNC_A_CNTL: u32 = 0x1A10;

/// D1 CRT v total
pub const AVIVO_D1CRTC_V_TOTAL: u32 = 0x1A14;

/// D1 CRT v blank start/end
pub const AVIVO_D1CRTC_V_BLANK_START_END: u32 = 0x1A18;

/// D1 CRT v sync a
pub const AVIVO_D1CRTC_V_SYNC_A: u32 = 0x1A1C;

/// D1 CRT v sync a cntl
pub const AVIVO_D1CRTC_V_SYNC_A_CNTL: u32 = 0x1A20;

// =====================================================================
// Framebuffer
// =====================================================================

/// D1 primary surface address
pub const AVIVO_D1GRPH_PRIMARY_SURFACE_ADDRESS: u32 = 0x1A40;

/// D1 primary surface address high
pub const AVIVO_D1GRPH_PRIMARY_SURFACE_ADDRESS_HIGH: u32 = 0x1A44;

/// D1 primary surface pitch
pub const AVIVO_D1GRPH_PITCH: u32 = 0x1A48;

/// D1 primary surface offset x
pub const AVIVO_D1GRPH_SURFACE_OFFSET_X: u32 = 0x1A4C;

/// D1 primary surface offset y
pub const AVIVO_D1GRPH_SURFACE_OFFSET_Y: u32 = 0x1A50;

/// D1 primary surface width
pub const AVIVO_D1GRPH_WIDTH: u32 = 0x1A54;

/// D1 primary surface height
pub const AVIVO_D1GRPH_HEIGHT: u32 = 0x1A58;

/// D1 primary surface format
pub const AVIVO_D1GRPH_FORMAT: u32 = 0x1A5C;

/// D1 primary surface enable
pub const AVIVO_D1GRPH_ENABLE: u32 = 0x1A70;

/// D1 primary surface swap
pub const AVIVO_D1GRPH_SWAP: u32 = 0x1A70;

/// D1 primary surface swap: 16-bit
pub const AVIVO_D1GRPH_SWAP_16BIT: u32 = 0;

/// D1 primary surface swap: 32-bit
pub const AVIVO_D1GRPH_SWAP_32BIT: u32 = 1;

/// D1 primary surface swap: none
pub const AVIVO_D1GRPH_SWAP_NONE: u32 = 2;

/// D2 primary surface address
pub const AVIVO_D2GRPH_PRIMARY_SURFACE_ADDRESS: u32 = 0x1B40;

/// D2 primary surface pitch
pub const AVIVO_D2GRPH_PITCH: u32 = 0x1B48;

/// D2 primary surface enable
pub const AVIVO_D2GRPH_ENABLE: u32 = 0x1B5C;

// =====================================================================
// Interrupt Registers
// =====================================================================

/// Interrupt status
pub const RBBM_INT_STATUS: u32 = 0x564;

/// Interrupt mask
pub const RBBM_INT_MASK: u32 = 0x568;

/// DCE Int status
pub const DC_INT_STATUS: u32 = 0x1F0;

/// DCE Int mask
pub const DC_INT_MASK: u32 = 0x1F4;

/// VBlank interrupt
pub const RBBM_INT_VBLANK: u32 = 1 << 0;

// =====================================================================
// Power Management
// =====================================================================

/// General power mode
pub const CG_STATUS: u32 = 0x620;

/// GPU clock status
pub const CG_CLOCK_STATUS: u32 = 0x624;

// =====================================================================
// MC (Memory Controller)
// =====================================================================

/// MC address config
pub const MC_MISC_AMOUNT: u32 = 0x2008;

// =====================================================================
// Clock Management
// =====================================================================

/// PLL control
pub const CG_PLLS_CNTL: u32 = 0x600;

/// PLL status
pub const CG_PLLS_STATUS: u32 = 0x604;

/// Clock divider
pub const CG_CLOCK_CNTL: u32 = 0x608;

/// Clock divider (graphics)
pub const CG_DISPLAY_CNTL: u32 = 0x610;

// =====================================================================
// Cursor
// =====================================================================

/// D1 cursor control
pub const AVIVO_D1CUR_CONTROL: u32 = 0x1A80;

/// D1 cursor position
pub const AVIVO_D1CUR_POSITION: u32 = 0x1A84;

/// D1 cursor hot spot
pub const AVIVO_D1CUR_HOT_SPOT: u32 = 0x1A88;

/// D1 cursor address
pub const AVIVO_D1CUR_ADDR: u32 = 0x1A8C;

/// D2 cursor control
pub const AVIVO_D2CUR_CONTROL: u32 = 0x1B80;

// =====================================================================
// Helper Functions
// =====================================================================

/// Calculate stride from width
pub fn calc_stride(width: u32, bpp: u32) -> u32 {
    let bytes_per_row = (width * bpp / 8) + 255;
    bytes_per_row & !255
}
