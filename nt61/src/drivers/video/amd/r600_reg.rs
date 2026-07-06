//! AMD R600 GPU Register Definitions
//
//! This module contains the register definitions for AMD R600 GPU architecture
//! (HD 2000-4000 series).
//
//! The R600 was AMD's first unified shader GPU and introduced the R6xx/R7xx ISA.
//! The display controller uses the older UNIPHY/PLL blocks.
//
//! Clean-room implementation based on AMD documentation and Linux radeon driver.

#![cfg(target_arch = "x86_64")]

// =====================================================================
// Configuration Registers
// =====================================================================

/// Config control register
pub const R600_CONFIG_CNTL: u32 = 0x0000;

/// Config control start
pub const R600_CONFIG_CNTL_START: u32 = 0x0002;

// =====================================================================
// RBBM (Raster Backend Manager)
// =====================================================================

/// RBBM soft reset register
pub const R600_RBBM_SOFT_RESET: u32 = 0x3;

/// RBBM clock cntl index
pub const R600_RBBM_CLOCK_CNTL_INDEX: u32 = 0x4;

/// RBBM clock cntl data
pub const R600_RBBM_CLOCK_CNTL_DATA: u32 = 0x5;

/// RBBM number of instances
pub const R600_RBBM_NUM_INSTANCES: u32 = 0x6;

/// RBBM SE (Shader Engine) control
pub const R600_RBBM_SE_CNTL: u32 = 0x7;

/// RBBM control
pub const R600_RBBM_CNTL: u32 = 0x8;

/// RBBM status
pub const R600_RBBM_STATUS: u32 = 0xE;

/// RBBM status 2
pub const R600_RBBM_STATUS2: u32 = 0x0F;

// RBBM soft reset bits
/// Soft reset CP (Command Processor)
pub const R600_SOFT_RESET_CP: u32 = 1 << 0;
/// Soft reset HDP (Host Data Path)
pub const R600_SOFT_RESET_HDP: u32 = 1 << 1;
/// Soft reset RB (Render Backend)
pub const R600_SOFT_RESET_RB: u32 = 1 << 2;
/// Soft reset DB (Depth Backend)
pub const R600_SOFT_RESET_DB: u32 = 1 << 3;
/// Soft reset PA (Primitive Assembly)
pub const R600_SOFT_RESET_PA: u32 = 1 << 4;
/// Soft reset SP (Stream Processor)
pub const R600_SOFT_RESET_SP: u32 = 1 << 5;
/// Soft reset SMX (Stream Multiplexer)
pub const R600_SOFT_RESET_SMX: u32 = 1 << 6;
/// Soft reset VGT (Vertex Generator)
pub const R600_SOFT_RESET_VGT: u32 = 1 << 7;

// =====================================================================
// CP (Command Processor)
// =====================================================================

/// CP DMA BASE address
pub const R600_CP_DMA_BASE: u32 = 0x200;

/// CP DMA count
pub const R600_CP_DMA_COUNT: u32 = 0x201;

/// CP DMA next address low
pub const R600_CP_DMA_NEXT_ADDR_LOW: u32 = 0x202;

/// CP DMA next address high
pub const R600_CP_DMA_NEXT_ADDR_HIGH: u32 = 0x203;

/// CP DMA_CNTL
pub const R600_CP_DMA_CNTL: u32 = 0x204;

/// CP DMA leader compute shader count
pub const R600_CP_DMA_LEADER_SHADOW: u32 = 0x205;

/// CP DMA leader compute shader data low
pub const R600_CP_DMA_LEADER_DATA0: u32 = 0x206;

/// CP DMA leader compute shader data high
pub const R600_CP_DMA_LEADER_DATA1: u32 = 0x207;

/// CP ring buffer base
pub const R600_CP_RB_BASE: u32 = 0x1F40;

/// CP ring buffer base high
pub const R600_CP_RB_BASE_HI: u32 = 0x1F41;

/// CP ring buffer size
pub const R600_CP_RB_CNTL: u32 = 0x1F42;

/// CP ring buffer rp (read pointer)
pub const R600_CP_RB_RPTR: u32 = 0x1F43;

/// CP ring buffer wp (write pointer)
pub const R600_CP_RB_WPTR: u32 = 0x1F44;

// CP DMA control bits
/// CP DMA enable
pub const R600_CP_DMA_ENABLE: u32 = 1 << 0;
/// CP DMA auto request
pub const R600_CP_DMA_AUTO_REQUEST: u32 = 1 << 2;

// =====================================================================
// MC (Memory Controller)
// =====================================================================

/// MC address config
pub const R600_MC_ADDR_CONFIG: u32 = 0x2008;

/// MC initial aperture physical address high
pub const R600_MC_INIT_APERTURE_PHYSICAL_ADDRESS_HIGH: u32 = 0x2018;

/// MC initial aperture virtual address high
pub const R600_MC_INIT_APERTURE_VIRTUAL_ADDRESS_HIGH: u32 = 0x201C;

// =====================================================================
// Display Controller (Pre-AVIVO)
// =====================================================================

/// D1 CRTC control
pub const R600_D1CRTC_CONTROL: u32 = 0x1C8;

/// D1 CRTC horizontal total
pub const R600_D1CRTC_H_TOTAL: u32 = 0x1CC;

/// D1 CRTC horizontal blank start
pub const R600_D1CRTC_H_BLANK_START: u32 = 0x1D0;

/// D1 CRTC horizontal blank end
pub const R600_D1CRTC_H_BLANK_END: u32 = 0x1D4;

/// D1 CRTC horizontal sync start
pub const R600_D1CRTC_H_SYNC_START: u32 = 0x1D8;

/// D1 CRTC horizontal sync end
pub const R600_D1CRTC_H_SYNC_END: u32 = 0x1DC;

/// D1 CRTC vertical total
pub const R600_D1CRTC_V_TOTAL: u32 = 0x1E0;

/// D1 CRTC vertical blank start
pub const R600_D1CRTC_V_BLANK_START: u32 = 0x1E4;

/// D1 CRTC vertical blank end
pub const R600_D1CRTC_V_BLANK_END: u32 = 0x1E8;

/// D1 CRTC vertical sync start
pub const R600_D1CRTC_V_SYNC_START: u32 = 0x1EC;

/// D1 CRTC vertical sync end
pub const R600_D1CRTC_V_SYNC_END: u32 = 0x1F0;

// CRTC control bits
/// CRT enable
pub const R600_CRTC_ENABLE: u32 = 1 << 0;
/// CRTC disable
pub const R600_CRTC_DISABLE: u32 = 0;
/// CRTC display read request disable
pub const R600_CRTC_DISP_READ_REQUEST_DISABLE: u32 = 1 << 1;
/// CRTC double scan enable
pub const R600_CRTC_DOUBLE_SCAN_EN: u32 = 1 << 2;

// =====================================================================
// Framebuffer
// =====================================================================

/// D1 framebuffer location
pub const R600_D1FRAME_BUFFER_LOCATION: u32 = 0x1E4;

/// D1 framebuffer stride
pub const R600_D1FRAME_BUFFER_STRIDE: u32 = 0x1E8;

/// D1B framebuffer location
pub const R600_D1BFRAME_BUFFER_LOCATION: u32 = 0x1FC;

/// D1B framebuffer stride
pub const R600_D1BFRAME_BUFFER_STRIDE: u32 = 0x200;

// =====================================================================
// Clock Management
// =====================================================================

/// General purpose PLL control
pub const R600_GPLL_CNTL: u32 = 0x600;

/// General purpose PLL status
pub const R600_GPLL_STATUS: u32 = 0x604;

/// Display PLL control
pub const R600_DPLL_CNTL: u32 = 0x608;

/// Display PLL status
pub const R600_DPLL_STATUS: u32 = 0x60C;

/// Display PLL reference divider
pub const R600_DPLL_REF_DIV: u32 = 0x610;

/// Display PLL feedback divider
pub const R600_DPLL_FB_DIV: u32 = 0x614;

/// Display A PLL control
pub const R600_DPLL_A_CNTL: u32 = 0x620;

/// Display A PLL feedback divider
pub const R600_DPLL_A_FB_DIV: u32 = 0x624;

/// Display A PLL reference divider
pub const R600_DPLL_A_REF_DIV: u32 = 0x628;

//// Display A PLL post divider
pub const R600_DPLL_A_POST_DIV: u32 = 0x62C;

// PLL control bits
/// PLL reset
pub const R600_PLL_RESET: u32 = 1 << 0;
/// PLL sleep
pub const R600_PLL_SLEEP: u32 = 1 << 1;
/// PLL power down
pub const R600_PLL_POWER_DOWN: u32 = 1 << 2;

// =====================================================================
// Power Management
// =====================================================================

/// Current power state
pub const R600_CURRENT_PWR_GATE: u32 = 0xF0;

/// Controller power status
pub const R600_CONTROLLER_POWER_STATUS: u32 = 0xF4;

/// PCIE link training
pub const R600_PCIE_LC_TRAINING: u32 = 0xF8;

// Power gate bits
/// Memory controller power gate
pub const R600_PWR_GATE_EN_MEMORY: u32 = 1 << 0;
/// Display engine power gate
pub const R600_PWR_GATE_EN_DISPLAY: u32 = 1 << 2;

// =====================================================================
// Interrupt Registers
// =====================================================================

/// Interrupt status
pub const R600_RBBM_INT_STATUS: u32 = 0x564;

/// Interrupt mask
pub const R600_RBBM_INT_MASK: u32 = 0x568;

/// DCE (Display Component Engine) interrupt status
pub const R600_DCE_INT_STATUS: u32 = 0x1F0;

/// DCE interrupt mask
pub const R600_DCE_INT_MASK: u32 = 0x1F4;

// Interrupt status bits
/// VBlank interrupt
pub const R600_RBBM_INT_VBLANK: u32 = 1 << 0;
/// GUI idle interrupt
pub const R600_RBBM_INT_GUI_IDLE: u32 = 1 << 1;
/// CP interrupt
pub const R600_RBBM_INT_CP: u32 = 1 << 2;

// =====================================================================
// Surface and Render Target
// =====================================================================

/// Surface pitch
pub const R600_SURFACE_PITCH: u32 = 0x280;

/// Surface info
pub const R600_SURFACE_INFO: u32 = 0x284;

/// Surface location
pub const R600_SURFACE_LOCATION: u32 = 0x288;

// =====================================================================
// 3D Engine (R6xx Shader)
// =====================================================================

/// Vertex shader instruction fetch
pub const R600_VGT_INDX_DRAW_INIT: u32 = 0xCF0;

/// Vertex shader draw index
pub const R600_VGT_DRAW_INIT_INDEX: u32 = 0xCF4;

/// Vertex shader number of indices
pub const R600_VGT_NUM_INDICES: u32 = 0xCF8;

/// Vertex shader draw index count
pub const R600_VGT_DRAW_INDEX: u32 = 0xCFC;

/// Primitive type
pub const R600_VGT_PRIMITIVE_TYPE: u32 = 0xD00;

/// Vertex shader parameter cache
pub const R600_VGT_SHADER_CACHE_INvalidate: u32 = 0xD04;

// Primitive types
/// Point list
pub const R600_PRIMITIVE_TYPE_POINT: u32 = 0x00;
/// Line list
pub const R600_PRIMITIVE_TYPE_LINE: u32 = 0x01;
/// Line strip
pub const R600_PRIMITIVE_TYPE_LINESTRIP: u32 = 0x02;
/// Triangle list
pub const R600_PRIMITIVE_TYPE_TRIANGLE: u32 = 0x03;
/// Triangle strip
pub const R600_PRIMITIVE_TYPE_TRIANGLESTRIP: u32 = 0x04;
/// Triangle fan
pub const R600_PRIMITIVE_TYPE_TRIANGLEFAN: u32 = 0x05;

// =====================================================================
// Helper Functions
// =====================================================================

/// Calculate stride from width
pub fn calc_stride(width: u32, bpp: u32) -> u32 {
    let bytes_per_row = (width * bpp / 8) + 255;
    bytes_per_row & !255
}

/// Calculate CRTC timing values
pub fn calc_crtc_timing(
    width: u32,
    height: u32,
    _refresh_rate: u32,
) -> (u32, u32, u32, u32, u32, u32) {
    // Standard 1080p timing for 60Hz
    let h_total = width + 160;
    let h_sync_start = width + 48;
    let h_sync_end = width + 112;
    let v_total = height + 30;
    let v_sync_start = height + 10;
    let v_sync_end = height + 12;
    (h_total, h_sync_start, h_sync_end, v_total, v_sync_start, v_sync_end)
}

/// Check if GPU is idle
pub fn is_gpu_idle(status: u32) -> bool {
    status & 0x80000000 == 0
}
