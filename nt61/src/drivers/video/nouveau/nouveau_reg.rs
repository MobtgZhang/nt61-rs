//! NVIDIA Nouveau Register Definitions
//
//! This module defines the MMIO register layout for NVIDIA GPUs
//! used by the Nouveau open-source driver.
//
//! Different architectures have different register layouts:
//! - NV50 (Tesla): Basic 2D/3D engine
//! - NVC0 (Fermi): Enhanced with Fermi-style registers
//! - NVD0 (Kepler): Improved power management
//! - NV110+ (Maxwell/Pascal/Turing): Modern register layout
//
//! Reference: Nouveau project, Linux nouveau driver
//
//! Clean-room implementation based on public specifications.

use super::pci_ids::NouveauArchitecture;

// =====================================================================
// NV50 (Tesla) Register Offsets
// =====================================================================

/// NV50 PVPIO register block
pub const NV50_PVPIO_OFFSET: u32 = 0x000000;

/// NV50 PMC (Performance and Membership Control) registers
pub const NV50_PMC_OFFSET: u32 = 0x000000;
pub const NV50_PMC_ENABLE: u32 = 0x000148;

/// NV50 PFB (Performance and Frame Buffer) registers
pub const NV50_PFB_OFFSET: u32 = 0x001000;
pub const NV50_PFB_CFG: u32 = 0x001004;
pub const NV50_PFB_FIFO: u32 = 0x001008;
pub const NV50_PFB_PITCH: u32 = 0x00100C;
pub const NV50_PFB_SURFACE: u32 = 0x001010;

/// NV50 PCRTC (PCRTC) registers
pub const NV50_PCRTC_OFFSET: u32 = 0x006000;
pub const NV50_PCRTC_ENABLE: u32 = 0x006000;
pub const NV50_PCRTC_CONFIG: u32 = 0x006004;
pub const NV50_PCRTC_H_START: u32 = 0x006008;
pub const NV50_PCRTC_H_END: u32 = 0x00600C;
pub const NV50_PCRTC_V_START: u32 = 0x006010;
pub const NV50_PCRTC_V_END: u32 = 0x006014;
pub const NV50_PCRTC_CURSOR: u32 = 0x006100;

/// NV50 PDISPLAY (Display) registers
pub const NV50_PDISPLAY_OFFSET: u32 = 0x006100;
pub const NV50_PDISPLAY_SET_CONTROL: u32 = 0x006100;
pub const NV50_PDISPLAY_SET_OFFSET: u32 = 0x006104;
pub const NV50_PDISPLAY_SET_PITCH: u32 = 0x006108;
pub const NV50_PDISPLAY_SET_SIZE: u32 = 0x00610C;

/// NV50 PGRAPH (Graphics Engine) registers
pub const NV50_PGRAPH_OFFSET: u32 = 0x004000;
pub const NV50_PGRAPH_CTXCTL: u32 = 0x004004;
pub const NV50_PGRAPH_TRAPPED_ADDR: u32 = 0x004100;
pub const NV50_PGRAPH_TRAPPED_DATA: u32 = 0x004104;

// NV50 register enables
pub const NV50_PFB_ENABLED: u32 = 1 << 0;
pub const NV50_PCRTC_ENABLE_ON: u32 = 1 << 0;

// =====================================================================
// NVC0 (Fermi) Register Offsets
// =====================================================================

/// NVC0 PMC (Performance and Membership Control) registers
pub const NVC0_PMC_OFFSET: u32 = 0x000000;
pub const NVC0_PMC_ENABLE: u32 = 0x000648;
pub const NVC0_PMC_INTR: u32 = 0x000100;
pub const NVC0_PMC_INTR_EN: u32 = 0x000140;

/// NVC0 PFB (Performance and Frame Buffer) registers
pub const NVC0_PFB_OFFSET: u32 = 0x001000;
pub const NVC0_PFB_CFG: u32 = 0x001004;
pub const NVC0_PFB_FIFO: u32 = 0x001008;
pub const NVC0_PFB_PITCH: u32 = 0x00100C;
pub const NVC0_PFB_SURFACE: u32 = 0x001010;
pub const NVC0_PFB_TILE: u32 = 0x001020;

/// NVC0 PCRTC (CRT Controller) registers
pub const NVC0_PCRTC_OFFSET: u32 = 0x006000;
pub const NVC0_PCRTC_ENABLE: u32 = 0x006000;
pub const NVC0_PCRTC_CONFIG: u32 = 0x006004;
pub const NVC0_PCRTC_H_TOTAL: u32 = 0x006008;
pub const NVC0_PCRTC_H_BLANK: u32 = 0x00600C;
pub const NVC0_PCRTC_H_SYNC: u32 = 0x006010;
pub const NVC0_PCRTC_V_TOTAL: u32 = 0x006014;
pub const NVC0_PCRTC_V_BLANK: u32 = 0x006018;
pub const NVC0_PCRTC_V_SYNC: u32 = 0x00601C;
pub const NVC0_PCRTC_CURSOR_CTRL: u32 = 0x006100;
pub const NVC0_PCRTC_CURSOR_POS: u32 = 0x006104;
pub const NVC0_PCRTC_CURSOR_COLOR: u32 = 0x006200;

/// NVC0 PDISPLAY (Display) registers
pub const NVC0_PDISPLAY_OFFSET: u32 = 0x006400;
pub const NVC0_PDISPLAY_SET_CONTROL: u32 = 0x006400;
pub const NVC0_PDISPLAY_SET_OFFSET: u32 = 0x006404;
pub const NVC0_PDISPLAY_SET_PITCH: u32 = 0x006408;
pub const NVC0_PDISPLAY_SET_SIZE: u32 = 0x00640C;
pub const NVC0_PDISPLAY_DAC_CTRL: u32 = 0x006800;

/// NVC0 PGRAPH (Graphics Engine) registers
pub const NVC0_PGRAPH_OFFSET: u32 = 0x004000;
pub const NVC0_PGRAPH_CTXCTL: u32 = 0x004000;
pub const NVC0_PGRAPH_TRAPPED_ADDR: u32 = 0x004700;
pub const NVC0_PGRAPH_TRAPPED_DATA: u32 = 0x004704;

// NVC0 register enables
pub const NVC0_PFB_ENABLED: u32 = 1 << 0;
pub const NVC0_PCRTC_ENABLE_ON: u32 = 1 << 0;
pub const NVC0_PDISPLAY_ENABLE: u32 = 1 << 0;

// =====================================================================
// NVD0 (Kepler) Register Offsets
// =====================================================================

/// NVD0 uses similar register layout to NVC0 with enhancements
pub const NVD0_PMC_OFFSET: u32 = 0x000000;
pub const NVD0_PFB_OFFSET: u32 = 0x001000;
pub const NVD0_PCRTC_OFFSET: u32 = 0x006000;
pub const NVD0_PDISPLAY_OFFSET: u32 = 0x006400;
pub const NVD0_PGRAPH_OFFSET: u32 = 0x004000;

/// NVD0 specific PMU (Power Management Unit)
pub const NVD0_PMU_OFFSET: u32 = 0x0010A0;
pub const NVD0_PMU_ENABLE: u32 = 0x0010A0;
pub const NVD0_PMU_INTR: u32 = 0x0010A4;
pub const NVD0_PMU_INTR_EN: u32 = 0x0010A8;
pub const NVD0_PMU_FW_LOAD: u32 = 0x0010C0;

pub const NVD0_PFB_ENABLED: u32 = 1 << 0;
pub const NVD0_PCRTC_ENABLE_ON: u32 = 1 << 0;

// =====================================================================
// NV110+ (Maxwell/Pascal/Turing) Register Offsets
// =====================================================================

/// NV110+ uses a new register layout
pub const NV110_PMC_OFFSET: u32 = 0x000000;
pub const NV110_PFB_OFFSET: u32 = 0x001000;
pub const NV110_PCRTC_OFFSET: u32 = 0x006000;
pub const NV110_PDISPLAY_OFFSET: u32 = 0x007000;
pub const NV110_PGRAPH_OFFSET: u32 = 0x004000;

/// NV110+ PMU
pub const NV110_PMU_OFFSET: u32 = 0x0010A0;
pub const NV110_PMU_FALCON: u32 = 0x001100;

pub const NV110_PFB_ENABLED: u32 = 1 << 0;
pub const NV110_PCRTC_ENABLE_ON: u32 = 1 << 0;

// =====================================================================
// Display Controller Registers (Common)
// =====================================================================

/// Framebuffer address register (32-bit)
pub const DISPLAY_FB_ADDR: u32 = 0x0000;
/// Framebuffer address high (for 64-bit addressing)
pub const DISPLAY_FB_ADDR_HIGH: u32 = 0x0004;
/// Framebuffer pitch (bytes per line)
pub const DISPLAY_FB_PITCH: u32 = 0x0008;
/// Framebuffer size (width/height)
pub const DISPLAY_FB_SIZE: u32 = 0x000C;
/// Framebuffer format
pub const DISPLAY_FB_FORMAT: u32 = 0x0010;

/// CRT timing registers
pub const DISPLAY_CRTC_H_TOTAL: u32 = 0x0010;
pub const DISPLAY_CRTC_H_BLANK_START: u32 = 0x0014;
pub const DISPLAY_CRTC_H_BLANK_END: u32 = 0x0018;
pub const DISPLAY_CRTC_H_SYNC_START: u32 = 0x001C;
pub const DISPLAY_CRTC_H_SYNC_END: u32 = 0x0020;
pub const DISPLAY_CRTC_V_TOTAL: u32 = 0x0024;
pub const DISPLAY_CRTC_V_BLANK_START: u32 = 0x0028;
pub const DISPLAY_CRTC_V_BLANK_END: u32 = 0x002C;
pub const DISPLAY_CRTC_V_SYNC_START: u32 = 0x0030;
pub const DISPLAY_CRTC_V_SYNC_END: u32 = 0x0034;

/// Cursor registers
pub const DISPLAY_CURSOR_CTRL: u32 = 0x0100;
pub const DISPLAY_CURSOR_POS: u32 = 0x0104;
pub const DISPLAY_CURSOR_COLOR: u32 = 0x0200;

// Cursor control flags
pub const CURSOR_ENABLE: u32 = 1 << 0;
pub const CURSOR_FORMAT_32BPP: u32 = 2 << 4;
pub const CURSOR_SIZE_64X64: u32 = 0 << 8;
pub const CURSOR_SIZE_32X32: u32 = 1 << 8;

// =====================================================================
// PMU/PMM Registers (Power Management)
// =====================================================================

/// PMU registers
pub const PMU_ENABLE: u32 = 0x0000;
pub const PMU_INTR: u32 = 0x0004;
pub const PMU_INTR_EN: u32 = 0x0008;
pub const PMU_STATUS: u32 = 0x0010;
pub const PMU_FW_VERSION: u32 = 0x0014;

// PMU states
pub const PMU_STATE_IDLE: u32 = 0;
pub const PMU_STATE_BUSY: u32 = 1;
pub const PMU_STATE_RESET: u32 = 2;

// =====================================================================
// Interrupt Registers
// =====================================================================

/// Interrupt status register
pub const PMC_INTR: u32 = 0x000100;
/// Interrupt enable register
pub const PMC_INTR_EN: u32 = 0x000140;

/// Interrupt sources
pub const INTR_VBLANK_A: u32 = 1 << 0;
pub const INTR_VBLANK_B: u32 = 1 << 1;
pub const INTR_DISPLAY_A: u32 = 1 << 4;
pub const INTR_DISPLAY_B: u32 = 1 << 5;
pub const INTR_PGRAPH: u32 = 1 << 12;
pub const INTR_PMU: u32 = 1 << 20;
pub const INTR_NVDEC: u32 = 1 << 22;

// =====================================================================
// Helper Functions
// =====================================================================

/// Get register base offset for architecture
pub fn get_arch_offset(arch: NouveauArchitecture, block: RegisterBlock) -> u32 {
    match arch {
        NouveauArchitecture::NV50 => match block {
            RegisterBlock::PMC => NV50_PMC_OFFSET,
            RegisterBlock::PFB => NV50_PFB_OFFSET,
            RegisterBlock::PCRTC => NV50_PCRTC_OFFSET,
            RegisterBlock::PDISPLAY => NV50_PDISPLAY_OFFSET,
            RegisterBlock::PGRAPH => NV50_PGRAPH_OFFSET,
        },
        NouveauArchitecture::NVC0 => match block {
            RegisterBlock::PMC => NVC0_PMC_OFFSET,
            RegisterBlock::PFB => NVC0_PFB_OFFSET,
            RegisterBlock::PCRTC => NVC0_PCRTC_OFFSET,
            RegisterBlock::PDISPLAY => NVC0_PDISPLAY_OFFSET,
            RegisterBlock::PGRAPH => NVC0_PGRAPH_OFFSET,
        },
        NouveauArchitecture::NVD0 => match block {
            RegisterBlock::PMC => NVD0_PMC_OFFSET,
            RegisterBlock::PFB => NVD0_PFB_OFFSET,
            RegisterBlock::PCRTC => NVD0_PCRTC_OFFSET,
            RegisterBlock::PDISPLAY => NVD0_PDISPLAY_OFFSET,
            RegisterBlock::PGRAPH => NVD0_PGRAPH_OFFSET,
        },
        _ => match block {
            RegisterBlock::PMC => NV110_PMC_OFFSET,
            RegisterBlock::PFB => NV110_PFB_OFFSET,
            RegisterBlock::PCRTC => NV110_PCRTC_OFFSET,
            RegisterBlock::PDISPLAY => NV110_PDISPLAY_OFFSET,
            RegisterBlock::PGRAPH => NV110_PGRAPH_OFFSET,
        },
    }
}

/// Register block types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterBlock {
    /// Performance and Membership Control
    PMC,
    /// Performance and Frame Buffer
    PFB,
    /// CRT Controller
    PCRTC,
    /// Display Controller
    PDISPLAY,
    /// Graphics Engine
    PGRAPH,
}

/// Get enable bit for architecture
pub fn get_pfb_enable(arch: NouveauArchitecture) -> u32 {
    match arch {
        NouveauArchitecture::NV50 => NV50_PFB_ENABLED,
        NouveauArchitecture::NVC0 => NVC0_PFB_ENABLED,
        NouveauArchitecture::NVD0 => NVD0_PFB_ENABLED,
        _ => NV110_PFB_ENABLED,
    }
}

/// Get CRTC enable bit for architecture
pub fn get_crtc_enable(arch: NouveauArchitecture) -> u32 {
    match arch {
        NouveauArchitecture::NV50 => NV50_PCRTC_ENABLE_ON,
        NouveauArchitecture::NVC0 => NVC0_PCRTC_ENABLE_ON,
        NouveauArchitecture::NVD0 => NVD0_PCRTC_ENABLE_ON,
        _ => NV110_PCRTC_ENABLE_ON,
    }
}

/// Calculate CRTC timing parameters
pub fn calculate_crtc_timing(width: u32, height: u32, _refresh: u32) -> CrtcTiming {
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

    /// Encode horizontal blank register
    pub fn h_blank_reg(&self) -> u32 {
        (self.h_blank_end << 16) | self.h_blank_start
    }

    /// Encode horizontal sync register
    pub fn h_sync_reg(&self) -> u32 {
        (self.h_sync_end << 16) | self.h_sync_start
    }

    /// Encode vertical total register
    pub fn v_total_reg(&self) -> u32 {
        (self.v_total << 16) | self.v_blank_start
    }

    /// Encode vertical blank register
    pub fn v_blank_reg(&self) -> u32 {
        (self.v_blank_end << 16) | self.v_blank_start
    }

    /// Encode vertical sync register
    pub fn v_sync_reg(&self) -> u32 {
        (self.v_sync_end << 16) | self.v_sync_start
    }
}
