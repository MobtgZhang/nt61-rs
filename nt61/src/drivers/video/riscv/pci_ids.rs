//! RISC-V GPU PCI ID Database
//
//! This module provides PCI vendor and device ID definitions for RISC-V
//! graphics adapters found on various RISC-V platforms.
//
//! Clean-room implementation based on public specifications.

use crate::drivers::video::core::gpu_common::GpuFeatures;

// =====================================================================
// Vendor IDs
// =====================================================================

/// StarFive vendor ID
pub const STARFIVE_VENDOR_ID: u16 = 0x1D17;

/// virtio vendor ID (Red Hat / QEMU)
pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;

/// Allwinner vendor ID (for completeness, though usually accessed via MMIO)
pub const ALLWINNER_VENDOR_ID: u16 = 0x1D3D;

// =====================================================================
// Device IDs
// =====================================================================

/// StarFive JH7100 device IDs
pub const STARFIVE_JH7100_DEVICE_IDS: &[u16] = &[
    0x0001, // JH7100
    0x0002, // JH7100 variant
];

/// StarFive JH7110 device IDs
pub const STARFIVE_JH7110_DEVICE_IDS: &[u16] = &[
    0x0003, // JH7110
    0x0004, // JH7110 variant (VisionFive 2)
];

/// virtio-gpu device ID
pub const VIRTIO_GPU_DEVICE_ID: u16 = 0x1050;

/// virtio-gpu-virgl device ID (with VirGL acceleration)
pub const VIRTIO_GPU_VIRGL_DEVICE_ID: u16 = 0x1051;

// =====================================================================
// RISC-V SoC Classification
// =====================================================================

/// RISC-V SoC variant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiscVSoc {
    /// StarFive JH7100 - 2-core RISC-V + IMG BXE-4-32
    StarfiveJH7100,
    /// StarFive JH7110 - 4-core RISC-V + IMG BXE-4-32
    StarfiveJH7110,
    /// Allwinner D1 - RISC-V single-core + DEBE
    AllwinnerD1,
    /// Allwinner F133 - RISC-V single-core + DEBE
    AllwinnerF133,
    /// virtio-gpu (QEMU)
    VirtioGpu,
    /// Unknown variant
    Unknown,
}

impl RiscVSoc {
    /// Get SoC name
    pub fn name(&self) -> &'static str {
        match self {
            RiscVSoc::StarfiveJH7100 => "StarFive JH7100",
            RiscVSoc::StarfiveJH7110 => "StarFive JH7110",
            RiscVSoc::AllwinnerD1 => "Allwinner D1",
            RiscVSoc::AllwinnerF133 => "Allwinner F133",
            RiscVSoc::VirtioGpu => "virtio-gpu",
            RiscVSoc::Unknown => "Unknown",
        }
    }
}

/// Determine SoC from device ID
pub fn soc_from_device_id(vendor_id: u16, device_id: u16) -> RiscVSoc {
    match vendor_id {
        STARFIVE_VENDOR_ID => {
            if STARFIVE_JH7100_DEVICE_IDS.contains(&device_id) {
                RiscVSoc::StarfiveJH7100
            } else if STARFIVE_JH7110_DEVICE_IDS.contains(&device_id) {
                RiscVSoc::StarfiveJH7110
            } else {
                RiscVSoc::Unknown
            }
        }
        VIRTIO_VENDOR_ID => {
            if device_id == VIRTIO_GPU_DEVICE_ID || device_id == VIRTIO_GPU_VIRGL_DEVICE_ID {
                RiscVSoc::VirtioGpu
            } else {
                RiscVSoc::Unknown
            }
        }
        ALLWINNER_VENDOR_ID => {
            // Allwinner D1/F133 don't use standard PCI IDs
            // Detection is usually done via device tree
            RiscVSoc::AllwinnerD1
        }
        _ => RiscVSoc::Unknown,
    }
}

// =====================================================================
// Feature Support
// =====================================================================

/// Feature flags for RISC-V GPU variants
#[derive(Debug, Clone, Copy)]
pub struct RiscVGpuFeatures {
    /// Has display controller
    pub has_display: bool,
    /// Has DEBE display engine
    pub has_debe: bool,
    /// Has TCON
    pub has_tcon: bool,
    /// Has HDMI output
    pub has_hdmi: bool,
    /// Has MIPI DSI
    pub has_mipi_dsi: bool,
    /// Has 2D acceleration (G2D)
    pub has_2d_accel: bool,
    /// Has 3D acceleration
    pub has_3d_accel: bool,
    /// GPU type
    pub gpu_type: GpuType,
    /// Maximum resolution width
    pub max_width: u32,
    /// Maximum resolution height
    pub max_height: u32,
}

impl Default for RiscVGpuFeatures {
    fn default() -> Self {
        Self {
            has_display: false,
            has_debe: false,
            has_tcon: false,
            has_hdmi: false,
            has_mipi_dsi: false,
            has_2d_accel: false,
            has_3d_accel: false,
            gpu_type: GpuType::None,
            max_width: 1920,
            max_height: 1080,
        }
    }
}

/// GPU type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuType {
    /// IMG BXE-4-32 (StarFive)
    ImgBxe,
    /// ARM Mali-like (not used on RISC-V)
    Mali,
    /// Display Engine Backend (Allwinner)
    Debe,
    /// virtio-gpu (virtual)
    Virtio,
    /// No GPU
    None,
}

impl RiscVGpuFeatures {
    /// Features for StarFive JH7100
    pub fn starfive_jh7100() -> Self {
        Self {
            has_display: true,
            has_debe: false,
            has_tcon: true,
            has_hdmi: true,
            has_mipi_dsi: false,
            has_2d_accel: false,
            has_3d_accel: true, // IMG BXE-4-32
            gpu_type: GpuType::ImgBxe,
            max_width: 4096,
            max_height: 2160,
        }
    }

    /// Features for StarFive JH7110
    pub fn starfive_jh7110() -> Self {
        Self {
            has_display: true,
            has_debe: false,
            has_tcon: true,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_2d_accel: false,
            has_3d_accel: true, // IMG BXE-4-32
            gpu_type: GpuType::ImgBxe,
            max_width: 4096,
            max_height: 2160,
        }
    }

    /// Features for Allwinner D1
    pub fn allwinner_d1() -> Self {
        Self {
            has_display: true,
            has_debe: true,
            has_tcon: true,
            has_hdmi: false,
            has_mipi_dsi: true,
            has_2d_accel: true, // G2D engine
            has_3d_accel: false,
            gpu_type: GpuType::Debe,
            max_width: 1920,
            max_height: 1080,
        }
    }

    /// Features for virtio-gpu
    pub fn virtio_gpu() -> Self {
        Self {
            has_display: true,
            has_debe: true,
            has_tcon: false, // virtio handles this
            has_hdmi: true,
            has_mipi_dsi: false,
            has_2d_accel: true,
            has_3d_accel: true, // VirGL
            gpu_type: GpuType::Virtio,
            max_width: 4096,
            max_height: 2160,
        }
    }
}

/// Get features for a SoC
pub fn features_for_soc(soc: RiscVSoc) -> RiscVGpuFeatures {
    match soc {
        RiscVSoc::StarfiveJH7100 => RiscVGpuFeatures::starfive_jh7100(),
        RiscVSoc::StarfiveJH7110 => RiscVGpuFeatures::starfive_jh7110(),
        RiscVSoc::AllwinnerD1 | RiscVSoc::AllwinnerF133 => RiscVGpuFeatures::allwinner_d1(),
        RiscVSoc::VirtioGpu => RiscVGpuFeatures::virtio_gpu(),
        RiscVSoc::Unknown => RiscVGpuFeatures::default(),
    }
}

/// Convert RiscVGpuFeatures to core GpuFeatures
pub fn to_gpu_features(features: &RiscVGpuFeatures) -> GpuFeatures {
    GpuFeatures {
        has_2d_accel: features.has_2d_accel,
        has_3d_accel: features.has_3d_accel,
        has_video_decode: false,
        has_compute: false,
        max_texture_size: if features.has_3d_accel { 4096 } else { 2048 },
        max_render_targets: if features.has_3d_accel { 4 } else { 2 },
        has_cursor: true,
        cursor_size: 64,
        has_vram: features.gpu_type != GpuType::None,
        vram_size: 0, // Dynamic based on hardware
    }
}

// =====================================================================
// Device Name Database
// =====================================================================

/// Device name lookup
pub fn device_name(vendor_id: u16, device_id: u16) -> &'static str {
    match vendor_id {
        STARFIVE_VENDOR_ID => {
            if STARFIVE_JH7100_DEVICE_IDS.contains(&device_id) {
                "StarFive JH7100"
            } else if STARFIVE_JH7110_DEVICE_IDS.contains(&device_id) {
                "StarFive JH7110"
            } else {
                "StarFive Unknown"
            }
        }
        VIRTIO_VENDOR_ID => {
            if device_id == VIRTIO_GPU_DEVICE_ID {
                "virtio-gpu"
            } else if device_id == VIRTIO_GPU_VIRGL_DEVICE_ID {
                "virtio-gpu (VirGL)"
            } else {
                "virtio Unknown"
            }
        }
        ALLWINNER_VENDOR_ID => "Allwinner SoC",
        _ => "Unknown GPU",
    }
}

// =====================================================================
// SoC Memory Map
// =====================================================================

/// SoC memory map for common RISC-V platforms
pub mod memmap {
    /// StarFive JH7110 display controller base address
    pub const STARFIVE_JH7110_DC_BASE: u64 = 0x118E_0000;
    
    /// StarFive JH7110 display controller size
    pub const STARFIVE_JH7110_DC_SIZE: u64 = 0x10000;

    /// StarFive JH7110 framebuffer base (from device tree)
    pub const STARFIVE_JH7110_FB_BASE: u64 = 0x0; // Dynamic

    /// Allwinner D1 DEBE base address
    pub const ALLWINNER_D1_DEBE_BASE: u64 = 0x0540_0000;

    /// Allwinner D1 TCON base address
    pub const ALLWINNER_D1_TCON_BASE: u64 = 0x0510_0000;

    /// Allwinner D1 G2D base address
    pub const ALLWINNER_D1_G2D_BASE: u64 = 0x0580_0000;

    /// Allwinner D1 DEBE/TCON size
    pub const ALLWINNER_D1_DEBE_SIZE: u64 = 0x10000;
    pub const ALLWINNER_D1_TCON_SIZE: u64 = 0x10000;
}

// =====================================================================
// virtio-gpu Constants
// =====================================================================

/// virtio-gpu configuration offsets
pub mod virtio {
    /// virtio-gpu MMIO configuration base
    pub const VIRTIO_GPU_BASE: u64 = 0x1000_0000;

    /// virtio-gpu configuration size
    pub const VIRTIO_GPU_SIZE: u64 = 0x2000;

    /// virtio-gpu configuration register: device ID
    pub const VIRTIO_GPU_CONFIG_DEVICE_ID: u32 = 0x00;
    
    /// virtio-gpu configuration register: display info
    pub const VIRTIO_GPU_CONFIG_DISPLAY: u32 = 0x10;

    /// virtio-gpu control register
    pub const VIRTIO_GPU_CTRL: u32 = 0x100;

    /// virtio-gpu irq status
    pub const VIRTIO_GPU_IRQ_STATUS: u32 = 0x180;
}
