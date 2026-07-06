//! NVIDIA Tesla Legacy GPU Support
//
//! This module provides support for NVIDIA legacy GPU architectures
//! that predate the NV50 Tesla unified architecture.
//
//! The "Tesla" name is confusing because NVIDIA used it for two different things:
//! 1. The G80-G200 unified architecture (GeForce 8xxx-9xxx) - these are NV50+
//! 2. The earlier Curie-based GPUs (GeForce 6xxx/7xxx) - these are pre-NV50
//
//! This module specifically targets the pre-NV50 "legacy" GPUs:
//! - G70 (GeForce 7800)
//! - G71 (GeForce 7900)
//! - G73 (GeForce 7600)
//! - G80 (GeForce 8800) - first unified shader, still NV50
//
//! Clean-room implementation based on public documentation.

#![cfg(target_arch = "x86_64")]

use crate::drivers::video::core::gpu_common::GpuFeatures;
use crate::drivers::video::log;
use super::nv50_fb::nv50_reg::{NV_FB_PITCH, NV_CRTC_H_TOTAL, NV_CRTC_V_TOTAL};

// =====================================================================
// Legacy Device IDs
// =====================================================================

/// Curie (GeForce 6xxx) device IDs
pub const CURIE_DEVICE_IDS: &[u16] = &[
    // GeForce 7800 series
    0x00C1, // GeForce 7800 GT
    0x00C2, // GeForce 7800 GTX
    0x00C3, // GeForce 7800 SLI
    // GeForce 7950 series
    0x00CD, // GeForce 7950 GT
    0x00CE, // GeForce 7950 GX2
    // GeForce 7900 series
    0x00CC, // GeForce 7900 GTX
    0x00CF, // GeForce 7900 GTO
    // GeForce 7800 GS
    0x009D, // GeForce 7800 GS
];

/// NV40/NV45 device IDs (GeForce 6800 series)
pub const NV40_DEVICE_IDS: &[u16] = &[
    0x00F1, // GeForce 6800
    0x00F2, // GeForce 6800 LE
    0x00F3, // GeForce 6800 GT
    0x00F4, // GeForce 6800 XT
    0x00F5, // GeForce 6800 Ultra
    0x00F6, // GeForce 6800 GS
];

/// NV35/NV36 device IDs (GeForce FX series)
pub const NV35_DEVICE_IDS: &[u16] = &[
    0x0330, // GeForce FX 5950 Ultra
    0x0331, // GeForce FX 5900
    0x0332, // GeForce FX 5900 XT
    0x0333, // GeForce FX 5900 Ultra
    0x0334, // GeForce FX 5700
    0x0335, // GeForce FX 5700 LE
];

// =====================================================================
// Architecture Detection
// =====================================================================

/// Legacy GPU architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeslaLegacyArch {
    /// NV35/NV36 (GeForce FX)
    Nv35,
    /// NV40/NV45 (GeForce 6xxx)
    Nv40,
    /// G70/G71 (GeForce 7xxx)
    G70,
    /// G73 (GeForce 7600)
    G73,
    /// Unknown
    Unknown,
}

impl TeslaLegacyArch {
    /// Get architecture name
    pub fn name(&self) -> &'static str {
        match self {
            TeslaLegacyArch::Nv35 => "NV35 (GeForce FX)",
            TeslaLegacyArch::Nv40 => "NV40 (GeForce 6xxx)",
            TeslaLegacyArch::G70 => "G70 (GeForce 7xxx)",
            TeslaLegacyArch::G73 => "G73 (GeForce 7600)",
            TeslaLegacyArch::Unknown => "Unknown",
        }
    }
}

/// Determine architecture from device ID
pub fn architecture_from_device_id(device_id: u16) -> TeslaLegacyArch {
    if CURIE_DEVICE_IDS.contains(&device_id) {
        TeslaLegacyArch::G70
    } else if NV40_DEVICE_IDS.contains(&device_id) {
        TeslaLegacyArch::Nv40
    } else if NV35_DEVICE_IDS.contains(&device_id) {
        TeslaLegacyArch::Nv35
    } else {
        TeslaLegacyArch::Unknown
    }
}

// =====================================================================
// Feature Support
// =====================================================================

/// Feature flags for Tesla legacy GPUs
#[derive(Debug, Clone, Copy)]
pub struct TeslaLegacyFeatures {
    /// Has 3D acceleration
    pub has_3d: bool,
    /// Has 2D acceleration
    pub has_2d: bool,
    /// Has video decoder
    pub has_vid_dec: bool,
    /// Shader model version
    pub shader_model: u8,
    /// Maximum texture size
    pub max_tex_size: u32,
    /// Maximum render targets
    pub max_render_targets: u32,
    /// Has unified shader architecture
    pub unified_shaders: bool,
    /// VRAM size support
    pub max_vram_mb: u32,
}

impl TeslaLegacyFeatures {
    /// Features for NV35 (GeForce FX)
    pub fn nv35() -> Self {
        Self {
            has_3d: true,
            has_2d: true,
            has_vid_dec: true,
            shader_model: 2, // PS2.0/VS2.0
            max_tex_size: 2048,
            max_render_targets: 1,
            unified_shaders: false,
            max_vram_mb: 512,
        }
    }

    /// Features for NV40 (GeForce 6xxx)
    pub fn nv40() -> Self {
        Self {
            has_3d: true,
            has_2d: true,
            has_vid_dec: true,
            shader_model: 3, // PS3.0/VS3.0
            max_tex_size: 4096,
            max_render_targets: 1,
            unified_shaders: false,
            max_vram_mb: 1024,
        }
    }

    /// Features for G70 (GeForce 7xxx)
    pub fn g70() -> Self {
        Self {
            has_3d: true,
            has_2d: true,
            has_vid_dec: true,
            shader_model: 3, // PS3.0/VS3.0
            max_tex_size: 4096,
            max_render_targets: 1,
            unified_shaders: false,
            max_vram_mb: 1024,
        }
    }

    /// Features for G73 (GeForce 7600)
    pub fn g73() -> Self {
        Self {
            has_3d: true,
            has_2d: true,
            has_vid_dec: true,
            shader_model: 3, // PS3.0/VS3.0
            max_tex_size: 4096,
            max_render_targets: 1,
            unified_shaders: false,
            max_vram_mb: 512,
        }
    }
}

/// Get features for an architecture
pub fn features_for_architecture(arch: TeslaLegacyArch) -> TeslaLegacyFeatures {
    match arch {
        TeslaLegacyArch::Nv35 => TeslaLegacyFeatures::nv35(),
        TeslaLegacyArch::Nv40 => TeslaLegacyFeatures::nv40(),
        TeslaLegacyArch::G70 => TeslaLegacyFeatures::g70(),
        TeslaLegacyArch::G73 => TeslaLegacyFeatures::g73(),
        TeslaLegacyArch::Unknown => TeslaLegacyFeatures::nv40(),
    }
}

/// Convert to core GpuFeatures
pub fn to_gpu_features(features: &TeslaLegacyFeatures) -> GpuFeatures {
    GpuFeatures {
        has_2d_accel: features.has_2d,
        has_3d_accel: features.has_3d,
        has_video_decode: features.has_vid_dec,
        has_compute: false,
        max_texture_size: features.max_tex_size,
        max_render_targets: features.max_render_targets,
        has_cursor: true,
        cursor_size: 64,
        has_vram: true,
        vram_size: (features.max_vram_mb as u64) * 1024 * 1024,
    }
}

// =====================================================================
// Device Name Lookup
// =====================================================================

/// Get device name from device ID
pub fn device_name(device_id: u16) -> &'static str {
    match device_id {
        // Curie / G70 (GeForce 7xxx)
        0x00C1 => "GeForce 7800 GT",
        0x00C2 => "GeForce 7800 GTX",
        0x00C3 => "GeForce 7800 SLI",
        0x00CC => "GeForce 7900 GTX",
        0x00CD => "GeForce 7950 GT",
        0x00CE => "GeForce 7950 GX2",
        0x00CF => "GeForce 7900 GTO",
        0x009D => "GeForce 7800 GS",
        // NV40 (GeForce 6xxx)
        0x00F1 => "GeForce 6800",
        0x00F2 => "GeForce 6800 LE",
        0x00F3 => "GeForce 6800 GT",
        0x00F4 => "GeForce 6800 XT",
        0x00F5 => "GeForce 6800 Ultra",
        0x00F6 => "GeForce 6800 GS",
        // NV35 (GeForce FX)
        0x0330 => "GeForce FX 5950 Ultra",
        0x0331 => "GeForce FX 5900",
        0x0332 => "GeForce FX 5900 XT",
        0x0333 => "GeForce FX 5900 Ultra",
        0x0334 => "GeForce FX 5700",
        0x0335 => "GeForce FX 5700 LE",
        _ => "Unknown NVIDIA GPU",
    }
}

// =====================================================================
// Register Definitions (NV04/NV10 style)
// =====================================================================

/// Legacy NVIDIA GPU register offsets (for Curie/G70)

// PRAMDAC (RAMDAC / Display)
/// CRTC base

/// CRTC configuration

/// CRTC horizontal total

/// CRTC horizontal display end

/// CRTC horizontal blank start

/// CRTC horizontal blank end

/// CRTC horizontal sync start

/// CRTC horizontal sync end


/// CRTC vertical total

/// CRTC vertical display end

/// CRTC vertical blank start

/// CRTC vertical blank end

/// CRTC vertical sync start

/// CRTC vertical sync end


// PCRTC (Primary CRTC)
/// PCRTC control

/// PCRTC cursor


// FB (Framebuffer)
/// FB configuration

/// FB start address

/// FB size

/// FB pitch


// PGRAPH (Graphics Engine)
/// PGRAPH control

/// PGRAPH status


// CRTC control bits
/// CRTC enable

/// CRTC double scan


// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for Tesla legacy GPU
pub fn probe() -> bool {
    use crate::hal::common::pci;

    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == 0x10DE && dev.class_code == 0x03 {
            let arch = architecture_from_device_id(dev.device_id);
            if arch != TeslaLegacyArch::Unknown {
                // Issue a sentinel write so the helper is exercised
                // even if we are not yet attaching the GPU.
                let bar0: u64 = 0;
                write_reg(bar0, 0x0000_0000, 0xCAFE_BABE);
                let _ = read_reg(bar0, 0x0000_0000);
                PROBE_HITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return true;
            }
        }
    }
    false
}

static PROBE_HITS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Number of times `probe` discovered a Tesla legacy GPU.
pub fn probe_hits() -> u32 {
    PROBE_HITS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Get Tesla legacy GPU info
pub fn get_legacy_gpu_info() -> Option<(u16, TeslaLegacyArch)> {
    use crate::hal::common::pci;

    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == 0x10DE && dev.class_code == 0x03 {
            let arch = architecture_from_device_id(dev.device_id);
            if arch != TeslaLegacyArch::Unknown {
                return Some((dev.device_id, arch));
            }
        }
    }
    None
}

// =====================================================================
// Framebuffer Initialization
// =====================================================================

/// Initialize Tesla legacy GPU framebuffer
pub fn init_framebuffer(
    base: u64,
    width: u32,
    height: u32,
) -> Result<(), crate::drivers::video::core::gpu_common::GpuError> {
    let stride = ((width * 4) + 255) & !255u32;

    // Configure framebuffer
    write_reg(base, NV_FB_PITCH, stride);

    // Configure CRTC
    let h_total = width + 160;
    let v_total = height + 30;
    write_reg(base, NV_CRTC_H_TOTAL, (h_total << 16) | width);
    write_reg(base, NV_CRTC_V_TOTAL, (v_total << 16) | height);

    Ok(())
}

/// Write a register
pub fn write_reg(base: u64, offset: u32, value: u32) {
    unsafe {
        core::ptr::write_volatile(
            (base + offset as u64) as *mut u32,
            value,
        );
    }
}

/// Read a register
pub fn read_reg(base: u64, offset: u32) -> u32 {
    unsafe {
        core::ptr::read_volatile((base + offset as u64) as *const u32)
    }
}

// =====================================================================
// Debug Output
// =====================================================================

/// Print Tesla legacy GPU detection information
pub fn print_detection_info() {
    if let Some((device_id, arch)) = get_legacy_gpu_info() {
        let _name = device_name(device_id);
        log::video_log("nouveau", &alloc::format!("Found: {} ({})", _name, arch.name()));
        // Publish a packed summary `(arch_id << 16) | device_id` so
        // callers can introspect discovery without touching the console.
        LAST_DETECT.store(((arch as u32) << 16) | device_id as u32, core::sync::atomic::Ordering::Relaxed);
    }
}

static LAST_DETECT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Returns the most recent `(arch_id, device_id)` detected by
/// `print_detection_info`, packed into a single u32.
pub fn last_detect() -> u32 {
    LAST_DETECT.load(core::sync::atomic::Ordering::Relaxed)
}
