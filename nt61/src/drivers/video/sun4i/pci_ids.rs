//! Allwinner PCI ID Database
//
//! This module provides PCI vendor and device ID definitions for Allwinner
//! graphics found in various Allwinner SoCs.
//
//! Hardware support:
//! - A10/A13/A20 (Mali-400)
//! - A31/A31s (PowerVR SGX544)
//! - A64 (Mali-400 MP2)
//! - H3/H5/H6 (Mali-400/450/T720)
//! - D1/F133 (RISC-V, no GPU)
//
//! Clean-room implementation based on public specifications.

/// Allwinner vendor ID
pub const ALLWINNER_VENDOR_ID: u16 = 0x1D3D;

// =====================================================================
// SoC Identifiers
// =====================================================================

/// SoC name strings
pub const SOC_NAMES: &[&str] = &[
    "sun4i-a10",    // A10
    "sun5i-a13",    // A13
    "sun7i-a20",     // A20
    "sun8i-a33",     // A33
    "sun8i-h3",      // H3
    "sun50i-h5",     // H5
    "sun50i-h6",     // H6
    "sun50i-h616",   // H616
    "sun50i-a64",    // A64
    "sunxi-d1",      // D1 (RISC-V)
    "sun50i-f133",   // F133 (RISC-V)
    "sun20i-d1",     // D1 (alternative)
];

// =====================================================================
// Device Name Database
// =====================================================================

/// Get SoC name
pub fn soc_name(soc_id: &str) -> &'static str {
    match soc_id {
        "sun4i-a10" => "Allwinner A10",
        "sun5i-a13" => "Allwinner A13",
        "sun7i-a20" => "Allwinner A20",
        "sun8i-a33" => "Allwinner A33",
        "sun8i-h3" => "Allwinner H3",
        "sun50i-h5" => "Allwinner H5",
        "sun50i-h6" => "Allwinner H6",
        "sun50i-h616" => "Allwinner H616",
        "sun50i-a64" => "Allwinner A64",
        "sunxi-d1" => "Allwinner D1",
        "sun50i-f133" => "Allwinner F133",
        _ => "Unknown Allwinner SoC",
    }
}

// =====================================================================
// SoC Classification
// =====================================================================

/// Allwinner SoC variant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SunxiSoc {
    /// A10 - Single-core Cortex-A8 with Mali-400
    A10,
    /// A13 - Single-core Cortex-A8 with Mali-400
    A13,
    /// A20 - Dual-core Cortex-A7 with Mali-400
    A20,
    /// A31 - Quad-core Cortex-A7 with PowerVR SGX544
    A31,
    /// A33 - Quad-core Cortex-A7 with Mali-400
    A33,
    /// A64 - Quad-core Cortex-A53 with Mali-400 MP2
    A64,
    /// H3 - Quad-core Cortex-A7 with Mali-400
    H3,
    /// H5 - Quad-core Cortex-A53 with Mali-450
    H5,
    /// H6 - Quad-core Cortex-A53 with Mali-T720
    H6,
    /// H616 - Quad-core Cortex-A53 with Mali-G31
    H616,
    /// D1 - RISC-V single-core (no GPU)
    D1,
    /// F133 - RISC-V single-core (no GPU)
    F133,
    /// Unknown SoC
    Unknown,
}

impl SunxiSoc {
    /// Get SoC name
    pub fn name(&self) -> &'static str {
        match self {
            SunxiSoc::A10 => "A10",
            SunxiSoc::A13 => "A13",
            SunxiSoc::A20 => "A20",
            SunxiSoc::A31 => "A31",
            SunxiSoc::A33 => "A33",
            SunxiSoc::A64 => "A64",
            SunxiSoc::H3 => "H3",
            SunxiSoc::H5 => "H5",
            SunxiSoc::H6 => "H6",
            SunxiSoc::H616 => "H616",
            SunxiSoc::D1 => "D1",
            SunxiSoc::F133 => "F133",
            SunxiSoc::Unknown => "Unknown",
        }
    }
}

// =====================================================================
// Feature Support
// =====================================================================

/// Feature flags for Allwinner variants
#[derive(Debug, Clone, Copy)]
pub struct SunxiFeatures {
    /// Has DEBE display engine
    pub has_debe: bool,
    /// Has TCON LCD controller
    pub has_tcon: bool,
    /// Has HDMI
    pub has_hdmi: bool,
    /// Has MIPI DSI
    pub has_mipi_dsi: bool,
    /// Has CedarX video codec
    pub has_cedarx: bool,
    /// GPU type
    pub gpu_type: GpuType,
}

impl SunxiFeatures {
    /// Features for A10/A13
    pub fn a10() -> Self {
        Self {
            has_debe: true,
            has_tcon: true,
            has_hdmi: true,
            has_mipi_dsi: false,
            has_cedarx: true,
            gpu_type: GpuType::Mali400,
        }
    }

    /// Features for A20
    pub fn a20() -> Self {
        Self {
            has_debe: true,
            has_tcon: true,
            has_hdmi: true,
            has_mipi_dsi: false,
            has_cedarx: true,
            gpu_type: GpuType::Mali400,
        }
    }

    /// Features for A31
    pub fn a31() -> Self {
        Self {
            has_debe: true,
            has_tcon: true,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_cedarx: true,
            gpu_type: GpuType::PowerVR,
        }
    }

    /// Features for A33
    pub fn a33() -> Self {
        Self {
            has_debe: true,
            has_tcon: true,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_cedarx: true,
            gpu_type: GpuType::Mali400,
        }
    }

    /// Features for A64
    pub fn a64() -> Self {
        Self {
            has_debe: true,
            has_tcon: true,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_cedarx: true,
            gpu_type: GpuType::Mali400,
        }
    }

    /// Features for H3
    pub fn h3() -> Self {
        Self {
            has_debe: true,
            has_tcon: true,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_cedarx: true,
            gpu_type: GpuType::Mali400,
        }
    }

    /// Features for H5
    pub fn h5() -> Self {
        Self {
            has_debe: true,
            has_tcon: true,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_cedarx: true,
            gpu_type: GpuType::Mali450,
        }
    }

    /// Features for H6
    pub fn h6() -> Self {
        Self {
            has_debe: true,
            has_tcon: true,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_cedarx: true,
            gpu_type: GpuType::MaliT720,
        }
    }

    /// Features for D1 (RISC-V)
    pub fn d1() -> Self {
        Self {
            has_debe: true,
            has_tcon: true,
            has_hdmi: false,
            has_mipi_dsi: true,
            has_cedarx: true,
            gpu_type: GpuType::None,
        }
    }
}

/// GPU type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuType {
    /// ARM Mali-400
    Mali400,
    /// ARM Mali-450
    Mali450,
    /// ARM Mali-T720
    MaliT720,
    /// ARM Mali-G31
    MaliG31,
    /// PowerVR SGX544
    PowerVR,
    /// No GPU
    None,
}

/// Get features for a SoC
pub fn features_for_soc(soc: SunxiSoc) -> SunxiFeatures {
    match soc {
        SunxiSoc::A10 | SunxiSoc::A13 => SunxiFeatures::a10(),
        SunxiSoc::A20 => SunxiFeatures::a20(),
        SunxiSoc::A31 => SunxiFeatures::a31(),
        SunxiSoc::A33 => SunxiFeatures::a33(),
        SunxiSoc::A64 => SunxiFeatures::a64(),
        SunxiSoc::H3 => SunxiFeatures::h3(),
        SunxiSoc::H5 => SunxiFeatures::h5(),
        SunxiSoc::H6 | SunxiSoc::H616 => SunxiFeatures::h6(),
        SunxiSoc::D1 | SunxiSoc::F133 => SunxiFeatures::d1(),
        SunxiSoc::Unknown => SunxiFeatures::a10(),
    }
}
