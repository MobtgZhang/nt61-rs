//! Rockchip PCI ID Database
//
//! This module provides PCI vendor and device ID definitions for Rockchip
//! graphics adapters found in ARM SoCs.
//
//! Hardware support:
//! - RK3066 (Mali-400 MP4)
//! - RK3288 (Mali-T760)
//! - RK3399 (Mali-T860)
//! - RK3566/RK3568 (Mali-G52)
//! - RK3588 (Mali-G610)
//
//! Clean-room implementation based on public specifications.

/// Rockchip vendor ID
pub const ROCKCHIP_VENDOR_ID: u16 = 0x220E;

// =====================================================================
// RK3xxx SoC IDs
// =====================================================================

/// RK3066 SoC ID
pub const SOC_RK3066: u32 = 0x3066;
/// RK3288 SoC ID
pub const SOC_RK3288: u32 = 0x3288;
/// RK3399 SoC ID
pub const SOC_RK3399: u32 = 0x3399;
/// RK3566 SoC ID
pub const SOC_RK3566: u32 = 0x3566;
/// RK3568 SoC ID
pub const SOC_RK3568: u32 = 0x3568;
/// RK3588 SoC ID
pub const SOC_RK3588: u32 = 0x3588;

// =====================================================================
// Device Name Database
// =====================================================================

/// Get SoC name from ID
pub fn soc_name(soc_id: u32) -> &'static str {
    match soc_id {
        SOC_RK3066 => "Rockchip RK3066",
        SOC_RK3288 => "Rockchip RK3288",
        SOC_RK3399 => "Rockchip RK3399",
        SOC_RK3566 => "Rockchip RK3566",
        SOC_RK3568 => "Rockchip RK3568",
        SOC_RK3588 => "Rockchip RK3588",
        _ => "Unknown Rockchip SoC",
    }
}

// =====================================================================
// SoC Classification
// =====================================================================

/// Rockchip SoC variant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RockchipSoc {
    /// RK3066 - Dual-core Cortex-A9 with Mali-400 MP4
    RK3066,
    /// RK3288 - Quad-core Cortex-A17 with Mali-T760
    RK3288,
    /// RK3399 - Dual-core Cortex-A72 + Quad-core Cortex-A53 with Mali-T860
    RK3399,
    /// RK3566 - Quad-core Cortex-A55 with Mali-G52
    RK3566,
    /// RK3568 - Quad-core Cortex-A55 with Mali-G52
    RK3568,
    /// RK3588 - Octa-core with Mali-G610
    RK3588,
    /// Unknown SoC
    Unknown,
}

impl RockchipSoc {
    /// Get SoC name
    pub fn name(&self) -> &'static str {
        match self {
            RockchipSoc::RK3066 => "RK3066",
            RockchipSoc::RK3288 => "RK3288",
            RockchipSoc::RK3399 => "RK3399",
            RockchipSoc::RK3566 => "RK3566",
            RockchipSoc::RK3568 => "RK3568",
            RockchipSoc::RK3588 => "RK3588",
            RockchipSoc::Unknown => "Unknown",
        }
    }
}

/// Determine SoC from device ID
pub fn soc_from_device_id(device_id: u16) -> RockchipSoc {
    match device_id {
        0x3066 => RockchipSoc::RK3066,
        0x3288 => RockchipSoc::RK3288,
        0x3399 => RockchipSoc::RK3399,
        0x3566 => RockchipSoc::RK3566,
        0x3568 => RockchipSoc::RK3568,
        0x3588 => RockchipSoc::RK3588,
        _ => RockchipSoc::Unknown,
    }
}

// =====================================================================
// Feature Support
// =====================================================================

/// Feature flags for Rockchip variants
#[derive(Debug, Clone, Copy)]
pub struct RockchipFeatures {
    /// Has VOP display controller
    pub has_vop: bool,
    /// Number of VOP pipes
    pub num_vop: u8,
    /// Has HDMI output
    pub has_hdmi: bool,
    /// Has MIPI DSI
    pub has_mipi_dsi: bool,
    /// Has eDP
    pub has_edp: bool,
    /// GPU type
    pub gpu_type: GpuType,
}

impl RockchipFeatures {
    /// Features for RK3066
    pub fn rk3066() -> Self {
        Self {
            has_vop: true,
            num_vop: 1,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_edp: false,
            gpu_type: GpuType::Mali400,
        }
    }

    /// Features for RK3288
    pub fn rk3288() -> Self {
        Self {
            has_vop: true,
            num_vop: 1,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_edp: true,
            gpu_type: GpuType::MaliT760,
        }
    }

    /// Features for RK3399
    pub fn rk3399() -> Self {
        Self {
            has_vop: true,
            num_vop: 2,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_edp: true,
            gpu_type: GpuType::MaliT860,
        }
    }

    /// Features for RK3588
    pub fn rk3588() -> Self {
        Self {
            has_vop: true,
            num_vop: 3,
            has_hdmi: true,
            has_mipi_dsi: true,
            has_edp: true,
            gpu_type: GpuType::MaliG610,
        }
    }
}

/// GPU type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuType {
    /// ARM Mali-400
    Mali400,
    /// ARM Mali-T760
    MaliT760,
    /// ARM Mali-T860
    MaliT860,
    /// ARM Mali-G52
    MaliG52,
    /// ARM Mali-G610
    MaliG610,
    /// No GPU
    None,
}

/// Get features for a SoC
pub fn features_for_soc(soc: RockchipSoc) -> RockchipFeatures {
    match soc {
        RockchipSoc::RK3066 => RockchipFeatures::rk3066(),
        RockchipSoc::RK3288 => RockchipFeatures::rk3288(),
        RockchipSoc::RK3399 => RockchipFeatures::rk3399(),
        RockchipSoc::RK3566 | RockchipSoc::RK3568 => RockchipFeatures::rk3588(),
        RockchipSoc::RK3588 => RockchipFeatures::rk3588(),
        RockchipSoc::Unknown => RockchipFeatures::rk3066(),
    }
}
