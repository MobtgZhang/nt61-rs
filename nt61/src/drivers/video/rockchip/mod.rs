//! Rockchip Graphics Driver
//
//! This module implements the graphics driver for Rockchip ARM SoCs.
//
//! Clean-room implementation based on public specifications.

pub mod pci_ids;
pub mod vop_reg;
pub mod vop_fb;
pub mod vop_crtc;
pub mod rk_mipi_dsi;
pub mod rk_hdmi;
pub mod rk_gpu;

pub use pci_ids::{ROCKCHIP_VENDOR_ID, RockchipSoc};
pub use vop_fb::VopDevice;

// =====================================================================
// Hardware Support
// =====================================================================
// - RK3066: Dual-core Cortex-A9 with Mali-400 MP4
// - RK3288: Quad-core Cortex-A17 with Mali-T760
// - RK3399: Dual-core Cortex-A72 + Quad-core Cortex-A53 with Mali-T860
// - RK3566/RK3568: Quad-core Cortex-A55 with Mali-G52
// - RK3588: Octa-core with Mali-G610
//
// Display Pipeline:
// 1. VOP (Video Output Processor) - Display controller
// 2. HDMI/MIPI DSI/eDP - Output interfaces
// 3. GPU (Mali) - Graphics processing

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for Rockchip GPU
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub fn probe() -> bool {
    vop_fb::probe()
}

/// Initialize Rockchip GPU
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub fn init() -> Option<VopDevice> {
    vop_fb::init()
}

/// Probe function stub for other architectures
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
pub fn probe() -> bool {
    false
}

/// Init function stub for other architectures
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
pub fn init() -> Option<VopDevice> {
    None
}
