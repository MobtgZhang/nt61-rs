//! Allwinner Graphics Driver
//
//! This module implements the graphics driver for Allwinner ARM and RISC-V SoCs.
//
//! Clean-room implementation based on public specifications.

pub mod pci_ids;
pub mod sunxi_de_reg;
pub mod sunxi_de_fb;
pub mod sunxi_tcon;
pub mod sunxi_hdmi;
pub mod sunxi_mipi_dsi;
pub mod cedarx_reg;
pub mod mali400_reg;
pub mod mali450_reg;
pub mod malit7_reg;

pub use pci_ids::{ALLWINNER_VENDOR_ID, SunxiSoc};
pub use sunxi_de_fb::DebeDevice;

// =====================================================================
// Hardware Support
// =====================================================================
// - A10/A13/A20 (Mali-400)
// - A31 (PowerVR SGX544)
// - A33/A64 (Mali-400)
// - H3/H5/H6 (Mali-400/450/T720)
// - D1/F133 (RISC-V, DEBE only)
//
// Display Pipeline:
// 1. DEBE (Display Engine Backend) - Layer composition
// 2. TCON (Timing Controller) - Display timing
// 3. HDMI/MIPI DSI - Output interfaces
// 4. CedarX - Video codec (separate block)

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for Allwinner GPU
#[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "riscv64"))]
pub fn probe() -> bool {
    sunxi_de_fb::probe()
}

/// Initialize Allwinner GPU
#[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "riscv64"))]
pub fn init() -> Option<DebeDevice> {
    sunxi_de_fb::init()
}

/// Probe function stub for other architectures
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm", target_arch = "riscv64")))]
pub fn probe() -> bool {
    false
}

/// Init function stub for other architectures
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm", target_arch = "riscv64")))]
pub fn init() -> Option<DebeDevice> {
    None
}
