//! Qualcomm Adreno GPU Driver
//
//! This module implements the graphics driver for Qualcomm Adreno GPUs.
//
//! Clean-room implementation based on public specifications.

pub mod pci_ids;
pub mod adreno_reg;
pub mod adreno_fb;
pub mod adreno_gmu;
pub mod a3xx_reg;
pub mod a4xx_reg;
pub mod a5xx_reg;
pub mod a6xx_reg;

pub use pci_ids::{QUALCOMM_VENDOR_ID, AdrenoGeneration};
pub use adreno_fb::AdrenoDevice;

// =====================================================================
// Hardware Support
// =====================================================================
// - Adreno 3xx: Snapdragon S4
// - Adreno 4xx: Snapdragon 800/801
// - Adreno 5xx: Snapdragon 820/835
// - Adreno 6xx: Snapdragon 845+
//
// Features:
// - Hardware-accelerated 2D/3D graphics
// - Video encode/decode
// - GPU compute (OpenCL)

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for Adreno GPU
#[cfg(target_arch = "aarch64")]
pub fn probe() -> bool {
    adreno_fb::probe()
}

/// Initialize Adreno GPU
#[cfg(target_arch = "aarch64")]
pub fn init() -> Option<AdrenoDevice> {
    adreno_fb::init()
}

/// Probe function stub for other architectures
#[cfg(not(target_arch = "aarch64"))]
pub fn probe() -> bool {
    false
}

/// Init function stub for other architectures
#[cfg(not(target_arch = "aarch64"))]
pub fn init() -> Option<AdrenoDevice> {
    None
}
