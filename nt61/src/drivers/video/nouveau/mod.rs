//! NVIDIA Nouveau GPU Driver
//
//! This module implements the Nouveau open-source GPU driver for NVIDIA
//! graphics adapters:
//
//! - NV50 (Tesla): GeForce 8xxx/9xxx
//! - NVC0 (Fermi): GeForce GTX 400/500
//! - NVD0 (Kepler): GeForce GTX 600/700
//! - NV110 (Maxwell): GeForce GTX 900
//! - NV120 (Pascal): GeForce GTX 1000
//! - NV140 (Turing): GeForce RTX 2000
//
//! Legacy GPU support:
//! - Curie/G70 (GeForce 6xxx/7xxx)

pub mod pci_ids;
pub mod nouveau_reg;
pub mod nouveau_fb;

// Architecture-specific framebuffer drivers
mod nv50_fb;
mod nvc0_fb;
mod gm107_fb;

// Legacy GPU support
mod tesla_legacy;

// Re-exports for convenience
pub use pci_ids::{NVIDIA_VENDOR_ID, NouveauArchitecture, arch_from_device_id};
pub use nouveau_fb::NouveauDevice;

// Re-exports for legacy GPU support
pub use tesla_legacy::{
    architecture_from_device_id as legacy_arch_from_device_id,
    device_name as legacy_device_name,
    features_for_architecture as legacy_features,
    print_detection_info as print_legacy_detection_info,
    probe as legacy_probe,
    probe_hits as legacy_probe_hits,
    last_detect as legacy_last_detect,
    init_framebuffer as legacy_init_framebuffer,
    read_reg as legacy_read_reg,
    write_reg as legacy_write_reg,
    to_gpu_features as legacy_to_gpu_features,
};

// Re-exports for architecture-specific framebuffer drivers
pub use nv50_fb::nv50_fb_init;
pub use nvc0_fb::nvc0_fb_init;
pub use gm107_fb::gm107_fb_init;

// =====================================================================
// Interrupt Handling
// =====================================================================

pub mod nouveau_irq;

pub use nouveau_irq::{
    nouveau_irq_handler,
    nouveau_irq_enable,
    nouveau_irq_disable,
    nouveau_irq_status,
    nouveau_irq_clear,
    irq_counts,
    last_irq,
    handler_calls,
};

// =====================================================================
// Power Management
// =====================================================================

pub mod nouveau_pm;

pub use nouveau_pm::{
    nouveau_pm_init,
    nouveau_set_power_state,
    nouveau_get_power_state,
    nouveau_enable_clock_gating,
    nouveau_disable_clock_gating,
    pm_counts,
};

// =====================================================================
// Device Information
// =====================================================================

use crate::drivers::video::core::gpu_common::{
    GpuDeviceInfo, GpuDriver, GpuFeatures, GpuFramebufferInfo,
};

/// Get GPU name
pub fn gpu_name(device_id: u16) -> &'static str {
    pci_ids::device_name(device_id)
}

/// Probe for NVIDIA GPU
#[cfg(target_arch = "x86_64")]
pub fn probe() -> bool {
    use crate::hal::common::pci;

    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == NVIDIA_VENDOR_ID && dev.class_code == 0x03 {
            return true;
        }
    }
    false
}

/// Initialize NVIDIA GPU
#[cfg(target_arch = "x86_64")]
pub fn init() -> Option<NouveauDevice> {
    use crate::hal::common::pci;

    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == NVIDIA_VENDOR_ID && dev.class_code == 0x03 {
            let mut device = NouveauDevice::new(&dev);

            if device.init().is_ok() {
                return Some(device);
            }
        }
    }
    None
}

/// Probe stub for non-x86_64
#[cfg(not(target_arch = "x86_64"))]
pub fn probe() -> bool {
    false
}

/// Init stub for non-x86_64
#[cfg(not(target_arch = "x86_64"))]
pub fn init() -> Option<NouveauDevice> {
    None
}
