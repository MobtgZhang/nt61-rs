//! RISC-V GPU Driver
//
//! This module implements GPU drivers for RISC-V platforms:
//
//! - StarFive JH7100/JH7110 (VisionFive 2)
//! - Allwinner D1/F133 (RISC-V)
//! - QEMU virtio-gpu
//
//! Clean-room implementation based on public specifications.

pub mod pci_ids;
pub mod starfive_jh71x0;
pub mod allwinner_d1;
pub mod virt_gpu;

// Re-exports for convenience. The StarfiveSoc / VirtioGpuDeviceId
// enums are defined in `drivers::video::core::gpu_common` (the
// shared "core" module); we re-export them from there so legacy
// callers can still reach them via the riscv GPU module.
pub use crate::drivers::video::core::gpu_common::{StarfiveSoc, VirtioGpuDeviceId};
pub use starfive_jh71x0::StarfiveDevice;
pub use allwinner_d1::AllwinnerD1Device;
pub use virt_gpu::VirtioGpuDevice;

// =====================================================================
// Module Documentation
// =====================================================================

// ## Hardware Support
//
// ### StarFive JH71x0
// - JH7100: 2-core RISC-V + IMG BXE-4-32 GPU
// - JH7110: 4-core RISC-V + IMG BXE-4-32 GPU
//
// ### Allwinner D1/F133
// - D1: RISC-V single-core + DEBE display engine
// - F133: RISC-V single-core + DEBE display engine
//
// ### QEMU virtio-gpu
// - Standard virtio-gpu device for virtualized environments
// - Primary development target for RISC-V
//
// ## Display Pipeline
//
// 1. Display Controller (DC) - Frame timing and control
// 2. Display Engine Backend (DEBE) - Layer composition
// 3. Timing Controller (TCON) - Signal generation
// 4. Output Interface (HDMI/MIPI DSI) - Physical connection

// =====================================================================
// Device Information
// =====================================================================

use crate::drivers::video::core::gpu_common::{
    GpuDeviceInfo, GpuDriver, GpuFeatures, GpuFramebufferInfo,
};

/// Get device name for a RISC-V GPU
pub fn gpu_name(soc: pci_ids::RiscVSoc) -> &'static str {
    match soc {
        pci_ids::RiscVSoc::StarfiveJH7100 => "StarFive JH7100",
        pci_ids::RiscVSoc::StarfiveJH7110 => "StarFive JH7110",
        pci_ids::RiscVSoc::AllwinnerD1 => "Allwinner D1",
        pci_ids::RiscVSoc::AllwinnerF133 => "Allwinner F133",
        pci_ids::RiscVSoc::VirtioGpu => "virtio-gpu",
        pci_ids::RiscVSoc::Unknown => "Unknown RISC-V GPU",
    }
}

// =====================================================================
// Unified RISC-V GPU Device
// =====================================================================

/// Unified RISC-V GPU device enum for driver selection
#[derive(Debug)]
pub enum RiscVGpuDevice {
    /// StarFive JH71x0 device
    Starfive(StarfiveDevice),
    /// Allwinner D1/F133 device
    AllwinnerD1(AllwinnerD1Device),
    /// virtio-gpu device
    VirtioGpu(VirtioGpuDevice),
}

impl RiscVGpuDevice {
    /// Get the device info
    pub fn device_info(&self) -> GpuDeviceInfo {
        match self {
            RiscVGpuDevice::Starfive(dev) => dev.device_info(),
            RiscVGpuDevice::AllwinnerD1(dev) => dev.device_info(),
            RiscVGpuDevice::VirtioGpu(dev) => dev.device_info(),
        }
    }

    /// Initialize the framebuffer
    pub fn init_framebuffer(
        &mut self,
        mode: Option<crate::drivers::video::core::gpu_common::DisplayMode>,
    ) -> Result<GpuFramebufferInfo, crate::drivers::video::core::gpu_common::GpuError> {
        match self {
            RiscVGpuDevice::Starfive(dev) => dev.init_framebuffer(mode),
            RiscVGpuDevice::AllwinnerD1(dev) => dev.init_framebuffer(mode),
            RiscVGpuDevice::VirtioGpu(dev) => dev.init_framebuffer(mode),
        }
    }
}

// =====================================================================
// Platform Detection and Hardware Probe
// =====================================================================

/// Probe for RISC-V GPU hardware
///
/// This function checks for available GPU hardware on RISC-V platforms:
/// 1. First checks for virtio-gpu (QEMU/virtualization)
/// 2. Then checks for StarFive JH71x0
/// 3. Finally checks for Allwinner D1/F133
#[cfg(target_arch = "riscv64")]
pub fn probe() -> bool {
    // Try virtio-gpu first (most common in virtual environments)
    if virt_gpu::probe() {
        return true;
    }

    // Try StarFive JH71x0
    if starfive_jh71x0::probe() {
        return true;
    }

    // Try Allwinner D1/F133
    if allwinner_d1::probe() {
        return true;
    }

    false
}

/// Initialize the first available RISC-V GPU
#[cfg(target_arch = "riscv64")]
pub fn init() -> Option<RiscVGpuDevice> {
    // Try virtio-gpu first (most common in virtual environments)
    if let Some(dev) = virt_gpu::init() {
        return Some(RiscVGpuDevice::VirtioGpu(dev));
    }

    // Try StarFive JH71x0
    if let Some(dev) = starfive_jh71x0::init() {
        return Some(RiscVGpuDevice::Starfive(dev));
    }

    // Try Allwinner D1/F133
    if let Some(dev) = allwinner_d1::init() {
        return Some(RiscVGpuDevice::AllwinnerD1(dev));
    }

    None
}

/// Probe stub for non-RISC-V architectures
#[cfg(not(target_arch = "riscv64"))]
pub fn probe() -> bool {
    false
}

/// Init stub for non-RISC-V architectures
#[cfg(not(target_arch = "riscv64"))]
pub fn init() -> Option<RiscVGpuDevice> {
    None
}

// =====================================================================
// Debug Output Helpers
// =====================================================================

/// Print RISC-V GPU detection information
pub fn print_detection_info() {
    use crate::drivers::video::log;

    log::video_log("riscv-gpu", "Scanning for display hardware...");

    #[cfg(target_arch = "riscv64")]
    {
        if virt_gpu::probe() {
            log::video_log("riscv-gpu", "Found: virtio-gpu (QEMU)");
        }
        if starfive_jh71x0::probe() {
            log::video_log("riscv-gpu", "Found: StarFive JH71x0");
        }
        if allwinner_d1::probe() {
            log::video_log("riscv-gpu", "Found: Allwinner D1/F133");
        }
    }

    #[cfg(not(target_arch = "riscv64"))]
    {
        log::video_log("riscv-gpu", "Not a RISC-V platform, skipping...");
    }
}
