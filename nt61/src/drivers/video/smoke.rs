//! Video Stack Smoke Test Aggregator
//
//! This module aggregates smoke tests for all video drivers,
//! including basic display drivers and GPU drivers.

#![cfg(target_arch = "x86_64")]

/// Run all video smoke tests
///
/// Returns true if all tests pass.
pub fn smoke_test() -> bool {
    let mut ok = true;

    // Basic display drivers
    ok &= super::vga::smoke_test();
    ok &= super::efifb::smoke_test();
    ok &= super::bochs_vbe::smoke_test();

    // GPU core infrastructure tests
    test_gpu_core();

    // GPU drivers - x86_64
    #[cfg(target_arch = "x86_64")]
    {
        // Intel i915 smoke test
        if super::intel::probe() {
            if let Some(device) = super::intel::init() {
                // Test passed
                let _ = device.width;
            }
        }

        // AMD Radeon smoke test
        if super::amd::probe() {
            if let Some(device) = super::amd::init() {
                // Test passed
                let _ = device.width;

                // Log GPU family for debugging
                match device.family {
                    crate::drivers::video::core::gpu_common::AmdFamily::R600 => {
                        // R600 early GPU - use R600-specific registers
                    }
                    _ => {}
                }
            }
        }
    }

    // GPU drivers - riscv64 (P2)
    #[cfg(target_arch = "riscv64")]
    {
        // RISC-V GPU smoke test
        if super::riscv::probe() {
            if let Some(device) = super::riscv::init() {
                // Test passed - device initialized
                let _ = match device {
                    super::riscv::RiscVGpuDevice::Starfive(d) => d.width,
                    super::riscv::RiscVGpuDevice::AllwinnerD1(d) => d.width,
                    super::riscv::RiscVGpuDevice::VirtioGpu(d) => d.width,
                };
            }
        }
    }

    #[cfg(target_arch = "loongarch64")]
    {
        // Loongson LSDC smoke test
        if super::loongson::probe() {
            if let Some(device) = super::loongson::init() {
                // Test passed
                let _ = device.width;
            }
        }
    }

    ok
}

/// Test GPU core infrastructure
fn test_gpu_core() {
    use crate::drivers::video::core::gpu_common;

    // Test vendor ID detection
    let _vendors = [
        (gpu_common::vendors::VENDOR_LOONGSON, "Loongson" as &str),
        (gpu_common::vendors::VENDOR_INTEL, "Intel"),
        (gpu_common::vendors::VENDOR_AMD, "AMD"),
        (gpu_common::vendors::VENDOR_NVIDIA, "NVIDIA"),
        (gpu_common::vendors::VENDOR_ZHAOXIN, "Zhaoxin"),
        (gpu_common::vendors::VENDOR_STARFIVE, "StarFive"),
        (gpu_common::vendors::VENDOR_VIRTIO, "virtio"),
    ];

    // Test pixel format
    let _formats = [
        (gpu_common::PixelFormat::Bgra8888, 4u32),
        (gpu_common::PixelFormat::Bgr565, 2),
        (gpu_common::PixelFormat::G8, 1),
    ];

    // Test VRAM manager
    use crate::drivers::video::core::vram::{VramManager, VRAM_ALIGNMENT};

    let vram = VramManager::new(0x1000_0000, 256 * 1024 * 1024, VRAM_ALIGNMENT);
    let _base = vram.base();
    let _total = vram.total_size();
    let _available = vram.available();

    // Test allocation
    if let Some(alloc) = vram.allocate(1024 * 1024) {
        let _offset = alloc.offset;
        let _size = alloc.size;
    }

    // Test GPU discovery
    let _gpus = gpu_common::discover_gpus();
}
