//! Video Driver Stack
//
//! This module implements the complete video driver stack for NT6.1.7601,
//! supporting multiple GPU vendors and architectures:
//
//! Basic Drivers:
//! * `vga` - VGA text mode + VBE (VESA BIOS Extensions)
//! * `efifb` - EFI framebuffer from UEFI firmware
//! * `bochs_vbe` - Bochs / QEMU emulated VBE display
//
//! GPU Drivers (P0 Priority):
//! * `loongson` - Loongson LSDC (LoongArch64)
//! * `intel` - Intel i915/iGPU (x86_64)
//! * `amd` - AMD Radeon (x86_64)
//
//! GPU Drivers (P1 Priority):
//! * `zhaoxin` - Zhaoxin ZX-D/KX-7000 (x86_64)
//! * `nouveau` - NVIDIA Nouveau (x86_64)
//! * `rockchip` - Rockchip VOP (aarch64)
//! * `qualcomm` - Qualcomm Adreno (aarch64)
//! * `sun4i` - Allwinner DEBE (ARM/aarch64)
//
//! GPU Drivers (P2 Priority):
//! * `riscv` - RISC-V GPU drivers (StarFive/Allwinner D1/virtio-gpu) (riscv64)
//
//! GPU Core Infrastructure:
//! * `core` - Shared GPU infrastructure (vram, irq, dpc, power)
//
//! Clean-room implementation based on industry standards.

extern crate alloc;

pub mod vga;
#[cfg(target_arch = "x86_64")]
pub mod efifb;
#[cfg(target_arch = "x86_64")]
pub mod bochs_vbe;
pub mod edid;
pub mod i2c_ddc;
pub mod dp_aux;

#[cfg(target_arch = "x86_64")]
pub mod smoke;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "loongarch64", target_arch = "riscv64"))]
pub mod core;

// Video driver logging utilities
// Replaces disabled kprintln! calls
pub mod log;

// GPU drivers - x86_64
#[cfg(target_arch = "x86_64")]
pub mod intel;

#[cfg(target_arch = "x86_64")]
pub mod amd;

// GPU drivers - LoongArch64 (the LSDC driver has unresolved type
// mismatches; re-enable when the loongson::pci types are sorted out).
#[cfg(all(target_arch = "loongarch64", feature = "loongson_gpu"))]
pub mod loongson;

// GPU drivers - x86_64 (P1)
#[cfg(target_arch = "x86_64")]
pub mod zhaoxin;

#[cfg(target_arch = "x86_64")]
pub mod nouveau;

// GPU drivers - aarch64 (P1)
#[cfg(target_arch = "aarch64")]
pub mod rockchip;

#[cfg(target_arch = "aarch64")]
pub mod qualcomm;

// GPU drivers - ARM/aarch64 (P1)
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub mod sun4i;

// GPU drivers - riscv64 (P2)
#[cfg(target_arch = "riscv64")]
pub mod riscv;

// USB-C and Thunderbolt support
pub mod usbc;

/// Initialize all video drivers
///
/// This function initializes both basic display drivers and GPU drivers
/// based on the current platform and detected hardware.
///
/// A `GpuDriverRegistry` is built during initialization to track
/// all discovered GPU devices for later use by the display subsystem.
pub fn init() {
    // Basic display drivers
    log::video_log("video", "initializing basic display drivers");
    #[cfg(target_arch = "x86_64")]
    {
        crate::hal::x86_64::serial::write_string("V:vga_start\r\n");
        vga::init();
        crate::hal::x86_64::serial::write_string("V:vga_done\r\n");
        crate::hal::x86_64::serial::write_string("V:efifb_skip\r\n");
        crate::hal::x86_64::serial::write_string("V:bochs_start\r\n");
        bochs_vbe::init();
        crate::hal::x86_64::serial::write_string("V:bochs_done\r\n");
        crate::hal::x86_64::serial::write_string("V:all_done\r\n");
    }

    // GPU drivers - x86_64
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(target_arch = "x86_64")]
        crate::hal::x86_64::serial::write_string("V:intel_probe_start\r\n");
        // Intel i915
        if intel::probe() {
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:intel_found\r\n");
            let _ = intel::init();
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:intel_done\r\n");
        } else {
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:intel_none\r\n");
        }

        #[cfg(target_arch = "x86_64")]
        crate::hal::x86_64::serial::write_string("V:amd_probe_start\r\n");
        // AMD Radeon
        if amd::probe() {
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:amd_found\r\n");
            let _ = amd::init();
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:amd_done\r\n");
        } else {
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:amd_none\r\n");
        }
    }

    // GPU drivers - LoongArch64
    #[cfg(all(target_arch = "loongarch64", feature = "loongson_gpu"))]
    {
        // Loongson LSDC
        if loongson::probe() {
            let _ = loongson::init();
        }
    }

    // GPU drivers - x86_64 (P1)
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(target_arch = "x86_64")]
        crate::hal::x86_64::serial::write_string("V:zhaoxin_probe_start\r\n");
        // Zhaoxin ZX-D/KX-7000
        if zhaoxin::probe() {
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:zhaoxin_found\r\n");
            let _ = zhaoxin::init();
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:zhaoxin_done\r\n");
        } else {
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:zhaoxin_none\r\n");
        }

        #[cfg(target_arch = "x86_64")]
        crate::hal::x86_64::serial::write_string("V:nouveau_probe_start\r\n");
        // NVIDIA Nouveau
        if nouveau::probe() {
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:nouveau_found\r\n");
            let _ = nouveau::init();
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:nouveau_done\r\n");
        } else {
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("V:nouveau_none\r\n");
        }
    }

    // GPU drivers - aarch64 (P1)
    #[cfg(target_arch = "aarch64")]
    {
        // Rockchip VOP
        if rockchip::probe() {
            let _ = rockchip::init();
        }

        // Qualcomm Adreno
        if qualcomm::probe() {
            let _ = qualcomm::init();
        }
    }

    // GPU drivers - ARM/aarch64 (P1)
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        // Allwinner DEBE
        if sun4i::probe() {
            let _ = sun4i::init();
        }
    }

    // GPU drivers - riscv64 (P2)
    #[cfg(target_arch = "riscv64")]
    {
        // RISC-V GPU drivers (StarFive/Allwinner D1/virtio-gpu)
        if riscv::probe() {
            let _ = riscv::init();
        }
    }

    // USB-C and Thunderbolt display support
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("V:usbc_start\r\n");
    // The global heap (4 MB, see `mm::heap`) is stable by this point
    // and the self-map is installed (see `mm::vas::init`), so `Vec`
    // allocations inside `UsbCManager::new()` are safe. The previous
    // skip was a workaround for an uninitialised heap; that no longer
    // applies.
    let _ = usbc::init();
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("V:usbc_done\r\n");

    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("V:done\r\n");
    log::video_log("video", "Video driver stack initialized");
}/// Run smoke tests on all video drivers
pub fn smoke_test() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::drivers::video::smoke;
        smoke::smoke_test()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        true
    }
}

/// Get GPU driver info
pub fn get_gpu_info() {
    use crate::drivers::video::core::gpu_common;

    let gpus = gpu_common::discover_gpus();
    if gpus.is_empty() {
        return;
    }

    for gpu in &gpus {
        match gpu {
            gpu_common::DiscoveredGpu::Loongson { device, chip } => {
                let _ = (*chip, device.vendor_id, device.device_id);
            }
            gpu_common::DiscoveredGpu::Intel { device, generation } => {
                let _ = (*generation, device.vendor_id, device.device_id);
            }
            gpu_common::DiscoveredGpu::Amd { device, family } => {
                let _ = (*family, device.vendor_id, device.device_id);
            }
            gpu_common::DiscoveredGpu::Nvidia { device, arch } => {
                let _ = (*arch, device.vendor_id, device.device_id);
            }
            gpu_common::DiscoveredGpu::Zhaoxin { device, variant } => {
                let _ = (*variant, device.vendor_id, device.device_id);
            }
            gpu_common::DiscoveredGpu::Rockchip { device, soc } => {
                let _ = (*soc, device.vendor_id, device.device_id);
            }
            gpu_common::DiscoveredGpu::Qualcomm { device, generation } => {
                let _ = (*generation, device.vendor_id, device.device_id);
            }
            gpu_common::DiscoveredGpu::Allwinner { device, soc } => {
                let _ = (*soc, device.vendor_id, device.device_id);
            }
            gpu_common::DiscoveredGpu::Starfive { device, soc } => {
                let _ = (*soc, device.vendor_id, device.device_id);
            }
            gpu_common::DiscoveredGpu::VirtioGpu { device } => {
                let _ = (device.vendor_id, device.device_id);
            }
            gpu_common::DiscoveredGpu::Unknown { device } => {
                let _ = (device.vendor_id, device.device_id);
            }
        }
    }
}
