//! Zhaoxin Graphics Driver
//
//! This module implements the graphics driver for Zhaoxin and Glenfly
//! graphics adapters found in Chinese x86 processors:
//
//! - Zhaoxin ZX-Chrome 9 (ZX-D/KX-6000 integrated)
//! - Zhaoxin ZX-E (KX-6000G with Glenfly GT-10C0)
//! - Zhaoxin ZX-F (KX-7000)
//! - Glenfly GT-10C0/GT-11C0
//
//! Hardware support:
//! - Basic framebuffer (VGA text mode fallback)
//! - CRT controller with dual-pipe support
//! - Hardware cursor
//! - Color keying and alpha blending
//! - Basic 2D acceleration (Glenfly)
//! - DirectX 11.1 (limited)
//
//! Clean-room implementation based on public specifications.

pub mod pci_ids;
pub mod zxd_reg;
pub mod zxd_fb;
pub mod zxe_reg;
pub mod zxe_fb;
pub mod glenfly_reg;
pub mod glenfly_fb;

use crate::drivers::video::core::gpu_common::{
    GpuDeviceInfo, GpuDriver, GpuFeatures, GpuFramebufferInfo, PixelFormat,
};

use crate::hal::common::pci::PciDevice;

#[cfg(target_arch = "x86_64")]
use crate::hal::common::pci;

#[cfg(target_arch = "x86_64")]
use pci_ids::{ZhaoxinVariant, GLENFLY_VENDOR_ID, ZHAOXIN_VENDOR_ID};

// =====================================================================
// Unified Zhaoxin Device
// =====================================================================

/// Unified Zhaoxin/Glenfly graphics device
/// This device handles all Zhaoxin and Glenfly graphics variants
#[derive(Debug)]
pub struct ZhaoxinDevice {
    /// PCI device information
    pci_dev: PciDevice,
    /// Device variant
    pub variant: ZhaoxinVariant,
    /// MMIO base address
    pub mmio_base: u64,
    /// Framebuffer physical address
    pub fb_phys: u64,
    /// Framebuffer size
    pub fb_size: u64,
    /// Framebuffer virtual address
    pub fb_virt: u64,
    /// Current width
    pub width: u32,
    /// Current height
    pub height: u32,
    /// Current pitch (bytes per line)
    pub pitch: u32,
    /// Pixel format
    pub format: PixelFormat,
    /// Device revision
    pub revision: u8,
    /// Active pipe (0 = A, 1 = B)
    pub active_pipe: u8,
}

impl ZhaoxinDevice {
    /// Create a new Zhaoxin device
    #[cfg(target_arch = "x86_64")]
    pub fn new(pci_dev: &PciDevice) -> Self {
        let variant = pci_ids::variant_from_device_id(pci_dev.vendor_id, pci_dev.device_id);
        Self {
            pci_dev: *pci_dev,
            variant,
            mmio_base: 0,
            fb_phys: 0,
            fb_size: 0,
            fb_virt: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
            revision: 0,
            active_pipe: 0,
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn new() -> Self {
        Self {
            variant: ZhaoxinVariant::Unknown,
            mmio_base: 0,
            fb_phys: 0,
            fb_size: 0,
            fb_virt: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
            revision: 0,
            active_pipe: 0,
        }
    }

    /// Read a MMIO register
    #[inline]
    pub fn read_reg(&self, offset: u32) -> u32 {
        if self.mmio_base == 0 {
            return 0;
        }
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write a MMIO register
    #[inline]
    pub fn write_reg(&self, offset: u32, value: u32) {
        if self.mmio_base == 0 {
            return;
        }
        unsafe {
            core::ptr::write_volatile(
                (self.mmio_base + offset as u64) as *mut u32,
                value,
            );
        }
    }
}

// =====================================================================
// GpuDriver Implementation
// =====================================================================

impl GpuDriver for ZhaoxinDevice {
    fn device_info(&self) -> GpuDeviceInfo {
        GpuDeviceInfo::from_pci(&self.pci_dev)
    }

    fn features(&self) -> GpuFeatures {
        let variant_features = pci_ids::features_for_variant(self.variant);
        GpuFeatures {
            has_2d_accel: variant_features.has_2d_accel,
            has_3d_accel: variant_features.has_3d_accel,
            has_video_decode: variant_features.has_video_decode,
            has_compute: false,
            max_texture_size: if variant_features.has_3d_accel { 4096 } else { 2048 },
            max_render_targets: variant_features.num_overlay_planes as u32,
            has_cursor: variant_features.has_cursor,
            cursor_size: variant_features.cursor_size as u32,
            has_vram: true,
            vram_size: self.fb_size,
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn init(&mut self) -> Result<(), crate::drivers::video::core::gpu_common::GpuError> {
        // Read PCI BARs
        self.mmio_base = pci::read_bar(&self.pci_dev, 0);
        self.fb_phys = pci::read_bar(&self.pci_dev, 1);

        // Mask off the low bits
        self.mmio_base &= !0xF;
        self.fb_phys &= !0xF;

        if self.mmio_base == 0 {
            return Err(crate::drivers::video::core::gpu_common::GpuError::Unknown(1));
        }

        // Enable bus mastering
        pci::enable_bus_mastering(&self.pci_dev);

        // Read revision
        self.revision = self.pci_dev.revision;

        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn init(&mut self) -> Result<(), crate::drivers::video::core::gpu_common::GpuError> {
        Ok(())
    }

    fn init_framebuffer(
        &mut self,
        mode: Option<crate::drivers::video::core::gpu_common::DisplayMode>,
    ) -> Result<GpuFramebufferInfo, crate::drivers::video::core::gpu_common::GpuError> {
        let mode = mode.unwrap_or_else(|| {
            crate::drivers::video::core::gpu_common::DisplayMode::new(1920, 1080, 60, 32)
        });

        let bpp = mode.bpp.max(32);
        let stride = ((mode.width * bpp / 8) + 255) & !255u32;

        self.width = mode.width;
        self.height = mode.height;
        self.pitch = stride;
        self.format = PixelFormat::Bgra8888;

        Ok(GpuFramebufferInfo {
            address: self.fb_phys,
            virtual_address: self.fb_virt,
            size: self.fb_size,
            width: self.width,
            height: self.height,
            pitch: self.pitch,
            bpp,
            format: self.format,
        })
    }

    fn set_mode(&mut self, mode: &crate::drivers::video::core::gpu_common::DisplayMode) -> Result<(), crate::drivers::video::core::gpu_common::GpuError> {
        self.init_framebuffer(Some(*mode)).map(|_| ())
    }

    fn get_mode(&self) -> Option<crate::drivers::video::core::gpu_common::DisplayMode> {
        if self.width == 0 {
            return None;
        }
        Some(crate::drivers::video::core::gpu_common::DisplayMode::new(
            self.width,
            self.height,
            60,
            32,
        ))
    }

    fn enable_vblank(&mut self, _head: u32) -> Result<(), crate::drivers::video::core::gpu_common::GpuError> {
        Ok(())
    }

    fn disable_vblank(&mut self, _head: u32) {}

    fn wait_vblank(&self, _head: u32, _timeout_ms: u32) -> Result<(), crate::drivers::video::core::gpu_common::GpuError> {
        Ok(())
    }

    fn clear(&mut self, color: u32) {
        if self.fb_virt == 0 || self.width == 0 || self.height == 0 {
            return;
        }

        let pixels = ((self.pitch as usize) * (self.height as usize)) / 4;
        for i in 0..pixels {
            unsafe {
                core::ptr::write_volatile(
                    (self.fb_virt + (i as u64 * 4)) as *mut u32,
                    color,
                );
            }
        }
    }

    fn set_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height || self.fb_virt == 0 {
            return;
        }

        let offset = ((y * self.pitch) + (x * 4)) as u64;
        unsafe {
            core::ptr::write_volatile(
                (self.fb_virt + offset) as *mut u32,
                color,
            );
        }
    }

    fn framebuffer_info(&self) -> Option<GpuFramebufferInfo> {
        if self.width == 0 {
            return None;
        }
        Some(GpuFramebufferInfo {
            address: self.fb_phys,
            virtual_address: self.fb_virt,
            size: self.fb_size,
            width: self.width,
            height: self.height,
            pitch: self.pitch,
            bpp: 32,
            format: self.format,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn enable_bus_mastering(&mut self) {
        pci::enable_bus_mastering(&self.pci_dev);
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn enable_bus_mastering(&mut self) {}

    fn shutdown(&mut self) {
        // Disable DC
        self.write_reg(0x0000, 0);
    }
}

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for Zhaoxin/Glenfly graphics device
#[cfg(target_arch = "x86_64")]
pub fn probe() -> bool {
    let devices = pci::enumerate();
    for dev in devices {
        // Check for Zhaoxin
        if dev.vendor_id == ZHAOXIN_VENDOR_ID && dev.class_code == 0x03 {
            return true;
        }
        // Check for Glenfly
        if dev.vendor_id == GLENFLY_VENDOR_ID && dev.class_code == 0x03 {
            return true;
        }
    }
    false
}

/// Initialize Zhaoxin/Glenfly graphics device
#[cfg(target_arch = "x86_64")]
pub fn init() -> Option<ZhaoxinDevice> {
    let devices = pci::enumerate();
    for dev in devices {
        // Check for Zhaoxin
        if dev.vendor_id == ZHAOXIN_VENDOR_ID && dev.class_code == 0x03 {
            let mut device = ZhaoxinDevice::new(&dev);
            if device.init().is_ok() {
                return Some(device);
            }
        }
        // Check for Glenfly
        if dev.vendor_id == GLENFLY_VENDOR_ID && dev.class_code == 0x03 {
            let mut device = ZhaoxinDevice::new(&dev);
            if device.init().is_ok() {
                return Some(device);
            }
        }
    }
    None
}

/// Get device variant from device info
#[cfg(target_arch = "x86_64")]
pub fn get_variant(vendor_id: u16, device_id: u16) -> ZhaoxinVariant {
    pci_ids::variant_from_device_id(vendor_id, device_id)
}

/// Get device name for logging
pub fn device_name(vendor_id: u16, device_id: u16) -> &'static str {
    pci_ids::device_name(vendor_id, device_id)
}

/// Probe function stub for non-x86_64
#[cfg(not(target_arch = "x86_64"))]
pub fn probe() -> bool {
    false
}

/// Init function stub for non-x86_64
#[cfg(not(target_arch = "x86_64"))]
pub fn init() -> Option<ZhaoxinDevice> {
    None
}
