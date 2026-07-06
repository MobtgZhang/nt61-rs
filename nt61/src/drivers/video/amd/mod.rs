//! AMD Radeon GPU Driver
//
//! This module implements the GPU driver for AMD Radeon graphics
//! found in various AMD processors and discrete GPUs:
//
//! - R600/R700 (HD 2000-5000)
//! - Evergreen (HD 5000-6000)
//! - Southern Islands / GCN 1.x (HD 7000)
//! - Sea Islands / GCN 2.x (R9 200/300)
//! - Volcanic Islands / GCN 3.x (R9 390/Fury)
//! - Polaris / GCN 4.x (RX 400/500)
//! - Vega
//! - Navi / RDNA

pub mod pci_ids;
pub mod radeon_reg;
pub mod radeon_fb;
pub mod radeon_cursor;
pub mod radeon_irq;
pub mod radeon_pm;

// R600/R700 early GPU support
pub mod r600_reg;
pub mod r700_reg;

use crate::drivers::video::core::gpu_common::{
    self, GpuDeviceInfo, GpuDriver, GpuFeatures, GpuFramebufferInfo,
    AmdFamily, DisplayMode, PixelFormat,
};
use crate::drivers::video::core::mmio_guard::{MmioGuard, MAX_MMIO_SIZE};
use crate::drivers::video::log;

#[cfg(target_arch = "x86_64")]
use crate::hal::common::pci;

use crate::hal::common::pci::PciDevice;

/// AMD Radeon device
#[derive(Debug)]
pub struct RadeonDevice {
    /// PCI device
    pci_dev: PciDevice,
    /// GPU family
    pub family: AmdFamily,
    /// MMIO guard with bounds checking and spinlock
    mmio: MmioGuard,
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
    /// Current pitch
    pub pitch: u32,
    /// Pixel format
    pub format: PixelFormat,
    /// Device revision
    pub revision: u8,
}

impl RadeonDevice {
    /// Create new Radeon device
    pub fn new(pci_dev: &PciDevice, family: AmdFamily) -> Self {
        Self {
            pci_dev: *pci_dev,
            family,
            mmio: MmioGuard::new(0, MAX_MMIO_SIZE),
            fb_phys: 0,
            fb_size: 0,
            fb_virt: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
            revision: 0,
        }
    }

    /// Read MMIO register with bounds checking
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        self.mmio.read_reg(offset)
    }

    /// Write MMIO register with bounds checking
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        let _ = self.mmio.write_reg(offset, value);
    }

    /// Reset GPU
    pub fn reset(&mut self) {
        use radeon_reg::*;

        // Soft reset CP
        self.write_reg(R_0003_RBBM_SOFT_RESET, RBBM_SOFT_RESET_CP);
        for _ in 0..10 {
            self.write_reg(R_0003_RBBM_SOFT_RESET, 0);
        }
    }
}

impl GpuDriver for RadeonDevice {
    fn device_info(&self) -> GpuDeviceInfo {
        GpuDeviceInfo::from_pci(&self.pci_dev)
    }

    fn features(&self) -> GpuFeatures {
        GpuFeatures {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            max_texture_size: 16384,
            max_render_targets: 8,
            has_cursor: true,
            cursor_size: 64,
            has_vram: true,
            vram_size: self.fb_size,
        }
    }

    fn init(&mut self) -> Result<(), gpu_common::GpuError> {
        #[cfg(target_arch = "x86_64")]
        {
            let mmio_bar = pci::read_bar(&self.pci_dev, 0);
            let fb_bar = pci::read_bar(&self.pci_dev, 2);

            if mmio_bar == 0 {
                log::video_error("amd", "MMIO BAR0 is zero");
                return Err(gpu_common::GpuError::Unknown(1));
            }

            // AMD display MMIO is typically 1-8 MB depending on generation.
            let mmio_size = match self.family {
                AmdFamily::R600 | AmdFamily::Evergreen => 2 * 1024 * 1024,
                AmdFamily::Northern | AmdFamily::Southern | AmdFamily::Sea => 4 * 1024 * 1024,
                AmdFamily::Volcanic | AmdFamily::Polaris => 8 * 1024 * 1024,
                AmdFamily::Vega | AmdFamily::Navi => 8 * 1024 * 1024,
                _ => MAX_MMIO_SIZE,
            };
            self.mmio = MmioGuard::new(mmio_bar, mmio_size);
            self.fb_phys = fb_bar;

            log::video_ok("amd", "PCI BARs read");
            log::video_log_hex64("amd", "MMIO base", mmio_bar);
            log::video_log_hex64("amd", "FB base", fb_bar);

            // Reset GPU
            self.reset();
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            return Err(gpu_common::GpuError::Unknown(1));
        }

        Ok(())
    }

    fn init_framebuffer(
        &mut self,
        mode: Option<DisplayMode>,
    ) -> Result<GpuFramebufferInfo, gpu_common::GpuError> {
        let mode = mode.unwrap_or_else(|| DisplayMode::new(1920, 1080, 60, 32));

        let stride = ((mode.width * mode.bpp / 8) + 255) & !255;
        let fb_size_needed = (stride as u64) * (mode.height as u64);

        if fb_size_needed > self.fb_size {
            return Err(gpu_common::GpuError::MemAccessError);
        }

        self.width = mode.width;
        self.height = mode.height;
        self.pitch = stride;
        self.format = mode.format;

        // Initialize display
        self.init_display()?;

        Ok(GpuFramebufferInfo {
            address: self.fb_phys,
            virtual_address: self.fb_virt,
            size: self.fb_size,
            width: self.width,
            height: self.height,
            pitch: self.pitch,
            bpp: mode.bpp,
            format: self.format,
        })
    }

    fn set_mode(&mut self, mode: &DisplayMode) -> Result<(), gpu_common::GpuError> {
        self.init_framebuffer(Some(*mode))?;
        Ok(())
    }

    fn get_mode(&self) -> Option<DisplayMode> {
        if self.width == 0 {
            return None;
        }
        Some(DisplayMode::new(self.width, self.height, 60, 32))
    }

    fn enable_vblank(&mut self, _head: u32) -> Result<(), gpu_common::GpuError> {
        Ok(())
    }

    fn disable_vblank(&mut self, _head: u32) {}

    fn wait_vblank(&self, _head: u32, _timeout_ms: u32) -> Result<(), gpu_common::GpuError> {
        Ok(())
    }

    fn clear(&mut self, color: u32) {
        if self.fb_virt == 0 {
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

    fn enable_bus_mastering(&mut self) {
        #[cfg(target_arch = "x86_64")]
        {
            pci::enable_bus_mastering(&self.pci_dev);
        }
    }

    fn shutdown(&mut self) {}
}

impl RadeonDevice {
    /// Initialize display
    fn init_display(&mut self) -> Result<(), gpu_common::GpuError> {
        use radeon_reg::*;

        // Configure CRTC
        let h_total = self.width + 160;
        let h_sync_start = self.width + 48;
        let h_sync_end = self.width + 112;
        self.write_reg(AVIVO_D1CRTC_H_TOTAL, (h_total << 16) | self.width);
        self.write_reg(AVIVO_D1CRTC_H_SYNC_A, (h_sync_end << 16) | h_sync_start);

        let v_total = self.height + 30;
        let v_sync_start = self.height + 10;
        let v_sync_end = self.height + 12;
        self.write_reg(AVIVO_D1CRTC_V_TOTAL, (v_total << 16) | self.height);
        self.write_reg(AVIVO_D1CRTC_V_SYNC_A, (v_sync_end << 16) | v_sync_start);

        // Configure plane
        self.write_reg(AVIVO_D1GRPH_PRIMARY_SURFACE_ADDRESS, self.fb_phys as u32);
        self.write_reg(
            AVIVO_D1GRPH_PRIMARY_SURFACE_ADDRESS_HIGH,
            (self.fb_phys >> 32) as u32,
        );
        self.write_reg(AVIVO_D1GRPH_PITCH, self.pitch / 8);
        self.write_reg(AVIVO_D1GRPH_WIDTH, self.width);
        self.write_reg(AVIVO_D1GRPH_HEIGHT, self.height);
        self.write_reg(AVIVO_D1GRPH_FORMAT, 0xC << 16);
        self.write_reg(AVIVO_D1GRPH_SWAP, AVIVO_D1GRPH_SWAP_32BIT);

        // Enable plane and CRTC
        let grph_enable = self.read_reg(AVIVO_D1GRPH_ENABLE);
        self.write_reg(AVIVO_D1GRPH_ENABLE, grph_enable | AVIVO_D1GRPH_ENABLE);
        self.write_reg(AVIVO_D1CRTC_CONTROL, AVIVO_CRTC_ENABLE);

        Ok(())
    }
}

/// Probe for AMD GPU
#[cfg(target_arch = "x86_64")]
pub fn probe() -> bool {
    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == pci_ids::AMD_VENDOR_ID && dev.class_code == 0x03 {
            return true;
        }
    }
    false
}

/// Initialize AMD GPU
#[cfg(target_arch = "x86_64")]
pub fn init() -> Option<RadeonDevice> {
    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == pci_ids::AMD_VENDOR_ID && dev.class_code == 0x03 {
            let family = pci_ids::family_from_device_id(dev.device_id);
            let mut device = RadeonDevice::new(&dev, family);

            if device.init().is_ok() {
                return Some(device);
            }
        }
    }
    None
}

/// Probe for AMD GPU (stub)
#[cfg(not(target_arch = "x86_64"))]
pub fn probe() -> bool {
    false
}

/// Initialize AMD GPU (stub)
#[cfg(not(target_arch = "x86_64"))]
pub fn init() -> Option<RadeonDevice> {
    None
}
