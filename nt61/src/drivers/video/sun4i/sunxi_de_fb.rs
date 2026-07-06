//! Allwinner DEBE Framebuffer Driver
//
//! This module implements the framebuffer driver for Allwinner DEBE
//! display engine backend.
//
//! Clean-room implementation based on public specifications.

use crate::drivers::video::core::gpu_common::{
    GpuDriver, GpuError, GpuFeatures, GpuFramebufferInfo, PixelFormat,
};

use super::pci_ids::{self, SunxiSoc};
use super::sunxi_de_reg::*;

// =====================================================================
// DEBE Device Structure
// =====================================================================

/// Allwinner DEBE device
#[derive(Debug)]
pub struct DebeDevice {
    /// SoC variant
    pub soc: SunxiSoc,
    /// DEBE MMIO base address
    pub debe_base: u64,
    /// TCON MMIO base address
    pub tcon_base: u64,
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
}

impl DebeDevice {
    /// Create a new DEBE device
    pub fn new(soc: SunxiSoc) -> Self {
        Self {
            soc,
            debe_base: 0,
            tcon_base: 0,
            fb_phys: 0,
            fb_size: 0,
            fb_virt: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
        }
    }

    /// Read a DEBE register
    #[inline]
    fn read_debe(&self, offset: u32) -> u32 {
        if self.debe_base == 0 {
            return 0;
        }
        unsafe { core::ptr::read_volatile((self.debe_base + offset as u64) as *const u32) }
    }

    /// Write a DEBE register
    #[inline]
    fn write_debe(&self, offset: u32, value: u32) {
        if self.debe_base == 0 {
            return;
        }
        unsafe {
            core::ptr::write_volatile(
                (self.debe_base + offset as u64) as *mut u32,
                value,
            );
        }
    }

    /// Read a TCON register
    #[inline]
    fn read_tcon(&self, offset: u32) -> u32 {
        if self.tcon_base == 0 {
            return 0;
        }
        unsafe { core::ptr::read_volatile((self.tcon_base + offset as u64) as *const u32) }
    }

    /// Write a TCON register
    #[inline]
    fn write_tcon(&self, offset: u32, value: u32) {
        if self.tcon_base == 0 {
            return;
        }
        unsafe {
            core::ptr::write_volatile(
                (self.tcon_base + offset as u64) as *mut u32,
                value,
            );
        }
    }
}

// =====================================================================
// GpuDriver Implementation
// =====================================================================

impl GpuDriver for DebeDevice {
    fn device_info(&self) -> crate::drivers::video::core::gpu_common::GpuDeviceInfo {
        crate::drivers::video::core::gpu_common::GpuDeviceInfo {
            vendor_id: pci_ids::ALLWINNER_VENDOR_ID,
            device_id: 0,
            revision: 0,
            bus: 0,
            device: 0,
            function: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
        }
    }

    fn features(&self) -> GpuFeatures {
        let soc_features = pci_ids::features_for_soc(self.soc);
        GpuFeatures {
            has_2d_accel: false,
            has_3d_accel: false,
            has_video_decode: soc_features.has_cedarx,
            has_compute: false,
            max_texture_size: 4096,
            max_render_targets: 2,
            has_cursor: true,
            cursor_size: 64,
            has_vram: false,
            vram_size: 0,
        }
    }

    fn init(&mut self) -> Result<(), GpuError> {
        // Get register bases based on SoC
        self.debe_base = get_debe_base(self.soc);
        self.tcon_base = get_tcon_base(self.soc);
        Ok(())
    }

    fn init_framebuffer(
        &mut self,
        mode: Option<crate::drivers::video::core::gpu_common::DisplayMode>,
    ) -> Result<GpuFramebufferInfo, GpuError> {
        let mode = mode.unwrap_or_else(|| {
            crate::drivers::video::core::gpu_common::DisplayMode::new(1024, 768, 60, 32)
        });

        let bpp = mode.bpp.max(32);
        let stride = ((mode.width * bpp / 8) + 31) & !31u32;

        self.width = mode.width;
        self.height = mode.height;
        self.pitch = stride;
        self.format = PixelFormat::Bgra8888;

        // Initialize DEBE
        self.init_debe()?;

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

    fn set_mode(&mut self, mode: &crate::drivers::video::core::gpu_common::DisplayMode) -> Result<(), GpuError> {
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

    fn enable_vblank(&mut self, _head: u32) -> Result<(), GpuError> {
        let int_en = self.read_debe(DEBE_INT_ENABLE);
        self.write_debe(DEBE_INT_ENABLE, int_en | DEBE_INT_VBLANK);
        Ok(())
    }

    fn disable_vblank(&mut self, _head: u32) {
        let int_en = self.read_debe(DEBE_INT_ENABLE);
        self.write_debe(DEBE_INT_ENABLE, int_en & !DEBE_INT_VBLANK);
    }

    fn wait_vblank(&self, _head: u32, _timeout_ms: u32) -> Result<(), GpuError> {
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

    fn enable_bus_mastering(&mut self) {}

    fn shutdown(&mut self) {
        // Disable DEBE
        self.write_debe(DEBE_CTRL, 0);
        // Disable TCON
        self.write_tcon(TCON_CTRL, 0);
    }
}

// =====================================================================
// DEBE Specific Methods
// =====================================================================

impl DebeDevice {
    /// Initialize DEBE
    pub fn init_debe(&mut self) -> Result<(), GpuError> {
        // Enable DEBE
        self.write_debe(DEBE_CTRL, DEBE_CTRL_ENABLE);

        // Configure primary layer (layer 0)
        self.configure_layer_0()?;

        // Configure framebuffer
        self.configure_framebuffer()?;

        Ok(())
    }

    /// Configure layer 0 (primary)
    fn configure_layer_0(&mut self) -> Result<(), GpuError> {
        let format_val = match self.format {
            PixelFormat::Bgra8888 => DEBE_FORMAT_ARGB8888,
            PixelFormat::Rgba8888 => DEBE_FORMAT_RGBA8888,
            PixelFormat::Bgr565 => DEBE_FORMAT_RGB565,
            _ => DEBE_FORMAT_ARGB8888,
        };

        let ctrl = DEBE_LAYER_ENABLE | (format_val << DEBE_LAYER_FORMAT_SHIFT);

        self.write_debe(DEBE_LAYER0_CTRL, ctrl);
        self.write_debe(DEBE_LAYER0_ADDR, self.fb_phys as u32);
        self.write_debe(DEBE_LAYER0_STRIDE, self.pitch);
        self.write_debe(DEBE_LAYER0_SIZE, (self.height << 16) | self.width);
        self.write_debe(DEBE_LAYER0_FORMAT, format_val);

        Ok(())
    }

    /// Configure framebuffer
    fn configure_framebuffer(&mut self) -> Result<(), GpuError> {
        let format_val = match self.format {
            PixelFormat::Bgra8888 => DEBE_FORMAT_ARGB8888,
            PixelFormat::Rgba8888 => DEBE_FORMAT_RGBA8888,
            PixelFormat::Bgr565 => DEBE_FORMAT_RGB565,
            _ => DEBE_FORMAT_ARGB8888,
        };

        self.write_debe(DEBE_FB0_ADDR, self.fb_phys as u32);
        self.write_debe(DEBE_FB0_STRIDE, self.pitch);
        self.write_debe(DEBE_FB0_SIZE, (self.height << 16) | self.width);
        self.write_debe(DEBE_FB0_FORMAT, format_val);

        Ok(())
    }

    /// Initialize TCON
    pub fn init_tcon(&mut self, width: u32, height: u32) -> Result<(), GpuError> {
        // Calculate timing parameters
        let h_total = width + 160;
        let h_sync = 96;
        let h_fp = 24;
        let h_bp = 40;
        let v_total = height + 30;
        let v_sync = 2;
        let v_fp = 3;
        let v_bp = 25;

        // Configure horizontal timing
        self.write_tcon(TCON_HTOTAL, h_total);
        self.write_tcon(TCON_HBP, h_bp);
        self.write_tcon(TCON_HFP, h_fp);
        self.write_tcon(TCON_HSYNC, h_sync);

        // Configure vertical timing
        self.write_tcon(TCON_VTOTAL, v_total);
        self.write_tcon(TCON_VBP, v_bp);
        self.write_tcon(TCON_VFP, v_fp);
        self.write_tcon(TCON_VSYNC, v_sync);

        // Configure active area
        self.write_tcon(TCON_ACT_WIDTH, width);
        self.write_tcon(TCON_ACT_HEIGHT, height);

        // Enable TCON
        self.write_tcon(TCON_CTRL, TCON_CTRL_ENABLE);

        Ok(())
    }
}

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for Allwinner DEBE
#[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "riscv64"))]
pub fn probe() -> bool {
    // In real implementation, would check for Allwinner SoC via device tree or ACPI
    true
}

/// Initialize Allwinner DEBE
#[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "riscv64"))]
pub fn init() -> Option<DebeDevice> {
    // In real implementation, would detect the specific SoC
    let mut device = DebeDevice::new(SunxiSoc::H3);
    if device.init().is_ok() {
        return Some(device);
    }
    None
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
