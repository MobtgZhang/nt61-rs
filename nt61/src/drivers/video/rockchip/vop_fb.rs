//! Rockchip VOP Framebuffer Driver
//
//! This module implements the framebuffer driver for Rockchip VOP
//! display controller.
//
//! Clean-room implementation based on public specifications.

use crate::drivers::video::core::gpu_common::{
    GpuDriver, GpuError, GpuFeatures, GpuFramebufferInfo, PixelFormat,
};

use super::pci_ids::{self, RockchipSoc};
use super::vop_reg::*;

// =====================================================================
// VOP Device Structure
// =====================================================================

/// Rockchip VOP device
#[derive(Debug)]
pub struct VopDevice {
    /// SoC variant
    pub soc: RockchipSoc,
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
    /// Active window (0 or 1)
    pub active_window: u8,
}

impl VopDevice {
    /// Create a new VOP device
    pub fn new(soc: RockchipSoc) -> Self {
        Self {
            soc,
            mmio_base: 0,
            fb_phys: 0,
            fb_size: 0,
            fb_virt: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
            active_window: 0,
        }
    }

    /// Read a MMIO register
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        if self.mmio_base == 0 {
            return 0;
        }
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write a MMIO register
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
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

impl GpuDriver for VopDevice {
    fn device_info(&self) -> crate::drivers::video::core::gpu_common::GpuDeviceInfo {
        crate::drivers::video::core::gpu_common::GpuDeviceInfo {
            vendor_id: pci_ids::ROCKCHIP_VENDOR_ID,
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
            has_video_decode: false,
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
        // Get VOP base address based on SoC
        self.mmio_base = get_vop_base(self.soc);
        Ok(())
    }

    fn init_framebuffer(
        &mut self,
        mode: Option<crate::drivers::video::core::gpu_common::DisplayMode>,
    ) -> Result<GpuFramebufferInfo, GpuError> {
        let mode = mode.unwrap_or_else(|| {
            crate::drivers::video::core::gpu_common::DisplayMode::new(1920, 1080, 60, 32)
        });

        let bpp = mode.bpp.max(32);
        let stride = ((mode.width * bpp / 8) + 63) & !63u32;

        self.width = mode.width;
        self.height = mode.height;
        self.pitch = stride;
        self.format = PixelFormat::Bgra8888;

        // Initialize VOP
        self.init_vop()?;

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
        let int_mask = self.read_reg(VOP_INT_MASK);
        self.write_reg(VOP_INT_MASK, int_mask | VOP_INT_VBLANK);
        Ok(())
    }

    fn disable_vblank(&mut self, _head: u32) {
        let int_mask = self.read_reg(VOP_INT_MASK);
        self.write_reg(VOP_INT_MASK, int_mask & !VOP_INT_VBLANK);
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
        // Disable VOP
        self.write_reg(VOP_CTRL, 0);
        // Disable windows
        self.write_reg(VOP_WIN0_CTRL, 0);
        self.write_reg(VOP_WIN1_CTRL, 0);
    }
}

// =====================================================================
// VOP Specific Methods
// =====================================================================

impl VopDevice {
    /// Initialize VOP
    pub fn init_vop(&mut self) -> Result<(), GpuError> {
        // Enable VOP
        self.write_reg(VOP_CTRL, VOP_CTRL_ENABLE);

        // Configure window 0 (primary)
        self.configure_window_0()?;

        // Configure CRTC
        self.configure_crtc()?;

        // Enable vblank interrupt
        self.write_reg(VOP_INT_MASK, VOP_INT_VBLANK);

        Ok(())
    }

    /// Configure window 0 (primary)
    fn configure_window_0(&mut self) -> Result<(), GpuError> {
        // Enable window 0
        let format_val = match self.format {
            PixelFormat::Bgra8888 => VOP_FORMAT_BGRA8888,
            PixelFormat::Rgba8888 => VOP_FORMAT_RGBA8888,
            PixelFormat::Bgr565 => VOP_FORMAT_RGB565,
            _ => VOP_FORMAT_BGRA8888,
        };

        let ctrl = VOP_WIN_CTRL_ENABLE | (format_val << VOP_WIN_CTRL_FORMAT_SHIFT);

        self.write_reg(VOP_WIN0_CTRL, ctrl);
        self.write_reg(VOP_WIN0_ADDR, self.fb_phys as u32);
        self.write_reg(VOP_WIN0_STRIDE, self.pitch);
        self.write_reg(VOP_WIN0_SIZE, (self.height << 16) | self.width);
        self.write_reg(VOP_WIN0_FORMAT, format_val);

        // Configure framebuffer
        self.write_reg(VOP_FB0_ADDR, self.fb_phys as u32);
        self.write_reg(VOP_FB0_STRIDE, self.pitch);
        self.write_reg(VOP_FB0_FORMAT, format_val);

        self.active_window = 0;
        Ok(())
    }

    /// Configure CRTC
    fn configure_crtc(&mut self) -> Result<(), GpuError> {
        let timing = calculate_crtc_timing(self.width, self.height, 60);

        // Set CRTC timing
        self.write_reg(VOP_CRTC_H_TOTAL, timing.h_total_reg());
        self.write_reg(VOP_CRTC_H_ACT, self.width);
        self.write_reg(VOP_CRTC_H_SYNC, timing.h_sync_reg());
        self.write_reg(VOP_CRTC_V_TOTAL, timing.v_total_reg());
        self.write_reg(VOP_CRTC_V_ACT, self.height);
        self.write_reg(VOP_CRTC_V_SYNC, timing.v_sync_reg());

        // Enable CRTC
        let ctrl = VOP_CRTC_CTRL_ENABLE
            | VOP_CRTC_CTRL_HSYNC_POS
            | VOP_CRTC_CTRL_VSYNC_POS;
        self.write_reg(VOP_CRTC_CTRL, ctrl);

        Ok(())
    }

    /// Get interrupt status
    pub fn get_interrupt_status(&self) -> u32 {
        self.read_reg(VOP_INT_STATUS)
    }

    /// Clear interrupt
    pub fn clear_interrupt(&self, mask: u32) {
        self.write_reg(VOP_INT_CLEAR, mask);
    }
}

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for Rockchip VOP
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub fn probe() -> bool {
    // In real implementation, would check for Rockchip SoC via device tree or ACPI
    // For now, return true if we're on a known Rockchip platform
    true
}

/// Initialize Rockchip VOP
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub fn init() -> Option<VopDevice> {
    // In real implementation, would detect the specific SoC
    // For now, create a generic device
    let mut device = VopDevice::new(RockchipSoc::RK3399);
    if device.init().is_ok() {
        return Some(device);
    }
    None
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
