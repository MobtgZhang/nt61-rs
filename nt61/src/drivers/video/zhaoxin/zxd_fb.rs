//! Zhaoxin ZX-D Framebuffer Driver
//
//! This module implements the framebuffer driver for the ZX-D display
//! controller found in KX-5000/KX-6000 processors.
//
//! The ZX-D DC provides basic display output with support for:
//! - Two CRT controllers (pipes)
//! - Primary and overlay planes
//! - Hardware cursor
//! - Color keying and alpha blending
//
//! Clean-room implementation based on public specifications.

use crate::drivers::video::core::gpu_common::{
    GpuDriver, GpuError, GpuFeatures, GpuFramebufferInfo, PixelFormat,
};
use crate::hal::common::pci::PciDevice;

use super::pci_ids::{self, DisplayFormat, ZhaoxinVariant};
use super::zxd_reg::*;

// =====================================================================
// ZX-D Device Structure
// =====================================================================

/// ZX-D Display Controller device
#[derive(Debug)]
pub struct ZxDDevice {
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

impl ZxDDevice {
    /// Create a new ZX-D device
    pub fn new(pci_dev: &PciDevice, variant: ZhaoxinVariant) -> Self {
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

    /// Read a MMIO register with 64-bit address
    #[inline]
    pub fn read_reg64(&self, offset: u32) -> u64 {
        if self.mmio_base == 0 {
            return 0;
        }
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u64) }
    }

    /// Write a MMIO register with 64-bit address
    #[inline]
    pub fn write_reg64(&self, offset: u32, value: u64) {
        if self.mmio_base == 0 {
            return;
        }
        unsafe {
            core::ptr::write_volatile(
                (self.mmio_base + offset as u64) as *mut u64,
                value,
            );
        }
    }

    /// Get DC version
    pub fn get_version(&self) -> u32 {
        self.read_reg(ZX_DC_VERSION)
    }

    /// Check if DC is enabled
    pub fn is_enabled(&self) -> bool {
        let status = self.read_reg(ZX_DC_STATUS);
        (status & ZX_DC_STATUS_ENABLE) != 0
    }

    /// Check if DC is running
    pub fn is_running(&self) -> bool {
        let status = self.read_reg(ZX_DC_STATUS);
        (status & ZX_DC_STATUS_RUN) != 0
    }

    /// Get framebuffer format value
    fn get_format_value(&self) -> u32 {
        match self.format {
            PixelFormat::Bgra8888 => ZX_FB_FORMAT_BGRA8888,
            PixelFormat::Rgba8888 => ZX_FB_FORMAT_RGBA8888,
            PixelFormat::Bgr565 => ZX_FB_FORMAT_RGB565,
            _ => ZX_FB_FORMAT_BGRA8888,
        }
    }
}

// =====================================================================
// GpuDriver Implementation
// =====================================================================

impl GpuDriver for ZxDDevice {
    fn device_info(&self) -> crate::drivers::video::core::gpu_common::GpuDeviceInfo {
        crate::drivers::video::core::gpu_common::GpuDeviceInfo::from_pci(&self.pci_dev)
    }

    fn features(&self) -> GpuFeatures {
        let variant_features = pci_ids::features_for_variant(self.variant);
        GpuFeatures {
            has_2d_accel: variant_features.has_2d_accel,
            has_3d_accel: variant_features.has_3d_accel,
            has_video_decode: variant_features.has_video_decode,
            has_compute: false,
            max_texture_size: 2048,
            max_render_targets: variant_features.num_overlay_planes as u32,
            has_cursor: variant_features.has_cursor,
            cursor_size: variant_features.cursor_size as u32,
            has_vram: true,
            vram_size: self.fb_size,
        }
    }

    fn init(&mut self) -> Result<(), GpuError> {
        #[cfg(target_arch = "x86_64")]
        {
            use crate::hal::common::pci;

            // Read PCI BARs
            self.mmio_base = pci::read_bar(&self.pci_dev, 0);
            self.fb_phys = pci::read_bar(&self.pci_dev, 1);

            // Mask off the low bits
            self.mmio_base &= !0xF;
            self.fb_phys &= !0xF;

            if self.mmio_base == 0 {
                return Err(GpuError::Unknown(1));
            }

            // Enable bus mastering
            pci::enable_bus_mastering(&self.pci_dev);

            // Read revision
            self.revision = self.pci_dev.revision;

            // Reset DC
            self.reset()?;
        }

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
        let stride = ((mode.width * bpp / 8) + 255) & !255u32;
        let fb_size_needed = (stride as u64) * (mode.height as u64);

        if fb_size_needed > self.fb_size && self.fb_size > 0 {
            return Err(GpuError::MemAccessError);
        }

        self.width = mode.width;
        self.height = mode.height;
        self.pitch = stride;
        self.format = PixelFormat::Bgra8888;

        // Initialize display controller
        self.init_display()?;

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
        self.init_framebuffer(Some(*mode))
            .map(|_| ())
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

    fn enable_vblank(&mut self, head: u32) -> Result<(), GpuError> {
        let int_mask = self.read_reg(ZX_DC_INT_MASK);
        let mask = if head == 0 {
            ZX_DC_INT_VBLANK_A
        } else {
            ZX_DC_INT_VBLANK_B
        };
        self.write_reg(ZX_DC_INT_MASK, int_mask | mask);
        Ok(())
    }

    fn disable_vblank(&mut self, head: u32) {
        let int_mask = self.read_reg(ZX_DC_INT_MASK);
        let mask = if head == 0 {
            ZX_DC_INT_VBLANK_A
        } else {
            ZX_DC_INT_VBLANK_B
        };
        self.write_reg(ZX_DC_INT_MASK, int_mask & !mask);
    }

    fn wait_vblank(&self, _head: u32, _timeout_ms: u32) -> Result<(), GpuError> {
        // Poll vblank status
        for _ in 0..1000 {
            let status = self.read_reg(ZX_DC_STATUS);
            if (status & ZX_DC_STATUS_VBLANK) != 0 {
                return Ok(());
            }
        }
        Err(GpuError::Timeout)
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

    fn enable_bus_mastering(&mut self) {
        #[cfg(target_arch = "x86_64")]
        {
            use crate::hal::common::pci;
            pci::enable_bus_mastering(&self.pci_dev);
        }
    }

    fn shutdown(&mut self) {
        // Disable DC
        self.write_reg(ZX_DC_CTRL, 0);
        // Disable both pipes
        self.write_reg(ZX_CRTC_A_CTRL, 0);
        self.write_reg(ZX_CRTC_B_CTRL, 0);
        // Disable planes
        self.write_reg(ZX_PLANE_PRIMARY_CTRL, 0);
        self.write_reg(ZX_PLANE_OVERLAY_CTRL, 0);
    }
}

// =====================================================================
// ZX-D Specific Methods
// =====================================================================

impl ZxDDevice {
    /// Reset the display controller
    pub fn reset(&mut self) -> Result<(), GpuError> {
        // Reset DC
        self.write_reg(ZX_DC_CTRL, ZX_DC_CTRL_RESET);
        for _ in 0..10 {
            self.write_reg(ZX_DC_CTRL, 0);
        }

        // Wait for reset to complete
        for _ in 0..100 {
            let status = self.read_reg(ZX_DC_STATUS);
            if (status & ZX_DC_STATUS_RUN) == 0 {
                return Ok(());
            }
        }

        Err(GpuError::Unknown(2))
    }

    /// Initialize the display controller
    pub fn init_display(&mut self) -> Result<(), GpuError> {
        // Enable DC
        self.write_reg(ZX_DC_CTRL, ZX_DC_CTRL_ENABLE);

        // Configure framebuffer
        self.write_reg(ZX_FB_ADDR, self.fb_phys as u32);
        self.write_reg(ZX_FB_STRIDE, self.pitch);
        self.write_reg(ZX_FB_FORMAT, self.get_format_value());

        // Calculate CRT timing
        let timing = calculate_crtc_timing(self.width, self.height, 60);

        // Configure primary plane
        self.write_reg(ZX_PLANE_PRIMARY_CTRL, ZX_PLANE_CTRL_ENABLE);
        self.write_reg(ZX_PLANE_PRIMARY_ADDR, self.fb_phys as u32);
        self.write_reg(ZX_PLANE_PRIMARY_STRIDE, self.pitch);
        self.write_reg(
            ZX_PLANE_PRIMARY_SIZE,
            (self.height << 16) | self.width,
        );
        self.write_reg(
            ZX_PLANE_PRIMARY_FORMAT,
            self.get_format_value(),
        );

        // Configure CRT controller A
        self.configure_crtc_a(&timing)?;

        Ok(())
    }

    /// Configure CRT controller A
    fn configure_crtc_a(&mut self, timing: &CrtcTiming) -> Result<(), GpuError> {
        // Horizontal timing
        self.write_reg(ZX_CRTC_A_H_TOTAL, timing.h_total_reg());
        self.write_reg(ZX_CRTC_A_H_SYNC, timing.h_sync_reg());

        // Vertical timing
        self.write_reg(ZX_CRTC_A_V_TOTAL, timing.v_total_reg());
        self.write_reg(ZX_CRTC_A_V_SYNC, timing.v_sync_reg());

        // Display address
        self.write_reg(ZX_CRTC_A_ADDR, self.fb_phys as u32);
        self.write_reg(ZX_CRTC_A_ADDR_OFFSET, self.pitch / 8);

        // Enable CRT A with 32bpp
        let ctrl = ZX_CRTC_A_CTRL_ENABLE
            | ZX_CRTC_A_CTRL_32BPP
            | ZX_CRTC_A_CTRL_HSYNC_POS
            | ZX_CRTC_A_CTRL_VSYNC_POS;
        self.write_reg(ZX_CRTC_A_CTRL, ctrl);

        self.active_pipe = 0;
        Ok(())
    }

    /// Configure CRT controller B
    pub fn configure_crtc_b(&mut self, timing: &CrtcTiming) -> Result<(), GpuError> {
        // Horizontal timing
        self.write_reg(ZX_CRTC_B_H_TOTAL, timing.h_total_reg());
        self.write_reg(ZX_CRTC_B_H_SYNC, timing.h_sync_reg());

        // Vertical timing
        self.write_reg(ZX_CRTC_B_V_TOTAL, timing.v_total_reg());
        self.write_reg(ZX_CRTC_B_V_SYNC, timing.v_sync_reg());

        // Display address
        self.write_reg(ZX_CRTC_B_ADDR, self.fb_phys as u32);
        self.write_reg(ZX_CRTC_B_ADDR_OFFSET, self.pitch / 8);

        // Enable CRT B with 32bpp
        let ctrl = ZX_CRTC_B_CTRL_ENABLE
            | ZX_CRTC_B_CTRL_32BPP
            | ZX_CRTC_B_CTRL_HSYNC_POS
            | ZX_CRTC_B_CTRL_VSYNC_POS;
        self.write_reg(ZX_CRTC_B_CTRL, ctrl);

        self.active_pipe = 1;
        Ok(())
    }

    /// Enable hardware cursor
    pub fn enable_cursor(&mut self, enable: bool) {
        let mut ctrl = self.read_reg(ZX_CURSOR_CTRL);
        if enable {
            ctrl |= ZX_CURSOR_CTRL_ENABLE;
            ctrl |= ZX_CURSOR_CTRL_64X64;
        } else {
            ctrl &= !ZX_CURSOR_CTRL_ENABLE;
        }
        self.write_reg(ZX_CURSOR_CTRL, ctrl);
    }

    /// Set cursor position
    pub fn set_cursor_position(&mut self, x: i32, y: i32) {
        // Encode position: bits [31:16] = X, bits [15:0] = Y
        let pos = ((x as u32) << 16) | ((y as u32) & 0xFFFF);
        self.write_reg(ZX_CURSOR_POS, pos);
    }

    /// Get interrupt status
    pub fn get_interrupt_status(&self) -> u32 {
        self.read_reg(ZX_DC_INT)
    }

    /// Clear interrupt
    pub fn clear_interrupt(&self, mask: u32) {
        self.write_reg(ZX_DC_INT, mask);
    }
}

// =====================================================================
// Firmware Framebuffer Support
// =====================================================================

/// Get framebuffer info from firmware (UEFI/BIOS)
pub fn get_firmware_fb_info() -> Result<FirmwareFbInfo, GpuError> {
    // Try to get framebuffer from multiboot or UEFI GOP
    // For now, return a default 1024x768 framebuffer
    // In a real implementation, this would query the firmware
    Ok(FirmwareFbInfo {
        fb_phys: 0xE000_0000,
        width: 1024,
        height: 768,
        pitch: 4096,
        bpp: 32,
    })
}

/// Firmware-provided framebuffer information
#[derive(Debug)]
pub struct FirmwareFbInfo {
    /// Physical address of framebuffer
    pub fb_phys: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bytes per line
    pub pitch: u32,
    /// Bits per pixel
    pub bpp: u32,
}

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for ZX-D display controller
#[cfg(target_arch = "x86_64")]
pub fn probe() -> bool {
    use crate::hal::common::pci;
    use super::pci_ids::ZHAOXIN_VENDOR_ID;

    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == ZHAOXIN_VENDOR_ID && dev.class_code == 0x03 {
            return true;
        }
    }
    false
}

/// Initialize ZX-D display controller
#[cfg(target_arch = "x86_64")]
pub fn init() -> Option<ZxDDevice> {
    use crate::hal::common::pci;
    use super::pci_ids::{variant_from_device_id, ZHAOXIN_VENDOR_ID};

    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == ZHAOXIN_VENDOR_ID && dev.class_code == 0x03 {
            let variant = variant_from_device_id(dev.vendor_id, dev.device_id);
            let mut device = ZxDDevice::new(&dev, variant);

            if device.init().is_ok() {
                // Try to initialize framebuffer
                if device.init_framebuffer(None).is_ok() {
                    return Some(device);
                }
            }
        }
    }
    None
}

/// Probe function stub for non-x86_64
#[cfg(not(target_arch = "x86_64"))]
pub fn probe() -> bool {
    false
}

/// Init function stub for non-x86_64
#[cfg(not(target_arch = "x86_64"))]
pub fn init() -> Option<ZxDDevice> {
    None
}
