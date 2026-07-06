//! Zhaoxin ZX-E / KX-6000 Framebuffer Driver
//
//! This module implements the framebuffer driver for the ZX-E display
//! controller used in KX-6000 and KX-6000G processors.
//
//! The ZX-E DC is an enhanced version with:
//! - DirectX 11.1 support
//! - Enhanced video processor
//! - Better power management
//! - 64-bit framebuffer addressing
//
//! Clean-room implementation based on public specifications.

use crate::drivers::video::core::gpu_common::{
    GpuDriver, GpuError, GpuFeatures, GpuFramebufferInfo, PixelFormat,
};
use crate::hal::common::pci::PciDevice;

use super::pci_ids::{self, ZhaoxinVariant};
use super::zxe_reg::*;

// =====================================================================
// ZX-E Device Structure
// =====================================================================

/// ZX-E Display Controller device
#[derive(Debug)]
pub struct ZxEDevice {
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
    /// DirectX feature level
    pub dx_feature_level: u32,
}

impl ZxEDevice {
    /// Create a new ZX-E device
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
            dx_feature_level: 0,
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
        self.read_reg(ZX_E_DC_VERSION)
    }

    /// Get DC feature flags
    pub fn get_feature(&self) -> u32 {
        self.read_reg(ZX_E_DC_FEATURE)
    }

    /// Check if DC is enabled
    pub fn is_enabled(&self) -> bool {
        let status = self.read_reg(ZX_E_DC_STATUS);
        (status & ZX_E_DC_STATUS_ENABLE) != 0
    }

    /// Check if DC is running
    pub fn is_running(&self) -> bool {
        let status = self.read_reg(ZX_E_DC_STATUS);
        (status & ZX_E_DC_STATUS_RUN) != 0
    }

    /// Get DirectX feature level
    pub fn get_dx_feature_level(&self) -> u32 {
        self.dx_feature_level
    }

    /// Get framebuffer format value
    fn get_format_value(&self) -> u32 {
        match self.format {
            PixelFormat::Bgra8888 => ZX_E_FB_FORMAT_BGRA8888,
            PixelFormat::Rgba8888 => ZX_E_FB_FORMAT_RGBA8888,
            PixelFormat::Bgr565 => ZX_E_FB_FORMAT_RGB565,
            _ => ZX_E_FB_FORMAT_BGRA8888,
        }
    }
}

// =====================================================================
// GpuDriver Implementation
// =====================================================================

impl GpuDriver for ZxEDevice {
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
            max_texture_size: 4096,
            max_render_targets: 4,
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

            // Read DirectX feature level
            self.dx_feature_level = self.read_reg(ZX_E_DX_FEATURE_LEVEL);

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
        let int_mask = self.read_reg(ZX_E_DC_INT_MASK);
        let mask = if head == 0 {
            ZX_E_DC_INT_VBLANK_A
        } else {
            ZX_E_DC_INT_VBLANK_B
        };
        self.write_reg(ZX_E_DC_INT_MASK, int_mask | mask);
        Ok(())
    }

    fn disable_vblank(&mut self, head: u32) {
        let int_mask = self.read_reg(ZX_E_DC_INT_MASK);
        let mask = if head == 0 {
            ZX_E_DC_INT_VBLANK_A
        } else {
            ZX_E_DC_INT_VBLANK_B
        };
        self.write_reg(ZX_E_DC_INT_MASK, int_mask & !mask);
    }

    fn wait_vblank(&self, _head: u32, _timeout_ms: u32) -> Result<(), GpuError> {
        // Poll vblank status
        for _ in 0..1000 {
            let status = self.read_reg(ZX_E_DC_STATUS);
            if (status & ZX_E_DC_STATUS_VBLANK) != 0 {
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
        self.write_reg(ZX_E_DC_CTRL, 0);
        // Disable both pipes
        self.write_reg(ZX_E_CRTC_A_CTRL, 0);
        self.write_reg(ZX_E_CRTC_B_CTRL, 0);
        // Disable planes
        self.write_reg(ZX_E_PLANE_PRIMARY_CTRL, 0);
        self.write_reg(ZX_E_PLANE_OVERLAY_CTRL, 0);
    }
}

// =====================================================================
// ZX-E Specific Methods
// =====================================================================

impl ZxEDevice {
    /// Reset the display controller
    pub fn reset(&mut self) -> Result<(), GpuError> {
        // Reset DC
        self.write_reg(ZX_E_DC_CTRL, ZX_E_DC_CTRL_RESET);
        for _ in 0..10 {
            self.write_reg(ZX_E_DC_CTRL, 0);
        }

        // Wait for reset to complete
        for _ in 0..100 {
            let status = self.read_reg(ZX_E_DC_STATUS);
            if (status & ZX_E_DC_STATUS_RUN) == 0 {
                return Ok(());
            }
        }

        Err(GpuError::Unknown(2))
    }

    /// Initialize the display controller
    pub fn init_display(&mut self) -> Result<(), GpuError> {
        // Enable DC
        self.write_reg(ZX_E_DC_CTRL, ZX_E_DC_CTRL_ENABLE);

        // Configure framebuffer (64-bit addressing)
        self.write_reg(ZX_E_FB_ADDR, self.fb_phys as u32);
        self.write_reg(ZX_E_FB_ADDR_HIGH, (self.fb_phys >> 32) as u32);
        self.write_reg(ZX_E_FB_STRIDE, self.pitch);
        self.write_reg(ZX_E_FB_FORMAT, self.get_format_value());

        // Calculate CRT timing
        let timing = calculate_crtc_timing_enhanced(self.width, self.height, 60);

        // Configure primary plane (64-bit addressing)
        self.write_reg(ZX_E_PLANE_PRIMARY_CTRL, ZX_E_PLANE_CTRL_ENABLE);
        self.write_reg(ZX_E_PLANE_PRIMARY_ADDR, self.fb_phys as u32);
        self.write_reg(ZX_E_PLANE_PRIMARY_ADDR_HIGH, (self.fb_phys >> 32) as u32);
        self.write_reg(ZX_E_PLANE_PRIMARY_STRIDE, self.pitch);
        self.write_reg(
            ZX_E_PLANE_PRIMARY_SIZE,
            (self.height << 16) | self.width,
        );
        self.write_reg(
            ZX_E_PLANE_PRIMARY_FORMAT,
            self.get_format_value(),
        );

        // Configure CRT controller A
        self.configure_crtc_a(&timing)?;

        Ok(())
    }

    /// Configure CRT controller A
    fn configure_crtc_a(&mut self, timing: &EnhancedCrtcTiming) -> Result<(), GpuError> {
        // Horizontal timing
        self.write_reg(ZX_E_CRTC_A_H_TOTAL, timing.h_total_reg());
        self.write_reg(ZX_E_CRTC_A_H_BLANK, timing.h_blank_reg());
        self.write_reg(ZX_E_CRTC_A_H_SYNC, timing.h_sync_reg());

        // Vertical timing
        self.write_reg(ZX_E_CRTC_A_V_TOTAL, timing.v_total_reg());
        self.write_reg(ZX_E_CRTC_A_V_BLANK, timing.v_blank_reg());
        self.write_reg(ZX_E_CRTC_A_V_SYNC, timing.v_sync_reg());

        // Display address
        self.write_reg(ZX_E_CRTC_A_ADDR, self.fb_phys as u32);
        self.write_reg(ZX_E_CRTC_A_ADDR_OFFSET, self.pitch / 8);

        // Enable CRT A with 32bpp
        let ctrl = ZX_E_CRTC_A_CTRL_ENABLE
            | ZX_E_CRTC_A_CTRL_32BPP
            | ZX_E_CRTC_A_CTRL_HSYNC_POS
            | ZX_E_CRTC_A_CTRL_VSYNC_POS;
        self.write_reg(ZX_E_CRTC_A_CTRL, ctrl);

        self.active_pipe = 0;
        Ok(())
    }

    /// Configure CRT controller B
    pub fn configure_crtc_b(&mut self, timing: &EnhancedCrtcTiming) -> Result<(), GpuError> {
        // Horizontal timing
        self.write_reg(ZX_E_CRTC_B_H_TOTAL, timing.h_total_reg());
        self.write_reg(ZX_E_CRTC_B_H_BLANK, timing.h_blank_reg());
        self.write_reg(ZX_E_CRTC_B_H_SYNC, timing.h_sync_reg());

        // Vertical timing
        self.write_reg(ZX_E_CRTC_B_V_TOTAL, timing.v_total_reg());
        self.write_reg(ZX_E_CRTC_B_V_BLANK, timing.v_blank_reg());
        self.write_reg(ZX_E_CRTC_B_V_SYNC, timing.v_sync_reg());

        // Display address
        self.write_reg(ZX_E_CRTC_B_ADDR, self.fb_phys as u32);
        self.write_reg(ZX_E_CRTC_B_ADDR_OFFSET, self.pitch / 8);

        // Enable CRT B with 32bpp
        let ctrl = ZX_E_CRTC_B_CTRL_ENABLE
            | ZX_E_CRTC_B_CTRL_32BPP
            | ZX_E_CRTC_B_CTRL_HSYNC_POS
            | ZX_E_CRTC_B_CTRL_VSYNC_POS;
        self.write_reg(ZX_E_CRTC_B_CTRL, ctrl);

        self.active_pipe = 1;
        Ok(())
    }

    /// Enable hardware cursor
    pub fn enable_cursor(&mut self, enable: bool) {
        let mut ctrl = self.read_reg(ZX_E_CURSOR_CTRL);
        if enable {
            ctrl |= ZX_E_CURSOR_CTRL_ENABLE;
            ctrl |= ZX_E_CURSOR_CTRL_64X64;
        } else {
            ctrl &= !ZX_E_CURSOR_CTRL_ENABLE;
        }
        self.write_reg(ZX_E_CURSOR_CTRL, ctrl);
    }

    /// Set cursor position
    pub fn set_cursor_position(&mut self, x: i32, y: i32) {
        // Encode position: bits [31:16] = X, bits [15:0] = Y
        let pos = ((x as u32) << 16) | ((y as u32) & 0xFFFF);
        self.write_reg(ZX_E_CURSOR_POS, pos);
    }

    /// Get interrupt status
    pub fn get_interrupt_status(&self) -> u32 {
        self.read_reg(ZX_E_DC_INT)
    }

    /// Clear interrupt
    pub fn clear_interrupt(&self, mask: u32) {
        self.write_reg(ZX_E_DC_INT, mask);
    }

    /// Get DirectX capabilities
    pub fn get_dx_capabilities(&self) -> u32 {
        self.read_reg(ZX_E_DX_CAPS)
    }

    /// Enable video processor
    pub fn enable_video_processor(&mut self, enable: bool) {
        let ctrl = if enable {
            ZX_E_VP_CTRL_ENABLE
        } else {
            0
        };
        self.write_reg(ZX_E_VP_CTRL, ctrl);
    }

    /// Set power state
    pub fn set_power_state(&mut self, state: u32) {
        self.write_reg(ZX_E_PM_DSTATE, state);
    }
}

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for ZX-E display controller
#[cfg(target_arch = "x86_64")]
pub fn probe() -> bool {
    use crate::hal::common::pci;
    use super::pci_ids::ZHAOXIN_VENDOR_ID;

    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == ZHAOXIN_VENDOR_ID && dev.class_code == 0x03 {
            // ZX-E has specific device IDs
            let variant = super::pci_ids::variant_from_device_id(dev.vendor_id, dev.device_id);
            if matches!(variant, ZhaoxinVariant::ZXE | ZhaoxinVariant::Unknown) {
                return true;
            }
        }
    }
    false
}

/// Initialize ZX-E display controller
#[cfg(target_arch = "x86_64")]
pub fn init() -> Option<ZxEDevice> {
    use crate::hal::common::pci;
    use super::pci_ids::{variant_from_device_id, ZHAOXIN_VENDOR_ID};

    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == ZHAOXIN_VENDOR_ID && dev.class_code == 0x03 {
            let variant = variant_from_device_id(dev.vendor_id, dev.device_id);
            let mut device = ZxEDevice::new(&dev, variant);

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
pub fn init() -> Option<ZxEDevice> {
    None
}
