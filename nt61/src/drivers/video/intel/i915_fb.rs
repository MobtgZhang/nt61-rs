//! Intel i915 Framebuffer Driver
//
//! Implements framebuffer initialization and pixel operations

use crate::drivers::video::intel::i915_reg::*;
use crate::drivers::video::intel::i915_reg::PIPEA_DSPABASE;
use crate::drivers::video::core::gpu_common::{DisplayMode, GpuFramebufferInfo, PixelFormat};

/// i915 framebuffer
#[derive(Debug)]
pub struct I915Framebuffer {
    /// MMIO base
    mmio_base: u64,
    /// Framebuffer physical address
    fb_phys: u64,
    /// Framebuffer virtual address
    fb_virt: u64,
    /// Framebuffer size
    fb_size: u64,
    /// Width
    width: u32,
    /// Height
    height: u32,
    /// Pitch
    pitch: u32,
    /// Format
    format: PixelFormat,
}

impl I915Framebuffer {
    /// Create new framebuffer
    pub fn new(mmio_base: u64, fb_phys: u64, fb_size: u64) -> Self {
        Self {
            mmio_base,
            fb_phys,
            fb_virt: 0,
            fb_size,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
        }
    }

    /// Read register
    #[inline]
    pub fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write register
    #[inline]
    pub fn write_reg(&self, offset: u32, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.mmio_base + offset as u64) as *mut u32,
                value,
            )
        }
    }

    /// Initialize framebuffer
    pub fn init(&mut self, mode: &DisplayMode) -> Result<GpuFramebufferInfo, &'static str> {
        let stride = calc_stride(mode.width, mode.bpp);
        let needed = (stride as u64) * (mode.height as u64);

        if needed > self.fb_size {
            return Err("Framebuffer too small");
        }

        self.width = mode.width;
        self.height = mode.height;
        self.pitch = stride;
        self.format = mode.format;

        // Configure pipe timing
        self.configure_pipe_a()?;

        // Configure plane
        self.configure_plane_a()?;

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

    /// Configure pipe A
    fn configure_pipe_a(&mut self) -> Result<(), &'static str> {
        // Disable pipe for configuration
        self.write_reg(PIPEA_CONF, 0);

        // Horizontal timing
        let h_total = self.width + 160;
        let h_sync_start = self.width + 48;
        let h_sync_end = self.width + 112;
        self.write_reg(PIPEA_H_TOTAL, (h_total << 16) | self.width);
        self.write_reg(PIPEA_H_SYNC, (h_sync_end << 16) | h_sync_start);

        // Vertical timing
        let v_total = self.height + 30;
        let v_sync_start = self.height + 10;
        let v_sync_end = self.height + 12;
        self.write_reg(PIPEA_V_TOTAL, (v_total << 16) | self.height);
        self.write_reg(PIPEA_V_SYNC, (v_sync_end << 16) | v_sync_start);

        // Enable pipe
        self.write_reg(PIPEA_CONF, PIPEA_CONF_ENABLE);

        Ok(())
    }

    /// Configure plane A
    fn configure_plane_a(&mut self) -> Result<(), &'static str> {
        // Framebuffer address
        self.write_reg(PIPEA_DSPABASE, self.fb_phys as u32);

        // Stride
        self.write_reg(PIPEA_DSPSURFACE_STRIDE, self.pitch);

        // Offset
        self.write_reg(PIPEA_DSPAOFFSET, 0);

        // Size
        self.write_reg(
            PIPEA_DSPASIZE,
            ((self.height - 1) << 16) | (self.width - 1),
        );

        // Enable plane
        let format_val = pixel_format_to_reg(self.format);
        self.write_reg(PIPEA_DSPCNTR, DISPLAY_ENABLE | format_val);

        Ok(())
    }

    /// Clear framebuffer
    pub fn clear(&self, color: u32) {
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

    /// Set pixel
    pub fn set_pixel(&self, x: u32, y: u32, color: u32) {
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

    /// Get pixel
    pub fn get_pixel(&self, x: u32, y: u32) -> u32 {
        if x >= self.width || y >= self.height || self.fb_virt == 0 {
            return 0;
        }

        let offset = ((y * self.pitch) + (x * 4)) as u64;
        unsafe {
            core::ptr::read_volatile((self.fb_virt + offset) as *const u32)
        }
    }

    /// Get info
    pub fn info(&self) -> GpuFramebufferInfo {
        GpuFramebufferInfo {
            address: self.fb_phys,
            virtual_address: self.fb_virt,
            size: self.fb_size,
            width: self.width,
            height: self.height,
            pitch: self.pitch,
            bpp: 32,
            format: self.format,
        }
    }
}
