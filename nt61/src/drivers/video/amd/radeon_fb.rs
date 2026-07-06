//! AMD Radeon Framebuffer Driver
//
//! Implements framebuffer initialization and operations

use crate::drivers::video::amd::radeon_reg::*;
use crate::drivers::video::core::gpu_common::{DisplayMode, GpuFramebufferInfo, PixelFormat};

/// Radeon framebuffer
#[derive(Debug)]
pub struct RadeonFramebuffer {
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

impl RadeonFramebuffer {
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
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write register
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
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

        // Configure CRTC
        self.configure_crtc()?;

        // Configure plane
        self.configure_plane()?;

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

    /// Configure CRTC
    fn configure_crtc(&mut self) -> Result<(), &'static str> {
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

        // Enable CRTC
        let crtc = self.read_reg(AVIVO_D1CRTC_CONTROL);
        self.write_reg(AVIVO_D1CRTC_CONTROL, crtc | AVIVO_CRTC_ENABLE);

        Ok(())
    }

    /// Configure plane
    fn configure_plane(&mut self) -> Result<(), &'static str> {
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

        // Enable plane
        let enable = self.read_reg(AVIVO_D1GRPH_ENABLE);
        self.write_reg(AVIVO_D1GRPH_ENABLE, enable | 1);

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
