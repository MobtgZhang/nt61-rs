//! Loongson Display Controller Framebuffer Driver
//
//! Implements framebuffer initialization, mode setting, and pixel
//! operations for the Loongson DC.

use crate::drivers::video::loongson::lsdc_reg::*;
use crate::drivers::video::core::gpu_common::{DisplayMode, GpuFramebufferInfo, PixelFormat};

/// Loongson DC framebuffer
#[derive(Debug)]
pub struct LsDcFramebuffer {
    /// DC MMIO base address
    dc_base: u64,
    /// Framebuffer physical address
    fb_phys: u64,
    /// Framebuffer virtual address
    fb_virt: u64,
    /// Framebuffer size
    fb_size: u64,
    /// Current width
    width: u32,
    /// Current height
    height: u32,
    /// Pitch (bytes per row)
    pitch: u32,
    /// Pixel format
    format: PixelFormat,
}

impl LsDcFramebuffer {
    /// Create a new framebuffer
    pub fn new(dc_base: u64, fb_phys: u64, fb_size: u64) -> Self {
        Self {
            dc_base,
            fb_phys,
            fb_virt: 0,
            fb_size,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
        }
    }

    /// Read a DC register
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.dc_base + offset as u64) as *const u32) }
    }

    /// Write a DC register
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.dc_base + offset as u64) as *mut u32,
                value,
            )
        }
    }

    /// Get DC version
    pub fn get_version(&self) -> (u16, u8) {
        let ver = self.read_reg(DC_VERSION);
        let chip_ver = (ver & 0xFFFF) as u16;
        let rev = ((ver >> 16) & 0xFF) as u8;
        (chip_ver, rev)
    }

    /// Reset the DC controller
    pub fn reset(&mut self) {
        self.write_reg(DC_CTRL, DC_CTRL_RESET);
        // Wait for reset
        for _ in 0..1000 {
            if self.read_reg(DC_CTRL) & DC_CTRL_RESET == 0 {
                break;
            }
        }
    }

    /// Initialize the framebuffer with a display mode
    pub fn init(&mut self, mode: &DisplayMode) -> Result<GpuFramebufferInfo, &'static str> {
        // Calculate stride (128-byte aligned)
        let stride = ((mode.width * mode.bpp / 8) + 127) & !127;
        let needed_size = (stride as u64) * (mode.height as u64);

        if needed_size > self.fb_size {
            return Err("Framebuffer too small for mode");
        }

        self.width = mode.width;
        self.height = mode.height;
        self.pitch = stride;
        self.format = mode.format;

        // Configure framebuffer format
        let format_reg = match mode.format {
            PixelFormat::Bgra8888 | PixelFormat::Bgrx8888 => FB_FORMAT_BGRA8888,
            PixelFormat::Rgba8888 | PixelFormat::Xrgb8888 => FB_FORMAT_RGBA8888,
            PixelFormat::Bgr565 => FB_FORMAT_RGB565,
            _ => FB_FORMAT_BGRA8888,
        };
        self.write_reg(FB_FORMAT, format_reg);

        // Configure CRTC A timing
        self.configure_crtc_a()?;

        // Configure primary plane
        self.configure_primary_plane()?;

        // Enable CRTC A
        self.write_reg(CRTC_A_CTRL, CRTC_ENABLE | CRTC_DOUBLE_SCAN);

        // Enable DC
        let ctrl = self.read_reg(DC_CTRL);
        self.write_reg(DC_CTRL, ctrl | DC_CTRL_ENABLE);

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

    /// Configure CRTC A timing
    fn configure_crtc_a(&mut self) -> Result<(), &'static str> {
        // Disable CRTC for configuration
        self.write_reg(CRTC_A_CTRL, 0);

        // Calculate timing parameters
        // These are typical values; actual values depend on the display
        let h_total = self.width + 160;
        let h_sync_start = self.width + 48;
        let h_sync_end = self.width + 112;
        let h_timing = (h_total << 16) | (h_sync_end << 8) | h_sync_start;
        self.write_reg(CRTC_A_TIMING_H, h_timing);

        let v_total = self.height + 30;
        let v_sync_start = self.height + 10;
        let v_sync_end = self.height + 12;
        let v_timing = (v_total << 16) | (v_sync_end << 8) | v_sync_start;
        self.write_reg(CRTC_A_TIMING_V, v_timing);

        // Configure sync signals (active mode)
        self.write_reg(CRTC_A_SYNC, 0);
        self.write_reg(CRTC_A_POLARITY, 0);

        // Set CRTC A framebuffer address
        self.write_reg(CRTC_A_ADDR, self.fb_phys as u32);

        Ok(())
    }

    /// Configure primary plane
    fn configure_primary_plane(&mut self) -> Result<(), &'static str> {
        self.write_reg(PLANE_PRIMARY_ADDR, self.fb_phys as u32);
        self.write_reg(PLANE_PRIMARY_STRIDE, self.pitch);
        self.write_reg(
            PLANE_PRIMARY_SIZE,
            (self.height << 16) | self.width,
        );
        self.write_reg(
            PLANE_PRIMARY_CTRL,
            PLANE_ENABLE | PLANE_FORMAT_BGRA,
        );
        Ok(())
    }

    /// Enable CRTC B (for dual display)
    pub fn enable_crtc_b(&mut self, width: u32, height: u32) -> Result<(), &'static str> {
        // Disable CRTC B for configuration
        self.write_reg(CRTC_B_CTRL, 0);

        // Calculate timing parameters
        let h_total = width + 160;
        let h_sync_start = width + 48;
        let h_sync_end = width + 112;
        let h_timing = (h_total << 16) | (h_sync_end << 8) | h_sync_start;
        self.write_reg(CRTC_B_TIMING_H, h_timing);

        let v_total = height + 30;
        let v_sync_start = height + 10;
        let v_sync_end = height + 12;
        let v_timing = (v_total << 16) | (v_sync_end << 8) | v_sync_start;
        self.write_reg(CRTC_B_TIMING_V, v_timing);

        // Configure sync signals
        self.write_reg(CRTC_B_SYNC, 0);
        self.write_reg(CRTC_B_POLARITY, 0);

        // Enable CRTC B
        self.write_reg(CRTC_B_CTRL, CRTC_ENABLE | CRTC_DOUBLE_SCAN);

        Ok(())
    }

    /// Disable CRTC B
    pub fn disable_crtc_b(&self) {
        self.write_reg(CRTC_B_CTRL, 0);
    }

    /// Clear the framebuffer with a color
    pub fn clear(&self, color: u32) {
        if self.fb_virt == 0 {
            return;
        }

        let num_pixels = ((self.pitch as usize) * (self.height as usize)) / 4;
        for i in 0..num_pixels {
            unsafe {
                core::ptr::write_volatile(
                    (self.fb_virt + (i as u64 * 4)) as *mut u32,
                    color,
                );
            }
        }
    }

    /// Set a single pixel
    pub fn set_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }

        if self.fb_virt == 0 {
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

    /// Get pixel color
    pub fn get_pixel(&self, x: u32, y: u32) -> u32 {
        if x >= self.width || y >= self.height {
            return 0;
        }

        if self.fb_virt == 0 {
            return 0;
        }

        let offset = ((y * self.pitch) + (x * 4)) as u64;
        unsafe {
            core::ptr::read_volatile((self.fb_virt + offset) as *const u32)
        }
    }

    /// Fill a rectangle
    pub fn fill_rect(&mut self, x: u32, y: u32, width: u32, height: u32, color: u32) {
        let end_x = (x + width).min(self.width);
        let end_y = (y + height).min(self.height);

        for py in y..end_y {
            for px in x..end_x {
                self.set_pixel(px, py, color);
            }
        }
    }

    /// Copy a region within the framebuffer
    pub fn copy_region(&mut self, src_x: u32, src_y: u32, dst_x: u32, dst_y: u32, width: u32, height: u32) {
        // Ensure source and destination don't overlap
        let src_offset = (src_y * self.pitch + src_x * 4) as usize;
        let dst_offset = (dst_y * self.pitch + dst_x * 4) as usize;
        let copy_size = (width * 4) as usize;

        if self.fb_virt == 0 {
            return;
        }

        let fb_ptr = self.fb_virt as *mut u8;

        // Simple copy for non-overlapping regions
        for row in 0..height {
            let src_row_offset = src_offset + (row as usize * self.pitch as usize);
            let dst_row_offset = dst_offset + (row as usize * self.pitch as usize);

            unsafe {
                core::ptr::copy_nonoverlapping(
                    fb_ptr.add(src_row_offset),
                    fb_ptr.add(dst_row_offset),
                    copy_size,
                );
            }
        }
    }

    /// Get framebuffer information
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
