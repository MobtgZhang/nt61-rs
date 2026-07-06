//! Loongson Display Controller (LSDC) Driver
//
//! This module implements the GPU driver for Loongson's integrated
//! display controller found in:
//
//! - Loongson LS7A chipset
//! - Loongson 3A5000 (LoongArch64)
//! - Loongson 2K2000
//! - Loongson 2K3000
//
//! The LSDC supports dual display output (Pipeline A and B),
//! hardware cursor, and multiple pixel formats.

pub mod pci_ids;
pub mod lsdc_reg;
pub mod lsdc_fb;
pub mod lsdc_irq;
pub mod lsdc_crtc;
pub mod lsdc_connector;
pub mod lsdc_plane;

#[cfg(target_arch = "loongarch64")]
use crate::hal::common::pci;
use crate::drivers::video::core::gpu_common::{
    self, GpuDeviceInfo, GpuDriver, GpuFeatures, GpuFramebufferInfo,
    DisplayMode, LoongsonChip, PixelFormat,
};
use crate::drivers::video::core::mmio_guard::{MmioGuard, MAX_MMIO_SIZE};
use crate::drivers::video::log;

/// Loongson DC device
#[derive(Debug)]
pub struct LsDcDevice {
    /// PCI device information
    pub pci_dev: crate::hal::common::pci::PciDevice,
    /// Chip type
    pub chip: LoongsonChip,
    /// DC MMIO guard with bounds checking and spinlock
    dc_mmio: MmioGuard,
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
    /// IRQ number
    pub irq: u8,
    /// CRTC A enabled
    pub crtc_a_enabled: bool,
    /// CRTC B enabled
    pub crtc_b_enabled: bool,
    /// Cursor enabled
    pub cursor_enabled: bool,
}

impl LsDcDevice {
    /// Create a new LSDC device
    #[allow(dead_code)]
    pub fn new(pci_dev: crate::hal::common::pci::PciDevice, chip: LoongsonChip) -> Self {
        Self {
            pci_dev,
            chip,
            dc_mmio: MmioGuard::new(0, MAX_MMIO_SIZE),
            fb_phys: 0,
            fb_size: 0,
            fb_virt: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
            irq: 0,
            crtc_a_enabled: false,
            crtc_b_enabled: false,
            cursor_enabled: false,
        }
    }

    /// Read a DC register with bounds checking
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        self.dc_mmio.read_reg(offset)
    }

    /// Write a DC register with bounds checking
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        let _ = self.dc_mmio.write_reg(offset, value);
    }

    /// Get DC version
    pub fn get_version(&self) -> (u16, u8) {
        let ver = self.read_reg(lsdc_reg::DC_VERSION);
        let chip_ver = (ver & 0xFFFF) as u16;
        let rev = ((ver >> 16) & 0xFF) as u8;
        (chip_ver, rev)
    }

    /// Reset the DC controller
    pub fn reset(&mut self) {
        use lsdc_reg::*;
        self.write_reg(DC_CTRL, DC_CTRL_RESET);
        // Wait for reset to complete
        for _ in 0..1000 {
            if self.read_reg(DC_CTRL) & DC_CTRL_RESET == 0 {
                break;
            }
        }
    }

    /// Enable the DC controller
    pub fn enable(&mut self) {
        use lsdc_reg::*;
        let ctrl = self.read_reg(DC_CTRL);
        self.write_reg(DC_CTRL, ctrl | DC_CTRL_ENABLE);
    }

    /// Disable the DC controller
    pub fn disable(&mut self) {
        use lsdc_reg::*;
        let ctrl = self.read_reg(DC_CTRL);
        self.write_reg(DC_CTRL, ctrl & !DC_CTRL_ENABLE);
    }
}

impl GpuDriver for LsDcDevice {
    fn device_info(&self) -> GpuDeviceInfo {
        GpuDeviceInfo::from_pci(&self.pci_dev)
    }

    fn features(&self) -> GpuFeatures {
        GpuFeatures {
            has_2d_accel: true,
            has_3d_accel: false,
            has_video_decode: false,
            has_compute: false,
            max_texture_size: 4096,
            max_render_targets: 1,
            has_cursor: true,
            cursor_size: 64,
            has_vram: false,
            vram_size: self.fb_size,
        }
    }

    fn init(&mut self) -> Result<(), gpu_common::GpuError> {
        use crate::drivers::video::core::gpu_common::GpuError;

        // Read PCI BARs
        #[cfg(target_arch = "loongarch64")]
        {
            let dc_bar = pci::read_bar(&self.pci_dev, 0);
            let fb_bar = pci::read_bar(&self.pci_dev, 1);

            if dc_bar == 0 {
                log::video_error("loongson", "DC BAR0 is zero");
                return Err(GpuError::Unknown(1));
            }

            // Loongson display MMIO is typically 64 KB.
            self.dc_mmio = MmioGuard::new(dc_bar, 64 * 1024);
            self.fb_phys = fb_bar;

            log::video_ok("loongson", "PCI BARs read");
            log::video_log_hex64("loongson", "DC base", dc_bar);
            log::video_log_hex64("loongson", "FB base", fb_bar);
        }

        #[cfg(not(target_arch = "loongarch64"))]
        {
            return Err(GpuError::Unknown(1));
        }

        // Reset and initialize
        self.reset();
        self.enable();

        Ok(())
    }

    fn init_framebuffer(
        &mut self,
        mode: Option<DisplayMode>,
    ) -> Result<GpuFramebufferInfo, gpu_common::GpuError> {
        use crate::drivers::video::core::gpu_common::GpuError;

        // Use provided mode or default
        let mode = mode.unwrap_or_else(|| DisplayMode::new(1920, 1080, 60, 32));

        // Calculate pitch (128-byte aligned)
        let pitch = ((mode.width * mode.bpp / 8) + 127) & !127;
        let fb_size_needed = (pitch as u64) * (mode.height as u64);

        if fb_size_needed > self.fb_size {
            return Err(GpuError::MemAccessError);
        }

        self.width = mode.width;
        self.height = mode.height;
        self.pitch = pitch;
        self.format = mode.format;

        // Initialize framebuffer
        self.init_crtc_a(mode.width, mode.height)?;

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
        Some(DisplayMode::new(
            self.width,
            self.height,
            60, // Assume 60Hz
            32,
        ))
    }

    fn enable_vblank(&mut self, head: u32) -> Result<(), gpu_common::GpuError> {
        use lsdc_reg::*;
        
        let mask = match head {
            0 => INT_VBLANK_A,
            1 => INT_VBLANK_B,
            _ => return Err(gpu_common::GpuError::Unknown(head as u32)),
        };

        let current = self.read_reg(DC_INT_MASK);
        self.write_reg(DC_INT_MASK, current | mask);
        Ok(())
    }

    fn disable_vblank(&mut self, head: u32) {
        use lsdc_reg::*;
        
        let mask = match head {
            0 => INT_VBLANK_A,
            1 => INT_VBLANK_B,
            _ => return,
        };

        let current = self.read_reg(DC_INT_MASK);
        self.write_reg(DC_INT_MASK, current & !mask);
    }

    fn wait_vblank(&self, head: u32, timeout_ms: u32) -> Result<(), gpu_common::GpuError> {
        use lsdc_reg::*;
        
        // Poll for vblank
        let int_mask = match head {
            0 => INT_VBLANK_A,
            1 => INT_VBLANK_B,
            _ => return Err(gpu_common::GpuError::Unknown(head as u32)),
        };

        let max_iterations = timeout_ms * 1000;
        let mut iterations = 0;

        while iterations < max_iterations {
            let status = self.read_reg(DC_INT);
            if status & int_mask != 0 {
                // Clear the interrupt
                self.write_reg(DC_INT, int_mask);
                return Ok(());
            }
            iterations += 1;
        }

        Err(gpu_common::GpuError::Timeout)
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
        if x >= self.width || y >= self.height {
            return;
        }

        if self.fb_virt == 0 {
            return;
        }

        let offset = (y * self.pitch / 4) + x;
        unsafe {
            core::ptr::write_volatile(
                (self.fb_virt + (offset as u64 * 4)) as *mut u32,
                color,
            );
        }
    }

    fn framebuffer_info(&self) -> Option<GpuFramebufferInfo> {
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
        #[cfg(target_arch = "loongarch64")]
        {
            pci::enable_bus_mastering(&self.pci_dev);
        }
    }

    fn shutdown(&mut self) {
        self.disable();
    }
}

impl LsDcDevice {
    /// Initialize CRTC A (Pipeline A)
    fn init_crtc_a(&mut self, width: u32, height: u32) -> Result<(), gpu_common::GpuError> {
        use lsdc_reg::*;

        // Disable CRTC for configuration
        self.write_reg(CRTC_A_CTRL, 0);

        // Configure horizontal timing
        let h_total = width + 160;
        let h_sync_start = width + 48;
        let h_sync_end = width + 112;
        let h_timing = (h_total << 16) | (h_sync_end << 8) | h_sync_start;
        self.write_reg(CRTC_A_TIMING_H, h_timing);

        // Configure vertical timing
        let v_total = height + 30;
        let v_sync_start = height + 10;
        let v_sync_end = height + 12;
        let v_timing = (v_total << 16) | (v_sync_end << 8) | v_sync_start;
        self.write_reg(CRTC_A_TIMING_V, v_timing);

        // Configure sync signals (active mode)
        self.write_reg(CRTC_A_SYNC, 0);
        self.write_reg(CRTC_A_POLARITY, 0);

        // Configure primary plane
        self.write_reg(PLANE_PRIMARY_ADDR, self.fb_phys as u32);
        self.write_reg(PLANE_PRIMARY_STRIDE, self.pitch);
        self.write_reg(
            PLANE_PRIMARY_SIZE,
            (height << 16) | width,
        );
        self.write_reg(
            PLANE_PRIMARY_CTRL,
            PLANE_ENABLE | PLANE_FORMAT_BGRA,
        );

        // Set CRTC A framebuffer address
        self.write_reg(CRTC_A_ADDR, self.fb_phys as u32);

        // Enable CRTC A
        self.write_reg(CRTC_A_CTRL, CRTC_ENABLE | CRTC_DOUBLE_SCAN);

        self.crtc_a_enabled = true;
        Ok(())
    }
}

/// Probe for Loongson DC
pub fn probe() -> bool {
    #[cfg(target_arch = "loongarch64")]
    {
        let devices = pci::enumerate();
        for dev in devices {
            if dev.vendor_id == pci_ids::LOONGSON_VENDOR_ID {
                return true;
            }
        }
    }
    false
}

/// Initialize Loongson DC
pub fn init() -> Option<LsDcDevice> {
    #[cfg(target_arch = "loongarch64")]
    {
        let devices = pci::enumerate();
        for dev in devices {
            if dev.vendor_id == pci_ids::LOONGSON_VENDOR_ID {
                let chip = pci_ids::chip_from_device_id(dev.device_id);
                let mut device = LsDcDevice::new(dev, chip);

                if device.init().is_ok() {
                    return Some(device);
                }
            }
        }
    }
    None
}
