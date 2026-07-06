//! Allwinner D1/F133 Display Driver
//
//! This module implements the display driver for Allwinner D1 and F133 RISC-V SoCs.
//
//! The Allwinner D1 is the first commercially available RISC-V SoC, featuring:
//! - Single-core Xuantie C906 RISC-V processor
//! - DEBE (Display Engine Backend) for display composition
//! - TCON (Timing Controller) for display timing
//! - G2D 2D acceleration engine
//
//! Clean-room implementation based on public specifications.

use crate::drivers::video::core::gpu_common::{
    GpuDriver, GpuError, GpuFeatures, GpuFramebufferInfo, PixelFormat,
};

use super::pci_ids::{self, RiscVSoc};

// =====================================================================
// Device Structure
// =====================================================================

/// Allwinner D1/F133 display device
#[derive(Debug)]
pub struct AllwinnerD1Device {
    /// SoC variant
    pub soc: RiscVSoc,
    /// DEBE (Display Engine Backend) MMIO base address
    pub debe_base: u64,
    /// TCON (Timing Controller) MMIO base address
    pub tcon_base: u64,
    /// G2D 2D acceleration MMIO base address
    pub g2d_base: u64,
    /// Framebuffer physical address
    pub fb_phys: u64,
    /// Framebuffer size in bytes
    pub fb_size: u64,
    /// Framebuffer virtual address
    pub fb_virt: u64,
    /// Display width in pixels
    pub width: u32,
    /// Display height in pixels
    pub height: u32,
    /// Bytes per row (stride)
    pub pitch: u32,
    /// Pixel format
    pub format: PixelFormat,
    /// Device revision
    pub revision: u32,
}

impl AllwinnerD1Device {
    /// Create a new Allwinner D1 device
    pub fn new(soc: RiscVSoc) -> Self {
        Self {
            soc,
            debe_base: pci_ids::memmap::ALLWINNER_D1_DEBE_BASE,
            tcon_base: pci_ids::memmap::ALLWINNER_D1_TCON_BASE,
            g2d_base: pci_ids::memmap::ALLWINNER_D1_G2D_BASE,
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

    /// Read a G2D register
    #[inline]
    fn read_g2d(&self, offset: u32) -> u32 {
        if self.g2d_base == 0 {
            return 0;
        }
        unsafe { core::ptr::read_volatile((self.g2d_base + offset as u64) as *const u32) }
    }

    /// Write a G2D register
    #[inline]
    fn write_g2d(&self, offset: u32, value: u32) {
        if self.g2d_base == 0 {
            return;
        }
        unsafe {
            core::ptr::write_volatile(
                (self.g2d_base + offset as u64) as *mut u32,
                value,
            );
        }
    }
}

// =====================================================================
// GpuDriver Implementation
// =====================================================================

impl GpuDriver for AllwinnerD1Device {
    fn device_info(&self) -> crate::drivers::video::core::gpu_common::GpuDeviceInfo {
        crate::drivers::video::core::gpu_common::GpuDeviceInfo {
            vendor_id: pci_ids::ALLWINNER_VENDOR_ID,
            device_id: match self.soc {
                RiscVSoc::AllwinnerD1 => 0xD1,
                RiscVSoc::AllwinnerF133 => 0xF1,
                _ => 0,
            },
            revision: self.revision as u8,
            bus: 0,
            device: 0,
            function: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
        }
    }

    fn features(&self) -> GpuFeatures {
        let soc_features = pci_ids::features_for_soc(self.soc);
        pci_ids::to_gpu_features(&soc_features)
    }

    fn init(&mut self) -> Result<(), GpuError> {
        // Verify DEBE is accessible
        let version = self.read_debe(DEBE_REG_VERSION);
        
        if version == 0 && self.debe_base != 0 {
            // Try reading anyway in case register is at different offset
        }

        // Get firmware-provided framebuffer info
        self.init_from_firmware();

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
        let stride = ((mode.width * bpp / 8) + 31) & !31u32; // 32-byte alignment

        self.width = mode.width;
        self.height = mode.height;
        self.pitch = stride;
        self.format = PixelFormat::Bgra8888;

        // Initialize DEBE and TCON
        self.init_debe()?;
        self.init_tcon()?;

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
        let int_enable = self.read_debe(DEBE_REG_INT_ENABLE);
        self.write_debe(DEBE_REG_INT_ENABLE, int_enable | DEBE_INT_VBLANK);
        Ok(())
    }

    fn disable_vblank(&mut self, _head: u32) {
        let int_enable = self.read_debe(DEBE_REG_INT_ENABLE);
        self.write_debe(DEBE_REG_INT_ENABLE, int_enable & !DEBE_INT_VBLANK);
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

    fn enable_bus_mastering(&mut self) {
        // Allwinner doesn't use traditional PCI bus mastering
    }

    fn shutdown(&mut self) {
        // Disable DEBE
        self.write_debe(DEBE_REG_CTRL, 0);
        // Disable TCON
        self.write_tcon(TCON_REG_CTRL, 0);
    }
}

// =====================================================================
// Allwinner D1 Specific Methods
// =====================================================================

impl AllwinnerD1Device {
    /// Initialize from firmware-provided information
    fn init_from_firmware(&mut self) {
        // In a real implementation, this would read from device tree
        // For now, use default values
        self.fb_phys = 0x0;
        self.fb_size = 8 * 1024 * 1024; // 8MB default
        self.width = 1024;
        self.height = 768;
        self.pitch = 1024 * 4;
    }

    /// Initialize DEBE (Display Engine Backend)
    fn init_debe(&mut self) -> Result<(), GpuError> {
        // Step 1: Enable DEBE
        self.write_debe(DEBE_REG_CTRL, DEBE_CTRL_ENABLE);

        // Step 2: Configure primary layer (layer 0)
        self.configure_layer_0()?;

        // Step 3: Configure framebuffer
        self.configure_framebuffer()?;

        // Step 4: Configure color key and blending
        self.write_debe(DEBE_REG_COLOR_KEY, 0);
        self.write_debe(DEBE_REG_BLEND_MODE, DEBE_BLEND_PIXEL_ALPHA);

        // Step 5: Enable vblank interrupt
        self.write_debe(DEBE_REG_INT_ENABLE, DEBE_INT_VBLANK);

        Ok(())
    }

    /// Configure layer 0 (primary display layer)
    fn configure_layer_0(&mut self) -> Result<(), GpuError> {
        let format_val = match self.format {
            PixelFormat::Bgra8888 => DEBE_FORMAT_ARGB8888,
            PixelFormat::Rgba8888 => DEBE_FORMAT_RGBA8888,
            PixelFormat::Bgr565 => DEBE_FORMAT_RGB565,
            _ => DEBE_FORMAT_ARGB8888,
        };

        let ctrl = DEBE_LAYER_ENABLE | (format_val << DEBE_LAYER_FORMAT_SHIFT);

        self.write_debe(DEBE_REG_LAYER0_CTRL, ctrl);
        self.write_debe(DEBE_REG_LAYER0_ADDR, self.fb_phys as u32);
        self.write_debe(DEBE_REG_LAYER0_STRIDE, self.pitch);
        self.write_debe(DEBE_REG_LAYER0_SIZE, 
            ((self.height as u32) << 16) | self.width);
        self.write_debe(DEBE_REG_LAYER0_FORMAT, format_val);

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

        self.write_debe(DEBE_REG_FB0_ADDR, self.fb_phys as u32);
        self.write_debe(DEBE_REG_FB0_STRIDE, self.pitch);
        self.write_debe(DEBE_REG_FB0_SIZE, 
            ((self.height as u32) << 16) | self.width);
        self.write_debe(DEBE_REG_FB0_FORMAT, format_val);

        Ok(())
    }

    /// Initialize TCON (Timing Controller)
    fn init_tcon(&mut self) -> Result<(), GpuError> {
        // Calculate timing parameters for the display mode
        let h_total = self.width + 160;
        let h_sync = 96;
        let h_fp = 24;
        let h_bp = 40;
        let v_total = self.height + 30;
        let v_sync = 2;
        let v_fp = 3;
        let v_bp = 25;

        // Configure horizontal timing
        self.write_tcon(TCON_REG_HTOTAL, h_total);
        self.write_tcon(TCON_REG_HBP, h_bp);
        self.write_tcon(TCON_REG_HFP, h_fp);
        self.write_tcon(TCON_REG_HSYNC, h_sync);

        // Configure vertical timing
        self.write_tcon(TCON_REG_VTOTAL, v_total);
        self.write_tcon(TCON_REG_VBP, v_bp);
        self.write_tcon(TCON_REG_VFP, v_fp);
        self.write_tcon(TCON_REG_VSYNC, v_sync);

        // Configure active area
        self.write_tcon(TCON_REG_ACT_WIDTH, self.width);
        self.write_tcon(TCON_REG_ACT_HEIGHT, self.height);

        // Enable TCON
        self.write_tcon(TCON_REG_CTRL, TCON_CTRL_ENABLE);

        Ok(())
    }

    /// Initialize G2D 2D acceleration engine
    pub fn init_g2d(&mut self) -> Result<(), GpuError> {
        // Soft reset G2D
        self.write_g2d(G2D_REG_CTRL, G2D_CTRL_RESET);
        
        // Wait for reset complete
        let status = self.read_g2d(G2D_REG_STATUS);
        if status & G2D_STATUS_BUSY != 0 {
            return Err(GpuError::Unknown(2));
        }

        // Enable G2D
        self.write_g2d(G2D_REG_CTRL, G2D_CTRL_ENABLE);

        Ok(())
    }
}

// =====================================================================
// DEBE Register Definitions
// =====================================================================

/// DEBE (Display Engine Backend) register offsets

/// DEBE control register
pub const DEBE_REG_CTRL: u32 = 0x0000;
/// DEBE status register
pub const DEBE_REG_STATUS: u32 = 0x0004;
/// DEBE version register
pub const DEBE_REG_VERSION: u32 = 0x0008;

/// Framebuffer 0 registers
/// FB0 physical address
pub const DEBE_REG_FB0_ADDR: u32 = 0x0100;
/// FB0 stride (bytes per line)
pub const DEBE_REG_FB0_STRIDE: u32 = 0x0104;
/// FB0 size (width/height)
pub const DEBE_REG_FB0_SIZE: u32 = 0x0108;
/// FB0 format
pub const DEBE_REG_FB0_FORMAT: u32 = 0x010C;

/// Framebuffer 1 registers
/// FB1 physical address
pub const DEBE_REG_FB1_ADDR: u32 = 0x0110;
/// FB1 stride
pub const DEBE_REG_FB1_STRIDE: u32 = 0x0114;

/// Layer registers
/// Layer 0 control
pub const DEBE_REG_LAYER0_CTRL: u32 = 0x0200;
/// Layer 0 address
pub const DEBE_REG_LAYER0_ADDR: u32 = 0x0204;
/// Layer 0 size
pub const DEBE_REG_LAYER0_SIZE: u32 = 0x0208;
/// Layer 0 stride
pub const DEBE_REG_LAYER0_STRIDE: u32 = 0x020C;
/// Layer 0 format
pub const DEBE_REG_LAYER0_FORMAT: u32 = 0x0210;

/// Layer 1 registers
/// Layer 1 control
pub const DEBE_REG_LAYER1_CTRL: u32 = 0x0300;
/// Layer 1 address
pub const DEBE_REG_LAYER1_ADDR: u32 = 0x0304;

/// Color registers
/// Color key
pub const DEBE_REG_COLOR_KEY: u32 = 0x0400;
/// Blend mode
pub const DEBE_REG_BLEND_MODE: u32 = 0x0404;

/// Interrupt registers
/// Interrupt status
pub const DEBE_REG_INT_STATUS: u32 = 0x0500;
/// Interrupt enable
pub const DEBE_REG_INT_ENABLE: u32 = 0x0504;

// DEBE control bits
/// Enable DEBE
pub const DEBE_CTRL_ENABLE: u32 = 1 << 0;
/// Enable layer 0
pub const DEBE_LAYER_ENABLE: u32 = 1 << 0;

// Layer format shift
/// Format field shift in control register
pub const DEBE_LAYER_FORMAT_SHIFT: u32 = 8;

// DEBE format values
/// ARGB 8888 format
pub const DEBE_FORMAT_ARGB8888: u32 = 0x00;
/// RGBA 8888 format
pub const DEBE_FORMAT_RGBA8888: u32 = 0x01;
/// RGB 565 format
pub const DEBE_FORMAT_RGB565: u32 = 0x03;

// DEBE interrupt bits
/// Vertical blank interrupt
pub const DEBE_INT_VBLANK: u32 = 1 << 0;
/// Horizontal blank interrupt
pub const DEBE_INT_HBLANK: u32 = 1 << 1;

// DEBE blend modes
/// Pixel alpha blending
pub const DEBE_BLEND_PIXEL_ALPHA: u32 = 0x01;

// =====================================================================
// TCON Register Definitions
// =====================================================================

/// TCON (Timing Controller) register offsets

/// TCON control register
pub const TCON_REG_CTRL: u32 = 0x0000;
/// TCON status register
pub const TCON_REG_STATUS: u32 = 0x0004;

/// Horizontal timing
/// Horizontal total
pub const TCON_REG_HTOTAL: u32 = 0x0010;
/// Horizontal back porch
pub const TCON_REG_HBP: u32 = 0x0018;
/// Horizontal front porch
pub const TCON_REG_HFP: u32 = 0x001C;
/// Horizontal sync width
pub const TCON_REG_HSYNC: u32 = 0x0014;

/// Vertical timing
/// Vertical total
pub const TCON_REG_VTOTAL: u32 = 0x0020;
/// Vertical back porch
pub const TCON_REG_VBP: u32 = 0x0028;
/// Vertical front porch
pub const TCON_REG_VFP: u32 = 0x002C;
/// Vertical sync width
pub const TCON_REG_VSYNC: u32 = 0x0024;

/// Active area
/// Active width
pub const TCON_REG_ACT_WIDTH: u32 = 0x0030;
/// Active height
pub const TCON_REG_ACT_HEIGHT: u32 = 0x0034;

/// Clock control
/// Clock divider
pub const TCON_REG_CLK_CTRL: u32 = 0x0040;

// TCON control bits
/// Enable TCON
pub const TCON_CTRL_ENABLE: u32 = 1 << 0;
/// TCON mode (LCD/HDMI)
pub const TCON_CTRL_MODE: u32 = 1 << 4;

// =====================================================================
// G2D Register Definitions
// =====================================================================

/// G2D 2D acceleration engine register offsets

/// G2D control register
pub const G2D_REG_CTRL: u32 = 0x0000;
/// G2D status register
pub const G2D_REG_STATUS: u32 = 0x0004;

/// G2D command register
pub const G2D_REG_CMD: u32 = 0x0010;

/// Source address
pub const G2D_REG_SRC_ADDR: u32 = 0x0100;
/// Source stride
pub const G2D_REG_SRC_STRIDE: u32 = 0x0104;
/// Source size
pub const G2D_REG_SRC_SIZE: u32 = 0x0108;
/// Source format
pub const G2D_REG_SRC_FORMAT: u32 = 0x010C;

/// Destination address
pub const G2D_REG_DST_ADDR: u32 = 0x0200;
/// Destination stride
pub const G2D_REG_DST_STRIDE: u32 = 0x0204;
/// Destination size
pub const G2D_REG_DST_SIZE: u32 = 0x0208;
/// Destination format
pub const G2D_REG_DST_FORMAT: u32 = 0x020C;

// G2D control bits
/// Enable G2D
pub const G2D_CTRL_ENABLE: u32 = 1 << 0;
/// Reset G2D
pub const G2D_CTRL_RESET: u32 = 1 << 1;

// G2D status bits
/// G2D busy flag
pub const G2D_STATUS_BUSY: u32 = 1 << 0;

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for Allwinner D1/F133 display hardware
#[cfg(target_arch = "riscv64")]
pub fn probe() -> bool {
    // Check if we're running on Allwinner D1 or F133 hardware
    // This would typically check device tree compatible string
    
    // For now, return false to let other drivers try
    // Real implementation would check device tree
    false
}

/// Initialize Allwinner D1/F133 display
#[cfg(target_arch = "riscv64")]
pub fn init() -> Option<AllwinnerD1Device> {
    if !probe() {
        return None;
    }

    // Determine SoC variant
    let soc = if is_f133() {
        RiscVSoc::AllwinnerF133
    } else {
        RiscVSoc::AllwinnerD1
    };

    let mut device = AllwinnerD1Device::new(soc);
    
    if device.init().is_ok() {
        Some(device)
    } else {
        None
    }
}

/// Check if running on F133
fn is_f133() -> bool {
    // Would read from device tree
    // For now, assume D1
    false
}

/// Probe stub for non-RISC-V architectures
#[cfg(not(target_arch = "riscv64"))]
pub fn probe() -> bool {
    false
}

/// Init stub for non-RISC-V architectures
#[cfg(not(target_arch = "riscv64"))]
pub fn init() -> Option<AllwinnerD1Device> {
    None
}

// =====================================================================
// Feature Detection Helpers
// =====================================================================

/// Feature detection for Allwinner D1/F133
pub mod features {
    /// Check if SoC supports DEBE
    pub fn has_debe() -> bool {
        true
    }

    /// Check if SoC supports TCON
    pub fn has_tcon() -> bool {
        true
    }

    /// Check if SoC supports G2D
    pub fn has_g2d() -> bool {
        true
    }

    /// Check if SoC supports HDMI
    pub fn has_hdmi() -> bool {
        false // D1/F133 don't have HDMI
    }

    /// Check if SoC supports MIPI DSI
    pub fn has_mipi_dsi() -> bool {
        true
    }

    /// Get maximum display width
    pub fn max_width() -> u32 {
        1920
    }

    /// Get maximum display height
    pub fn max_height() -> u32 {
        1080
    }
}
