//! NVIDIA Nouveau Framebuffer Driver
//
//! This module implements the framebuffer driver for NVIDIA GPUs
//! using the Nouveau open-source driver interface.
//
//! Hardware support:
//! - NV50 (Tesla): GeForce 8xxx/9xxx
//! - NVC0 (Fermi): GeForce GTX 400/500
//! - NVD0 (Kepler): GeForce GTX 600/700
//! - NV110 (Maxwell): GeForce GTX 900
//! - NV120 (Pascal): GeForce GTX 1000
//! - NV140 (Turing): GeForce RTX 2000
//
//! Clean-room implementation based on public specifications.

use crate::drivers::video::core::gpu_common::{
    GpuDriver, GpuError, GpuFeatures, GpuFramebufferInfo, PixelFormat,
};
use crate::hal::common::pci::PciDevice;

use super::pci_ids::{self, NouveauArchitecture};
use super::nouveau_reg::{self, CrtcTiming, NVC0_PFB_OFFSET, NVC0_PFB_ENABLED, NVD0_PFB_OFFSET, NVD0_PFB_ENABLED, NV110_PFB_OFFSET, NV110_PFB_ENABLED};

// =====================================================================
// Nouveau Device Structure
// =====================================================================

/// Nouveau GPU device
#[derive(Debug)]
pub struct NouveauDevice {
    /// PCI device information
    pci_dev: PciDevice,
    /// GPU architecture
    pub arch: NouveauArchitecture,
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
    /// VRAM size
    pub vram_size: u64,
    /// Device name
    pub device_name: alloc::string::String,
}

impl NouveauDevice {
    /// Create a new Nouveau device
    #[cfg(target_arch = "x86_64")]
    pub fn new(pci_dev: &PciDevice) -> Self {
        let arch = pci_ids::architecture_from_device_id(pci_dev.device_id);
        let device_name = pci_ids::device_name(pci_dev.device_id);
        Self {
            pci_dev: *pci_dev,
            arch,
            mmio_base: 0,
            fb_phys: 0,
            fb_size: 0,
            fb_virt: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
            revision: 0,
            vram_size: 0,
            device_name: alloc::string::String::from(device_name),
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn new() -> Self {
        Self {
            arch: NouveauArchitecture::Unknown,
            mmio_base: 0,
            fb_phys: 0,
            fb_size: 0,
            fb_virt: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
            revision: 0,
            vram_size: 0,
            device_name: alloc::string::String::from("Unknown"),
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

    /// Get PFB offset for architecture
    fn pfb_offset(&self) -> u32 {
        nouveau_reg::get_arch_offset(self.arch, nouveau_reg::RegisterBlock::PFB)
    }

    /// Get CRTC offset for architecture
    fn crtc_offset(&self) -> u32 {
        nouveau_reg::get_arch_offset(self.arch, nouveau_reg::RegisterBlock::PCRTC)
    }

    /// Get display offset for architecture
    fn display_offset(&self) -> u32 {
        nouveau_reg::get_arch_offset(self.arch, nouveau_reg::RegisterBlock::PDISPLAY)
    }

    /// Check if PFB is enabled
    pub fn is_pfb_enabled(&self) -> bool {
        let pfb_enable = nouveau_reg::get_pfb_enable(self.arch);
        let cfg = self.read_reg(self.pfb_offset() + 0x04);
        (cfg & pfb_enable) != 0
    }
}

// =====================================================================
// GpuDriver Implementation
// =====================================================================

impl GpuDriver for NouveauDevice {
    fn device_info(&self) -> crate::drivers::video::core::gpu_common::GpuDeviceInfo {
        crate::drivers::video::core::gpu_common::GpuDeviceInfo::from_pci(&self.pci_dev)
    }

    fn features(&self) -> GpuFeatures {
        let arch_features = pci_ids::features_for_architecture(self.arch);
        GpuFeatures {
            has_2d_accel: arch_features.has_2d_accel,
            has_3d_accel: arch_features.has_3d_accel,
            has_video_decode: arch_features.has_video_decode,
            has_compute: arch_features.has_compute,
            max_texture_size: arch_features.max_texture_size,
            max_render_targets: 8,
            has_cursor: arch_features.has_cursor,
            cursor_size: arch_features.cursor_size as u32,
            has_vram: true,
            vram_size: self.vram_size,
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn init(&mut self) -> Result<(), GpuError> {
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

        // Read VRAM size from PFB
        self.vram_size = pci::read_bar(&self.pci_dev, 1) & !0xF;

        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn init(&mut self) -> Result<(), GpuError> {
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
        // Enable vblank interrupt
        Ok(())
    }

    fn disable_vblank(&mut self, _head: u32) {}

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

    #[cfg(target_arch = "x86_64")]
    fn enable_bus_mastering(&mut self) {
        use crate::hal::common::pci;
        pci::enable_bus_mastering(&self.pci_dev);
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn enable_bus_mastering(&mut self) {}

    fn shutdown(&mut self) {
        // Disable display
        let crtc_off = self.crtc_offset();
        self.write_reg(crtc_off, 0);
    }
}

// =====================================================================
// Nouveau Specific Methods
// =====================================================================

impl NouveauDevice {
    /// Initialize the display controller
    pub fn init_display(&mut self) -> Result<(), GpuError> {
        let crtc_off = self.crtc_offset();
        let pfb_off = self.pfb_offset();

        // Enable PFB
        let pfb_enable = nouveau_reg::get_pfb_enable(self.arch);
        self.write_reg(pfb_off + 0x04, pfb_enable);

        // Configure PFB
        self.write_reg(pfb_off + 0x0C, self.pitch); // Pitch

        // Calculate timing
        let timing = nouveau_reg::calculate_crtc_timing(self.width, self.height, 60);

        // Configure CRTC
        self.write_reg(crtc_off + 0x08, timing.h_total_reg());
        self.write_reg(crtc_off + 0x0C, timing.h_blank_reg());
        self.write_reg(crtc_off + 0x10, timing.h_sync_reg());
        self.write_reg(crtc_off + 0x14, timing.v_total_reg());
        self.write_reg(crtc_off + 0x18, timing.v_blank_reg());
        self.write_reg(crtc_off + 0x1C, timing.v_sync_reg());

        // Configure framebuffer
        let display_off = self.display_offset();
        self.write_reg(display_off + 0x0000, self.fb_phys as u32);
        self.write_reg(display_off + 0x0008, self.pitch);
        self.write_reg(display_off + 0x000C, (self.height << 16) | self.width);

        // Enable CRTC
        let crtc_enable = nouveau_reg::get_crtc_enable(self.arch);
        self.write_reg(crtc_off, crtc_enable);

        Ok(())
    }

    /// Get interrupt status
    pub fn get_interrupt_status(&self) -> u32 {
        self.read_reg(0x000100)
    }

    /// Clear interrupt
    pub fn clear_interrupt(&self, mask: u32) {
        self.write_reg(0x000100, mask);
    }
}

// =====================================================================
// NV50 Specific Implementation
// =====================================================================

/// Initialize NV50 (Tesla) GPU
pub fn nv50_init(dev: &mut NouveauDevice) -> Result<(), GpuError> {
    dev.arch = NouveauArchitecture::NV50;

    // NV50 uses PV Baptized block for display
    let pv_offset = 0x000000;

    // Enable PV Baptized
    dev.write_reg(pv_offset + 0x0000, 1);

    // Configure framebuffer
    let pfb_off = dev.pfb_offset();
    dev.write_reg(pfb_off + 0x0C, dev.pitch);
    dev.write_reg(pfb_off + 0x10, (dev.height << 16) | dev.width);

    Ok(())
}

// =====================================================================
// NVC0/NVD0 Specific Implementation
// =====================================================================

/// Initialize NVC0 (Fermi) GPU
pub fn nvc0_init(dev: &mut NouveauDevice) -> Result<(), GpuError> {
    dev.arch = NouveauArchitecture::NVC0;

    // Enable PFB
    dev.write_reg(NVC0_PFB_OFFSET + 0x04, NVC0_PFB_ENABLED);

    // Configure framebuffer
    dev.write_reg(NVC0_PFB_OFFSET + 0x0C, dev.pitch);

    Ok(())
}

/// Initialize NVD0 (Kepler) GPU
pub fn nvd0_init(dev: &mut NouveauDevice) -> Result<(), GpuError> {
    dev.arch = NouveauArchitecture::NVD0;

    // Enable PFB
    dev.write_reg(NVD0_PFB_OFFSET + 0x04, NVD0_PFB_ENABLED);

    // Configure framebuffer
    dev.write_reg(NVD0_PFB_OFFSET + 0x0C, dev.pitch);

    Ok(())
}

// =====================================================================
// NV110+ Specific Implementation
// =====================================================================

/// Initialize NV110+ (Maxwell/Pascal/Turing) GPU
pub fn nv110_init(dev: &mut NouveauDevice) -> Result<(), GpuError> {
    // Enable PFB
    dev.write_reg(NV110_PFB_OFFSET + 0x04, NV110_PFB_ENABLED);

    // Configure framebuffer
    dev.write_reg(NV110_PFB_OFFSET + 0x0C, dev.pitch);

    Ok(())
}

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for NVIDIA GPU
#[cfg(target_arch = "x86_64")]
pub fn probe() -> bool {
    use crate::hal::common::pci;
    use super::pci_ids::NVIDIA_VENDOR_ID;

    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == NVIDIA_VENDOR_ID && dev.class_code == 0x03 {
            return true;
        }
    }
    false
}

/// Initialize NVIDIA GPU
#[cfg(target_arch = "x86_64")]
pub fn init() -> Option<NouveauDevice> {
    use crate::hal::common::pci;
    use super::pci_ids::NVIDIA_VENDOR_ID;

    let devices = pci::enumerate();
    for dev in devices {
        if dev.vendor_id == NVIDIA_VENDOR_ID && dev.class_code == 0x03 {
            let mut device = NouveauDevice::new(&dev);

            if device.init().is_ok() {
                // Initialize architecture-specific
                match device.arch {
                    NouveauArchitecture::NV50 => { let _ = nv50_init(&mut device); }
                    NouveauArchitecture::NVC0 => { let _ = nvc0_init(&mut device); }
                    NouveauArchitecture::NVD0 => { let _ = nvd0_init(&mut device); }
                    _ => { let _ = nv110_init(&mut device); }
                }

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
pub fn init() -> Option<NouveauDevice> {
    None
}
