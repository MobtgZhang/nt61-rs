//! QEMU virtio-gpu Driver
//
//! This module implements the virtio-gpu driver for QEMU virtualized environments.
//
//! virtio-gpu is the standard virtual GPU device exposed by QEMU for RISC-V,
//! and provides a straightforward way to develop and test GPU drivers in
//! virtualized environments without requiring actual hardware.
//
//! Clean-room implementation based on virtio specification and QEMU documentation.

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;

use crate::drivers::video::core::gpu_common::{
    GpuDriver, GpuError, GpuFeatures, GpuFramebufferInfo, PixelFormat,
};
use crate::drivers::video::log;

use super::pci_ids::{self, RiscVSoc};

// =====================================================================
// Device Structure
// =====================================================================

/// virtio-gpu device
#[derive(Debug)]
pub struct VirtioGpuDevice {
    /// MMIO base address
    pub mmio_base: u64,
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
    /// virtio device ID
    pub device_id: u32,
}

impl VirtioGpuDevice {
    /// Create a new virtio-gpu device
    pub fn new(device_id: u32) -> Self {
        Self {
            mmio_base: pci_ids::virtio::VIRTIO_GPU_BASE,
            fb_phys: 0,
            fb_size: 0,
            fb_virt: 0,
            width: 0,
            height: 0,
            pitch: 0,
            format: PixelFormat::Bgra8888,
            revision: 0,
            device_id,
        }
    }

    /// Read a virtio-gpu register
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        if self.mmio_base == 0 {
            return 0;
        }
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write a virtio-gpu register
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

impl GpuDriver for VirtioGpuDevice {
    fn device_info(&self) -> crate::drivers::video::core::gpu_common::GpuDeviceInfo {
        crate::drivers::video::core::gpu_common::GpuDeviceInfo {
            vendor_id: pci_ids::VIRTIO_VENDOR_ID,
            device_id: self.device_id as u16,
            revision: self.revision as u8,
            bus: 0,
            device: 0,
            function: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
        }
    }

    fn features(&self) -> GpuFeatures {
        let soc_features = pci_ids::features_for_soc(RiscVSoc::VirtioGpu);
        pci_ids::to_gpu_features(&soc_features)
    }

    fn init(&mut self) -> Result<(), GpuError> {
        // Step 1: Reset the device
        self.reset();

        // Step 2: Read device configuration
        self.read_config();

        // Step 3: Get framebuffer information from firmware
        self.init_from_firmware();

        // Step 4: Acknowledge and set driver OK
        self.set_driver_status();

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
        let stride = ((mode.width * bpp / 8) + 63) & !63u32; // 64-byte alignment

        self.width = mode.width;
        self.height = mode.height;
        self.pitch = stride;
        self.format = PixelFormat::Bgra8888;

        // Initialize virtio-gpu framebuffer
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
        // virtio-gpu uses interrupt-driven updates
        Ok(())
    }

    fn disable_vblank(&mut self, _head: u32) {
        // virtio-gpu uses interrupt-driven updates
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
        // virtio devices handle bus mastering internally
    }

    fn shutdown(&mut self) {
        // Disable display
        self.write_reg(VIRTIO_GPU_REG_DISPLAY_READ, 0);
        self.write_reg(VIRTIO_GPU_REG_DISPLAY_WRITE, 0);
    }
}

// =====================================================================
// virtio-gpu Specific Methods
// =====================================================================

impl VirtioGpuDevice {
    /// Reset the virtio-gpu device
    fn reset(&mut self) {
        // Write to reset register
        self.write_reg(VIRTIO_GPU_REG_STATUS, VIRTIO_GPU_STATUS_RESET);
        
        // Wait for reset to complete
        let mut retries = 100;
        while retries > 0 {
            let status = self.read_reg(VIRTIO_GPU_REG_STATUS);
            if status == 0 {
                break;
            }
            retries -= 1;
        }
    }

    /// Read device configuration
    fn read_config(&mut self) {
        // Read display configuration
        let width = self.read_reg(VIRTIO_GPU_REG_H);
        let height = self.read_reg(VIRTIO_GPU_REG_W);
        
        // Only update if valid
        if width > 0 && width < 8192 {
            self.width = width;
        }
        if height > 0 && height < 8192 {
            self.height = height;
        }

        // Default to 1024x768 if not set
        if self.width == 0 {
            self.width = 1024;
        }
        if self.height == 0 {
            self.height = 768;
        }
    }

    /// Initialize from firmware-provided information
    fn init_from_firmware(&mut self) {
        // Get framebuffer info from virtio-gpu configuration
        // In QEMU, the framebuffer is typically set up by the firmware
        
        // Default values
        self.fb_phys = 0x0;
        self.fb_size = (self.width * self.height * 4) as u64;
        self.pitch = self.width * 4;
    }

    /// Set virtio driver status
    fn set_driver_status(&mut self) {
        let mut status = 0u32;
        status |= VIRTIO_GPU_STATUS_ACK;       // Acknowledge
        status |= VIRTIO_GPU_STATUS_DRIVER;    // Driver loaded
        status |= VIRTIO_GPU_STATUS_DRIVER_OK;  // Driver ready
        self.write_reg(VIRTIO_GPU_REG_STATUS, status);
    }

    /// Initialize display
    fn init_display(&mut self) -> Result<(), GpuError> {
        // Configure display resolution
        self.write_reg(VIRTIO_GPU_REG_H, self.height);
        self.write_reg(VIRTIO_GPU_REG_W, self.width);
        
        // Set framebuffer address
        self.write_reg(VIRTIO_GPU_REG_FB_ADDR, self.fb_phys as u32);
        
        // Enable scanout
        self.write_reg(VIRTIO_GPU_REG_SCANOUT_ID, 0);
        
        // Request display update
        self.write_reg(VIRTIO_GPU_REG_DISPLAY_READ, 0);
        self.write_reg(VIRTIO_GPU_REG_DISPLAY_WRITE, 0);

        Ok(())
    }

    /// Send a virtio-gpu command
    fn send_command(&mut self, cmd: u32, flags: u32) {
        self.write_reg(VIRTIO_GPU_REG_CTRL, cmd | flags);
    }

    /// Wait for command completion
    fn wait_command_complete(&self, timeout_ms: u32) -> Result<(), GpuError> {
        let mut retries = timeout_ms * 100;
        while retries > 0 {
            let status = self.read_reg(VIRTIO_GPU_REG_STATUS);
            if status & VIRTIO_GPU_STATUS_OK != 0 {
                return Ok(());
            }
            retries -= 1;
        }
        Err(GpuError::Timeout)
    }

    /// Get display information
    pub fn get_display_info(&mut self) -> Option<VirtGpuDisplayInfo> {
        self.send_command(VIRTIO_GPU_CMD_GET_DISPLAY_INFO, 0);
        
        if self.wait_command_complete(1000).is_ok() {
            let rect = self.read_reg(VIRTIO_GPU_REG_DISPLAY_READ);
            Some(VirtGpuDisplayInfo {
                rect: VirtGpuRect {
                    x: rect & 0xFFFF,
                    y: (rect >> 16) & 0xFFFF,
                    width: self.read_reg(VIRTIO_GPU_REG_W),
                    height: self.read_reg(VIRTIO_GPU_REG_H),
                },
            })
        } else {
            None
        }
    }

    /// Create a 2D resource
    pub fn resource_create_2d(&mut self, resource_id: u32, format: u32, width: u32, height: u32) -> Result<(), GpuError> {
        // For virtio-gpu 2D resources
        // In blob mode, this would create a backing store
        // For simple framebuffer mode, the scanout is direct
        
        // Store resource info
        log::video_log("virtio-gpu", &alloc::format!("Resource {}: {}x{} format {}", resource_id, width, height, format));
        
        Ok(())
    }

    /// Set scanout configuration
    pub fn set_scanout(&mut self, scanout_id: u32, resource_id: u32, x: u32, y: u32, width: u32, height: u32) -> Result<(), GpuError> {
        self.write_reg(VIRTIO_GPU_REG_SCANOUT_ID, scanout_id);
        
        // In virtio-gpu 0.2+, scanout is configured via resource
        log::video_log("virtio-gpu", &alloc::format!("Scanout {}: resource {} at ({}, {}) {}x{}", scanout_id, resource_id, x, y, width, height));
        
        Ok(())
    }

    /// Transfer to host (upload to GPU)
    pub fn transfer_to_host_2d(&mut self, resource_id: u32, offset: u64, x: u32, y: u32, width: u32, height: u32) -> Result<(), GpuError> {
        // Upload a region of the resource from guest to host
        self.send_command(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, 0);
        
        log::video_log("virtio-gpu", &alloc::format!("Transfer to host: resource {} region ({}, {}) {}x{}", resource_id, x, y, width, height));
        
        self.wait_command_complete(1000)
    }

    /// Flush display
    pub fn flush(&mut self, x: u32, y: u32, width: u32, height: u32) -> Result<(), GpuError> {
        self.send_command(VIRTIO_GPU_CMD_FLUSH, 0);
        
        // Signal display update
        self.write_reg(VIRTIO_GPU_REG_DISPLAY_WRITE, 1);
        
        log::video_log("virtio-gpu", &alloc::format!("Flush: ({}, {}) {}x{}", x, y, width, height));
        
        self.wait_command_complete(100)
    }

    /// Attach backing storage to a resource
    pub fn resource_attach_backing(&mut self, resource_id: u32, entries: &[VirtGpuMemEntry]) -> Result<(), GpuError> {
        self.send_command(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING, 0);
        
        log::video_log("virtio-gpu", &alloc::format!("Attach backing to resource {}", resource_id));
        
        self.wait_command_complete(100)
    }

    /// Detach backing storage
    pub fn resource_detach_backing(&mut self, resource_id: u32) -> Result<(), GpuError> {
        self.send_command(VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING, 0);
        
        log::video_log("virtio-gpu", &alloc::format!("Detach backing from resource {}", resource_id));
        
        self.wait_command_complete(100)
    }

    /// Create a 3D context (for VirGL)
    pub fn context_create(&mut self, context_id: u32, nlen: u32, name: &str) -> Result<(), GpuError> {
        self.send_command(VIRTIO_GPU_CMD_CTX_CREATE, 0);
        
        log::video_log("virtio-gpu", &alloc::format!("Create 3D context {}", context_id));
        
        self.wait_command_complete(100)
    }

    /// Submit 3D commands (for VirGL)
    pub fn context_submit(&mut self, context_id: u32, commands: &[u8]) -> Result<(), GpuError> {
        self.send_command(VIRTIO_GPU_CMD_CTX_ATTACH_BACKING, 0);
        
        log::video_log("virtio-gpu", &alloc::format!("Submit {} bytes to context {}", commands.len(), context_id));
        
        self.wait_command_complete(1000)
    }

    /// Get the scanout count supported by this device
    pub fn get_scanout_count(&self) -> u32 {
        // Read from device config or default to 1
        1
    }

    /// Poll for display changes (used when not using interrupts)
    pub fn poll_display(&mut self) -> bool {
        let display_write = self.read_reg(VIRTIO_GPU_REG_DISPLAY_WRITE);
        display_write != 0
    }

    /// Acknowledge display update
    pub fn ack_display_update(&mut self) {
        self.write_reg(VIRTIO_GPU_REG_DISPLAY_WRITE, 0);
    }
}

// =====================================================================
// virtio-gpu Register Definitions
// =====================================================================

/// virtio-gpu MMIO register offsets

/// Virtio GPU device ID
pub const VIRTIO_GPU_REG_H: u32 = 0x0000;
/// Display height
pub const VIRTIO_GPU_REG_W: u32 = 0x0004;
/// Framebuffer address
pub const VIRTIO_GPU_REG_FB_ADDR: u32 = 0x0008;
/// virtio status register
pub const VIRTIO_GPU_REG_STATUS: u32 = 0x0010;
/// virtio control register
pub const VIRTIO_GPU_REG_CTRL: u32 = 0x0014;
/// Scanout ID
pub const VIRTIO_GPU_REG_SCANOUT_ID: u32 = 0x0018;

/// Display configuration
/// Display read
pub const VIRTIO_GPU_REG_DISPLAY_READ: u32 = 0x0140;
/// Display write
pub const VIRTIO_GPU_REG_DISPLAY_WRITE: u32 = 0x0144;

/// Interrupt status
pub const VIRTIO_GPU_REG_INT_STATUS: u32 = 0x0180;

/// virtio-gpu status flags
/// Reset
pub const VIRTIO_GPU_STATUS_RESET: u32 = 0;
/// Acknowledge
pub const VIRTIO_GPU_STATUS_ACK: u32 = 1 << 0;
/// Driver loaded
pub const VIRTIO_GPU_STATUS_DRIVER: u32 = 1 << 1;
/// Driver ready
pub const VIRTIO_GPU_STATUS_DRIVER_OK: u32 = 1 << 2;
/// Features acknowledged
pub const VIRTIO_GPU_STATUS_FEATURES_OK: u32 = 1 << 3;
/// Device needs reset
pub const VIRTIO_GPU_STATUS_FAILED: u32 = 1 << 7;
/// Command completed successfully
pub const VIRTIO_GPU_STATUS_OK: u32 = 1 << 0;

/// virtio-gpu control commands
/// Get display info
pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
/// Get fb info
pub const VIRTIO_GPU_CMD_GET_FB_INFO: u32 = 0x0101;
/// Set scanout
pub const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0102;
/// Resource attach backing
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0103;
/// Resource detach backing
pub const VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING: u32 = 0x0104;
/// Flush
pub const VIRTIO_GPU_CMD_FLUSH: u32 = 0x0105;
/// Transfer to host 2D
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0106;
/// Transfer to host 3D
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D: u32 = 0x0107;
/// Resource create 2D
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0108;
/// Resource unref
pub const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32 = 0x0109;
/// Update cursor
pub const VIRTIO_GPU_CMD_UPDATE_CURSOR: u32 = 0x010A;
/// Move cursor
pub const VIRTIO_GPU_CMD_MOVE_CURSOR: u32 = 0x010B;
/// Resource create 3D
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_3D: u32 = 0x010C;
/// Resource ref
pub const VIRTIO_GPU_CMD_RESOURCE_REF: u32 = 0x010D;
/// Context create
pub const VIRTIO_GPU_CMD_CTX_CREATE: u32 = 0x010E;
/// Context destroy
pub const VIRTIO_GPU_CMD_CTX_DESTROY: u32 = 0x010F;
/// Context attach backing
pub const VIRTIO_GPU_CMD_CTX_ATTACH_BACKING: u32 = 0x0110;
/// Context detach backing
pub const VIRTIO_GPU_CMD_CTX_DETACH_BACKING: u32 = 0x0111;
/// Submit 3D commands
pub const VIRTIO_GPU_CMD_SUBMIT_3D: u32 = 0x0112;

/// virtio-gpu feature flags
/// Virtio GPU feature: scanout blob
pub const VIRTIO_GPU_F_SCANOUT_BLOB: u32 = 1 << 0;
/// Virtio GPU feature: cross device
pub const VIRTIO_GPU_F_CROSS_DEVICE: u32 = 1 << 1;

// =====================================================================
// Probe and Init Functions
// =====================================================================

/// Probe for virtio-gpu device
#[cfg(target_arch = "riscv64")]
pub fn probe() -> bool {
    // Check if virtio-gpu is present
    // In QEMU, virtio-gpu is typically at a known MMIO address
    
    // For now, always return true to enable development
    // Real implementation would check PCI/vendor IDs
    true
}

/// Initialize virtio-gpu device
#[cfg(target_arch = "riscv64")]
pub fn init() -> Option<VirtioGpuDevice> {
    if !probe() {
        return None;
    }

    let mut device = VirtioGpuDevice::new(pci_ids::VIRTIO_GPU_DEVICE_ID as u32);
    
    if device.init().is_ok() {
        Some(device)
    } else {
        None
    }
}

/// Probe stub for non-RISC-V architectures
#[cfg(not(target_arch = "riscv64"))]
pub fn probe() -> bool {
    false
}

/// Init stub for non-RISC-V architectures
#[cfg(not(target_arch = "riscv64"))]
pub fn init() -> Option<VirtioGpuDevice> {
    None
}

// =====================================================================
// QEMU Configuration Constants
// =====================================================================

/// QEMU virtio-gpu default configuration
pub mod qemu_config {
    /// Default display width
    pub const DEFAULT_WIDTH: u32 = 1024;
    
    /// Default display height  
    pub const DEFAULT_HEIGHT: u32 = 768;
    
    /// Default pixel format
    pub const DEFAULT_FORMAT: u32 = 0x00; // ARGB
    
    /// Default framebuffer size (8MB)
    pub const DEFAULT_FB_SIZE: u64 = 8 * 1024 * 1024;
    
    /// MMIO base for virtio-gpu in QEMU riscv64 virt machine
    pub const QEMU_VIRTIO_GPU_BASE: u64 = 0x1000_0000;
    
    /// MMIO size for virtio-gpu
    pub const QEMU_VIRTIO_GPU_SIZE: u64 = 0x2000;
}

// =====================================================================
// Feature Detection Helpers
// =====================================================================

/// Feature detection for virtio-gpu
pub mod features {
    /// Check if virgl acceleration is available
    pub fn has_virgl() -> bool {
        // VirGL requires QEMU with --display virtio,gl=on
        false
    }

    /// Check if blob resource is supported
    pub fn has_blob() -> bool {
        // Blob resources are a newer feature
        true
    }

    /// Check if multi-scanout is supported
    pub fn has_multi_scanout() -> bool {
        // Multi-scanout requires blob resources
        false
    }

    /// Get maximum supported width
    pub fn max_width() -> u32 {
        4096
    }

    /// Get maximum supported height
    pub fn max_height() -> u32 {
        2160
    }

    /// Get default resolution
    pub fn default_resolution() -> (u32, u32) {
        (super::qemu_config::DEFAULT_WIDTH, super::qemu_config::DEFAULT_HEIGHT)
    }
}

// =====================================================================
// virtio-gpu Data Structures
// =====================================================================

/// Display information structure
#[derive(Debug, Clone, Default)]
pub struct VirtGpuDisplayInfo {
    /// Display rectangle
    pub rect: VirtGpuRect,
}

/// Rectangle structure
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtGpuRect {
    /// X coordinate
    pub x: u32,
    /// Y coordinate
    pub y: u32,
    /// Width
    pub width: u32,
    /// Height
    pub height: u32,
}

/// Memory entry for backing storage
#[derive(Debug, Clone, Copy)]
pub struct VirtGpuMemEntry {
    /// Physical address
    pub addr: u64,
    /// Length in bytes
    pub length: u32,
}

impl Default for VirtGpuMemEntry {
    fn default() -> Self {
        Self {
            addr: 0,
            length: 0,
        }
    }
}

/// Resource information
#[derive(Debug, Clone)]
pub struct VirtGpuResource {
    /// Resource ID
    pub id: u32,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Format
    pub format: u32,
    /// Backing entries
    pub backing: Option<Vec<VirtGpuMemEntry>>,
}

impl VirtGpuResource {
    /// Create a new resource
    pub fn new(id: u32, width: u32, height: u32, format: u32) -> Self {
        Self {
            id,
            width,
            height,
            format,
            backing: None,
        }
    }

    /// Calculate the required size for this resource
    pub fn required_size(&self) -> u64 {
        // For RGBA format, 4 bytes per pixel
        (self.width as u64) * (self.height as u64) * 4
    }
}

/// Resource tracking
pub struct VirtGpuResourceManager {
    /// Allocated resources
    resources: Vec<VirtGpuResource>,
    /// Next resource ID
    next_id: u32,
}

impl VirtGpuResourceManager {
    /// Create a new resource manager
    pub fn new() -> Self {
        Self {
            resources: Vec::new(),
            next_id: 1,
        }
    }

    /// Create a new resource
    pub fn create_resource(&mut self, width: u32, height: u32, format: u32) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        
        self.resources.push(VirtGpuResource::new(id, width, height, format));
        id
    }

    /// Get a resource by ID
    pub fn get_resource(&self, id: u32) -> Option<&VirtGpuResource> {
        self.resources.iter().find(|r| r.id == id)
    }

    /// Get a mutable resource by ID
    pub fn get_resource_mut(&mut self, id: u32) -> Option<&mut VirtGpuResource> {
        self.resources.iter_mut().find(|r| r.id == id)
    }

    /// Destroy a resource
    pub fn destroy_resource(&mut self, id: u32) -> bool {
        if let Some(pos) = self.resources.iter().position(|r| r.id == id) {
            self.resources.remove(pos);
            true
        } else {
            false
        }
    }
}

impl Default for VirtGpuResourceManager {
    fn default() -> Self {
        Self::new()
    }
}
