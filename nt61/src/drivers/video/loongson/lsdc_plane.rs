//! Loongson Display Plane/Layer Management
//
//! Implements plane (layer) management for the Loongson DC,
//! including primary plane and cursor plane.

use crate::drivers::video::loongson::lsdc_reg::*;

/// Plane types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneType {
    /// Primary plane (main display)
    Primary,
    /// Cursor plane (hardware cursor)
    Cursor,
}

/// Pixel format for planes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneFormat {
    /// 32-bit BGRA
    Bgra8888,
    /// 32-bit RGBA
    Rgba8888,
    /// 16-bit RGB 5:6:5
    Rgb565,
    /// 32-bit XRGB
    Xrgb8888,
}

impl PlaneFormat {
    /// Get format value for register
    pub fn to_reg_value(&self) -> u32 {
        match self {
            PlaneFormat::Bgra8888 | PlaneFormat::Xrgb8888 => 0,
            PlaneFormat::Rgba8888 => 1,
            PlaneFormat::Rgb565 => 2,
        }
    }

    /// Get bytes per pixel
    pub fn bytes_per_pixel(&self) -> u32 {
        match self {
            PlaneFormat::Bgra8888 | PlaneFormat::Rgba8888 | PlaneFormat::Xrgb8888 => 4,
            PlaneFormat::Rgb565 => 2,
        }
    }
}

/// Primary plane configuration
#[derive(Debug)]
pub struct PrimaryPlane {
    /// DC base address
    dc_base: u64,
    /// Whether plane is enabled
    enabled: bool,
    /// Current framebuffer address
    fb_addr: u64,
    /// Current stride
    stride: u32,
    /// Current width
    width: u32,
    /// Current height
    height: u32,
}

impl PrimaryPlane {
    /// Create a new primary plane
    pub fn new(dc_base: u64) -> Self {
        Self {
            dc_base,
            enabled: false,
            fb_addr: 0,
            stride: 0,
            width: 0,
            height: 0,
        }
    }

    /// Read a register
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.dc_base + offset as u64) as *const u32) }
    }

    /// Write a register
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.dc_base + offset as u64) as *mut u32,
                value,
            )
        }
    }

    /// Configure the primary plane
    pub fn configure(
        &mut self,
        fb_addr: u64,
        stride: u32,
        width: u32,
        height: u32,
        format: PlaneFormat,
    ) {
        self.fb_addr = fb_addr;
        self.stride = stride;
        self.width = width;
        self.height = height;

        // Configure address
        self.write_reg(PLANE_PRIMARY_ADDR, fb_addr as u32);

        // Configure stride
        self.write_reg(PLANE_PRIMARY_STRIDE, stride);

        // Configure size
        self.write_reg(PLANE_PRIMARY_SIZE, (height << 16) | width);

        // Configure format and enable
        let format_bits = format.to_reg_value() << 8;
        self.write_reg(PLANE_PRIMARY_CTRL, PLANE_ENABLE | format_bits);
    }

    /// Enable the plane
    pub fn enable(&mut self) {
        let ctrl = self.read_reg(PLANE_PRIMARY_CTRL);
        self.write_reg(PLANE_PRIMARY_CTRL, ctrl | PLANE_ENABLE);
        self.enabled = true;
    }

    /// Disable the plane
    pub fn disable(&mut self) {
        let ctrl = self.read_reg(PLANE_PRIMARY_CTRL);
        self.write_reg(PLANE_PRIMARY_CTRL, ctrl & !PLANE_ENABLE);
        self.enabled = false;
    }

    /// Check if enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Update framebuffer address
    pub fn set_fb_address(&mut self, fb_addr: u64) {
        self.fb_addr = fb_addr;
        self.write_reg(PLANE_PRIMARY_ADDR, fb_addr as u32);
    }

    /// Update stride
    pub fn set_stride(&mut self, stride: u32) {
        self.stride = stride;
        self.write_reg(PLANE_PRIMARY_STRIDE, stride);
    }

    /// Update position
    pub fn set_position(&self, x: u32, y: u32) {
        let pos = (y << 16) | x;
        self.write_reg(PLANE_PRIMARY_POS, pos);
    }

    /// Get plane status
    pub fn get_status(&self) -> PlaneStatus {
        let ctrl = self.read_reg(PLANE_PRIMARY_CTRL);
        let addr = self.read_reg(PLANE_PRIMARY_ADDR);
        let stride = self.read_reg(PLANE_PRIMARY_STRIDE);
        let size = self.read_reg(PLANE_PRIMARY_SIZE);

        PlaneStatus {
            enabled: ctrl & PLANE_ENABLE != 0,
            format: (ctrl >> 8) & 0xF,
            fb_addr: addr as u64,
            stride,
            width: size & 0xFFFF,
            height: (size >> 16) & 0xFFFF,
        }
    }
}

/// Primary plane status
#[derive(Debug, Clone, Copy)]
pub struct PlaneStatus {
    /// Whether plane is enabled
    pub enabled: bool,
    /// Format value
    pub format: u32,
    /// Framebuffer address
    pub fb_addr: u64,
    /// Stride
    pub stride: u32,
    /// Width
    pub width: u32,
    /// Height
    pub height: u32,
}

/// Cursor plane configuration
#[derive(Debug)]
pub struct CursorPlane {
    /// DC base address
    dc_base: u64,
    /// Whether cursor is enabled
    enabled: bool,
    /// Cursor format
    format: CursorFormat,
    /// Cursor size
    size: CursorSize,
}

impl CursorPlane {
    /// Create a new cursor plane
    pub fn new(dc_base: u64) -> Self {
        Self {
            dc_base,
            enabled: false,
            format: CursorFormat::Argb8888,
            size: CursorSize::Size64,
        }
    }

    /// Read a register
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.dc_base + offset as u64) as *const u32) }
    }

    /// Write a register
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.dc_base + offset as u64) as *mut u32,
                value,
            )
        }
    }

    /// Configure the cursor
    pub fn configure(&mut self, fb_addr: u64, format: CursorFormat, size: CursorSize) {
        self.format = format;
        self.size = size;

        // Configure address
        self.write_reg(PLANE_CURSOR_ADDR, fb_addr as u32);

        // Configure format and size
        let format_bits = format.to_reg_value() << 4;
        let size_bits = size.to_reg_value() << 8;
        self.write_reg(PLANE_CURSOR_CTRL, format_bits | size_bits);
    }

    /// Enable the cursor
    pub fn enable(&mut self) {
        let ctrl = self.read_reg(PLANE_CURSOR_CTRL);
        self.write_reg(PLANE_CURSOR_CTRL, ctrl | CURSOR_ENABLE);
        self.enabled = true;
    }

    /// Disable the cursor
    pub fn disable(&mut self) {
        let ctrl = self.read_reg(PLANE_CURSOR_CTRL);
        self.write_reg(PLANE_CURSOR_CTRL, ctrl & !CURSOR_ENABLE);
        self.enabled = false;
    }

    /// Check if enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set cursor position
    pub fn set_position(&self, x: i32, y: i32) {
        // Position is signed 16-bit
        let pos = ((y as u32) << 16) | ((x as u32) & 0xFFFF);
        self.write_reg(PLANE_CURSOR_POS, pos);
    }

    /// Get cursor status
    pub fn get_status(&self) -> CursorStatus {
        let ctrl = self.read_reg(PLANE_CURSOR_CTRL);
        let addr = self.read_reg(PLANE_CURSOR_ADDR);
        let pos = self.read_reg(PLANE_CURSOR_POS);

        CursorStatus {
            enabled: ctrl & CURSOR_ENABLE != 0,
            format: (ctrl >> 4) & 0xF,
            size: (ctrl >> 8) & 0xF,
            fb_addr: addr as u64,
            x: (pos & 0xFFFF) as i32,
            y: ((pos >> 16) & 0xFFFF) as i32,
        }
    }
}

/// Cursor status
#[derive(Debug, Clone, Copy)]
pub struct CursorStatus {
    /// Whether cursor is enabled
    pub enabled: bool,
    /// Format value
    pub format: u32,
    /// Size value
    pub size: u32,
    /// Framebuffer address
    pub fb_addr: u64,
    /// X position
    pub x: i32,
    /// Y position
    pub y: i32,
}

/// Cursor format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorFormat {
    /// 2-bit per pixel (4 colors)
    Bpp2,
    /// 8-bit per pixel (256 colors)
    Bpp8,
    /// 32-bit ARGB
    Argb8888,
}

impl CursorFormat {
    /// Get format value for register
    pub fn to_reg_value(&self) -> u32 {
        match self {
            CursorFormat::Bpp2 => 0,
            CursorFormat::Bpp8 => 1,
            CursorFormat::Argb8888 => 2,
        }
    }
}

/// Cursor size
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorSize {
    /// 32x32 pixels
    Size32,
    /// 64x64 pixels
    Size64,
}

impl CursorSize {
    /// Get size value for register
    pub fn to_reg_value(&self) -> u32 {
        match self {
            CursorSize::Size32 => 0,
            CursorSize::Size64 => 1,
        }
    }

    /// Get pixel dimensions
    pub fn dimensions(&self) -> (u32, u32) {
        match self {
            CursorSize::Size32 => (32, 32),
            CursorSize::Size64 => (64, 64),
        }
    }

    /// Get buffer size in bytes
    pub fn buffer_size(&self, format: CursorFormat) -> u32 {
        let (w, h) = self.dimensions();
        let pixels = w * h;
        match format {
            CursorFormat::Bpp2 => (pixels + 3) / 4,
            CursorFormat::Bpp8 => pixels,
            CursorFormat::Argb8888 => pixels * 4,
        }
    }
}

/// Plane manager
pub struct PlaneManager {
    /// Primary plane
    primary: PrimaryPlane,
    /// Cursor plane
    cursor: CursorPlane,
}

impl PlaneManager {
    /// Create a new plane manager
    pub fn new(dc_base: u64) -> Self {
        Self {
            primary: PrimaryPlane::new(dc_base),
            cursor: CursorPlane::new(dc_base),
        }
    }

    /// Get primary plane
    pub fn primary(&mut self) -> &mut PrimaryPlane {
        &mut self.primary
    }

    /// Get cursor plane
    pub fn cursor(&mut self) -> &mut CursorPlane {
        &mut self.cursor
    }

    /// Configure both planes
    pub fn configure(
        &mut self,
        fb_addr: u64,
        stride: u32,
        width: u32,
        height: u32,
    ) {
        self.primary.configure(fb_addr, stride, width, height, PlaneFormat::Bgra8888);
        self.primary.enable();
    }

    /// Disable all planes
    pub fn disable_all(&mut self) {
        self.primary.disable();
        self.cursor.disable();
    }
}
