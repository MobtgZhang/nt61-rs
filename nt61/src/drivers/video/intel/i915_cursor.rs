//! Intel i915 Hardware Cursor Driver
//
//! This module implements hardware cursor support for Intel integrated graphics.
//! The cursor is rendered using dedicated hardware and composited by the display
//! pipeline, providing efficient cursor rendering without CPU involvement.
//
//! Supported generations:
//! - Ironlake through Broadwell (legacy cursor)
//! - Skylake and later (enhanced cursor with larger sizes)
//! - Tiger Lake+ (Xe cursor architecture)
//
//! Reference: Intel Graphics Programmer's Reference Manuals (PRMs)

use crate::drivers::video::intel::i915_reg::*;

/// Hardware cursor size options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorSize {
    /// 32x32 cursor
    Size32x32,
    /// 64x64 cursor
    Size64x64,
    /// 256x256 cursor (Skylake+)
    Size256x256,
}

impl CursorSize {
    /// Get the cursor size value for the control register
    fn to_reg_value(&self) -> u32 {
        match self {
            CursorSize::Size32x32 => 0 << 24,
            CursorSize::Size64x64 => 1 << 24,
            CursorSize::Size256x256 => 3 << 24,
        }
    }

    /// Get the cursor size in pixels
    fn to_pixels(&self) -> u32 {
        match self {
            CursorSize::Size32x32 => 32,
            CursorSize::Size64x64 => 64,
            CursorSize::Size256x256 => 256,
        }
    }
}

/// Hardware cursor for i915
///
/// This struct provides access to the hardware cursor functionality
/// of Intel integrated graphics. The cursor is managed through MMIO
/// registers and supports ARGB sprite data.
#[derive(Debug)]
pub struct I915Cursor {
    /// MMIO base (needed for register access)
    mmio_base: u64,
    /// Current cursor size
    size: CursorSize,
    /// Whether the cursor is currently enabled
    enabled: bool,
}

impl I915Cursor {
    /// Create a new cursor for the given device
    ///
    /// # Arguments
    /// * `mmio_base` - The MMIO base address of the i915 device
    ///
    /// # Returns
    /// A new I915Cursor instance
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            size: CursorSize::Size64x64,
            enabled: false,
        }
    }

    /// Read a cursor register
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write a cursor register
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.mmio_base + offset as u64) as *mut u32,
                value,
            );
        }
    }

    /// Enable the hardware cursor
    ///
    /// # Arguments
    /// * `size` - The cursor size to use
    pub fn enable(&mut self, size: CursorSize) {
        let control = CURSOR_ENABLE
            | CURSOR_FORMAT_ARGB8888
            | size.to_reg_value();

        self.write_reg(CURACNTR, control);
        self.size = size;
    }

    /// Disable the hardware cursor
    ///
    /// Disables cursor rendering by clearing the enable bit.
    /// The cursor sprite data is preserved.
    pub fn disable(&mut self) {
        let control = self.read_reg(CURACNTR);
        self.write_reg(CURACNTR, control & !CURSOR_ENABLE);
        self.enabled = false;
    }

    /// Set cursor position (screen coordinates)
    ///
    /// The position is in screen pixels, with (0,0) being the top-left.
    /// Note: The cursor is clipped to the screen boundaries by hardware.
    ///
    /// # Arguments
    /// * `x` - Horizontal position (pixels from left edge)
    /// * `y` - Vertical position (pixels from top edge)
    pub fn set_position(&self, x: u32, y: u32) {
        // CURAPOS layout:
        // - Bits 31:16 = Y position
        // - Bits 15:0 = X position
        // - Bit 31 of low word = X sign (for off-screen positioning)
        // - Bit 15 of high word = Y sign
        let position = ((y & 0x7FFF) << 16) | (x & 0x7FFF);
        self.write_reg(CURAPOS, position);
    }

    /// Load cursor sprite data (ARGB format)
    ///
    /// The cursor sprite is stored in dedicated memory and must be
    /// physically contiguous and 64-byte aligned. The sprite is
    /// organized as 32-bit ARGB pixels in row-major order.
    ///
    /// # Arguments
    /// * `data` - Slice of ARGB pixel data (32-bit per pixel)
    ///
    /// # Panics
    /// Panics if the data size doesn't match the expected cursor size
    pub fn load_sprite(&self, data: &[u32]) {
        let expected_size = self.size.to_pixels() * self.size.to_pixels();
        assert_eq!(
            data.len() as u32,
            expected_size,
            "Cursor data size mismatch: expected {}, got {}",
            expected_size,
            data.len()
        );

        // Cursor sprite base address register
        // Note: On older hardware, this is CURABASE
        // On newer hardware (Skylake+), the sprite is accessed via CURBASE
        self.write_reg(CURABASE, 0);

        // Write sprite data to the cursor sprite area
        // The sprite data area is at MMIO base + 0x80000 to 0x81FFF (64KB)
        let sprite_base = self.mmio_base + 0x80000;
        for (i, &pixel) in data.iter().enumerate() {
            let offset = (i * 4) as u64;
            unsafe {
                core::ptr::write_volatile(
                    (sprite_base + offset) as *mut u32,
                    pixel,
                );
            }
        }

        // Set the cursor base address to point to the sprite data
        // The hardware will read from this location
        let sprite_phys: u32 = 0x80000; // Physical offset in BAR0
        self.write_reg(CURABASE, sprite_phys);
    }

    /// Load cursor sprite data with physical address
    ///
    /// This version allows specifying the physical address of cursor
    /// sprite data that was allocated elsewhere.
    ///
    /// # Arguments
    /// * `sprite_phys` - Physical address of the cursor sprite
    /// * `data` - The sprite data (for verification only)
    pub fn load_sprite_phys(&self, sprite_phys: u64, data: &[u32]) {
        let expected_size = self.size.to_pixels() * self.size.to_pixels();
        assert_eq!(
            data.len() as u32,
            expected_size,
            "Cursor data size mismatch"
        );

        // Write sprite data to the provided physical address
        // (In a real implementation, this would be mapped)
        let sprite_base = sprite_phys;
        for (i, &pixel) in data.iter().enumerate() {
            let offset = (i * 4) as u64;
            unsafe {
                core::ptr::write_volatile(
                    (sprite_base + offset) as *mut u32,
                    pixel,
                );
            }
        }

        // Set the cursor base address
        self.write_reg(CURABASE, sprite_phys as u32);
    }

    /// Set cursor color key (for transparency)
    ///
    /// The color key is used for transparent cursor pixels.
    /// When a cursor pixel matches the color key, it becomes
    /// transparent, showing the underlying framebuffer content.
    ///
    /// # Arguments
    /// * `key` - ARGB color to use as transparency key
    pub fn set_color_key(&self, key: u32) {
        // Color key is typically controlled through pipe plane settings
        // For cursor, we use the ARGB format where 0 alpha = transparent
        // This method is provided for compatibility but cursors typically
        // use alpha channel for transparency
        let _ = key;
    }

    /// Get current cursor position
    ///
    /// # Returns
    /// A tuple of (x, y) position
    pub fn get_position(&self) -> (u32, u32) {
        let pos = self.read_reg(CURAPOS);
        let x = pos & 0x7FFF;
        let y = (pos >> 16) & 0x7FFF;
        (x, y)
    }

    /// Get cursor control register value
    ///
    /// # Returns
    /// The current control register value
    pub fn get_control(&self) -> u32 {
        self.read_reg(CURACNTR)
    }

    /// Check if cursor is enabled
    ///
    /// # Returns
    /// True if cursor enable bit is set
    pub fn is_enabled(&self) -> bool {
        let control = self.read_reg(CURACNTR);
        (control & CURSOR_ENABLE) != 0
    }

    /// Hide the cursor (move off-screen)
    ///
    /// This is an alternative to disable() that preserves
    /// the cursor state and can be quickly restored.
    pub fn hide(&self) {
        // Move cursor far off-screen
        self.write_reg(CURAPOS, (0x3FFF << 16) | 0x3FFF);
    }

    /// Set cursor visibility
    ///
    /// # Arguments
    /// * `visible` - True to show, false to hide
    pub fn set_visible(&mut self, visible: bool) {
        if visible && !self.enabled {
            self.enable(self.size);
        } else if !visible && self.enabled {
            self.hide();
        }
    }
}

/// Cursor for Pipe B (second display head)
///
/// Some Intel platforms support multiple display pipes,
/// each with their own cursor hardware.
pub struct I915CursorPipeB {
    /// MMIO base
    mmio_base: u64,
    /// Current size
    size: CursorSize,
    /// Enabled state — tracked in software so we can answer
    /// "is the cursor on" queries without re-reading the MMIO.
    enabled: bool,
}

impl I915CursorPipeB {
    /// Create a new cursor for Pipe B
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            size: CursorSize::Size64x64,
            enabled: false,
        }
    }

    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.mmio_base + offset as u64) as *mut u32,
                value,
            );
        }
    }

    /// Read-only accessor for the cached `enabled` flag. Useful for
    /// the boot menu's "cursor on/off" indicator.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable cursor on Pipe B
    pub fn enable(&mut self, size: CursorSize) {
        let control = CURSOR_ENABLE
            | CURSOR_FORMAT_ARGB8888
            | size.to_reg_value();
        self.write_reg(CURBCNTR, control);
        self.size = size;
        self.enabled = true;
    }

    /// Disable cursor on Pipe B
    pub fn disable(&mut self) {
        let control = self.read_reg(CURBCNTR);
        self.write_reg(CURBCNTR, control & !CURSOR_ENABLE);
        self.enabled = false;
    }

    /// Set position on Pipe B
    pub fn set_position(&self, x: u32, y: u32) {
        let position = ((y & 0x7FFF) << 16) | (x & 0x7FFF);
        self.write_reg(CURBPOS, position);
    }

    /// Load sprite data for Pipe B
    pub fn load_sprite(&self, data: &[u32]) {
        let expected_size = self.size.to_pixels() * self.size.to_pixels();
        assert_eq!(data.len() as u32, expected_size);

        self.write_reg(CURBBASE, 0);
        let sprite_base = self.mmio_base + 0x80000;
        for (i, &pixel) in data.iter().enumerate() {
            let offset = (i * 4) as u64;
            unsafe {
                core::ptr::write_volatile(
                    (sprite_base + offset) as *mut u32,
                    pixel,
                );
            }
        }
        self.write_reg(CURBBASE, 0x80000);
    }
}
