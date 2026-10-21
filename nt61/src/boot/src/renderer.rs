//! Framebuffer renderer for direct pixel manipulation
//
//! Provides high-level drawing primitives.

use crate::graphics::FramebufferInfo;

/// 32-bit BGRA color (in memory: BB GG RR AA)
#[derive(Debug, Clone, Copy)]
pub struct Color(pub u32);

/// Framebuffer wrapper for drawing operations
pub struct Framebuffer {
    ptr: *mut u8,
    info: FramebufferInfo,
}

impl Framebuffer {
    pub fn with_ptr(info: FramebufferInfo, ptr: *mut u8) -> Self {
        Self { ptr, info }
    }

    pub fn width(&self) -> u32 {
        self.info.width
    }
    pub fn height(&self) -> u32 {
        self.info.height
    }
    pub fn set_pixel(&mut self, x: u32, y: u32, color: Color) {
        if x >= self.info.width || y >= self.info.height || self.ptr.is_null() {
            return;
        }

        let offset = (y as usize) * (self.info.stride as usize) + (x as usize) * 4;

        unsafe {
            let ptr = self.ptr.add(offset);
            // BGRA format
            *ptr = ((color.0 >> 16) & 0xFF) as u8; // B
            *ptr.add(1) = ((color.0 >> 8) & 0xFF) as u8; // G
            *ptr.add(2) = (color.0 & 0xFF) as u8; // R
            *ptr.add(3) = ((color.0 >> 24) & 0xFF) as u8; // A
        }
    }

    /// Read back the BGRA pixel at `(x, y)`, using the same
    /// packed representation as [`Framebuffer::set_pixel`].
    pub fn get_pixel(&self, x: u32, y: u32) -> Option<Color> {
        if x >= self.info.width || y >= self.info.height || self.ptr.is_null() {
            return None;
        }

        let offset = (y as usize) * (self.info.stride as usize) + (x as usize) * 4;

        unsafe {
            let ptr = self.ptr.add(offset);
            let blue = u32::from(*ptr);
            let green = u32::from(*ptr.add(1));
            let red = u32::from(*ptr.add(2));
            let alpha = u32::from(*ptr.add(3));
            Some(Color((blue << 16) | (green << 8) | red | (alpha << 24)))
        }
    }

    /// Fast fill rectangle using memory copy
    pub fn fill_rect_fast(&mut self, x: u32, y: u32, w: u32, h: u32, color: Color) {
        let x_end = (x + w).min(self.info.width);
        let y_end = (y + h).min(self.info.height);
        let actual_w = x_end - x;

        if actual_w == 0 || y_end <= y {
            return;
        }

        let r = ((color.0 >> 16) & 0xFF) as u8;
        let g = ((color.0 >> 8) & 0xFF) as u8;
        let b = (color.0 & 0xFF) as u8;
        let a = ((color.0 >> 24) & 0xFF) as u8;

        for py in y..y_end {
            let row_start = (py as usize) * (self.info.stride as usize) + (x as usize) * 4;
            for px in 0..actual_w {
                let offset = row_start + (px as usize) * 4;
                unsafe {
                    *self.ptr.add(offset) = b;
                    *self.ptr.add(offset + 1) = g;
                    *self.ptr.add(offset + 2) = r;
                    *self.ptr.add(offset + 3) = a;
                }
            }
        }
    }

}
