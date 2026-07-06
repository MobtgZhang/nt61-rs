//! Framebuffer renderer for direct pixel manipulation
//
//! Provides high-level drawing primitives.

#![allow(dead_code)]

use crate::graphics::FramebufferInfo;

/// Pixel format
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PixelFormat {
    Rgb,
    Bgr,
    Bitmask,
    BltOnly,
}

/// 32-bit BGRA color (in memory: BB GG RR AA)
#[derive(Debug, Clone, Copy)]
pub struct Color(pub u32);

impl Color {
    // Basic colors
    pub const BLACK:        Color = Color(0xFF_00_00_00);
    pub const WHITE:        Color = Color(0xFF_FF_FF_FF);
    pub const GRAY:         Color = Color(0xFF_80_80_80);
    pub const LIGHT_GRAY:   Color = Color(0xFF_C0_C0_C0);
    pub const DARK_GRAY:    Color = Color(0xFF_40_40_40);
    
    // Windows 7 Boot Manager specific colors
    pub const BOOT_BG:     Color = Color(0xFF_01_01_01);      // Almost black background
    pub const TITLE_BG:    Color = Color(0xFF_36_36_36);      // Dark gray title bar
    pub const SELECT_BG:    Color = Color(0xFF_00_33_99);      // Windows blue selection
    pub const SELECT_FG:    Color = Color(0xFF_FF_FF_FF);      // White text on selection
    pub const NORMAL_FG:   Color = Color(0xFF_FF_FF_FF);      // White text
    pub const HINT_FG:     Color = Color(0xFF_99_99_99);      // Gray hint text
    
    // Windows logo colors (standard Windows 7 logo)
    pub const WIN_ORANGE:   Color = Color(0xFF_F2_5C_01);      // Orange (#F25C01)
    pub const WIN_RED:      Color = Color(0xFF_ED_6C_1E);      // Red (#ED6C1E)
    pub const WIN_GREEN:    Color = Color(0xFF_3A_96_30);      // Green (#3A9630)
    pub const WIN_BLUE:     Color = Color(0xFF_0E_65_BF);      // Blue (#0E65BF)
    
    // Alternative simpler logo colors
    pub const LOGO_LEFT:    Color = Color(0xFF_00_A0_F0);      // Cyan/teal
    pub const LOGO_RIGHT:   Color = Color(0xFF_F0_A000);       // Orange
    
    pub const fn from_rgb(r: u8, g: u8, b: u8) -> Self {
        // BGRA format: 0xAARRGGBB
        Color(0xFF_00_00_00 | ((b as u32) << 16) | ((g as u32) << 8) | (r as u32))
    }
    
    pub const fn from_bgra(r: u8, g: u8, b: u8) -> Self {
        // Direct BGRA format
        Color(0xFF_00_00_00 | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32))
    }
    
    pub fn to_u32(&self) -> u32 {
        self.0
    }
    
    pub fn blend(&self, bg: Color, alpha: u8) -> Color {
        let a = alpha as f32 / 255.0;
        let inv = 1.0 - a;
        
        let fg_r = ((self.0 >> 16) & 0xFF) as f32;
        let fg_g = ((self.0 >> 8) & 0xFF) as f32;
        let fg_b = (self.0 & 0xFF) as f32;
        
        let bg_r = ((bg.0 >> 16) & 0xFF) as f32;
        let bg_g = ((bg.0 >> 8) & 0xFF) as f32;
        let bg_b = (bg.0 & 0xFF) as f32;
        
        let r = (fg_r * a + bg_r * inv) as u8;
        let g = (fg_g * a + bg_g * inv) as u8;
        let b = (fg_b * a + bg_b * inv) as u8;
        
        Color::from_rgb(r, g, b)
    }
}

/// Framebuffer wrapper for drawing operations
pub struct Framebuffer {
    ptr: *mut u8,
    info: FramebufferInfo,
    format: PixelFormat,
}

impl Clone for Framebuffer {
    fn clone(&self) -> Self {
        Self {
            ptr: self.ptr,
            info: self.info,
            format: self.format,
        }
    }
}

impl Framebuffer {
    pub fn new(info: FramebufferInfo) -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            info,
            format: PixelFormat::Bgr,
        }
    }
    
    pub fn with_ptr(info: FramebufferInfo, ptr: *mut u8) -> Self {
        Self {
            ptr,
            info,
            format: PixelFormat::Bgr,
        }
    }
    
    pub fn width(&self) -> u32 { self.info.width }
    pub fn height(&self) -> u32 { self.info.height }
    pub fn stride(&self) -> u32 { self.info.stride }
    
    pub fn clear(&mut self, color: Color) {
        if self.ptr.is_null() { return; }
        let _pixels = (self.info.size as usize) / 4;
        unsafe {
            core::ptr::write_bytes(self.ptr, 0, self.info.size as usize);
        }
        // Fill with color
        for y in 0..self.info.height {
            for x in 0..self.info.width {
                self.set_pixel(x, y, color);
            }
        }
    }
    
    pub fn clear_fast(&mut self, color: Color) {
        if self.ptr.is_null() { return; }
        // Fast clear using stride
        let row_bytes = (self.info.stride as usize) * (self.info.height as usize);
        unsafe {
            let r = ((color.0 >> 16) & 0xFF) as u8;
            let g = ((color.0 >> 8) & 0xFF) as u8;
            let b = (color.0 & 0xFF) as u8;
            let a = ((color.0 >> 24) & 0xFF) as u8;
            for i in (0..row_bytes).step_by(4) {
                *self.ptr.add(i) = b;
                *self.ptr.add(i + 1) = g;
                *self.ptr.add(i + 2) = r;
                *self.ptr.add(i + 3) = a;
            }
        }
    }
    
    pub fn set_pixel(&mut self, x: u32, y: u32, color: Color) {
        if x >= self.info.width || y >= self.info.height || self.ptr.is_null() {
            return;
        }
        
        let offset = (y as usize) * (self.info.stride as usize) + (x as usize) * 4;
        
        unsafe {
            let ptr = self.ptr.add(offset);
            // BGRA format
            *ptr = ((color.0 >> 16) & 0xFF) as u8;       // B
            *ptr.add(1) = ((color.0 >> 8) & 0xFF) as u8;  // G  
            *ptr.add(2) = (color.0 & 0xFF) as u8;          // R
            *ptr.add(3) = ((color.0 >> 24) & 0xFF) as u8; // A
        }
    }
    
    pub fn get_pixel(&self, x: u32, y: u32) -> Color {
        if x >= self.info.width || y >= self.info.height || self.ptr.is_null() {
            return Color::BLACK;
        }
        
        let offset = (y as usize) * (self.info.stride as usize) + (x as usize) * 4;
        
        unsafe {
            let ptr = self.ptr.add(offset);
            let b = *ptr;
            let g = *ptr.add(1);
            let r = *ptr.add(2);
            let _a = *ptr.add(3);
            Color::from_rgb(r, g, b)
        }
    }
    
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: Color) {
        let x_end = (x + w).min(self.info.width);
        let y_end = (y + h).min(self.info.height);
        
        for py in y..y_end {
            for px in x..x_end {
                self.set_pixel(px, py, color);
            }
        }
    }
    
    /// Fast fill rectangle using memory copy
    pub fn fill_rect_fast(&mut self, x: u32, y: u32, w: u32, h: u32, color: Color) {
        let x_end = (x + w).min(self.info.width);
        let y_end = (y + h).min(self.info.height);
        let actual_w = x_end - x;
        
        if actual_w == 0 || y_end <= y { return; }
        
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
    
    pub fn draw_hline(&mut self, x1: u32, x2: u32, y: u32, color: Color) {
        let x_start = x1.min(x2);
        let x_end = (x1.max(x2) + 1).min(self.info.width);
        let y = y.min(self.info.height - 1);
        
        for x in x_start..x_end {
            self.set_pixel(x, y, color);
        }
    }
    
    pub fn draw_vline(&mut self, x: u32, y1: u32, y2: u32, color: Color) {
        let y_start = y1.min(y2);
        let y_end = (y1.max(y2) + 1).min(self.info.height);
        let x = x.min(self.info.width - 1);
        
        for y in y_start..y_end {
            self.set_pixel(x, y, color);
        }
    }
    
    pub fn draw_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: Color) {
        if w == 0 || h == 0 { return; }
        self.draw_hline(x, x + w - 1, y, color);
        self.draw_hline(x, x + w - 1, y + h - 1, color);
        self.draw_vline(x, y + 1, y + h - 2, color);
        self.draw_vline(x + w - 1, y + 1, y + h - 2, color);
    }
    
    pub fn draw_gradient(&mut self, x: u32, y: u32, w: u32, h: u32, 
                         top_color: Color, bottom_color: Color) {
        let x_end = (x + w).min(self.info.width);
        let y_end = (y + h).min(self.info.height);
        
        if h <= 1 { return; }
        
        for py in y..y_end {
            let t = (py - y) as f32 / (h - 1) as f32;
            let t_inv = 1.0 - t;
            
            let r = (((top_color.0 >> 16) & 0xFF) as f32 * t_inv 
                   + (((bottom_color.0 >> 16) & 0xFF) as f32 * t)) as u8;
            let g = (((top_color.0 >> 8) & 0xFF) as f32 * t_inv 
                   + (((bottom_color.0 >> 8) & 0xFF) as f32 * t)) as u8;
            let b = (((top_color.0) & 0xFF) as f32 * t_inv 
                   + (((bottom_color.0) & 0xFF) as f32 * t)) as u8;
            
            let color = Color::from_rgb(r, g, b);
            self.draw_hline(x, x_end - 1, py, color);
        }
    }
    
    /// Draw Windows-style logo (4 colored quadrants)
    /// Logo position: center - half_size to center + half_size
    pub fn draw_windows_logo(&mut self, cx: u32, cy: u32, size: u32) {
        let half = size / 2;
        let quarter = size / 4;
        let _ = quarter;
        
        // Top-left (blue)
        self.fill_rect(cx - half, cy - half, half, half, Color::WIN_BLUE);
        // Top-right (green)  
        self.fill_rect(cx, cy - half, half, half, Color::WIN_GREEN);
        // Bottom-left (orange)
        self.fill_rect(cx - half, cy, half, half, Color::WIN_ORANGE);
        // Bottom-right (red)
        self.fill_rect(cx, cy, half, half, Color::WIN_RED);
    }
    
    /// Draw a simple progress bar
    pub fn draw_progress_bar(&mut self, x: u32, y: u32, w: u32, h: u32, 
                             progress: f32, bg_color: Color, fg_color: Color) {
        // Background
        self.fill_rect(x, y, w, h, bg_color);
        
        // Progress fill
        let fill_w = ((w as f32) * progress.min(1.0).max(0.0)) as u32;
        if fill_w > 0 {
            self.fill_rect(x, y, fill_w, h, fg_color);
        }
    }
}
