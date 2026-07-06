//! Windows 7 style loading progress screen
//
//! Shows the spinning animation and "Starting Windows" message during boot.

#![allow(dead_code)]

use alloc::format;
use alloc::string::String;
use crate::graphics::fast_sin;
use crate::renderer::{Color, Framebuffer};
use crate::font::{BitmapFont, draw_text_centered};

pub struct LoadingScreen {
    fb: *mut Framebuffer,
    font: BitmapFont,
    message: String,
    progress: f32,
    animation_frame: usize,
    dots_count: usize,
}

impl LoadingScreen {
    pub fn new(fb: *mut Framebuffer, message: &str) -> Self {
        Self {
            fb,
            font: BitmapFont::new(),
            message: String::from(message),
            progress: 0.0,
            animation_frame: 0,
            dots_count: 0,
        }
    }
    
    pub fn set_progress(&mut self, progress: f32) {
        self.progress = progress.clamp(0.0, 1.0);
    }
    
    pub fn set_message(&mut self, message: &str) {
        self.message = String::from(message);
    }
    
    pub fn tick(&mut self) {
        self.animation_frame = (self.animation_frame + 1) % 12;
        self.dots_count = (self.dots_count + 1) % 4;
    }
    
    pub fn draw(&mut self) {
        let fb = unsafe { &mut *self.fb };
        fb.fill_rect_fast(0, 0, fb.width(), fb.height(), Color::BOOT_BG);
        
        let width = fb.width();
        let height = fb.height();
        
        self.draw_windows_logo(fb, width / 2, height / 3);
        
        let dots = ".".repeat(self.dots_count);
        let msg = format!("{}{}", self.message, dots);
        draw_text_centered(fb, &self.font, &msg,
            (width / 2) as i32, (height / 3 + 100) as i32,
            Color::WHITE, None);
        
        self.draw_progress_bar(fb, width / 4, height - 80, width / 2, 20);
        self.draw_spinner(fb, width / 2, height / 3 + 50);
    }
    
    fn draw_windows_logo(&self, fb: &mut Framebuffer, center_x: u32, center_y: u32) {
        let colors = [
            Color::from_rgb(0xF2, 0x50, 0x09),
            Color::from_rgb(0x00, 0xA4, 0xE4),
            Color::from_rgb(0x7F, 0xBB, 0x3A),
            Color::from_rgb(0xFF, 0xB9, 0x00),
        ];
        
        let size = 40u32;
        
        self.draw_logo_quadrant(fb, center_x - size / 2 - 5, center_y - size / 2 - 5, size, size, colors[0]);
        self.draw_logo_quadrant(fb, center_x + 5, center_y - size / 2 - 5, size, size, colors[1]);
        self.draw_logo_quadrant(fb, center_x - size / 2 - 5, center_y + 5, size, size, colors[2]);
        self.draw_logo_quadrant(fb, center_x + 5, center_y + 5, size, size, colors[3]);
    }
    
    fn draw_logo_quadrant(&self, fb: &mut Framebuffer, x: u32, y: u32, w: u32, h: u32, color: Color) {
        for py in 0..h {
            for px in 0..w {
                let grad = (px + py) as f32 / (w + h) as f32;
                let factor = 1.0 - grad * 0.3;
                let r = ((color.0 >> 16) & 0xFF) as f32;
                let g = ((color.0 >> 8) & 0xFF) as f32;
                let b = (color.0 & 0xFF) as f32;
                
                let new_color = Color::from_rgb(
                    (r * factor) as u8,
                    (g * factor) as u8,
                    (b * factor) as u8
                );
                
                fb.set_pixel(x + px, y + py, new_color);
            }
        }
    }
    
    fn draw_progress_bar(&self, fb: &mut Framebuffer, x: u32, y: u32, width: u32, height: u32) {
        fb.fill_rect(x, y, width, height, Color::from_rgb(0x30, 0x30, 0x30));
        
        let fill_width = (width as f32 * self.progress) as u32;
        if fill_width > 0 {
            fb.draw_gradient(x, y, fill_width, height,
                Color::from_rgb(0x00, 0x36, 0x70),
                Color::from_rgb(0x00, 0x5C, 0xB8));
        }
        
        fb.draw_rect(x, y, width, height, Color::from_rgb(0x60, 0x60, 0x60));
    }
    
    fn draw_spinner(&self, fb: &mut Framebuffer, center_x: u32, center_y: u32) {
        let radius = 15u32;
        let num_dots = 8;
        let dot_radius = 3u32;
        let two_pi = 2.0 * 3.14159265358979323846;
        
        for i in 0..num_dots {
            let angle = ((i as f32 + self.animation_frame as f32) / num_dots as f32) * two_pi;
            
            let px = center_x as f32 + (radius as f32 * fast_sin(angle));
            let py = center_y as f32 + (radius as f32 * fast_sin(angle + 1.5708));
            
            let alpha = ((i as f32 + self.animation_frame as f32) % num_dots as f32) / num_dots as f32;
            let intensity = ((alpha * 255.0) as u8).saturating_add(100);
            
            let color = Color::from_rgb(intensity, intensity, intensity);
            self.draw_circle(fb, px as u32, py as u32, dot_radius, color);
        }
    }
    
    fn draw_circle(&self, fb: &mut Framebuffer, cx: u32, cy: u32, radius: u32, color: Color) {
        let r = radius as i32;
        let cx = cx as i32;
        let cy = cy as i32;
        
        for y in -r..=r {
            for x in -r..=r {
                if x * x + y * y <= r * r {
                    fb.set_pixel((cx + x) as u32, (cy + y) as u32, color);
                }
            }
        }
    }
}
