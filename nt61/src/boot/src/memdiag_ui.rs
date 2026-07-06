//! Windows Memory Diagnostic Tool UI
//
//! Displays the diagnostic interface with two options.

#![allow(dead_code)]

use crate::renderer::{Color, Framebuffer};
use crate::font::{BitmapFont, draw_text, draw_text_centered};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemDiagAction {
    RestartNow,
    ScheduleCheck,
    GoBack,
}

pub struct MemDiagUI {
    fb: *mut Framebuffer,
    font: BitmapFont,
    selected_option: usize,
}

impl MemDiagUI {
    pub fn new(fb: *mut Framebuffer) -> Self {
        Self {
            fb,
            font: BitmapFont::new(),
            selected_option: 0,
        }
    }
    
    pub fn select_prev(&mut self) {
        if self.selected_option > 0 {
            self.selected_option -= 1;
        }
    }
    
    pub fn select_next(&mut self) {
        if self.selected_option < 1 {
            self.selected_option += 1;
        }
    }
    
    pub fn confirm(&self) -> MemDiagAction {
        match self.selected_option {
            0 => MemDiagAction::RestartNow,
            _ => MemDiagAction::ScheduleCheck,
        }
    }
    
    pub fn go_back(&self) -> MemDiagAction {
        MemDiagAction::GoBack
    }
    
    pub fn draw(&self) {
        let fb = unsafe { &mut *self.fb };
        fb.fill_rect_fast(0, 0, fb.width(), fb.height(), Color::BOOT_BG);
        
        let width = fb.width();
        let height = fb.height();
        
        self.draw_title_bar(fb, width);
        self.draw_content(fb, width);
        self.draw_bottom_bar(fb, width, height);
    }
    
    fn draw_title_bar(&self, fb: &mut Framebuffer, width: u32) {
        let title_height = 60u32;
        
        fb.draw_gradient(0, 0, width, title_height,
            Color::from_rgb(0x00, 0x36, 0x70),
            Color::from_rgb(0x00, 0x28, 0x5C));
        
        draw_text_centered(fb, &self.font, "Windows Memory Diagnostic",
            (width / 2) as i32, 18, Color::WHITE, None);
    }
    
    fn draw_content(&self, fb: &mut Framebuffer, width: u32) {
        let content_y = 100u32;
        
        draw_text_centered(fb, &self.font, "What do you want to do?",
            (width / 2) as i32, content_y as i32, Color::WHITE, None);
        
        let option_y = content_y + 60;
        let box_width = 500;
        let box_height = 60;
        let box_x = (width - box_width) / 2;
        
        self.draw_option(fb, box_x, option_y, box_width, box_height,
            "Restart now and check for problems (recommended)",
            self.selected_option == 0);
        
        self.draw_option(fb, box_x, option_y + box_height + 20, box_width, box_height,
            "Check for problems the next time I start my computer",
            self.selected_option == 1);
    }
    
    fn draw_option(&self, fb: &mut Framebuffer, x: u32, y: u32, width: u32, height: u32, 
                   text: &str, selected: bool) {
        if selected {
            fb.fill_rect_fast(x, y, width, height, Color::WIN_BLUE);
            fb.draw_rect(x, y, width, height, Color::WHITE);
            
            let radio_x = x + 20;
            let radio_y = y + height / 2;
            self.draw_radio_button(fb, radio_x, radio_y, 8, true);
            
            draw_text(fb, &self.font, text, x as i32 + 45, (y + height / 2 - 8) as i32,
                Color::WHITE, None);
        } else {
            fb.fill_rect(x, y, width, height, Color::from_rgb(0x30, 0x30, 0x30));
            fb.draw_rect(x, y, width, height, Color::from_rgb(0x60, 0x60, 0x60));
            
            let radio_x = x + 20;
            let radio_y = y + height / 2;
            self.draw_radio_button(fb, radio_x, radio_y, 8, false);
            
            draw_text(fb, &self.font, text, x as i32 + 45, (y + height / 2 - 8) as i32,
                Color::from_rgb(0xC0, 0xC0, 0xC0), None);
        }
    }
    
    fn draw_radio_button(&self, fb: &mut Framebuffer, cx: u32, cy: u32, radius: u32, filled: bool) {
        let r = radius as i32;
        let cx = cx as i32;
        let cy = cy as i32;
        
        for dy in -r..=r {
            for dx in -r..=r {
                let dist_sq = dx * dx + dy * dy;
                if dist_sq <= r * r && dist_sq >= (r - 2) * (r - 2) {
                    fb.set_pixel((cx + dx) as u32, (cy + dy) as u32, Color::WHITE);
                } else if filled && dist_sq <= (r - 3) * (r - 3) {
                    fb.set_pixel((cx + dx) as u32, (cy + dy) as u32, Color::WHITE);
                }
            }
        }
    }
    
    fn draw_bottom_bar(&self, fb: &mut Framebuffer, width: u32, height: u32) {
        let bar_height = 50u32;
        let bar_y = height - bar_height;
        
        fb.fill_rect(0, bar_y, width, bar_height, Color::from_rgb(0x20, 0x20, 0x20));
        fb.draw_hline(0, width, bar_y, Color::from_rgb(0x40, 0x40, 0x40));
        
        draw_text_centered(fb, &self.font, "UP/DOWN=Select    ENTER=OK    ESC=Cancel",
            (width / 2) as i32, (bar_y + 15) as i32,
            Color::from_rgb(0x80, 0x80, 0x80), None);
    }
}
