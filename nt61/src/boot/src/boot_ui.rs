//! Windows 7 style Boot Manager UI
//
//! Renders the graphical boot menu with:
//! - Top gray bar: "Windows Boot Manager"
//! - Black body with boot entries
//! - Bottom gray bar with keyboard hints
//! - F8 advanced options support
//! - Auto-scaling based on resolution
//
//! This module owns the higher-level layout (margins, bar heights,
//! selection highlight) and delegates actual glyph rendering to
//! `font_ttf::TtfFont`. The legacy `BitmapFont` is retained as a
//! last-resort fallback if TTF parsing fails for any reason.

#![allow(dead_code)]

use alloc::vec::Vec;
use crate::renderer::{Color, Framebuffer};
use crate::font_ttf::TtfFont;
use crate::font::{BitmapFont, draw_text as draw_bitmap_text,
                  draw_text_centered as draw_bitmap_text_centered};

/// Render backend enum. TTF is used when available; the bitmap font is
/// only consulted if the TTF could not be loaded (e.g. corrupt
/// embedded bytes — extremely unlikely with `include_bytes!`).
pub enum FontBackend {
    Ttf(TtfFont),
    Bitmap {
        font: BitmapFont,
        char_w: u32,
        char_h: u32,
    },
}

impl FontBackend {
    /// Build a backend from an Open Sans TTF (preferred) or fall back
    /// to the bitmap font if TTF parsing fails.
    pub fn from_ttf(data: &'static [u8], pixel_size: f32) -> Self {
        match TtfFont::from_bytes(data) {
            Some(mut ttf) => {
                ttf.set_size(pixel_size);
                FontBackend::Ttf(ttf)
            }
            None => {
                let mut bm = BitmapFont::new();
                bm.set_size(pixel_size as u32);
                let char_w = bm.char_width();
                let char_h = bm.char_height();
                FontBackend::Bitmap { font: bm, char_w, char_h }
            }
        }
    }

    pub fn char_height(&self) -> u32 {
        match self {
            FontBackend::Ttf(f) => f.line_height(),
            FontBackend::Bitmap { char_h, .. } => *char_h,
        }
    }

    pub fn draw_text(&mut self, fb: &mut Framebuffer, text: &str,
                     x: i32, y: i32, fg: Color, bg: Option<Color>) {
        match self {
            FontBackend::Ttf(f) => f.draw_text(fb, text, x, y, fg, bg),
            FontBackend::Bitmap { font, .. } => {
                draw_bitmap_text(fb, font, text, x, y, fg, bg);
            }
        }
    }

    pub fn draw_text_centered(&mut self, fb: &mut Framebuffer, text: &str,
                              cx: i32, y: i32, fg: Color, bg: Option<Color>) {
        match self {
            FontBackend::Ttf(f) => f.draw_text_centered(fb, text, cx, y, fg, bg),
            FontBackend::Bitmap { font, .. } => {
                draw_bitmap_text_centered(fb, font, text, cx, y, fg, bg);
            }
        }
    }

    pub fn measure(&mut self, text: &str) -> (u32, u32) {
        match self {
            FontBackend::Ttf(f) => f.measure(text),
            FontBackend::Bitmap { char_w, char_h, .. } => {
                // Approximate: width = chars * char_w, height = char_h.
                let width = text.chars().count() as u32 * (*char_w);
                (width, *char_h)
            }
        }
    }
}

pub struct BootUI {
    fb: *mut Framebuffer,
    font: FontBackend,
    font_size: u32,
    selected_index: usize,
    scroll_offset: usize,
    show_advanced: bool,
    boot_entries: Vec<BootEntry>,
    // Layout constants (computed based on resolution)
    margin_top: u32,
    margin_bottom: u32,
    margin_left: u32,
    margin_right: u32,
    bar_height: u32,
    entry_height: u32,
}

#[derive(Debug, Clone)]
pub struct BootEntry {
    pub name: alloc::string::String,
    pub description: alloc::string::String,
    pub guid: [u8; 16],
    pub device_path: alloc::string::String,
}

impl BootUI {
    /// Build a BootUI that uses the embedded Open Sans Regular TTF.
    pub fn new(fb: *mut Framebuffer) -> Self {
        Self::with_font(fb, crate::font_ttf::OPEN_SANS_REGULAR)
    }

    /// Build a BootUI from a specific TTF byte slice. Used by
    /// `main.rs` so the font choice is explicit.
    pub fn with_font(fb: *mut Framebuffer, ttf_bytes: &'static [u8]) -> Self {
        let fb_ref = unsafe { &*fb };
        let width = fb_ref.width();
        let height = fb_ref.height();

        // Auto-calculate font size based on resolution
        // Base: 1024x768 -> font_size 14
        // Smaller font for better readability and proper glyph rendering
        let base_width: u32 = 1024;
        let base_height: u32 = 768;
        let base_font_size: u32 = 14;

        let scale_w = width as f32 / base_width as f32;
        let scale_h = height as f32 / base_height as f32;
        let scale = scale_w.min(scale_h).max(0.5);

        let font_size = (base_font_size as f32 * scale).max(12.0).min(18.0);

        let font = FontBackend::from_ttf(ttf_bytes, font_size);

        let margin_top = (height / 16).max(20);
        let margin_bottom = (height / 16).max(20);
        let margin_left = (width / 20).max(30);
        let margin_right = (width / 20).max(30);

        let char_h = font.char_height();
        let bar_height = (char_h + 20).max(44).min(72);
        let entry_height = (char_h + 16).max(32).min(56);

        Self {
            fb,
            font,
            font_size: font_size as u32,
            selected_index: 1,
            scroll_offset: 0,
            show_advanced: false,
            boot_entries: Vec::new(),
            margin_top,
            margin_bottom,
            margin_left,
            margin_right,
            bar_height,
            entry_height,
        }
    }

    pub fn set_entries(&mut self, entries: Vec<BootEntry>) {
        self.boot_entries = entries;
        if self.selected_index >= self.boot_entries.len() {
            self.selected_index = 0;
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn select_next(&mut self) {
        if self.selected_index < self.boot_entries.len().saturating_sub(1) {
            self.selected_index += 1;
        }
    }

    pub fn selected_entry(&self) -> Option<&BootEntry> {
        self.boot_entries.get(self.selected_index)
    }

    pub fn toggle_advanced(&mut self) {
        self.show_advanced = !self.show_advanced;
    }

    pub fn is_advanced_shown(&self) -> bool {
        self.show_advanced
    }

    pub fn draw(&mut self) {
        let fb = unsafe { &mut *self.fb };
        fb.fill_rect_fast(0, 0, fb.width(), fb.height(), Color::BOOT_BG);
        self.draw_top_bar(fb);
        self.draw_entries(fb);
        self.draw_bottom_bar(fb);

        if self.show_advanced {
            self.draw_advanced_options(fb);
        }
    }

    fn draw_top_bar(&mut self, fb: &mut Framebuffer) {
        let width = fb.width();
        let y = self.margin_top;
        let height = self.bar_height;

        // Draw top bar with gradient, respecting left/right margins
        fb.draw_gradient(self.margin_left, y, 200, height,
            Color::from_rgb(0x80, 0x80, 0x80),
            Color::from_rgb(0x70, 0x70, 0x70));

        let text_y = y + (height - self.font.char_height()) / 2;
        self.font.draw_text_centered(fb, "Windows Boot Manager",
            (width / 2) as i32, text_y as i32, Color::BLACK, None);
    }

    fn draw_bottom_bar(&mut self, fb: &mut Framebuffer) {
        let width = fb.width();
        let height = fb.height();
        let bar_height = self.bar_height;
        let y = height - self.margin_bottom - bar_height;

        fb.draw_gradient(self.margin_left, y, width - 2 * self.margin_left, bar_height,
            Color::from_rgb(0x60, 0x60, 0x60),
            Color::from_rgb(0x80, 0x80, 0x80));

        let hints = if self.show_advanced {
            "ESC=Cancel    ENTER=Continue    F8=Normal Boot"
        } else {
            "ENTER=Boot    F8=Advanced Options    ESC=Refresh"
        };

        let text_y = y + (bar_height - self.font.char_height()) / 2;
        self.font.draw_text_centered(fb, hints,
            (width / 2) as i32, text_y as i32,
            Color::BLACK, None);
    }

    fn draw_entries(&mut self, fb: &mut Framebuffer) {
        let menu_top = self.margin_top + self.bar_height + 30;
        let menu_bottom = fb.height() - self.margin_bottom - self.bar_height - 30;
        let item_height = self.entry_height;
        let visible_count = ((menu_bottom - menu_top) / item_height) as usize;

        let end_index = (self.scroll_offset + visible_count).max(self.boot_entries.len());

        for i in self.scroll_offset..end_index {
            // Copy the entry name out so we can drop the borrow on
            // self.boot_entries before calling self.draw_entry (which
            // borrows self mutably).
            let name = self.boot_entries[i].name.clone();
            let y = menu_top + ((i - self.scroll_offset) as u32) * item_height;
            let is_selected = i == self.selected_index;
            self.draw_entry_by_name(fb, &name, y, is_selected);
        }
    }

    fn draw_entry_by_name(&mut self, fb: &mut Framebuffer, name: &str, y: u32, selected: bool) {
        let text_y = y + (self.entry_height - self.font.char_height()) / 2;
        let entry_height = self.entry_height;
        let margin_left = self.margin_left;
        let margin_right = self.margin_right;

        if selected {
            let width = fb.width();
            let box_height = entry_height - 4;
            fb.fill_rect_fast(margin_left, y + 2,
                width.saturating_sub(margin_left).saturating_sub(margin_right),
                box_height, Color::SELECT_BG);
            self.font.draw_text(fb, "> ", (margin_left + 10) as i32, text_y as i32, Color::SELECT_FG, None);
            self.font.draw_text(fb, name, (margin_left + 35) as i32, text_y as i32, Color::SELECT_FG, None);
        } else {
            self.font.draw_text(fb, name, (margin_left + 20) as i32, text_y as i32, Color::NORMAL_FG, None);
        }
    }

    fn draw_entry(&mut self, fb: &mut Framebuffer, entry: &BootEntry, y: u32, selected: bool) {
        self.draw_entry_by_name(fb, &entry.name, y, selected);
    }

    fn draw_advanced_options(&mut self, fb: &mut Framebuffer) {
        let width = fb.width();
        let height = fb.height();

        let overlay_width = (width * 3 / 4).max(600);
        let overlay_height = (height * 3 / 4).max(400);
        let overlay_x = (width - overlay_width) / 2;
        let overlay_y = (height - overlay_height) / 2;

        for y in overlay_y..(overlay_y + overlay_height) {
            for x in overlay_x..(overlay_x + overlay_width) {
                let existing = fb.get_pixel(x, y);
                let blended = Color::from_rgb(0, 0, 0).blend(existing, 180);
                fb.set_pixel(x, y, blended);
            }
        }

        let window_padding = 20u32;
        let window_x = overlay_x + window_padding;
        let window_width = overlay_width - 2 * window_padding;
        let window_height = overlay_height - 2 * window_padding;
        let title_bar_height = self.bar_height;

        fb.draw_rect(window_x, overlay_y + window_padding, window_width, window_height,
            Color::from_rgb(0x80, 0x80, 0x80));

        fb.fill_rect_fast(window_x + 1, overlay_y + window_padding + 1, window_width - 2, title_bar_height,
            Color::WIN_BLUE);

        let title_y = overlay_y + window_padding + (title_bar_height - self.font.char_height()) / 2;
        self.font.draw_text_centered(fb, "Advanced Boot Options",
            (width / 2) as i32, title_y as i32,
            Color::WHITE, None);

        let options = [
            "Safe Mode",
            "Safe Mode with Networking",
            "Safe Mode with Command Prompt",
            "Enable Boot Logging",
            "Enable low-resolution video",
            "Last Known Good",
            "Directory Services Restore Mode",
            "Debugging Mode",
        ];

        let content_top = overlay_y + window_padding + title_bar_height + 20;
        let option_spacing = self.entry_height + 4;

        for (i, opt) in options.iter().enumerate() {
            let y = content_top + (i as u32) * option_spacing;
            if y + self.font.char_height() < overlay_y + overlay_height - window_padding - 10 {
                self.font.draw_text(fb, opt, (window_x + 20) as i32, y as i32,
                    Color::WHITE, None);
            }
        }
    }
}
