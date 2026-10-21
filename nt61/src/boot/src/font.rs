//! TrueType-backed text renderer for graphical boot interfaces.

extern crate alloc;

use crate::renderer::{Color, Framebuffer};
use alloc::vec::Vec;
use nt61_fonts::{FontFace, TERMINAL_FONT};

/// A rasterized glyph with antialiased coverage data.
pub struct BitmapGlyph {
    width: usize,
    height: usize,
    xmin: i32,
    ymin: i32,
    baseline_offset: i32,
    coverage: Vec<u8>,
}

impl BitmapGlyph {
    pub fn width(&self) -> u32 {
        self.width as u32
    }

    pub fn draw(&self, fb: &mut Framebuffer, x: i32, y: i32, fg: Color, bg: Option<Color>) {
        let top_y = y + self.baseline_offset - (self.height as i32 + self.ymin);
        let origin_x = x + self.xmin;

        for row in 0..self.height {
            for column in 0..self.width {
                let Some(coverage) = self.coverage.get(row * self.width + column) else {
                    continue;
                };
                if *coverage == 0 {
                    continue;
                }
                let pixel_x = origin_x + column as i32;
                let pixel_y = top_y + row as i32;
                if pixel_x < 0 || pixel_y < 0 {
                    continue;
                }
                let blended = match bg {
                    Some(bg_color) => blend_colors(bg_color, fg, *coverage),
                    None => match fb.get_pixel(pixel_x as u32, pixel_y as u32) {
                        Some(background) => blend_colors(background, fg, *coverage),
                        None => continue,
                    },
                };
                fb.set_pixel(pixel_x as u32, pixel_y as u32, blended);
            }
        }
    }
}

/// A text renderer backed by an embedded TrueType face.
pub struct BitmapFont {
    face: FontFace,
    size: u32,
}

impl BitmapFont {
    pub fn new() -> Self {
        Self::with_face(TERMINAL_FONT)
    }

    pub fn with_face(data: &[u8]) -> Self {
        let face =
            FontFace::from_bytes(data).expect("embedded boot font is not a valid TrueType face");
        Self {
            face,
            size: DEFAULT_FONT_SIZE,
        }
    }

    pub fn set_size(&mut self, size: u32) {
        self.size = size.max(1);
    }

    pub fn char_width(&self) -> u32 {
        self.face
            .metrics('M', self.size)
            .map_or(1, |metrics| ((metrics.advance_width + 0.5) as u32).max(1))
    }

    pub fn char_height(&self) -> u32 {
        self.face
            .line_metrics(self.size)
            .map_or(self.size, |metrics| metrics.line_height)
    }

    pub fn line_height(&self) -> u32 {
        self.char_height()
    }

    pub fn measure(&self, text: &str) -> (u32, u32) {
        measure_string(self, text)
    }

    fn get_char(&self, ch: char) -> Option<BitmapGlyph> {
        let glyph = self.face.rasterize(ch, self.size)?;
        let baseline_offset = self
            .face
            .line_metrics(self.size)
            .map_or(self.size as i32, |metrics| metrics.ascent);
        Some(BitmapGlyph {
            width: glyph.metrics.width,
            height: glyph.metrics.height,
            xmin: glyph.metrics.xmin,
            ymin: glyph.metrics.ymin,
            baseline_offset,
            coverage: glyph.coverage,
        })
    }

    pub fn draw_text(
        &mut self,
        fb: &mut Framebuffer,
        text: &str,
        x: i32,
        y: i32,
        fg: Color,
        bg: Option<Color>,
    ) {
        draw_text(fb, self, text, x, y, fg, bg);
    }

    pub fn draw_text_centered(
        &mut self,
        fb: &mut Framebuffer,
        text: &str,
        center_x: i32,
        y: i32,
        fg: Color,
        bg: Option<Color>,
    ) {
        let (width, _) = self.measure(text);
        self.draw_text(fb, text, center_x - width as i32 / 2, y, fg, bg);
    }
}

impl Default for BitmapFont {
    fn default() -> Self {
        Self::new()
    }
}

/// Draw text, advancing the cursor by each glyph's true advance width.
pub fn draw_text(
    fb: &mut Framebuffer,
    font: &BitmapFont,
    text: &str,
    x: i32,
    y: i32,
    fg: Color,
    bg: Option<Color>,
) {
    let mut cursor_x = x;
    let mut cursor_y = y;

    for ch in text.chars() {
        match ch {
            '\n' => {
                cursor_x = x;
                cursor_y += font.line_height() as i32;
            }
            '\r' => cursor_x = x,
            '\t' => {
                let advance = font.char_width() as i32 * TAB_COLUMNS;
                let remainder = (cursor_x - x) % advance;
                cursor_x += advance - remainder;
            }
            _ => {
                if let Some(glyph) = font.get_char(ch) {
                    let advance = font
                        .face
                        .metrics(ch, font.size)
                        .map_or(glyph.width() as i32, |metrics| {
                            (metrics.advance_width + 0.5) as i32
                        });
                    glyph.draw(fb, cursor_x, cursor_y, fg, bg);
                    cursor_x += advance.max(1);
                }
            }
        }
    }
}

/// Measure rendered text in pixels.
pub fn measure_string(font: &BitmapFont, text: &str) -> (u32, u32) {
    let mut width = 0;
    let mut max_width = 0;
    let mut height = font.line_height();

    for ch in text.chars() {
        match ch {
            '\n' => {
                max_width = max_width.max(width);
                width = 0;
                height += font.line_height();
            }
            '\t' => {
                let advance = font.char_width() * (TAB_COLUMNS as u32);
                width = ((width / advance) + 1) * advance;
            }
            _ => {
                if let Some(metrics) = font.face.metrics(ch, font.size) {
                    width += (metrics.advance_width + 0.5) as u32;
                }
            }
        }
    }

    (max_width.max(width), height)
}

/// Blend a glyph coverage value between a background and foreground colour.
fn blend_colors(background: Color, foreground: Color, coverage: u8) -> Color {
    let alpha = u32::from(coverage);
    let inverse = 255 - alpha;
    let background_b = (background.0 >> 16) & 0xFF;
    let background_g = (background.0 >> 8) & 0xFF;
    let background_r = background.0 & 0xFF;
    let foreground_b = (foreground.0 >> 16) & 0xFF;
    let foreground_g = (foreground.0 >> 8) & 0xFF;
    let foreground_r = foreground.0 & 0xFF;
    let b = (background_b * inverse + foreground_b * alpha) / 255;
    let g = (background_g * inverse + foreground_g * alpha) / 255;
    let r = (background_r * inverse + foreground_r * alpha) / 255;
    Color((b << 16) | (g << 8) | r | 0xFF00_0000)
}

/// Default rendered size for boot UI text.
const DEFAULT_FONT_SIZE: u32 = 16;

/// Number of character widths used by a tab stop.
const TAB_COLUMNS: i32 = 4;
