//! Shared TrueType font loading and rasterization helpers.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// License-safe sans-serif face used by graphical boot UI.
pub const UI_FONT: &[u8] = include_bytes!("../assets/DejaVuSans.ttf");

/// License-safe monospaced face used by terminal and boot logs.
pub const TERMINAL_FONT: &[u8] = include_bytes!("../assets/DejaVuSansMono.ttf");

/// Layout metrics for one rasterized glyph.
#[derive(Clone, Copy, Debug)]
pub struct GlyphMetrics {
    pub width: usize,
    pub height: usize,
    pub xmin: i32,
    pub ymin: i32,
    pub advance_width: f32,
}

/// Coverage bitmap for one glyph, with one byte per pixel.
#[derive(Clone, Debug)]
pub struct RasterizedGlyph {
    pub metrics: GlyphMetrics,
    pub coverage: Vec<u8>,
}

/// Vertical metrics used to lay out a line of text.
#[derive(Clone, Copy, Debug)]
pub struct FontLineMetrics {
    /// Distance from the top of a line to the baseline, rounded to pixels.
    pub ascent: i32,
    /// Distance from the baseline to the bottom of a line, rounded to pixels.
    /// This value is negative for a normal downward-facing descent.
    pub descent: i32,
    /// Extra gap requested by the font between two lines.
    pub line_gap: i32,
    /// Rounded distance from the top of one line to the top of the next line.
    pub line_height: u32,
}

impl RasterizedGlyph {
    pub fn coverage_at(&self, x: usize, y: usize) -> Option<u8> {
        if x >= self.metrics.width || y >= self.metrics.height {
            return None;
        }
        self.coverage.get(y * self.metrics.width + x).copied()
    }
}

/// A parsed TrueType face.
#[derive(Debug)]
pub struct FontFace {
    font: fontdue::Font,
}

impl FontFace {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let settings = fontdue::FontSettings {
            collection_index: 0,
            scale: DEFAULT_OPTIMIZATION_SIZE,
            load_substitutions: false,
        };
        let font = fontdue::Font::from_bytes(data, settings)?;
        Ok(Self { font })
    }

    pub fn has_glyph(&self, ch: char) -> bool {
        self.font.has_glyph(ch)
    }

    pub fn metrics(&self, ch: char, pixel_size: u32) -> Option<GlyphMetrics> {
        if !self.has_glyph(ch) {
            return None;
        }
        let metrics = self.font.metrics(ch, pixel_size as f32);
        Some(GlyphMetrics {
            width: metrics.width,
            height: metrics.height,
            xmin: metrics.xmin,
            ymin: metrics.ymin,
            advance_width: metrics.advance_width,
        })
    }

    /// Returns the vertical metrics needed to align a line of glyphs.
    pub fn line_metrics(&self, pixel_size: u32) -> Option<FontLineMetrics> {
        let metrics = self.font.horizontal_line_metrics(pixel_size as f32)?;
        Some(FontLineMetrics {
            ascent: (metrics.ascent + 0.5) as i32,
            descent: (metrics.descent - 0.5) as i32,
            line_gap: (metrics.line_gap + 0.5) as i32,
            line_height: (metrics.new_line_size + 0.5).max(1.0) as u32,
        })
    }

    pub fn rasterize(&self, ch: char, pixel_size: u32) -> Option<RasterizedGlyph> {
        if !self.has_glyph(ch) {
            return None;
        }
        let (metrics, coverage) = self.font.rasterize(ch, pixel_size as f32);
        Some(RasterizedGlyph {
            metrics: GlyphMetrics {
                width: metrics.width,
                height: metrics.height,
                xmin: metrics.xmin,
                ymin: metrics.ymin,
                advance_width: metrics.advance_width,
            },
            coverage,
        })
    }
}

/// The geometry optimization size requested by `fontdue`.
const DEFAULT_OPTIMIZATION_SIZE: f32 = 16.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_terminal_font_parses() {
        let face = FontFace::from_bytes(TERMINAL_FONT).expect("terminal font must parse");
        assert!(face.has_glyph('M'));
        assert!(face.has_glyph('C'));
        assert!(face.has_glyph('>'));
    }
}
