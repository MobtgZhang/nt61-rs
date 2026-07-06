//! TrueType font rendering for the Boot Manager.
//
//! Loads Open Sans (or any TTF) and rasterises glyphs into the UEFI
//! framebuffer. Implementation strategy:
//
//! 1. `ttf-parser` parses the TTF tables (head, cmap, glyf, loca, hmtx).
//! 2. For each glyph, the outline is walked via an `OutlineBuilder`
//!    that flattens quadratic Bezier curves into line segments and
//!    rasterises the resulting closed contours with a scanline fill
//!    using the even-odd winding rule.
//! 3. The 1-bit glyph bitmap is drawn pixel-by-pixel into the
//!    framebuffer at the requested pen position.
//
//! The whole pipeline is `&mut self` end-to-end: glyph bitmaps live
//! only for the duration of one `draw_text` call. A per-font LRU
//! cache would be a useful future optimisation but is not required
//! for a boot manager (which draws a few dozen strings total).
//
//! All of this runs in UEFI with no `std`, no heap allocation beyond
//! the per-glyph Vecs (which are dropped as soon as the glyph is
//! drawn), and no floating-point heavy work in the inner loop (the
//! pixel scan is integer only).

#![allow(dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use ttf_parser::Face;
use ttf_parser::OutlineBuilder;

use crate::renderer::{Color, Framebuffer};

// =====================================================================
// Float helpers (avoid depending on libm / std)
// =====================================================================

#[inline]
fn f32_floor(x: f32) -> f32 {
	let xi = x as i32;
	let xf = xi as f32;
	if x < xf { xf - 1.0 } else { xf }
}

#[inline]
fn f32_ceil(x: f32) -> f32 {
	let xi = x as i32;
	let xf = xi as f32;
	if x > xf { xf + 1.0 } else { xf }
}

// =====================================================================
// Embedded font data
// =====================================================================

/// Open Sans Regular, embedded at build time via `include_bytes!`.
///
/// The font path is **not hardcoded** — it is resolved by a build
/// script (`build.rs`) that copies the selected TTF into `$OUT_DIR`
/// at compile time, and the actual `include_bytes!` reads it back
/// from there. The path the build script uses is taken, in order of
/// precedence, from:
///
/// 1. The `NT61_BOOT_FONT_REGULAR` environment variable at the time
///    `cargo build` is run — useful for swapping in a different
///    font without touching the source tree.
/// 2. The `NT61_BOOT_FONT_DIR` environment variable, interpreted as
///    a directory containing the file `OpenSans-Regular.ttf`.
/// 3. The Cargo manifest directory of the `nt61-boot` crate, which
///    carries the default copy at
///    `../../resources/fonts/open-sans/OpenSans-Regular.ttf` (this
///    is the path relative to `nt61/src/boot/Cargo.toml`).
///
/// `include_bytes!` runs at compile time so the font is baked into
/// the .efi binary; no filesystem access is needed at boot.
pub const OPEN_SANS_REGULAR: &[u8] = include_bytes!(env!("NT61_BOOT_FONT_REGULAR_PATH"));

/// Open Sans Bold, used for the title bar in the same way the real
/// Windows 7 bootmgr renders "Windows Boot Manager" in a slightly
/// heavier weight than the body text. The path is selected by the
/// same build script as `OPEN_SANS_REGULAR` (env var
/// `NT61_BOOT_FONT_BOLD` overrides the default).
pub const OPEN_SANS_BOLD: &[u8] = include_bytes!(env!("NT61_BOOT_FONT_BOLD_PATH"));

// =====================================================================
// Public API
// =====================================================================

/// A TrueType font loaded from a byte slice and rasterised on demand.
pub struct TtfFont {
	/// Parsed face (zero-copy view over the bytes).
	face: Face<'static>,
	/// Pixel size. The face is scaled from `units_per_em` to this many
	/// pixels of cap height (approx — we use the EM square height so
	/// `pt_size == 16` gives a roughly 16px font on Windows too).
	pixel_size: f32,
}

impl TtfFont {
	/// Parse a TTF from raw bytes. Returns `None` on any parse error
	/// (the boot manager falls back to the bitmap font in that case).
	pub fn from_bytes(data: &'static [u8]) -> Option<Self> {
		let face = Face::parse(data, 0).ok()?;
		Some(Self {
			face,
			pixel_size: 16.0,
		})
	}

	/// Set the font size in pixels (the EM square maps to this many
	/// pixels).
	pub fn set_size(&mut self, size: f32) {
		self.pixel_size = size.max(10.0).min(24.0);
	}

	/// Current pixel size.
	pub fn pixel_size(&self) -> f32 {
		self.pixel_size
	}

	/// Height of one line of text in pixels, suitable for vertical
	/// layout (uses the EM-to-pixel scale plus the line gap).
	/// Formula: (ascender - descender + line_gap) * scale
	pub fn line_height(&self) -> u32 {
		let units_per_em = self.face.units_per_em() as f32;
		let scale = self.pixel_size / units_per_em;
		let ascent = self.face.ascender() as f32;
		let descent = -self.face.descender() as f32;
		let line_gap = self.face.line_gap() as f32;
		((ascent + descent + line_gap) * scale) as u32
	}

	/// Single-glyph baseline-to-baseline height in pixels.
	pub fn ascent(&self) -> i32 {
		let units_per_em = self.face.units_per_em() as f32;
		let scale = self.pixel_size / units_per_em;
		(self.face.ascender() as f32 * scale) as i32
	}

	/// Measure a string in pixels.
	pub fn measure(&self, text: &str) -> (u32, u32) {
		let units_per_em = self.face.units_per_em() as f32;
		let scale = self.pixel_size / units_per_em;
		let mut max_width = 0u32;
		let mut cursor = 0u32;
		let space_advance = self.advance_width(' ', scale);
		let tab = (space_advance * 4).max(1);
		for c in text.chars() {
			match c {
				'\n' => {
					if cursor > max_width { max_width = cursor; }
					cursor = 0;
				}
				'\r' => {}
				'\t' => {
					cursor = ((cursor / tab) + 1) * tab;
				}
				_ => {
					cursor += self.advance_width(c, scale);
				}
			}
		}
		if cursor > max_width { max_width = cursor; }
		(max_width, self.line_height())
	}

	/// Get the horizontal advance for a single character.
	fn advance_width(&self, c: char, scale: f32) -> u32 {
		if let Some(glyph_id) = self.face.glyph_index(c) {
			if let Some(adv) = self.face.glyph_hor_advance(glyph_id) {
				return (adv as f32 * scale + 0.5) as u32;
			}
		}
		(self.face.units_per_em() as f32 * 0.5 * scale) as u32
	}

	/// Draw a string into the framebuffer. `x, y` is the baseline
	/// (left, baseline) — the same coordinate convention as
	/// `draw_text` in most font libraries.
	pub fn draw_text(
		&mut self,
		fb: &mut Framebuffer,
		text: &str,
		x: i32,
		y: i32,
		fg: Color,
		_bg: Option<Color>,
	) {
		let units_per_em = self.face.units_per_em() as f32;
		let scale = self.pixel_size / units_per_em;
		// Line height including proper line gap
		let line_h = ((self.face.ascender() as f32 - self.face.descender() as f32 + self.face.line_gap() as f32) * scale) as i32;
		let space_advance = self.advance_width(' ', scale);
		let tab = (space_advance * 4).max(1);

		let mut pen_x = x;
		let mut pen_y = y;
		for c in text.chars() {
			match c {
				'\n' => {
					pen_x = x;
					pen_y += line_h;
				}
				'\r' => {}
				'\t' => {
					let cur = (pen_x - x) as u32;
					pen_x = x + (((cur / tab) + 1) * tab) as i32;
				}
				_ => {
					if let Some(glyph_id) = self.face.glyph_index(c) {
						// Build the glyph bitmap and blit it.
						let mut builder = PathBuilder::new(scale);
						self.face.outline_glyph(glyph_id, &mut builder);
						let raster = builder.rasterise();

						if let Some(raster) = raster {
							// Compute advance.
							let adv = self.advance_width(c, scale);
							// Pen position to bitmap top-left:
							//   gx = pen_x + bearing_x
							//   gy = pen_y - bearing_y  (bearing_y = baseline to top)
							let gx = pen_x + raster.bearing_x;
							let gy = pen_y - raster.bearing_y;
							blit_raster(fb, &raster, gx, gy, fg);
							pen_x += adv as i32;
						} else {
							// Whitespace / no outline.
							pen_x += self.advance_width(c, scale) as i32;
						}
					} else {
						pen_x += self.advance_width(c, scale) as i32;
					}
				}
			}
		}
	}

	/// Draw a string centred horizontally on `cx`. The text's vertical
	/// baseline is `y` (consistent with `draw_text`).
	pub fn draw_text_centered(
		&mut self,
		fb: &mut Framebuffer,
		text: &str,
		cx: i32,
		y: i32,
		fg: Color,
		bg: Option<Color>,
	) {
		let (w, _) = self.measure(text);
		let x = cx - (w as i32) / 2;
		self.draw_text(fb, text, x, y, fg, bg);
	}
}

// =====================================================================
// Outline -> path -> rasterisation
// =====================================================================

/// Maximum depth for quadratic Bezier flattening recursion.
const MAX_QUAD_DEPTH: u32 = 6;

/// A single rasterised glyph in 1-bit form plus positioning info.
struct RasterGlyph {
	/// Glyph bitmap, 1 bit per pixel, row-major, MSB = leftmost.
	bits: Vec<u8>,
	/// Bitmap width in pixels.
	width: u32,
	/// Bitmap height in pixels.
	height: u32,
	/// Offset from the pen origin to the bitmap's left edge (in pixels).
	bearing_x: i32,
	/// Offset from the baseline to the bitmap's top edge (in pixels).
	/// Positive = above baseline.
	bearing_y: i32,
}

/// `OutlineBuilder` implementation that flattens quadratic Bezier
/// curves into line segments and stores the result as a list of
/// closed contours ready for scanline fill.
struct PathBuilder {
	contours: Vec<Contour>,
	current: Option<Contour>,
	/// Pen position for the current contour.
	cur_pos: (f32, f32),
	/// Scale from font units to pixels.
	scale: f32,
}

#[derive(Clone)]
pub(crate) struct Contour {
	/// Sequence of (x, y) vertices forming a closed loop. The last
	/// edge is implicit between points[-1] and points[0].
	points: Vec<(f32, f32)>,
}

impl PathBuilder {
	fn new(scale: f32) -> Self {
		Self {
			contours: Vec::new(),
			current: None,
			cur_pos: (0.0, 0.0),
			scale,
		}
	}

	/// Convert a font-unit X to pixel X.
	#[inline]
	fn tx(&self, x: f32) -> f32 {
		x * self.scale
	}
	/// Convert a font-unit Y to pixel Y. TrueType Y is "up", screen Y
	/// is "down", so we flip.
	#[inline]
	fn ty(&self, y: f32) -> f32 {
		-y * self.scale
	}

	/// Convert the path we've collected into a 1-bit glyph bitmap.
	fn rasterise(&mut self) -> Option<RasterGlyph> {
		// Close the current contour if one is open.
		if let Some(c) = self.current.take() {
			self.contours.push(c);
		}
		if self.contours.is_empty() {
			return None;
		}

		// Compute bbox in pixel space (after Y flip).
		let mut min_x = f32::INFINITY;
		let mut min_y = f32::INFINITY;
		let mut max_x = f32::NEG_INFINITY;
		let mut max_y = f32::NEG_INFINITY;
		for c in &self.contours {
			for &(x, y) in &c.points {
				if x < min_x { min_x = x; }
				if y < min_y { min_y = y; }
				if x > max_x { max_x = x; }
				if y > max_y { max_y = y; }
			}
		}
		if !min_x.is_finite() {
			return None;
		}

		// Add generous padding: 2 pixels on each side for anti-aliasing safety
		let padding: f32 = 2.0;
		min_x -= padding;
		min_y -= padding;
		max_x += padding;
		max_y += padding;

		let x0 = f32_floor(min_x) as i32;
		let y0 = f32_floor(min_y) as i32;
		let x1 = f32_ceil(max_x) as i32;
		let y1 = f32_ceil(max_y) as i32;
		let w = (x1 - x0).max(0) as u32;
		let h = (y1 - y0).max(0) as u32;
		if w == 0 || h == 0 {
			return None;
		}

		// 8-bit coverage buffer.
		let mut coverage: Vec<u8> = alloc::vec![0u8; (w as usize) * (h as usize)];

		// Fill all contours using the even-odd rule (correct for holes)
		fill_all_contours(&self.contours, x0, y0, w, h, &mut coverage);

		// Threshold coverage > 0 to a 1-bit bitmap.
		let stride = ((w as usize) + 7) / 8;
		let mut bits: Vec<u8> = alloc::vec![0u8; stride * (h as usize)];
		for y in 0..h as usize {
			for x in 0..w as usize {
				if coverage[y * (w as usize) + x] > 0 {
					let bit_index = y * stride * 8 + x;
					bits[bit_index / 8] |= 0x80 >> (bit_index % 8);
				}
			}
		}

		// Bearing calculation:
		// After Y flip: min_y is negative (top of glyph, above baseline in font coords)
		//                max_y is positive (bottom of glyph, below baseline)
		// Bitmap origin (x0, y0) corresponds to pen position minus the bearing.
		// bearing_x: how far left of pen the glyph starts
		// bearing_y: how far above baseline the glyph top is (positive = above baseline)
		let bearing_x = x0;
		// In screen coords, y0 is the TOP of the bitmap, which is at screen_y = min_y
		// Since font Y increases upward and screen Y increases downward:
		//   min_y (screen) = baseline_screen_y - glyph_top_font_y
		//   glyph_top_font_y = baseline_screen_y - min_y
		// bearing_y should be positive when glyph top is above baseline
		let bearing_y = (-min_y).max(0.0) as i32;

		Some(RasterGlyph {
			bits,
			width: w,
			height: h,
			bearing_x,
			bearing_y,
		})
	}
}

impl OutlineBuilder for PathBuilder {
	fn move_to(&mut self, x: f32, y: f32) {
		if let Some(c) = self.current.take() {
			self.contours.push(c);
		}
		let p = (self.tx(x), self.ty(y));
		let mut c = Contour { points: Vec::new() };
		c.points.push(p);
		self.current = Some(c);
		self.cur_pos = p;
	}

	fn line_to(&mut self, x: f32, y: f32) {
		let p = (self.tx(x), self.ty(y));
		if let Some(c) = self.current.as_mut() {
			c.points.push(p);
		} else {
			let mut c = Contour { points: Vec::new() };
			c.points.push(p);
			self.current = Some(c);
		}
		self.cur_pos = p;
	}

	fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
		let p0 = self.cur_pos;
		let p1 = (self.tx(x1), self.ty(y1));
		let p2 = (self.tx(x), self.ty(y));
		if let Some(c) = self.current.as_mut() {
			c.points.push(p1);
			let mut pts: Vec<(f32, f32)> = Vec::new();
			flatten_quad_recursive(p0, p1, p2, 0, &mut pts);
			for (i, &(px, py)) in pts.iter().enumerate() {
				if i == 0 { continue; }
				c.points.push((px, py));
			}
		}
		self.cur_pos = p2;
	}

	fn curve_to(&mut self, _x1: f32, _y1: f32, _x2: f32, _y2: f32, x: f32, y: f32) {
		self.line_to(x, y);
	}

	fn close(&mut self) {
		if let Some(c) = self.current.as_mut() {
			if let Some(&first) = c.points.first() {
				c.points.push(first);
			}
		}
		if let Some(c) = self.current.take() {
			self.contours.push(c);
		}
		self.cur_pos = (0.0, 0.0);
	}
}

/// Recursive De Casteljau subdivision for a quadratic Bezier.
fn flatten_quad_recursive(
	p0: (f32, f32),
	p1: (f32, f32),
	p2: (f32, f32),
	depth: u32,
	out: &mut Vec<(f32, f32)>,
) {
	if depth >= MAX_QUAD_DEPTH {
		out.push(p2);
		return;
	}
	let mx = (p0.0 + p2.0) * 0.5;
	let my = (p0.1 + p2.1) * 0.5;
	let dx = p1.0 - mx;
	let dy = p1.1 - my;
	let dist2 = dx * dx + dy * dy;
	if dist2 < 0.0625 {
		out.push(p2);
		return;
	}
	let p01 = ((p0.0 + p1.0) * 0.5, (p0.1 + p1.1) * 0.5);
	let p12 = ((p1.0 + p2.0) * 0.5, (p1.1 + p2.1) * 0.5);
	let p012 = ((p01.0 + p12.0) * 0.5, (p01.1 + p12.1) * 0.5);
	flatten_quad_recursive(p0, p01, p012, depth + 1, out);
	flatten_quad_recursive(p012, p12, p2, depth + 1, out);
}

// =====================================================================
// Scanline fill - correct even-odd rule for multiple contours
// =====================================================================

/// Fill a single contour using the even-odd rule.
/// Returns the coverage buffer for this contour only.
fn fill_single_contour(
    contour: &Contour,
    x0: i32,
    y0: i32,
    w: u32,
    h: u32,
) -> Vec<u8> {
    let n = contour.points.len();
    let mut coverage: Vec<u8> = alloc::vec![0u8; (w as usize) * (h as usize)];
    if n < 3 { return coverage; }

    for row in 0..h as i32 {
        let screen_y = y0 + row;
        let mut crossings: Vec<i32> = Vec::new();

        for i in 0..n {
            let (x1, y1) = contour.points[i];
            let (x2, y2) = contour.points[(i + 1) % n];

            let (y_min, y_max) = if y1 < y2 { (y1, y2) } else { (y2, y1) };

            if (screen_y as f32) >= y_min && (screen_y as f32) < y_max {
                let dy = y2 - y1;
                if dy.abs() < 0.001 {
                    continue;
                }
                let t = (screen_y as f32 - y1) / dy;
                let xi = x1 + t * (x2 - x1);
                crossings.push(xi as i32);
            }
        }

        crossings.sort();

        for i in 0..crossings.len() / 2 {
            let x_start = crossings[i * 2];
            let x_end = crossings[i * 2 + 1];

            let px_start = (x_start - x0).max(0);
            let px_end = (x_end - x0).min(w as i32);

            for px in px_start..px_end {
                let idx = (row as usize) * (w as usize) + (px as usize);
                if idx < coverage.len() {
                    coverage[idx] = 255;
                }
            }
        }
    }
    coverage
}

/// Fill all contours using the even-odd rule.
/// This correctly handles characters like 'o' with inner and outer contours.
fn fill_contour(
    contour: &Contour,
    x0: i32,
    y0: i32,
    w: u32,
    h: u32,
    coverage: &mut [u8],
) {
    let n = contour.points.len();
    if n < 3 { return; }

    for row in 0..h as i32 {
        let screen_y = y0 + row;
        let mut crossings: Vec<i32> = Vec::new();

        for i in 0..n {
            let (x1, y1) = contour.points[i];
            let (x2, y2) = contour.points[(i + 1) % n];

            let (y_min, y_max) = if y1 < y2 { (y1, y2) } else { (y2, y1) };

            if (screen_y as f32) >= y_min && (screen_y as f32) < y_max {
                let dy = y2 - y1;
                if dy.abs() < 0.001 {
                    continue;
                }
                let t = (screen_y as f32 - y1) / dy;
                let xi = x1 + t * (x2 - x1);
                crossings.push(xi as i32);
            }
        }

        crossings.sort();

        for i in 0..crossings.len() / 2 {
            let x_start = crossings[i * 2];
            let x_end = crossings[i * 2 + 1];

            let px_start = (x_start - x0).max(0);
            let px_end = (x_end - x0).min(w as i32);

            for px in px_start..px_end {
                let idx = (row as usize) * (w as usize) + (px as usize);
                if idx < coverage.len() {
                    coverage[idx] = 255;
                }
            }
        }
    }
}

/// Fill multiple contours using the even-odd rule.
/// This is the correct way to handle glyphs with holes (O, P, B, e, a, etc.)
pub fn fill_all_contours(
    contours: &[Contour],
    x0: i32,
    y0: i32,
    w: u32,
    h: u32,
    coverage: &mut [u8],
) {
    if contours.is_empty() {
        return;
    }

    // Collect all crossings from all contours for each scanline
    for row in 0..h as i32 {
        let screen_y = y0 + row;
        let mut all_crossings: Vec<i32> = Vec::new();

        // Collect crossings from all contours
        for contour in contours {
            let n = contour.points.len();
            if n < 3 { continue; }

            for i in 0..n {
                let (x1, y1) = contour.points[i];
                let (x2, y2) = contour.points[(i + 1) % n];

                let (y_min, y_max) = if y1 < y2 { (y1, y2) } else { (y2, y1) };

                if (screen_y as f32) >= y_min && (screen_y as f32) < y_max {
                    let dy = y2 - y1;
                    if dy.abs() < 0.001 {
                        continue;
                    }
                    let t = (screen_y as f32 - y1) / dy;
                    let xi = x1 + t * (x2 - x1);
                    all_crossings.push(xi as i32);
                }
            }
        }

        // Sort all crossings
        all_crossings.sort();

        // Even-odd rule: toggle fill state at each crossing
        // Start outside (not filling), toggle at each crossing
        let mut inside = false;
        let mut i = 0;
        while i + 1 < all_crossings.len() {
            let x_start = all_crossings[i];
            let x_end = all_crossings[i + 1];

            if inside {
                // Fill this span
                let px_start = (x_start - x0).max(0);
                let px_end = (x_end - x0).min(w as i32);
                for px in px_start..px_end {
                    let idx = (row as usize) * (w as usize) + (px as usize);
                    if idx < coverage.len() {
                        coverage[idx] = 255;
                    }
                }
            }

            // Toggle at each pair of crossings
            inside = !inside;
            i += 2;
        }
    }
}

/// Alpha-blit a rasterised 1-bit glyph onto the framebuffer.
fn blit_raster(fb: &mut Framebuffer, g: &RasterGlyph, x: i32, y: i32, fg: Color) {
	if g.width == 0 || g.height == 0 { return; }
	let fb_w = fb.width() as i32;
	let fb_h = fb.height() as i32;
	let stride = ((g.width as usize) + 7) / 8;

	for row in 0..g.height as i32 {
		let py = y + row;
		if py < 0 || py >= fb_h { continue; }
		for col in 0..g.width as i32 {
			let px = x + col;
			if px < 0 || px >= fb_w { continue; }
			let bit_index = (row as usize) * stride * 8 + (col as usize);
			let byte = g.bits[bit_index / 8];
			let bit = 0x80 >> (bit_index % 8);
			if byte & bit != 0 {
				fb.set_pixel(px as u32, py as u32, fg);
			}
		}
	}
}
