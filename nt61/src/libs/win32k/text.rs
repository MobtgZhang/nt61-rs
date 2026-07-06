//! Text Rendering
//
//! Implements text drawing functions, font management, and text metrics.
//
//! ## Windows 7 Font Architecture
//
//! Fonts are described by LOGFONT structures and selected into DCs.
//! The system uses TrueType fonts primarily.
//
//! Reference: ReactOS win32ss/gdi/fonts, Geoff Chappell

extern crate alloc;

use crate::kprintln;
use crate::libs::win32k::objects::GdiFont;
use crate::libs::win32k::dc::{DcObject, TA_LEFT, TA_CENTER, TA_RIGHT, TA_TOP, TA_BOTTOM, TA_BASELINE};
use crate::libs::win32k::surface::{GdiSurface, PIXEL_FORMAT_32BPP_ARGB};
use alloc::vec::Vec;

// =============================================================================
// Font Metrics Structures
// =============================================================================

/// TEXTMETRIC structure (Windows)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TEXTMETRICW {
    pub tm_height: i32,
    pub tm_ascent: i32,
    pub tm_descent: i32,
    pub tm_internal_leading: i32,
    pub tm_external_leading: i32,
    pub tm_ave_char_width: i32,
    pub tm_max_char_width: i32,
    pub tm_weight: i32,
    pub tm_overhang: i32,
    pub tm_hanged_char_width: i32,
    pub tm_first_char: u16,
    pub tm_default_char: u16,
    pub tm_break_char: u16,
    pub tm_default_align: u8,
    pub tm_char_set: u8,
    pub tm_flags: u16,
}

impl TEXTMETRICW {
    pub fn new() -> Self {
        Self {
            tm_height: 16,
            tm_ascent: 14,
            tm_descent: 2,
            tm_internal_leading: 0,
            tm_external_leading: 2,
            tm_ave_char_width: 8,
            tm_max_char_width: 8,
            tm_weight: 400,
            tm_overhang: 0,
            tm_hanged_char_width: 0,
            tm_first_char: 0x20,
            tm_default_char: 0x1F,
            tm_break_char: 0x20,
            tm_default_align: 0,
            tm_char_set: 0,
            tm_flags: 0,
        }
    }
}

/// ABC structure (character width metrics)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ABC {
    pub abcA: i32,  // Left side bearing
    pub abcB: u32,  // Width of character
    pub abcC: i32,  // Right side bearing
}

/// LOGFONT structure (Windows)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LOGFONTW {
    pub lf_height: i32,
    pub lf_width: i32,
    pub lf_escapement: i32,
    pub lf_orientation: i32,
    pub lf_weight: i32,
    pub lf_italic: u8,
    pub lf_underline: u8,
    pub lf_strike_out: u8,
    pub lf_char_set: u8,
    pub lf_out_precision: u8,
    pub lf_clip_precision: u8,
    pub lf_quality: u8,
    pub lf_pitch_and_family: u8,
    pub lf_face_name: [u16; 32],
}

impl LOGFONTW {
    pub fn new() -> Self {
        Self::default()
    }
}

// =============================================================================
// Bitmap Font (8x8)
// =============================================================================

/// 8x8 bitmap font data
/// Each character is 8 bytes (one byte per row, MSB = leftmost pixel)
const FONT_DATA_8X8: &[u8] = &[
    // Space ' '
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // '!' (exclamation)
    0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00,
    // '"' (quote)
    0x6C, 0x6C, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
    // '#'
    0x24, 0x7E, 0x24, 0x24, 0x7E, 0x24, 0x00, 0x00,
    // '$'
    0x04, 0x2E, 0x68, 0x3C, 0x0E, 0x7B, 0x00, 0x00,
    // '%'
    0x60, 0x66, 0x0C, 0x18, 0x30, 0x66, 0x06, 0x00,
    // '&'
    0x3C, 0x66, 0x3C, 0x38, 0x67, 0x66, 0x3F, 0x00,
    // '''
    0x18, 0x18, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    // '('
    0x08, 0x10, 0x20, 0x20, 0x20, 0x10, 0x08, 0x00,
    // ')'
    0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08, 0x00,
    // '*'
    0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00,
    // '+'
    0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00,
    // ','
    0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x10, 0x00,
    // '-'
    0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00,
    // '.'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00,
    // '/'
    0x02, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x00, 0x00,
    // '0'
    0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C, 0x00,
    // '1'
    0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00,
    // '2'
    0x3C, 0x66, 0x06, 0x1C, 0x30, 0x60, 0x7E, 0x00,
    // '3'
    0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00,
    // '4'
    0x06, 0x0E, 0x1E, 0x66, 0x7F, 0x06, 0x06, 0x00,
    // '5'
    0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00,
    // '6'
    0x1C, 0x30, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00,
    // '7'
    0x7E, 0x66, 0x0C, 0x18, 0x18, 0x18, 0x18, 0x00,
    // '8'
    0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00,
    // '9'
    0x3C, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x38, 0x00,
    // ':'
    0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00,
    // ';'
    0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x10, 0x00,
    // '<'
    0x08, 0x10, 0x20, 0x40, 0x20, 0x10, 0x08, 0x00,
    // '='
    0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00,
    // '>'
    0x08, 0x04, 0x02, 0x01, 0x02, 0x04, 0x08, 0x00,
    // '?'
    0x3C, 0x66, 0x06, 0x1C, 0x18, 0x00, 0x18, 0x00,
    // '@'
    0x3C, 0x66, 0x6E, 0x6E, 0x60, 0x62, 0x3C, 0x00,
    // 'A'
    0x18, 0x24, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x00,
    // 'B'
    0x7C, 0x42, 0x42, 0x7C, 0x42, 0x42, 0x7C, 0x00,
    // 'C'
    0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00,
    // 'D'
    0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00,
    // 'E'
    0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00,
    // 'F'
    0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00,
    // 'G'
    0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3E, 0x00,
    // 'H'
    0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00,
    // 'I'
    0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00,
    // 'J'
    0x1F, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38, 0x00,
    // 'K'
    0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00,
    // 'L'
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00,
    // 'M'
    0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00,
    // 'N'
    0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00,
    // 'O'
    0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00,
    // 'P'
    0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00,
    // 'Q'
    0x3C, 0x66, 0x66, 0x66, 0x66, 0x6F, 0x3D, 0x00,
    // 'R'
    0x7C, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, 0x00,
    // 'S'
    0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00,
    // 'T'
    0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00,
    // 'U'
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00,
    // 'V'
    0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00,
    // 'W'
    0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00,
    // 'X'
    0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00,
    // 'Y'
    0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00,
    // 'Z'
    0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00,
    // 'a' (lowercase)
    0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00,
    // 'b'
    0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00,
    // 'c'
    0x00, 0x00, 0x3C, 0x66, 0x60, 0x66, 0x3C, 0x00,
    // 'd'
    0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x00,
    // 'e'
    0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00,
    // 'f'
    0x1C, 0x30, 0x30, 0x7E, 0x30, 0x30, 0x30, 0x00,
    // 'g'
    0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x3C,
    // 'h'
    0x60, 0x60, 0x6C, 0x76, 0x66, 0x66, 0x66, 0x00,
    // 'i'
    0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00,
    // 'j'
    0x0C, 0x00, 0x1C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38,
    // 'k'
    0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66, 0x00,
    // 'l'
    0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00,
    // 'm'
    0x00, 0x00, 0x6E, 0x7F, 0x7F, 0x6B, 0x63, 0x00,
    // 'n'
    0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00,
    // 'o'
    0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00,
    // 'p'
    0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60,
    // 'q'
    0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06,
    // 'r'
    0x00, 0x00, 0x6C, 0x76, 0x60, 0x60, 0x60, 0x00,
    // 's'
    0x00, 0x00, 0x3C, 0x66, 0x30, 0x66, 0x3C, 0x00,
    // 't'
    0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x1C, 0x00,
    // 'u'
    0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00,
    // 'v'
    0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00,
    // 'w'
    0x00, 0x00, 0x63, 0x6B, 0x7F, 0x7F, 0x36, 0x00,
    // 'x'
    0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00,
    // 'y'
    0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x3C,
    // 'z'
    0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00,
];

/// 16x16 font for better quality (block characters)
const FONT_DATA_16X16: &[u8] = &[
    // Space ' '
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 'A'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0xC0, 0xC0, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x40, 0x40, 0x70, 0x70, 0x40, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x38, 0x38, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x10, 0x1C, 0x1C, 0x10, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00,
    // 'B'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFC, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0xFC, 0xFC, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x40, 0x40, 0xFC, 0xFC, 0x40, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0xFC, 0xFC, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00,
    // 'C'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xC0, 0xF0, 0xF0, 0xC0, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x40, 0x40, 0xC0, 0xC0, 0x40, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x30, 0x30, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00,
];

/// Character width table for proportional fonts (ASCII 0x20-0x7A)
const CHAR_WIDTHS_8X8: &[u8] = &[
    8, 3, 4, 6, 6, 6, 6, 4, 3, 3, 6, 6, 3, 6, 3, 6,  // ' ' to '/'
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 3, 3, 6, 6, 6, 6,  // '0' to '?'
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,  // '@' to 'O'
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,  // 'P' to 'Z'
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,  // '[' to '_'
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,  // '`' to 'o'
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,  // 'p' to 'z'
];

// =============================================================================
// Text Drawing Functions
// =============================================================================

/// Get DC surface
fn get_dc_surface(dc: &DcObject) -> *mut GdiSurface {
    if dc.surface != 0 {
        dc.surface as *mut GdiSurface
    } else {
        crate::libs::win32k::surface::get_primary_surface()
    }
}

/// Set pixel on surface
fn set_pixel(surface: *mut GdiSurface, x: i32, y: i32, color: u32) -> bool {
    if surface.is_null() {
        return false;
    }

    let surf = unsafe { &mut *surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return false;
    }

    if x < 0 || x >= surf.width || y < 0 || y >= surf.height {
        return false;
    }

    let offset = (y * surf.pitch + x * 4) as isize;

    let _ = &offset;
    let _ = &offset;
    unsafe {
        core::ptr::write_unaligned(surf.bits.offset(offset) as *mut u32, color);
    }
    true
}

/// Get pixel from surface
fn get_pixel(surface: *mut GdiSurface, x: i32, y: i32) -> u32 {
    if surface.is_null() {
        return 0;
    }

    let surf = unsafe { &*surface };

    let _ = &surf;
    let _ = &surf;
    if surf.bits.is_null() {
        return 0;
    }

    if x < 0 || x >= surf.width || y < 0 || y >= surf.height {
        return 0;
    }

    let offset = (y * surf.pitch + x * 4) as isize;

    let _ = &offset;
    let _ = &offset;
    unsafe {
        core::ptr::read_unaligned(surf.bits.offset(offset) as *const u32)
    }
}

/// Draw a character using 8x8 bitmap font
pub fn draw_char_8x8(surface: *mut GdiSurface, x: i32, y: i32, ch: u8, fg_color: u32, bg_color: u32) {
    if surface.is_null() {
        return;
    }

    // Calculate font data index (ASCII 0x20-0x7A maps to indices 0-90)
    // Uppercase: 0x41-0x5A -> 0x41 - 0x20 = 65
    // Lowercase: 0x61-0x7A -> 0x61 - 0x20 = 97
    let char_idx = if ch >= 0x20 && ch <= 0x7A {
        (ch - 0x20) as usize
    } else {
        0  // Space for others
    };
    let _ = &char_idx;

    let font_base = char_idx * 8;

    let _ = &font_base;
    let _ = &font_base;

    for row in 0..8 {
        let row_data = if font_base + row < FONT_DATA_8X8.len() {
            FONT_DATA_8X8[font_base + row]
        } else {
            0
        };
        let _ = &row_data;

        for col in 0..8 {
            let bit = (row_data >> (7 - col)) & 1;
            let _ = &bit;
            let _ = &bit;
            let color = if bit != 0 { fg_color } else { bg_color };
            let _ = &color;
            let _ = &color;
            set_pixel(surface, x + col, y + row as i32, color);
        }
    }
}

/// Draw a character using 16x16 bitmap font
pub fn draw_char_16x16(surface: *mut GdiSurface, x: i32, y: i32, ch: u8, fg_color: u32, bg_color: u32) {
    if surface.is_null() {
        return;
    }

    let char_idx = if ch >= 0x41 && ch <= 0x46 {
        (ch - 0x41) as usize
    } else {
        0
    };

    let _ = &char_idx;

    let font_base = char_idx * 16;

    let _ = &font_base;
    let _ = &font_base;

    for row in 0..16 {
        let row_data_low = if font_base + row < FONT_DATA_16X16.len() {
            FONT_DATA_16X16[font_base + row]
        } else {
            0
        };
        let _ = &row_data_low;

        // For simplicity, draw each bit as a 1x1 pixel
        // In a full implementation, we'd upscale
        for col in 0..8 {
            let bit = (row_data_low >> (7 - col)) & 1;
            let _ = &bit;
            let _ = &bit;
            let color = if bit != 0 { fg_color } else { bg_color };
            let _ = &color;
            let _ = &color;
            set_pixel(surface, x + col, y + row as i32, color);
        }
    }
}

/// Get character width for 8x8 font
pub fn get_char_width_8x8(ch: u8) -> i32 {
    // Index: ASCII 0x20 maps to index 0, 0x7A maps to index 90
    let idx = if ch >= 0x20 && ch <= 0x7A {
        (ch - 0x20) as usize
    } else {
        0 // Default for invalid characters
    };
    let _ = &idx;

    if idx < CHAR_WIDTHS_8X8.len() {
        CHAR_WIDTHS_8X8[idx] as i32
    } else {
        8 // Default width
    }
}

/// Calculate text extent for ASCII string
pub fn calc_text_extent(text: &[u8], font_height: i32) -> (i32, i32) {
    let mut width = 0;
    for &ch in text {
        width += if ch >= 0x20 && ch <= 0x7E {
            get_char_width_8x8(ch)
        } else {
            8
        };
    }
    (width, font_height)
}

// =============================================================================
// Gre TextOut - Text Output
// =============================================================================

/// GreTextOut - Draw text string
pub fn GreTextOut(
    dc: &mut DcObject,
    x: i32,
    y: i32,
    text: &[u8],
) -> bool {
    let surface = get_dc_surface(dc);
    let _ = &surface;
    let _ = &surface;
    if surface.is_null() {
        return false;
    }

    let fg_color = dc.text_color;

    let _ = &fg_color;
    let _ = &fg_color;
    let bg_color = if dc.bk_mode == 2 {  // OPAQUE
        dc.bg_color
    } else {
        0  // TRANSPARENT
    };
    let _ = &bg_color;

    let mut cursor_x = x;
    let font_height = if dc.font != 0 {
        // Get font height from font object
        16  // Default
    } else {
        8  // System font
    };
    let _ = &font_height;

    for &ch in text {
        if ch >= 0x20 && ch <= 0x7E {
            draw_char_8x8(surface, cursor_x, y, ch, fg_color, bg_color);
            cursor_x += get_char_width_8x8(ch);
        }
    }

    // kprintln!("[win32k] GreTextOut: {} chars at ({},{})", text.len(), x, y)  // kprintln disabled (memcpy crash workaround);

    true
}

/// GreExtTextOut - Extended text output
pub fn GreExtTextOut(
    dc: &mut DcObject,
    x: i32,
    y: i32,
    options: u32,
    clip_rect: Option<&crate::libs::win32k::objects::Rect>,
    text: &[u16],
    dx: Option<&[i32]>,
) -> bool {
    let _ = options;
    let _ = clip_rect;
    let _ = text;
    let _ = dx;
    let surface = get_dc_surface(dc);
    let _ = &surface;
    let _ = &surface;
    if surface.is_null() {
        return false;
    }

    let fg_color = dc.text_color;

    let _ = &fg_color;
    let _ = &fg_color;
    let bg_color = if dc.bk_mode == 2 {
        dc.bg_color
    } else {
        0
    };
    let _ = &bg_color;

    // Convert UTF-16 to ASCII for our font
    let ascii_text: Vec<u8> = text.iter()
        .take(256)
        .map(|&c| if c < 128 { c as u8 } else { b'?' })
        .collect();

    let mut cursor_x = x;

    // Handle text alignment
    match dc.text_align & TA_RIGHT {
        0 => {}  // TA_LEFT
        _ => {
            // Calculate total width first
            let mut total_width = 0;
            for (i, &ch) in ascii_text.iter().enumerate() {
                let width = dx.and_then(|d| d.get(i)).copied().unwrap_or_else(|| get_char_width_8x8(ch));
                let _ = &width;
                let _ = &width;
                total_width += width;
            }
            cursor_x -= total_width;
        }
    }

    for (i, &ch) in ascii_text.iter().enumerate() {
        if ch >= 0x20 && ch <= 0x7E {
            draw_char_8x8(surface, cursor_x, y, ch, fg_color, bg_color);
            
            let char_width = dx.and_then(|d| d.get(i).copied())
                .unwrap_or_else(|| get_char_width_8x8(ch));
            
            let _ = &char_width;
            cursor_x += char_width;
        }
    }

    // kprintln!("[win32k] GreExtTextOut: {} chars at ({},{})", text.len(), x, y)  // kprintln disabled (memcpy crash workaround);

    true
}

// =============================================================================
// Text Metrics
// =============================================================================

/// Get text metrics for the current font
pub fn GreGetTextMetrics(dc: &DcObject, tm: &mut TEXTMETRICW) -> bool {
    let _ = dc;
    // Fill with default values for system font
    tm.tm_height = 16;
    tm.tm_ascent = 14;
    tm.tm_descent = 2;
    tm.tm_internal_leading = 0;
    tm.tm_external_leading = 2;
    tm.tm_ave_char_width = 8;
    tm.tm_max_char_width = 8;
    tm.tm_weight = 400;
    tm.tm_overhang = 0;
    tm.tm_hanged_char_width = 0;
    tm.tm_first_char = 0x20;
    tm.tm_default_char = 0x1F;
    tm.tm_break_char = 0x20;
    tm.tm_default_align = 0;
    tm.tm_char_set = 0;
    tm.tm_flags = 0;

    true
}

/// Get character widths (ABC widths)
pub fn GreGetCharABCWidths(
    dc: &DcObject,
    first: u16,
    last: u16,
    widths: &mut [ABC],
) -> bool {
    let _ = dc;
    for (i, ch) in (first..=last).enumerate() {
        if i < widths.len() {
            widths[i] = ABC {
                abcA: 0,
                abcB: get_char_width_8x8(ch as u8) as u32,
                abcC: 0,
            };
        }
    }
    true
}

/// Get character widths as integers
pub fn GreGetCharWidth32(
    dc: &DcObject,
    first: u16,
    last: u16,
    widths: &mut [i32],
) -> bool {
    let _ = dc;
    for (i, ch) in (first..=last).enumerate() {
        if i < widths.len() {
            widths[i] = get_char_width_8x8(ch as u8);
        }
    }
    true
}

// =============================================================================
// Text Extent
// =============================================================================

/// Get text extent (string dimensions)
pub fn GreGetTextExtentPoint(
    dc: &DcObject,
    text: &[u8],
    extent: &mut crate::libs::win32k::dc::SizeL,
) -> bool {
    let _ = dc;
    let (width, height) = calc_text_extent(text, 16);
    extent.cx = width;
    extent.cy = height;
    true
}

/// Get text extent with character widths
pub fn GreGetTextExtentPoint32(
    dc: &DcObject,
    text: &[u8],
    extent: &mut crate::libs::win32k::dc::SizeL,
) -> bool {
    let _ = dc;
    let (width, height) = calc_text_extent(text, 16);
    extent.cx = width;
    extent.cy = height;
    true
}

// =============================================================================
// Font Selection
// =============================================================================

/// Select a font into DC
pub fn GreSelectFont(dc: &mut DcObject, font_handle: u64) -> u64 {
    let old_font = dc.font;
    let _ = &old_font;
    let _ = &old_font;
    dc.font = font_handle;
    // kprintln!("[win32k] GreSelectFont: old=0x{:016x}, new=0x{:016x}", old_font, font_handle)  // kprintln disabled (memcpy crash workaround);
    old_font
}

/// Get current font from DC
pub fn GreGetCurrentFont(dc: &DcObject) -> u64 {
    dc.font
}

// =============================================================================
// Font Creation
// =============================================================================

/// Create a font from LOGFONT
pub fn GreCreateFontIndirect(lf: &LOGFONTW) -> u64 {
    crate::libs::win32k::objects::GdiCreateFont(
        lf.lf_height,
        lf.lf_width,
        lf.lf_weight,
        lf.lf_italic != 0,
        &lf.lf_face_name,
    )
}

// =============================================================================
// String Width Calculation
// =============================================================================

/// Calculate string width
pub fn GreTabbedTextOut(
    dc: &mut DcObject,
    x: i32,
    y: i32,
    text: &[u16],
    tab_stops: &[i32],
    tab_origin: i32,
) -> (i32, i32, i32) {
    let _ = (dc, x, y, tab_stops, tab_origin);
    // Simplified: just return width/height
    let mut width = 0;
    for &c in text {
        let ch = if c < 128 { c as u8 } else { b'?' };
        let _ = &ch;
        let _ = &ch;
        width += get_char_width_8x8(ch);
    }
    (width, 16, 0)  // width, height, last char width
}
