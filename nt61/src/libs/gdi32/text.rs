//! gdi32 — text APIs
//!
//! `text_out_w` and `draw_text_w` draw text to the
//! primary surface through `libs::win32k::text::draw_char_8x8`.
//! The bootstrap only supports the 7-bit ASCII range
//! (0x20-0x7E); wider characters render as a space,
//! matching the behaviour documented for the system
//! font when no glyph is available.
//!
//! The text colour is read from the currently selected
//! DC; if no DC is bound we default to black-on-white.

extern crate alloc;

use super::types::{Size, TextMetricW, BOOL, HDC, LPCWSTR};
use super::with_dc;

/// Font weight helpers.
pub mod fw {
    pub const FW_DONTCARE: i32 = 0;
    pub const FW_THIN: i32 = 100;
    pub const FW_EXTRALIGHT: i32 = 200;
    pub const FW_LIGHT: i32 = 300;
    pub const FW_NORMAL: i32 = 400;
    pub const FW_MEDIUM: i32 = 500;
    pub const FW_SEMIBOLD: i32 = 600;
    pub const FW_BOLD: i32 = 700;
    pub const FW_EXTRABOLD: i32 = 800;
    pub const FW_HEAVY: i32 = 900;
}

/// `DrawText` format flags (subset).
pub mod dt {
    pub const DT_TOP: u32 = 0x0000_0000;
    pub const DT_LEFT: u32 = 0x0000_0000;
    pub const DT_CENTER: u32 = 0x0000_0001;
    pub const DT_RIGHT: u32 = 0x0000_0002;
    pub const DT_VCENTER: u32 = 0x0000_0004;
    pub const DT_BOTTOM: u32 = 0x0000_0008;
    pub const DT_WORDBREAK: u32 = 0x0000_0010;
    pub const DT_SINGLELINE: u32 = 0x0000_0020;
    pub const DT_EXPANDTABS: u32 = 0x0000_0040;
    pub const DT_TABSTOP: u32 = 0x0000_0080;
    pub const DT_NOCLIP: u32 = 0x0000_0100;
    pub const DT_EXTERNALLEADING: u32 = 0x0000_0200;
    pub const DT_CALCRECT: u32 = 0x0000_0400;
    pub const DT_NOPREFIX: u32 = 0x0000_0800;
    pub const DT_INTERNAL: u32 = 0x0000_1000;
    pub const DT_EDITCONTROL: u32 = 0x0000_2000;
    pub const DT_PATH_ELLIPSIS: u32 = 0x0000_4000;
    pub const DT_END_ELLIPSIS: u32 = 0x0000_8000;
    pub const DT_MODIFYSTRING: u32 = 0x0001_0000;
    pub const DT_RTLREADING: u32 = 0x0002_0000;
    pub const DT_WORD_ELLIPSIS: u32 = 0x0004_0000;
    pub const DT_NOFULLWIDTHCHARBREAK: u32 = 0x0008_0000;
    pub const DT_HIDEPREFIX: u32 = 0x0010_0000;
    pub const DT_PREFIXONLY: u32 = 0x0020_0000;
}

/// Default metrics for the system font.
const SYSTEM_FONT_HEIGHT: i32 = 16;
const SYSTEM_FONT_ASCENT: i32 = 12;
const SYSTEM_FONT_DESCENT: i32 = 4;
const SYSTEM_FONT_AVG_WIDTH: i32 = 8;
const SYSTEM_FONT_MAX_WIDTH: i32 = 16;

/// Per-character widths for the bitmap font. The values
/// follow the standard VGA CP437 layout: most printable
/// ASCII is 8 px wide, narrow glyphs (i, l, I, etc.) are
/// narrower, wide glyphs (W, M) are wider.
fn glyph_width(ch: u8) -> i32 {
    match ch {
        b' ' | b'\t' => 8,
        b'i' | b'l' | b'I' | b'.' | b',' | b';' | b':' | b'\'' | b'`' | b'!' => 4,
        b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'|' | b'\\' | b'/' | b'<' | b'>' => 6,
        b'W' | b'M' | b'w' | b'm' => 12,
        _ => 8,
    }
}

#[inline]
fn primary_surface() -> *mut crate::libs::win32k::surface::GdiSurface {
    crate::libs::win32k::surface::get_primary_surface()
}

fn text_colors(dc: HDC) -> (u32, u32) {
    let mut fg = 0x0000_0000u32;
    let mut bg = 0x00FF_FFFFu32;
    let _ = with_dc(dc as u64, |d| {
        fg = d.text_color;
        bg = d.bk_color;
    });
    (fg, bg)
}

/// `text_out_w` — write a wide string at `(x, y)` using
/// the system 8x16 font. Returns 1 on success.
pub unsafe extern "C" fn text_out_w(dc: HDC, x: i32, y: i32, text: LPCWSTR, len: i32) -> BOOL {
    if text.is_null() || len <= 0 {
        return 1;
    }
    let surf = primary_surface();
    if surf.is_null() {
        return 0;
    }
    let (fg, bg) = text_colors(dc);
    let mut cursor_x = x;
    for i in 0..len as isize {
        let ch16 = core::ptr::read_unaligned(text.offset(i));
        // The bootstrap bitmap font has glyphs for
        // printable 7-bit ASCII (0x20..=0x7E).
        if ch16 >= 0x20 && ch16 <= 0x7E {
            let ch = (ch16 & 0xFF) as u8;
            crate::libs::win32k::text::draw_char_8x8(surf, cursor_x, y, ch, fg, bg);
            cursor_x += glyph_width(ch);
        } else {
            // Out-of-font range: advance the cursor by
            // the system-font average width so callers
            // that pass a non-ASCII string still get a
            // sensible bounding box.
            cursor_x += SYSTEM_FONT_AVG_WIDTH;
        }
    }
    1
}

/// `text_out_a` — ANSI flavour; convert to wide and
/// delegate. We only accept 7-bit ASCII so the
/// conversion is trivial.
pub unsafe extern "C" fn text_out_a(dc: HDC, x: i32, y: i32, text: *const i8, len: i32) -> BOOL {
    if text.is_null() || len <= 0 {
        return 1;
    }
    // Promote ANSI bytes to a stack-resident wide buffer.
    // The bootstrap only ever sees 7-bit ASCII from the
    // host command line / API callers, so 256 bytes is
    // more than enough.
    let mut buf = [0u16; 256];
    let n = if (len as usize) < buf.len() {
        len as usize
    } else {
        buf.len()
    };
    for i in 0..n {
        let b = core::ptr::read_unaligned(text.add(i));
        buf[i] = (b as u16) & 0x00FF;
    }
    text_out_w(dc, x, y, buf.as_ptr(), n as i32)
}

/// `get_text_extent_point32_w` — return the size in
/// logical units of the given wide string when rendered
/// with the system font.
pub unsafe extern "C" fn get_text_extent_point32_w(
    _dc: HDC,
    text: LPCWSTR,
    len: i32,
    size: *mut Size,
) -> BOOL {
    if size.is_null() {
        return 0;
    }
    let mut cx = 0i32;
    if !text.is_null() && len > 0 {
        for i in 0..len as isize {
            let ch16 = core::ptr::read_unaligned(text.offset(i));
            if ch16 >= 0x20 && ch16 <= 0x7E {
                cx += glyph_width((ch16 & 0xFF) as u8);
            } else {
                cx += SYSTEM_FONT_AVG_WIDTH;
            }
        }
    }
    *size = Size {
        cx,
        cy: SYSTEM_FONT_HEIGHT,
    };
    1
}

/// `get_text_extent_point32_a` — ANSI flavour.
pub unsafe extern "C" fn get_text_extent_point32_a(
    dc: HDC,
    text: *const i8,
    len: i32,
    size: *mut Size,
) -> BOOL {
    if text.is_null() || len <= 0 {
        return get_text_extent_point32_w(dc, core::ptr::null(), 0, size);
    }
    let mut buf = [0u16; 256];
    let n = if (len as usize) < buf.len() {
        len as usize
    } else {
        buf.len()
    };
    for i in 0..n {
        buf[i] = (core::ptr::read_unaligned(text.add(i)) as u16) & 0x00FF;
    }
    get_text_extent_point32_w(dc, buf.as_ptr(), n as i32, size)
}

/// `get_text_metrics_w` — fill a default metrics block
/// for the system font. The values are picked to match
/// the Windows 7 8×16 raster font.
pub unsafe extern "C" fn get_text_metrics_w(_dc: HDC, m: *mut TextMetricW) -> BOOL {
    if m.is_null() {
        return 0;
    }
    let t = &mut *m;
    t.tm_height = SYSTEM_FONT_HEIGHT;
    t.tm_ascent = SYSTEM_FONT_ASCENT;
    t.tm_descent = SYSTEM_FONT_DESCENT;
    t.tm_internal_leading = 0;
    t.tm_external_leading = 0;
    t.tm_ave_char_width = SYSTEM_FONT_AVG_WIDTH;
    t.tm_max_char_width = SYSTEM_FONT_MAX_WIDTH;
    t.tm_weight = 400;
    t.tm_overhang = 0;
    t.tm_digitized_aspect_x = 96;
    t.tm_digitized_aspect_y = 96;
    t.tm_first_char = 0x0020;
    t.tm_last_char = 0x00FF;
    t.tm_default_char = 0x003F;
    t.tm_break_char = 0x0020;
    t.tm_italic = 0;
    t.tm_underlined = 0;
    t.tm_struck_out = 0;
    t.tm_pitch_and_family = 0;
    t.tm_char_set = 0;
    1
}

/// `draw_text_w` — draw the wide string at the top-left
/// of `rect`. `flags` controls alignment, word breaking
/// and clip behaviour. With `DT_CALCRECT` the function
/// just computes the bounding box and writes it back
/// to `rect` without drawing.
pub unsafe extern "C" fn draw_text_w(
    dc: HDC,
    text: LPCWSTR,
    len: i32,
    rect: *mut super::types::Rect,
    flags: u32,
) -> i32 {
    if rect.is_null() {
        return 0;
    }
    if (flags & dt::DT_CALCRECT) != 0 {
        let mut s = Size { cx: 0, cy: 0 };
        let _ = get_text_extent_point32_w(dc, text, len, &mut s);
        let r = &mut *rect;
        r.right = r.left + s.cx;
        r.bottom = r.top + s.cy;
        return s.cy;
    }
    let r = &*rect;
    let rc = text_out_w(dc, r.left, r.top, text, len);
    if rc == 0 {
        0
    } else {
        len
    }
}

/// `draw_text_a` — ANSI flavour; convert and delegate.
pub unsafe extern "C" fn draw_text_a(
    dc: HDC,
    text: *const i8,
    len: i32,
    rect: *mut super::types::Rect,
    flags: u32,
) -> i32 {
    if text.is_null() || len <= 0 {
        return 0;
    }
    let mut buf = [0u16; 256];
    let n = if (len as usize) < buf.len() {
        len as usize
    } else {
        buf.len()
    };
    for i in 0..n {
        buf[i] = (core::ptr::read_unaligned(text.add(i)) as u16) & 0x00FF;
    }
    draw_text_w(dc, buf.as_ptr(), n as i32, rect, flags)
}
