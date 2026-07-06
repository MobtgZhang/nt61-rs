//! gdi32 — text APIs

extern crate alloc;

use super::types::{BOOL, HDC, HFONT, LPCWSTR, Size, TextMetricW};
use core::ptr;

/// `TextOutW` — placeholder, return non-zero.
pub unsafe extern "C" fn TextOutW(_dc: HDC, x: i32, y: i32, _text: LPCWSTR, len: i32) -> BOOL {
    let _ = (x, y, len);
    1
}

/// `TextOutA` — placeholder.
pub unsafe extern "C" fn TextOutA(_dc: HDC, x: i32, y: i32, _text: *const i8, len: i32) -> BOOL {
    let _ = (x, y, len);
    1
}

/// `GetTextExtentPoint32W` — return 0,0 size.
pub unsafe extern "C" fn GetTextExtentPoint32W(
    _dc: HDC,
    _text: LPCWSTR,
    len: i32,
    size: *mut Size,
) -> BOOL {
    if size.is_null() { return 0; }
    *size = Size { cx: (len as i32) * 8, cy: 16 };
    1
}

/// `GetTextMetricsW` — fill a default metrics block.
pub unsafe extern "C" fn GetTextMetricsW(_dc: HDC, m: *mut TextMetricW) -> BOOL {
    if m.is_null() { return 0; }
    let t = &mut *m;
    t.tm_height = 16;
    t.tm_ascent = 12;
    t.tm_descent = 4;
    t.tm_internal_leading = 0;
    t.tm_external_leading = 0;
    t.tm_ave_char_width = 8;
    t.tm_max_char_width = 16;
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

/// `DrawTextW` — return the length of the string.
pub unsafe extern "C" fn DrawTextW(
    _dc: HDC,
    text: LPCWSTR,
    len: i32,
    _rect: *mut super::types::Rect,
    flags: u32,
) -> i32 {
    let _ = (text, flags);
    len
}

/// `DrawTextA` — return the length.
pub unsafe extern "C" fn DrawTextA(
    _dc: HDC,
    text: LPCSTR,
    len: i32,
    _rect: *mut super::types::Rect,
    flags: u32,
) -> i32 {
    let _ = (text, flags);
    len
}

use super::types::LPCSTR;
