//! gdi32 — paint operations
//!
//! `pat_blt` / `fill_rect` / `frame_rect` / `bit_blt` /
//! `stretch_blt` all end up here. The real work happens
//! inside `libs::win32k::eng_*` — we forward the request
//! against the primary surface (the only surface the
//! bootstrap currently owns) and apply the raster-op
//! mask with `win32k::apply_rop`.
//!
//! The DC handle we receive is a gdi32 handle. If it
//! refers to a registered `DC` object, we honour the
//! `bk_color` and `rop` fields. Otherwise (NULL HDC,
//! or a stock handle) we fall back to a black-on-white
//! `SRCCOPY` operation against the primary surface.

extern crate alloc;

use super::types::{Rect, BOOL, HBRUSH, HDC, HRGN, HWND};
use super::with_dc;

/// Ternary raster-operation codes (subset of Windows 7).
pub mod rop {
    pub const SRCCOPY: u32 = 0x00CC_0020;
    pub const SRCPAINT: u32 = 0x00EE_0086;
    pub const SRCAND: u32 = 0x0088_00C6;
    pub const SRCINVERT: u32 = 0x0066_0046;
    pub const SRCERASE: u32 = 0x0044_0328;
    pub const NOTSRCCOPY: u32 = 0x0033_0008;
    pub const NOTSRCERASE: u32 = 0x0011_00A6;
    pub const MERGECOPY: u32 = 0x00C0_00CA;
    pub const MERGEPAINT: u32 = 0x00BB_0226;
    pub const PATCOPY: u32 = 0x00F0_0021;
    pub const PATPAINT: u32 = 0x00FB_0A09;
    pub const PATINVERT: u32 = 0x005A_0049;
    pub const DSTINVERT: u32 = 0x0055_0009;
    pub const BLACKNESS: u32 = 0x0000_0042;
    pub const WHITENESS: u32 = 0x00FF_0062;
}

#[inline]
fn primary_surface() -> *mut crate::libs::win32k::surface::GdiSurface {
    crate::libs::win32k::surface::get_primary_surface()
}

/// Read a pixel from the primary surface. Returns 0 if
/// the surface is uninitialised or the coordinate is
/// out of range.
#[inline]
fn read_pixel(surf: *mut crate::libs::win32k::surface::GdiSurface, x: i32, y: i32) -> u32 {
    if surf.is_null() {
        return 0;
    }
    unsafe { (*surf).get_pixel(x, y).unwrap_or(0) }
}

/// Write a pixel to the primary surface. Returns false
/// if the surface is uninitialised or the coordinate
/// is out of range.
#[inline]
fn write_pixel(
    surf: *mut crate::libs::win32k::surface::GdiSurface,
    x: i32,
    y: i32,
    color: u32,
) -> bool {
    if surf.is_null() {
        return false;
    }
    unsafe { (*surf).set_pixel(x, y, color) }
}

#[inline]
fn dc_rop(dc: HDC) -> u32 {
    let mut r = 0x00CC_0020u32; // SRCCOPY default.
    let _ = with_dc(dc as u64, |d| {
        r = d.rop;
    });
    r
}

/// `pat_blt` — fill / raster-op the rectangle
/// `(x, y, w, h)` on the surface backing `dc`. Returns
/// 1 on success, 0 on failure.
pub extern "C" fn pat_blt(dc: HDC, x: i32, y: i32, w: i32, h: i32, rop: u32) -> BOOL {
    if w == 0 || h == 0 {
        return 1;
    }
    let surf = primary_surface();
    if surf.is_null() {
        return 0;
    }
    let rop_eff = if rop == 0 { dc_rop(dc) } else { rop };
    let colour = match rop_eff {
        rop::BLACKNESS => 0x0000_0000,
        rop::WHITENESS => 0x00FF_FFFF,
        rop::DSTINVERT => {
            // Invert the destination in place.
            for yi in 0..h {
                for xi in 0..w {
                    let px = read_pixel(surf, x + xi, y + yi);
                    write_pixel(
                        surf,
                        x + xi,
                        y + yi,
                        crate::libs::win32k::apply_rop(px, 0, rop::DSTINVERT),
                    );
                }
            }
            return 1;
        }
        _ => 0x00FF_FFFF, // SRCCOPY / PATCOPY default to white.
    };
    crate::libs::win32k::surface::eng_fill_rectangle(surf, x, y, x + w, y + h, colour) as BOOL
}

/// `fill_rect` — fill the rectangle with the brush
/// referenced by `_brush`. If the brush is a real
/// gdi32 brush we recover its colour from the table;
/// otherwise we fall back to the DC background colour.
pub unsafe extern "C" fn fill_rect(dc: HDC, rect: *const Rect, brush: HBRUSH) -> i32 {
    if rect.is_null() {
        return 0;
    }
    let r = &*rect;
    let surf = primary_surface();
    if surf.is_null() {
        return 0;
    }
    // Recover the brush colour.
    let mut colour: u32 = 0x00FF_FFFF;
    if !brush.is_null() {
        if let Some(obj) = super::lookup_object(brush as u64) {
            if let super::GdiObjectPayload::Brush(b) = obj.payload {
                if b.is_null {
                    return 1; // Null brush: transparent fill.
                }
                colour = b.color;
            }
        } else if (brush as u64) >= super::pen_brush::STOCK_HANDLE_BASE {
            let idx = (brush as u64 - super::pen_brush::STOCK_HANDLE_BASE) as i32;
            colour = super::pen_brush::stock_brush_color(idx);
        }
    } else {
        // Use the DC background colour.
        let _ = with_dc(dc as u64, |d| {
            colour = d.bk_color;
        });
    }
    if crate::libs::win32k::surface::eng_fill_rectangle(
        surf, r.left, r.top, r.right, r.bottom, colour,
    ) {
        1
    } else {
        0
    }
}

/// `frame_rect` — draw a 1-pixel border around `rect`
/// with the brush colour.
pub unsafe extern "C" fn frame_rect(dc: HDC, rect: *const Rect, brush: HBRUSH) -> i32 {
    if rect.is_null() {
        return 0;
    }
    let r = &*rect;
    if r.left > r.right || r.top > r.bottom {
        return 0;
    }
    let mut colour: u32 = 0x0000_0000;
    if !brush.is_null() {
        if let Some(obj) = super::lookup_object(brush as u64) {
            if let super::GdiObjectPayload::Brush(b) = obj.payload {
                colour = b.color;
            }
        } else if (brush as u64) >= super::pen_brush::STOCK_HANDLE_BASE {
            let idx = (brush as u64 - super::pen_brush::STOCK_HANDLE_BASE) as i32;
            colour = super::pen_brush::stock_brush_color(idx);
        }
    }
    let surf = primary_surface();
    if surf.is_null() {
        return 0;
    }
    // Top + bottom edges.
    let _ = crate::libs::win32k::surface::eng_fill_rectangle(
        surf,
        r.left,
        r.top,
        r.right,
        r.top + 1,
        colour,
    );
    let _ = crate::libs::win32k::surface::eng_fill_rectangle(
        surf,
        r.left,
        r.bottom.saturating_sub(1),
        r.right,
        r.bottom,
        colour,
    );
    // Left + right edges.
    let _ = crate::libs::win32k::surface::eng_fill_rectangle(
        surf,
        r.left,
        r.top,
        r.left + 1,
        r.bottom,
        colour,
    );
    let _ = crate::libs::win32k::surface::eng_fill_rectangle(
        surf,
        r.right.saturating_sub(1),
        r.top,
        r.right,
        r.bottom,
        colour,
    );
    let _ = dc;
    1
}

/// `invalidate_rect` — mark a region as needing
/// repainting. Forwarded to the win32k paint scheduler.
pub unsafe extern "C" fn invalidate_rect(hwnd: HWND, rect: *const Rect, erase: BOOL) -> BOOL {
    // win32k::paint::invalidate_rect takes an
    // `Option<win32k::Rect>`; a null pointer means
    // "the whole window".
    let win_rect: Option<crate::libs::win32k::Rect> = if rect.is_null() {
        None
    } else {
        Some(*(rect as *const crate::libs::win32k::Rect))
    };
    crate::libs::win32k::paint::invalidate_rect(hwnd as u64, win_rect, erase != 0) as BOOL
}

/// `invalidate_rgn` — same as `invalidate_rect` but
/// for a region handle. The region table in win32k
/// does not currently distinguish shapes, so we map
/// the region to the full window rect.
pub unsafe extern "C" fn invalidate_rgn(hwnd: HWND, rgn: HRGN, erase: BOOL) -> BOOL {
    let _ = rgn;
    crate::libs::win32k::paint::invalidate_rect(hwnd as u64, None, erase != 0) as BOOL
}

/// `validate_rect` — mark a region as valid.
pub unsafe extern "C" fn validate_rect(hwnd: HWND, rect: *const Rect) -> BOOL {
    let win_rect: Option<crate::libs::win32k::Rect> = if rect.is_null() {
        None
    } else {
        Some(*(rect as *const crate::libs::win32k::Rect))
    };
    crate::libs::win32k::paint::validate_rect(hwnd as u64, win_rect) as BOOL
}

/// `update_window` — request immediate repaint. We
/// forward to `win32k::paint::update_window`; the
/// scheduler decides whether to actually walk the
/// window list.
pub unsafe extern "C" fn update_window(hwnd: HWND) -> BOOL {
    crate::libs::win32k::paint::update_window(hwnd as u64) as BOOL
}

/// `bit_blt` — block transfer from `hdc_src` to
/// `hdc_dest`. Only same-surface blits are supported
/// in the bootstrap; cross-DC blits collapse to a
/// `SRCCOPY` no-op.
pub extern "C" fn bit_blt(
    hdc_dest: HDC,
    x_dest: i32,
    y_dest: i32,
    width: i32,
    height: i32,
    hdc_src: HDC,
    x_src: i32,
    y_src: i32,
    rop: u32,
) -> BOOL {
    let _ = (hdc_dest, hdc_src);
    if width == 0 || height == 0 {
        return 1;
    }
    let surf = primary_surface();
    if surf.is_null() {
        return 0;
    }
    let _ = rop;
    for y in 0..height {
        for x in 0..width {
            let px = read_pixel(surf, x_src + x, y_src + y);
            write_pixel(surf, x_dest + x, y_dest + y, px);
        }
    }
    1
}

/// `stretch_blt` — scaled blit. Bootstrap implementation
/// performs a nearest-neighbour resize.
pub extern "C" fn stretch_blt(
    hdc_dest: HDC,
    x_dest: i32,
    y_dest: i32,
    width_dest: i32,
    height_dest: i32,
    hdc_src: HDC,
    x_src: i32,
    y_src: i32,
    width_src: i32,
    height_src: i32,
    rop: u32,
) -> BOOL {
    let _ = (hdc_dest, hdc_src, rop);
    if width_dest == 0 || height_dest == 0 || width_src == 0 || height_src == 0 {
        return 1;
    }
    let surf = primary_surface();
    if surf.is_null() {
        return 0;
    }
    for dy in 0..height_dest {
        let sy = y_src + (dy * height_src) / height_dest;
        for dx in 0..width_dest {
            let sx = x_src + (dx * width_src) / width_dest;
            let px = read_pixel(surf, sx, sy);
            write_pixel(surf, x_dest + dx, y_dest + dy, px);
        }
    }
    1
}

/// `pat_blt_surface` — internal helper used by
/// `tests` to fill a known `EngSurface` with a
/// solid colour, honouring BLACKNESS / WHITENESS /
/// the default PATCOPY semantics.
pub fn pat_blt_surface(
    surface: &crate::libs::win32k::EngSurface,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    color: u32,
    rop: u32,
) -> bool {
    use crate::libs::win32k::fill_rect_solid;

    match rop {
        rop::BLACKNESS => {
            fill_rect_solid(surface, x, y, x + w, y + h, 0x00000000);
            true
        }
        rop::WHITENESS => {
            fill_rect_solid(surface, x, y, x + w, y + h, 0x00FFFFFF);
            true
        }
        _ => {
            fill_rect_solid(surface, x, y, x + w, y + h, color);
            true
        }
    }
}
