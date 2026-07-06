//! gdi32 — paint operations

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use super::types::{BOOL, HBRUSH, HDC, HRGN, HWND, Rect};
#[cfg(target_arch = "x86_64")]
use crate::libs::win32k::{fill_rect_on_surface, draw_line_on_surface, clear_surface};
use core::ptr;

/// Ternary raster-operation codes (subset).
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

/// `PatBlt` — perform a pattern block transfer (fill operation)
/// In this stub implementation, we simulate the fill operation
pub extern "C" fn PatBlt(dc: HDC, x: i32, y: i32, w: i32, h: i32, rop: u32) -> BOOL {
    use crate::libs::win32k::apply_rop;
    use crate::libs::win32k::RasterOp;

    // For now, just return success
    // A full implementation would:
    // 1. Look up the DC's surface
    // 2. Fill the rectangle with the current brush pattern
    // 3. Apply the ROP operation
    let _ = (dc, x, y, w, h);
    match rop {
        rop::BLACKNESS => {
            // Would fill with black
        }
        rop::WHITENESS => {
            // Would fill with white
        }
        _ => {
            // PATCOPY and similar operations would use current brush
        }
    }
    1
}

/// `FillRect` — fill a rectangle with a brush
pub unsafe extern "C" fn FillRect(dc: HDC, rect: *const Rect, _brush: HBRUSH) -> i32 {
    if rect.is_null() {
        return 0;
    }

    // A full implementation would look up the brush color
    // For now, just return success
    let r = &*rect;
    let _ = (dc, r);
    1
}

/// `FrameRect` — draw a border around a rectangle
pub unsafe extern "C" fn FrameRect(dc: HDC, rect: *const Rect, _brush: HBRUSH) -> i32 {
    if rect.is_null() {
        return 0;
    }

    // A full implementation would:
    // 1. Look up the brush color
    // 2. Draw 4 lines around the rectangle border
    let r = &*rect;
    let _ = (dc, r);
    1
}

/// `InvalidateRect` — mark a region as needing to be redrawn
pub unsafe extern "C" fn InvalidateRect(hwnd: HWND, rect: *const Rect, _erase: BOOL) -> BOOL {
    // Add to update region
    let _ = (hwnd, rect);
    1
}

/// `InvalidateRgn` — mark a region as needing to be redrawn
pub unsafe extern "C" fn InvalidateRgn(hwnd: HWND, rgn: HRGN, _erase: BOOL) -> BOOL {
    let _ = (hwnd, rgn);
    1
}

/// `ValidateRect` — mark a region as valid (no longer needing redraw)
pub unsafe extern "C" fn ValidateRect(hwnd: HWND, rect: *const Rect) -> BOOL {
    let _ = (hwnd, rect);
    1
}

/// `UpdateWindow` — send WM_PAINT to a window
pub unsafe extern "C" fn UpdateWindow(hwnd: HWND) -> BOOL {
    // Would trigger WM_PAINT message processing
    let _ = hwnd;
    1
}

/// `BitBlt` — block transfer between device contexts
pub extern "C" fn BitBlt(
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
    // A full implementation would:
    // 1. Look up both DC's surfaces
    // 2. Copy the pixels from source to destination
    // 3. Apply the ROP operation
    let _ = (hdc_dest, x_dest, y_dest, width, height, hdc_src, x_src, y_src, rop);
    1
}

/// `StretchBlt` — block transfer with scaling
pub extern "C" fn StretchBlt(
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
    let _ = (hdc_dest, x_dest, y_dest, width_dest, height_dest,
             hdc_src, x_src, y_src, width_src, height_src, rop);
    1
}

/// `PatBlt` with actual surface (internal use)
pub fn pat_blt_surface(surface: &crate::libs::win32k::EngSurface, x: i32, y: i32, w: i32, h: i32, color: u32, rop: u32) -> bool {
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
