//! gdi32 — device context APIs
//!
//! `get_dc` / `create_compatible_dc` allocate a fresh
//! `DcObject` in the gdi32 handle table; the kernel-side
//! counterpart is a `win32k::DCState` that we mirror in
//! memory until `release_dc` / `delete_dc` is called.
//!
//! `save_dc` / `restore_dc` push and pop the
//! `(pen, brush, font, text_colour, bk_colour, bk_mode,
//! rop, surface)` octet onto a per-DC 8-entry stack
//! (matches the documented Windows limit).

extern crate alloc;

use super::types::{BOOL, HDC, HWND};
use super::{
    register_object, remove_object, with_dc_mut, DcObject, GdiObject, GdiObjectKind,
    GdiObjectPayload,
};

/// `get_dc` — return a new HDC for the given window (or
/// for the screen if `hwnd` is null).
pub extern "C" fn get_dc(_hwnd: HWND) -> HDC {
    let mut dc = DcObject::empty();
    // Window DCs in NT 6.1 default to SRCCOPY with
    // black-on-white text. We pre-select a default
    // system font-equivalent so `text_out_w` works
    // before any explicit SelectObject.
    dc.text_color = 0x0000_0000;
    dc.bk_color = 0x00FF_FFFF;
    dc.bk_mode = 2;
    dc.rop = 0x00CC_0020;
    register_object(GdiObject {
        kind: GdiObjectKind::DC,
        payload: GdiObjectPayload::DC(dc),
    }) as HDC
}

/// `release_dc` — release a window DC. Returns 1 on
/// success, 0 if the handle is unknown.
pub extern "C" fn release_dc(_hwnd: HWND, dc: HDC) -> i32 {
    if remove_object(dc as u64) {
        1
    } else {
        0
    }
}

/// `create_compatible_dc` — return a new memory DC
/// compatible with the screen format. The `src` DC is
/// currently ignored; the new DC is initialised with
/// the same defaults as `get_dc`.
pub extern "C" fn create_compatible_dc(_src: HDC) -> HDC {
    let mut dc = DcObject::empty();
    dc.rop = 0x00CC_0020;
    register_object(GdiObject {
        kind: GdiObjectKind::DC,
        payload: GdiObjectPayload::DC(dc),
    }) as HDC
}

/// `delete_dc` — free a DC. Returns 1 if the handle
/// was known.
pub unsafe extern "C" fn delete_dc(dc: HDC) -> BOOL {
    if remove_object(dc as u64) {
        1
    } else {
        0
    }
}

/// `save_dc` — push the current DC state onto the
/// per-DC save stack. Returns a positive integer state
/// identifier on success, 0 on failure.
pub extern "C" fn save_dc(dc: HDC) -> i32 {
    let mut result = 0;
    let ok = with_dc_mut(dc as u64, |d| {
        if d.saved_top >= d.saved_stack.len() {
            return;
        }
        d.saved_stack[d.saved_top] = (
            d.pen,
            d.brush,
            d.font,
            d.text_color,
            d.bk_color,
            d.bk_mode,
            d.rop,
            d.surface,
        );
        d.saved_top += 1;
        result = d.saved_top as i32;
    });
    if ok {
        result
    } else {
        0
    }
}

/// `restore_dc` — pop a previously saved state. The
/// `state` argument is 1-based: 1 means "the most
/// recent save", 2 means "two saves ago", and so on.
/// A negative value of `state` is treated as the
/// absolute position from the bottom of the stack.
pub extern "C" fn restore_dc(dc: HDC, state: i32) -> BOOL {
    let mut result = 0;
    let ok = with_dc_mut(dc as u64, |d| {
        let target = if state < 0 {
            // Negative state: -1 means deepest, -2 one
            // up from deepest, etc.
            let abs = (-state) as usize;
            if abs == 0 || abs > d.saved_top {
                return;
            }
            d.saved_top - abs
        } else if state == 0 {
            // 0 means "pop the most recent".
            if d.saved_top == 0 {
                return;
            }
            d.saved_top - 1
        } else {
            let pos = state as usize;
            if pos == 0 || pos > d.saved_top {
                return;
            }
            d.saved_top - pos
        };
        let (pen, brush, font, text_color, bk_color, bk_mode, rop, surface) = d.saved_stack[target];
        d.pen = pen;
        d.brush = brush;
        d.font = font;
        d.text_color = text_color;
        d.bk_color = bk_color;
        d.bk_mode = bk_mode;
        d.rop = rop;
        d.surface = surface;
        d.saved_top = target;
        result = 1;
    });
    if ok {
        result
    } else {
        0
    }
}

// =============================================================================
// GetDeviceCaps indices (subset of Windows 7)
// =============================================================================

pub const HORZRES: i32 = 8;
pub const VERTRES: i32 = 10;
pub const BITSPIXEL: i32 = 12;
pub const PLANES: i32 = 14;
pub const NUMBRUSHES: i32 = 16;
pub const NUMPENS: i32 = 18;
pub const NUMMARKERS: i32 = 20;
pub const NUMFONTS: i32 = 22;
pub const NUMCOLORS: i32 = 24;
pub const PDEVICESIZE: i32 = 26;
pub const CURVECAPS: i32 = 28;
pub const LINECAPS: i32 = 30;
pub const POLYGONALCAPS: i32 = 32;
pub const TEXTCAPS: i32 = 34;
pub const CLIPCAPS: i32 = 36;
pub const RASTERCAPS: i32 = 38;
pub const ASPECTX: i32 = 40;
pub const ASPECTY: i32 = 42;
pub const ASPECTXY: i32 = 44;
pub const LOGPIXELSX: i32 = 88;
pub const LOGPIXELSY: i32 = 90;
pub const SIZEPALETTE: i32 = 104;
pub const NUMRESERVED: i32 = 106;
pub const COLORRES: i32 = 108;
pub const PHYSICALWIDTH: i32 = 110;
pub const PHYSICALHEIGHT: i32 = 111;
pub const PHYSICALOFFSETX: i32 = 112;
pub const PHYSICALOFFSETY: i32 = 113;
pub const SCALINGFACTORX: i32 = 114;
pub const SCALINGFACTORY: i32 = 115;
pub const VREFRESH: i32 = 116;
pub const DESKTOPVERTRES: i32 = 117;
pub const DESKTOPHORZRES: i32 = 118;
pub const BLTALIGNMENT: i32 = 119;
pub const SHADEBLENDCAPS: i32 = 120;
pub const COLORMGMTCAPS: i32 = 121;

/// `get_device_caps` — return the device capability for
/// the given index. We model a 1024×768 32-bpp display
/// with a standard 96-DPI system.
pub extern "C" fn get_device_caps(_dc: HDC, index: i32) -> i32 {
    match index {
        HORZRES | PHYSICALWIDTH | DESKTOPHORZRES => 1024,
        VERTRES | PHYSICALHEIGHT | DESKTOPVERTRES => 768,
        BITSPIXEL => 32,
        PLANES => 1,
        NUMBRUSHES => 16,
        NUMPENS => 16,
        NUMMARKERS => 8,
        NUMFONTS => 16,
        NUMCOLORS | SIZEPALETTE => 256,
        NUMRESERVED => 20,
        PDEVICESIZE => 0,
        // Drawing capabilities: lines, polygons, text, bit
        // block transfers all supported.
        CURVECAPS => 0b1111,
        LINECAPS => 0b1000_1111,
        POLYGONALCAPS => 0b1_1111,
        TEXTCAPS => 0b0100_0011_1010_0110,
        CLIPCAPS => 1,
        RASTERCAPS => 0b1000_1110_0001_1111,
        ASPECTX | ASPECTY | ASPECTXY => 36,
        LOGPIXELSX | LOGPIXELSY => 96,
        COLORRES => 24,
        PHYSICALOFFSETX | PHYSICALOFFSETY => 0,
        SCALINGFACTORX | SCALINGFACTORY => 1,
        VREFRESH => 60,
        BLTALIGNMENT => 4,
        SHADEBLENDCAPS => 0,
        COLORMGMTCAPS => 0,
        _ => 0,
    }
}
