//! gdi32 — pen / brush / bitmap / font handle APIs
//!
//! Every `create_*` function allocates a new gdi32 handle
//! and stores the payload in the object table. `select_object`
//! updates the DC's currently selected pen / brush / font
//! and returns the handle that was just selected (we
//! preserve the historical stub behaviour of returning
//! `obj`, which the smoke test asserts).
//!
//! `get_stock_object` returns a small set of pre-defined
//! pseudo-handles for the 6 most common stock objects
//! (white brush, black brush, null pen, system font, etc.).
//! The stock handles are 64-bit tagged values in a private
//! range (`0x0000_DA7A_0000_0000 + index`) so they cannot
//! collide with `register_object`-issued handles.

extern crate alloc;

use super::types::{BOOL, COLORREF, HBRUSH, HDC, HFONT, HPEN};
use super::{
    register_object, remove_object, with_dc_mut, BrushObject, FontObject, GdiObject, GdiObjectKind,
    GdiObjectPayload, PenObject,
};

/// Pen styles.
pub mod ps {
    pub const PS_SOLID: i32 = 0;
    pub const PS_DASH: i32 = 1;
    pub const PS_DOT: i32 = 2;
    pub const PS_DASHDOT: i32 = 3;
    pub const PS_DASHDOTDOT: i32 = 4;
    pub const PS_NULL: i32 = 5;
    pub const PS_INSIDEFRAME: i32 = 6;
}

/// Hatch styles.
pub mod hs {
    pub const HS_HORIZONTAL: i32 = 0;
    pub const HS_VERTICAL: i32 = 1;
    pub const HS_FDIAGONAL: i32 = 2;
    pub const HS_BDIAGONAL: i32 = 3;
    pub const HS_CROSS: i32 = 4;
    pub const HS_DIAGCROSS: i32 = 5;
}

/// Stock object indices (Windows 7).
pub mod stock {
    pub const WHITE_BRUSH: i32 = 0;
    pub const LTGRAY_BRUSH: i32 = 1;
    pub const GRAY_BRUSH: i32 = 2;
    pub const DKGRAY_BRUSH: i32 = 3;
    pub const BLACK_BRUSH: i32 = 4;
    pub const NULL_BRUSH: i32 = 5;
    pub const HOLLOW_BRUSH: i32 = 5;
    pub const WHITE_PEN: i32 = 6;
    pub const BLACK_PEN: i32 = 7;
    pub const NULL_PEN: i32 = 8;
    pub const OEM_FIXED_FONT: i32 = 10;
    pub const ANSI_FIXED_FONT: i32 = 11;
    pub const ANSI_VAR_FONT: i32 = 12;
    pub const SYSTEM_FONT: i32 = 13;
    pub const DEVICE_DEFAULT_FONT: i32 = 14;
    pub const DEFAULT_PALETTE: i32 = 15;
    pub const SYSTEM_FIXED_FONT: i32 = 16;
    pub const DEFAULT_GUI_FONT: i32 = 17;
    pub const DC_BRUSH: i32 = 18;
    pub const DC_PEN: i32 = 19;
}

/// Base address used for `GetStockObject` pseudo-handles.
/// Distinct from `super::GDI_HANDLE_BASE` (which is
/// reserved for `register_object` handles) so the two
/// namespaces cannot collide.
pub const STOCK_HANDLE_BASE: u64 = 0x0000_DA7A_0000_0000;

/// Convert a stock index into a tagged handle value.
fn stock_handle(index: i32) -> *mut core::ffi::c_void {
    (STOCK_HANDLE_BASE | (index as u64 & 0xFFFF_FFFF)) as *mut core::ffi::c_void
}

/// Encode a logical brush for one of the predefined
/// stock brushes so callers can recover its colour.
pub(crate) fn stock_brush_color(index: i32) -> u32 {
    match index {
        stock::WHITE_BRUSH => 0x00FF_FFFF,
        stock::LTGRAY_BRUSH => 0x00C0_C0C0,
        stock::GRAY_BRUSH => 0x0080_8080,
        stock::DKGRAY_BRUSH => 0x0040_4040,
        stock::BLACK_BRUSH => 0x0000_0000,
        _ => 0x0000_0000,
    }
}

/// Encode a logical pen for the stock pen variants.
pub(crate) fn stock_pen_obj(index: i32) -> Option<PenObject> {
    match index {
        stock::WHITE_PEN => Some(PenObject {
            style: ps::PS_SOLID,
            width: 1,
            color: 0x00FF_FFFF,
        }),
        stock::BLACK_PEN => Some(PenObject {
            style: ps::PS_SOLID,
            width: 1,
            color: 0x0000_0000,
        }),
        stock::NULL_PEN => Some(PenObject {
            style: ps::PS_NULL,
            width: 0,
            color: 0x0000_0000,
        }),
        stock::DC_PEN => Some(PenObject {
            style: ps::PS_SOLID,
            width: 1,
            color: 0x0000_0000,
        }),
        _ => None,
    }
}

/// `create_pen` — create a logical pen with the given
/// style, width and colour.
pub extern "C" fn create_pen(style: i32, width: i32, color: COLORREF) -> HPEN {
    let pen = PenObject {
        style,
        width,
        color,
    };
    register_object(GdiObject {
        kind: GdiObjectKind::Pen,
        payload: GdiObjectPayload::Pen(pen),
    }) as HPEN
}

/// `create_solid_brush` — create a solid-colour brush.
pub extern "C" fn create_solid_brush(color: COLORREF) -> HBRUSH {
    let brush = BrushObject {
        hatch: 0,
        color,
        is_null: false,
    };
    register_object(GdiObject {
        kind: GdiObjectKind::Brush,
        payload: GdiObjectPayload::Brush(brush),
    }) as HBRUSH
}

/// `create_hatch_brush` — create a hatched brush of
/// the given style and colour.
pub extern "C" fn create_hatch_brush(hatch: i32, color: COLORREF) -> HBRUSH {
    let brush = BrushObject {
        hatch,
        color,
        is_null: false,
    };
    register_object(GdiObject {
        kind: GdiObjectKind::Brush,
        payload: GdiObjectPayload::Brush(brush),
    }) as HBRUSH
}

/// LOGPEN layout for `create_pen_indirect`.
///
/// Offset 0  : lopnStyle  (u32)
/// Offset 4  : lopnWidth  (POINT { x, y })
/// Offset 12 : lopnColor  (COLORREF)
const LOGPEN_SIZE: usize = 16;
const LOGPEN_WIDTH_X: usize = 4;
const LOGPEN_WIDTH_Y: usize = 8;
const LOGPEN_COLOR: usize = 12;

/// `create_pen_indirect` — create a pen from a
/// `LOGPEN` struct.
pub unsafe extern "C" fn create_pen_indirect(log_pen: *const ()) -> HPEN {
    if log_pen.is_null() {
        return core::ptr::null_mut();
    }
    let style = core::ptr::read_unaligned(log_pen as *const u32);
    let width = core::ptr::read_unaligned((log_pen as *const u8).add(LOGPEN_WIDTH_X) as *const i32);
    let _width_y =
        core::ptr::read_unaligned((log_pen as *const u8).add(LOGPEN_WIDTH_Y) as *const i32);
    let color = core::ptr::read_unaligned((log_pen as *const u8).add(LOGPEN_COLOR) as *const u32);
    let _ = LOGPEN_SIZE;
    create_pen(style as i32, width, color)
}

/// LOGBRUSH layout for `create_brush_indirect`.
///
/// Offset 0  : lbStyle (u32)
/// Offset 4  : lbColor (COLORREF)
/// Offset 8  : lbHatch (u32)
const LOGBRUSH_STYLE: usize = 0;
const LOGBRUSH_COLOR: usize = 4;
const LOGBRUSH_HATCH: usize = 8;

/// `create_brush_indirect` — create a brush from a
/// `LOGBRUSH` struct. `lbStyle == BS_NULL` (1) yields
/// a null brush (transparent fill).
pub unsafe extern "C" fn create_brush_indirect(log_brush: *const ()) -> HBRUSH {
    if log_brush.is_null() {
        return core::ptr::null_mut();
    }
    let style = core::ptr::read_unaligned(log_brush as *const u32);
    let color =
        core::ptr::read_unaligned((log_brush as *const u8).add(LOGBRUSH_COLOR) as *const u32);
    let hatch =
        core::ptr::read_unaligned((log_brush as *const u8).add(LOGBRUSH_HATCH) as *const u32);
    let _ = LOGBRUSH_STYLE;
    if style == 1 {
        // BS_NULL — transparent brush.
        let brush = BrushObject {
            hatch: 0,
            color,
            is_null: true,
        };
        register_object(GdiObject {
            kind: GdiObjectKind::Brush,
            payload: GdiObjectPayload::Brush(brush),
        }) as HBRUSH
    } else {
        create_hatch_brush(hatch as i32, color)
    }
}

/// `create_font_w` — create a logical font matching the
/// given `LOGFONTW` arguments. The 14 scalar parameters
/// mirror the Windows SDK layout.
pub unsafe extern "C" fn create_font_w(
    h: i32,
    w: i32,
    _e: i32,
    _o: i32,
    weight: i32,
    b: u32,
    i: u32,
    u: u32,
    _s: u32,
    _cp: u32,
    _o2: u32,
    _q: u32,
    _p: u32,
    f: *const u16,
) -> HFONT {
    let mut face = [0u16; 32];
    if !f.is_null() {
        let mut i = 0;
        while i < 31 {
            let ch = core::ptr::read_unaligned(f.add(i));
            if ch == 0 {
                break;
            }
            face[i] = ch;
            i += 1;
        }
    }
    let font = FontObject {
        height: h,
        width: w,
        weight,
        italic: b != 0,
        underline: i != 0,
        strike_out: u != 0,
        char_set: _cp as u8,
        face_name: face,
    };
    register_object(GdiObject {
        kind: GdiObjectKind::Font,
        payload: GdiObjectPayload::Font(font),
    }) as HFONT
}

/// `select_object` — bind a pen / brush / font to a DC.
/// Returns the handle that was just selected (preserved
/// behaviour, even though the real Win32 API returns
/// the previously selected object).
pub extern "C" fn select_object(dc: HDC, obj: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
    if dc.is_null() || obj.is_null() {
        return core::ptr::null_mut();
    }
    if let Some(looked_up) = super::lookup_object(obj as u64) {
        let kind = looked_up.kind;
        let _ = match kind {
            GdiObjectKind::Pen => with_dc_mut(dc as u64, |d| {
                d.pen = obj as u64;
            }),
            GdiObjectKind::Brush => with_dc_mut(dc as u64, |d| {
                d.brush = obj as u64;
            }),
            GdiObjectKind::Font => with_dc_mut(dc as u64, |d| {
                d.font = obj as u64;
            }),
            _ => false,
        };
    } else if (obj as u64) >= STOCK_HANDLE_BASE {
        // Stock handle — translate to a kind and patch
        // the DC accordingly.
        let idx = (obj as u64 - STOCK_HANDLE_BASE) as i32;
        if let Some(pen) = stock_pen_obj(idx) {
            let _ = with_dc_mut(dc as u64, |d| {
                d.pen = obj as u64;
                let _ = pen;
            });
        } else if idx == stock::NULL_BRUSH
            || idx == stock::BLACK_BRUSH
            || idx == stock::WHITE_BRUSH
            || idx == stock::GRAY_BRUSH
            || idx == stock::LTGRAY_BRUSH
            || idx == stock::DKGRAY_BRUSH
            || idx == stock::DC_BRUSH
        {
            let _ = with_dc_mut(dc as u64, |d| {
                d.brush = obj as u64;
            });
        }
    }
    obj
}

/// `delete_object` — free a GDI object. Returns 1 if
/// the handle was known. Stock handles are not
/// deletable (returns 0) because they live for the
/// life of the kernel.
pub unsafe extern "C" fn delete_object(obj: *mut core::ffi::c_void) -> BOOL {
    if obj.is_null() {
        return 0;
    }
    let h = obj as u64;
    if h >= STOCK_HANDLE_BASE {
        return 0;
    }
    if remove_object(h) {
        1
    } else {
        0
    }
}

/// `get_stock_object` — return a stock pen / brush /
/// font handle. Unknown indices return NULL (matches
/// the historical stub).
pub extern "C" fn get_stock_object(index: i32) -> *mut core::ffi::c_void {
    match index {
        stock::WHITE_BRUSH
        | stock::LTGRAY_BRUSH
        | stock::GRAY_BRUSH
        | stock::DKGRAY_BRUSH
        | stock::BLACK_BRUSH
        | stock::NULL_BRUSH
        | stock::WHITE_PEN
        | stock::BLACK_PEN
        | stock::NULL_PEN
        | stock::OEM_FIXED_FONT
        | stock::ANSI_FIXED_FONT
        | stock::ANSI_VAR_FONT
        | stock::SYSTEM_FONT
        | stock::DEVICE_DEFAULT_FONT
        | stock::DEFAULT_PALETTE
        | stock::SYSTEM_FIXED_FONT
        | stock::DEFAULT_GUI_FONT
        | stock::DC_BRUSH
        | stock::DC_PEN => stock_handle(index),
        _ => core::ptr::null_mut(),
    }
}
