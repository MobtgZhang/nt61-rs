//! gdi32 — pen / brush / bitmap / font handles

extern crate alloc;

use super::types::{BOOL, COLORREF, HBRUSH, HDC, HFONT, HPEN};
use super::{alloc_gdi_handle, has_gdi_handle};
use core::ptr;

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

/// Stock objects.
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

/// `CreatePen` — return a placeholder HPEN.
pub extern "C" fn CreatePen(_style: i32, _width: i32, _color: COLORREF) -> HPEN {
    alloc_gdi_handle() as HPEN
}

/// `CreateSolidBrush` — return a placeholder HBRUSH.
pub extern "C" fn CreateSolidBrush(_color: COLORREF) -> HBRUSH {
    alloc_gdi_handle() as HBRUSH
}

/// `CreateHatchBrush` — placeholder.
pub extern "C" fn CreateHatchBrush(_hatch: i32, _color: COLORREF) -> HBRUSH {
    alloc_gdi_handle() as HBRUSH
}

/// `CreatePenIndirect` — placeholder.
pub unsafe extern "C" fn CreatePenIndirect(_log_pen: *const ()) -> HPEN {
    alloc_gdi_handle() as HPEN
}

/// `CreateBrushIndirect` — placeholder.
pub unsafe extern "C" fn CreateBrushIndirect(_log_brush: *const ()) -> HBRUSH {
    alloc_gdi_handle() as HBRUSH
}

/// `CreateFontW` — placeholder.
pub unsafe extern "C" fn CreateFontW(
    _h: i32, _w: i32, _e: i32, _o: i32, _w2: i32, _b: u32, _i: u32, _u: u32, _s: u32,
    _cp: u32, _o2: u32, _q: u32, _p: u32, _f: *const u16,
) -> HFONT { alloc_gdi_handle() as HFONT }

/// `SelectObject` — return the previously selected object.
pub extern "C" fn SelectObject(_dc: HDC, obj: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
    obj
}

/// `DeleteObject` — return 1 if the handle was known.
pub unsafe extern "C" fn DeleteObject(obj: *mut core::ffi::c_void) -> BOOL {
    if has_gdi_handle(obj as u64) { 1 } else { 0 }
}

/// `GetStockObject` — return NULL (the stub has no real
/// stock objects).
pub extern "C" fn GetStockObject(_index: i32) -> *mut core::ffi::c_void {
    core::ptr::null_mut()
}
