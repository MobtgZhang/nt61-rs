//! gdi32 — shared types
//
//! GDI types. The handle types are all `*mut c_void` so
//! the stubs can use placeholder addresses.

#![allow(non_camel_case_types)]

pub type BOOL = i32;
pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

pub type DWORD = u32;
pub type WORD = u16;
pub type BYTE = u8;
pub type LONG = i32;
pub type INT = i32;
pub type UINT = u32;

pub type HANDLE = *mut core::ffi::c_void;
pub type HDC = *mut core::ffi::c_void;
pub type HWND = *mut core::ffi::c_void;
pub type HBITMAP = *mut core::ffi::c_void;
pub type HBRUSH = *mut core::ffi::c_void;
pub type HPEN = *mut core::ffi::c_void;
pub type HFONT = *mut core::ffi::c_void;
pub type HPALETTE = *mut core::ffi::c_void;
pub type HRGN = *mut core::ffi::c_void;

pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;
pub type LPCSTR = *const i8;
pub type LPSTR = *mut i8;
pub type LPVOID = *mut core::ffi::c_void;
pub type LPCVOID = *const core::ffi::c_void;

pub type COLORREF = u32;

pub fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    r as u32 | ((g as u32) << 8) | ((b as u32) << 16)
}

pub struct Rect {
    pub left: LONG,
    pub top: LONG,
    pub right: LONG,
    pub bottom: LONG,
}

pub struct Size {
    pub cx: LONG,
    pub cy: LONG,
}

pub struct Point {
    pub x: LONG,
    pub y: LONG,
}

pub struct TextMetricW {
    pub tm_height: LONG,
    pub tm_ascent: LONG,
    pub tm_descent: LONG,
    pub tm_internal_leading: LONG,
    pub tm_external_leading: LONG,
    pub tm_ave_char_width: LONG,
    pub tm_max_char_width: LONG,
    pub tm_weight: LONG,
    pub tm_overhang: LONG,
    pub tm_digitized_aspect_x: LONG,
    pub tm_digitized_aspect_y: LONG,
    pub tm_first_char: u16,
    pub tm_last_char: u16,
    pub tm_default_char: u16,
    pub tm_break_char: u16,
    pub tm_italic: u8,
    pub tm_underlined: u8,
    pub tm_struck_out: u8,
    pub tm_pitch_and_family: u8,
    pub tm_char_set: u8,
}