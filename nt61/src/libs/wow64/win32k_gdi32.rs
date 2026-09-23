//! wow64 — GDI32 Thunk Functions
//!
//! This module implements the thunk functions for 32-bit GDI32.dll API calls
//! going to the 64-bit win32k.sys driver.
//!
//! References:
//!   * Microsoft Windows SDK
//!   * ReactOS gdi32 implementation

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use super::win32k_thunk::syscall_numbers;
use super::win32k_thunk::Wow64Win32kSyscall;
use super::types::*;


pub type HDC32 = ULONG32;
pub type HPEN32 = ULONG32;
pub type HBRUSH32 = ULONG32;
pub type HBITMAP32 = ULONG32;
pub type HRGN32 = ULONG32;
pub type HPALETTE32 = ULONG32;
pub type HFONT32 = ULONG32;
pub type HICON32 = ULONG32;
pub type HCURSOR32 = ULONG32;
pub type HANDLE32 = ULONG32;
pub type BOOL32 = i32;


pub mod rop {
    use super::ULONG32;
    pub const SRCCOPY: ULONG32 = 0x00CC0020;
    pub const SRCPAINT: ULONG32 = 0x00EE0086;
    pub const SRCAND: ULONG32 = 0x008800C6;
    pub const SRCINVERT: ULONG32 = 0x00660046;
    pub const SRCERASE: ULONG32 = 0x00440328;
    pub const NOTSRCCOPY: ULONG32 = 0x00330088;
    pub const NOTSRCERASE: ULONG32 = 0x001100A6;
    pub const MERGECOPY: ULONG32 = 0x00C000CA;
    pub const MERGEPAINT: ULONG32 = 0x00BB0226;
    pub const PATCOPY: ULONG32 = 0x00F00021;
    pub const PATPAINT: ULONG32 = 0x00FB0A09;
    pub const PATINVERT: ULONG32 = 0x005A0049;
    pub const DSTINVERT: ULONG32 = 0x00550009;
    pub const BLACKNESS: ULONG32 = 0x00000042;
    pub const WHITENESS: ULONG32 = 0x00FF0062;
    pub const NOMIRRORBITMAP: ULONG32 = 0x80000000;
}


pub mod object_type {
    pub const REGION: ULONG32 = 1;
    pub const PEN: ULONG32 = 2;
    pub const FONT: ULONG32 = 6;
    pub const BRUSH: ULONG32 = 7;
    pub const PALETTE: ULONG32 = 9;
    pub const BITMAP: ULONG32 = 10;
    pub const DC: ULONG32 = 12;
    pub const METADC: ULONG32 = 14;
    pub const METAFILE: ULONG32 = 15;
    pub const EMF: ULONG32 = 19;
    pub const MEMORYDC: ULONG32 = 10;
    pub const EXTLOGPEN: ULONG32 = 19;
    pub const LOGPEN: ULONG32 = 2;
    pub const LOGBRUSH: ULONG32 = 7;
    pub const EXTLOGFONT: ULONG32 = 21;
}


pub mod pen_style {
    pub const PS_SOLID: ULONG32 = 0;
    pub const PS_DASH: ULONG32 = 1;
    pub const PS_DOT: ULONG32 = 2;
    pub const PS_DASHDOT: ULONG32 = 3;
    pub const PS_DASHDOTDOT: ULONG32 = 4;
    pub const PS_NULL: ULONG32 = 5;
    pub const PS_INSIDEFRAME: ULONG32 = 6;
    pub const PS_USERSTYLE: ULONG32 = 7;
    pub const PS_ALTERNATE: ULONG32 = 8;
    pub const PS_STYLE_MASK: ULONG32 = 0x0000000F;
    pub const PS_ENDCAP_ROUND: ULONG32 = 0x00000000;
    pub const PS_ENDCAP_SQUARE: ULONG32 = 0x00000100;
    pub const PS_ENDCAP_FLAT: ULONG32 = 0x00000200;
    pub const PS_ENDCAP_MASK: ULONG32 = 0x00000F00;
    pub const PS_JOIN_ROUND: ULONG32 = 0x00000000;
    pub const PS_JOIN_BEVEL: ULONG32 = 0x00001000;
    pub const PS_JOIN_MITER: ULONG32 = 0x00002000;
    pub const PS_JOIN_MASK: ULONG32 = 0x0000F000;
}


pub mod brush_style {
    pub const BS_SOLID: ULONG32 = 0;
    pub const BS_NULL: ULONG32 = 1;
    pub const BS_HOLLOW: ULONG32 = 1;
    pub const BS_HATCHED: ULONG32 = 2;
    pub const BS_PATTERN: ULONG32 = 3;
    pub const BS_INDEXED: ULONG32 = 4;
    pub const BS_DIBPATTERN: ULONG32 = 5;
    pub const BS_DIBPATTERNPT: ULONG32 = 6;
    pub const BS_PATTERN8X8: ULONG32 = 7;
    pub const BS_DIBPATTERN8X8: ULONG32 = 8;
    pub const BS_MONOPATTERN: ULONG32 = 9;
}


pub mod stock_object {
    pub const WHITE_BRUSH: ULONG32 = 0;
    pub const LTGRAY_BRUSH: ULONG32 = 1;
    pub const GRAY_BRUSH: ULONG32 = 2;
    pub const DKGRAY_BRUSH: ULONG32 = 3;
    pub const BLACK_BRUSH: ULONG32 = 4;
    pub const NULL_BRUSH: ULONG32 = 5;
    pub const HOLLOW_BRUSH: ULONG32 = 5;
    pub const WHITE_PEN: ULONG32 = 6;
    pub const BLACK_PEN: ULONG32 = 7;
    pub const NULL_PEN: ULONG32 = 8;
    pub const OEM_FIXED_FONT: ULONG32 = 10;
    pub const ANSI_FIXED_FONT: ULONG32 = 11;
    pub const ANSI_VAR_FONT: ULONG32 = 12;
    pub const SYSTEM_FONT: ULONG32 = 13;
    pub const DEFAULT_PALETTE: ULONG32 = 15;
    pub const SYSTEM_FIXED_FONT: ULONG32 = 16;
}


pub unsafe extern "C" fn Wow64CreateCompatibleDC(hdc: HDC32) -> HDC32 {

    let params: [ULONG32; 1] = [hdc];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtGdiCreateCompatibleDC,
        params.as_ptr(),
    );

    result
}


pub unsafe extern "C" fn Wow64DeleteDC(hdc: HDC32) -> BOOL32 {

    let params: [ULONG32; 1] = [hdc];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtGdiDeleteDC,
        params.as_ptr(),
    );

    result as BOOL32
}


pub unsafe extern "C" fn Wow64SelectObject(hdc: HDC32, h_object: HANDLE32) -> HANDLE32 {

    let params: [ULONG32; 2] = [hdc, h_object];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtGdiSelectObject,
        params.as_ptr(),
    );

    result
}


pub unsafe extern "C" fn Wow64DeleteObject(h_object: HANDLE32) -> BOOL32 {

    let params: [ULONG32; 1] = [h_object];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtGdiDeleteObject,
        params.as_ptr(),
    );

    result as BOOL32
}


pub unsafe extern "C" fn Wow64CreatePen(
    _style: ULONG32,
    _width: ULONG32,
    _color: ULONG32,
) -> HPEN32 {

    0
}


pub unsafe extern "C" fn Wow64CreateSolidBrush(_color: ULONG32) -> HBRUSH32 {

    0
}


pub unsafe extern "C" fn Wow64CreateCompatibleBitmap(
    _hdc: HDC32,
    _width: i32,
    _height: i32,
) -> HBITMAP32 {

    0
}


pub unsafe extern "C" fn Wow64GetObject(
    _h_object: HANDLE32,
    _buffer_size: ULONG32,
    _buffer: ULONG32,
) -> i32 {

    0
}


pub unsafe extern "C" fn Wow64TextOutW(
    hdc: HDC32,
    x: i32,
    y: i32,
    text: ULONG32,
    length: i32,
) -> BOOL32 {

    let params: [ULONG32; 5] = [
        hdc,
        x as ULONG32,
        y as ULONG32,
        text,
        length as ULONG32,
    ];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtGdiTextOut,
        params.as_ptr(),
    );

    result as BOOL32
}


pub unsafe extern "C" fn Wow64ExtTextOutW(
    _hdc: HDC32,
    _x: i32,
    _y: i32,
    _options: ULONG32,
    _rect: ULONG32,
    _text: ULONG32,
    _length: ULONG32,
    _dx: ULONG32,
) -> BOOL32 {

    0
}


pub unsafe extern "C" fn Wow64BitBlt(
    hdc_dest: HDC32,
    x_dest: i32,
    y_dest: i32,
    width: i32,
    height: i32,
    hdc_src: HDC32,
    x_src: i32,
    y_src: i32,
    rop: ULONG32,
) -> BOOL32 {

    let params: [ULONG32; 9] = [
        hdc_dest,
        x_dest as ULONG32,
        y_dest as ULONG32,
        width as ULONG32,
        height as ULONG32,
        hdc_src,
        x_src as ULONG32,
        y_src as ULONG32,
        rop,
    ];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtGdiBitBlt,
        params.as_ptr(),
    );

    result as BOOL32
}


pub unsafe extern "C" fn Wow64PatBlt(
    hdc: HDC32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    rop: ULONG32,
) -> BOOL32 {

    let params: [ULONG32; 6] = [
        hdc,
        x as ULONG32,
        y as ULONG32,
        width as ULONG32,
        height as ULONG32,
        rop,
    ];
    let result = Wow64Win32kSyscall(
        syscall_numbers::NtGdiPatBlt,
        params.as_ptr(),
    );

    result as BOOL32
}


pub unsafe extern "C" fn Wow64GetStockObject(object: i32) -> HANDLE32 {

    match object as ULONG32 {
        stock_object::WHITE_BRUSH => 0x80000001,
        stock_object::LTGRAY_BRUSH => 0x80000002,
        stock_object::GRAY_BRUSH => 0x80000003,
        stock_object::DKGRAY_BRUSH => 0x80000004,
        stock_object::BLACK_BRUSH => 0x80000005,
        stock_object::NULL_BRUSH => 0x80000006,
        stock_object::WHITE_PEN => 0x80000007,
        stock_object::BLACK_PEN => 0x80000008,
        stock_object::NULL_PEN => 0x80000009,
        stock_object::DEFAULT_PALETTE => 0x8000000F,
        _ => 0,
    }
}


pub unsafe extern "C" fn Wow64FillRect(
    _hdc: HDC32,
    _rect: ULONG32,
    _brush: HBRUSH32,
) -> i32 {

    // In a real implementation, this would use PatBlt or similar
    1
}


pub unsafe extern "C" fn Wow64GetPixel(_hdc: HDC32, _x: i32, _y: i32) -> ULONG32 {

    0
}


pub unsafe extern "C" fn Wow64SetPixel(
    _hdc: HDC32,
    _x: i32,
    _y: i32,
    _color: ULONG32,
) -> ULONG32 {

    0xFFFFFFFF
}
