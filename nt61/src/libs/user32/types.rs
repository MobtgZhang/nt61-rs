//! user32 — shared types
//
//! Win32 types used by the user32 stubs. They are all `usize`-
//! width pointer-sized to match the NT 6.1 x64 ABI.

#![allow(non_camel_case_types)]

pub type BOOL = i32;
pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

pub type DWORD = u32;
pub type WORD = u16;
pub type BYTE = u8;

pub type HANDLE = *mut core::ffi::c_void;
pub type HWND = *mut core::ffi::c_void;
pub type HMENU = *mut core::ffi::c_void;
pub type HINSTANCE = *mut core::ffi::c_void;
pub type HICON = *mut core::ffi::c_void;
pub type HCURSOR = *mut core::ffi::c_void;
pub type HBRUSH = *mut core::ffi::c_void;

pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;
pub type LPCSTR = *const i8;
pub type LPSTR = *mut i8;
pub type LPVOID = *mut core::ffi::c_void;
pub type LPCVOID = *const core::ffi::c_void;

pub type WPARAM = usize;
pub type LPARAM = isize;
pub type LRESULT = isize;

pub type ATOM = u16;
pub type UINT = u32;
pub type UINT_PTR = usize;
pub type LONG_PTR = isize;
pub type ULONG_PTR = usize;
