//! user32 — shared types
//
//! Win32 types used by the user32 stubs. They are all `usize`-
//! width pointer-sized to match the NT 6.1 x64 ABI.

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
pub type UintPtr = usize;
pub type LongPtr = isize;
pub type UlongPtr = usize;

/// WNDCLASSEXW (winuser.h) — layout matches the Win64 ABI; the
/// window procedure is stored raw and reinterpreted by the class
/// table.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WndClassExW {
    pub cb_size: u32,
    pub style: u32,
    pub lpfn_wnd_proc: *const core::ffi::c_void,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub h_instance: HINSTANCE,
    pub h_icon: HICON,
    pub h_cursor: HCURSOR,
    pub hbr_background: HBRUSH,
    pub lpsz_menu_name: LPCWSTR,
    pub lpsz_class_name: LPCWSTR,
    pub h_icon_sm: HICON,
}
