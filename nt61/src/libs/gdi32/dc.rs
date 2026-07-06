//! gdi32 — device context APIs

extern crate alloc;

use super::types::{BOOL, HDC, HWND};
use super::{alloc_gdi_handle, has_gdi_handle};
use core::ptr;

/// `GetDC` — return a placeholder HDC.
pub extern "C" fn GetDC(_hwnd: HWND) -> HDC {
    alloc_gdi_handle() as HDC
}

/// `ReleaseDC` — always returns 1.
pub extern "C" fn ReleaseDC(_hwnd: HWND, _dc: HDC) -> i32 { 1 }

/// `CreateCompatibleDC` — return a placeholder HDC.
pub extern "C" fn CreateCompatibleDC(_dc: HDC) -> HDC {
    alloc_gdi_handle() as HDC
}

/// `DeleteDC` — return 1.
pub unsafe extern "C" fn DeleteDC(dc: HDC) -> BOOL {
    if has_gdi_handle(dc as u64) { 1 } else { 0 }
}

/// `SaveDC` / `RestoreDC` — placeholder.
pub extern "C" fn SaveDC(_dc: HDC) -> i32 { 1 }
pub extern "C" fn RestoreDC(_dc: HDC, _state: i32) -> BOOL { 1 }

/// `GetDeviceCaps` — return 0 for everything.
pub extern "C" fn GetDeviceCaps(_dc: HDC, index: i32) -> i32 {
    let _ = index;
    0
}
