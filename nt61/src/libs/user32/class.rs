//! user32 — window class registration

extern crate alloc;

use super::types::{BOOL, DWORD, FALSE, HINSTANCE, LPCWSTR, TRUE};
use core::ptr;

/// WNDCLASSEXW — the NT 6.1 class registration struct.
#[repr(C)]
pub struct WndClassExW {
    pub cb_size: u32,
    pub style: u32,
    pub lpfn_wnd_proc: *const core::ffi::c_void,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub h_instance: HINSTANCE,
    pub h_icon: *mut core::ffi::c_void,
    pub h_cursor: *mut core::ffi::c_void,
    pub hbr_background: *mut core::ffi::c_void,
    pub lpsz_menu_name: LPCWSTR,
    pub lpsz_class_name: LPCWSTR,
    pub h_icon_sm: *mut core::ffi::c_void,
}

/// `RegisterClassExW` — return a non-zero ATOM for any
/// well-formed class registration. The kernel keeps no real
/// class table for the stub.
pub unsafe extern "C" fn RegisterClassExW(class: *const WndClassExW) -> u16 {
    if class.is_null() { return 0; }
    let c = &*class;
    if c.lpsz_class_name.is_null() { return 0; }
    0xBEEF
}

/// `UnregisterClassW` — placeholder.
pub unsafe extern "C" fn UnregisterClassW(
    class_name: LPCWSTR,
    instance: HINSTANCE,
) -> BOOL {
    let _ = (class_name, instance);
    TRUE
}

/// `GetClassInfoW` — return NULL; the kernel has no class
/// table.
pub unsafe extern "C" fn GetClassInfoW(
    instance: HINSTANCE,
    class_name: LPCWSTR,
    wnd: *mut WndClassExW,
) -> BOOL {
    let _ = (instance, class_name);
    if !wnd.is_null() {
        ptr::write_bytes(wnd, 0, 1);
    }
    FALSE
}
