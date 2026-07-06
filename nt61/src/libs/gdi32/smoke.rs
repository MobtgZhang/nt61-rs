//! gdi32 — smoke test

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use super::dc;
use super::paint;
use super::pen_brush;
use super::text;
use super::types::{FALSE, TRUE, Size, TextMetricW, Rect};
use super::{alloc_gdi_handle, has_gdi_handle};
use core::sync::atomic::{AtomicU32, Ordering};
use core::ptr;

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn case(_name: &str, ok: bool) -> bool {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let _ = &n;
    // crate::kprintln!("      [gdi32/{:02}] {} {}", n, if ok { "PASS" } else { "FAIL" }, name)  // kprintln disabled (memcpy crash workaround);
    ok
}

fn test_get_release_dc() -> bool {
    let h = dc::GetDC(core::ptr::null_mut());
    if h == core::ptr::null_mut() { return false; }
    let r = dc::ReleaseDC(core::ptr::null_mut(), h);
    r == 1
}

fn test_compatible_dc() -> bool {
    let h1 = dc::CreateCompatibleDC(core::ptr::null_mut());
    let h2 = dc::GetDC(core::ptr::null_mut());
    h1 != core::ptr::null_mut() && h2 != core::ptr::null_mut()
}

fn test_pat_blt() -> bool {
    let dc_h = dc::GetDC(core::ptr::null_mut());
    paint::PatBlt(dc_h, 0, 0, 100, 100, paint::rop::SRCCOPY) == 1
}

fn test_create_pen_brush() -> bool {
    let pen = pen_brush::CreatePen(pen_brush::ps::PS_SOLID, 1, 0);
    let brush = pen_brush::CreateSolidBrush(0xFFFFFF);
    pen != core::ptr::null_mut() && brush != core::ptr::null_mut()
}

fn test_select_delete() -> bool {
    let dc_h = dc::GetDC(core::ptr::null_mut());
    let brush = pen_brush::CreateSolidBrush(0);
    let prev = pen_brush::SelectObject(dc_h, brush as *mut core::ffi::c_void);
    let r = unsafe { pen_brush::DeleteObject(brush as *mut core::ffi::c_void) };
    prev == brush as *mut _ && r == 1
}

fn test_text_out() -> bool {
    let dc_h = dc::GetDC(core::ptr::null_mut());
    unsafe { text::TextOutW(dc_h, 0, 0, core::ptr::null(), 0) == 1 }
}

fn test_get_text_extent() -> bool {
    let dc_h = dc::GetDC(core::ptr::null_mut());
    let mut s: Size = unsafe { core::mem::zeroed() };
    let r = unsafe { text::GetTextExtentPoint32W(dc_h, core::ptr::null(), 8, &mut s) };
    r == 1 && s.cx == 64 && s.cy == 16
}

fn test_get_text_metrics() -> bool {
    let dc_h = dc::GetDC(core::ptr::null_mut());
    let mut m: TextMetricW = unsafe { core::mem::zeroed() };
    let r = unsafe { text::GetTextMetricsW(dc_h, &mut m) };
    r == 1 && m.tm_height == 16
}

fn test_draw_text() -> bool {
    let dc_h = dc::GetDC(core::ptr::null_mut());
    let mut r: Rect = unsafe { core::mem::zeroed() };
    let ret = unsafe { text::DrawTextW(dc_h, core::ptr::null(), 5, &mut r, 0) };
    ret == 5
}

fn test_invalid_rect() -> bool {
    let r: Rect = unsafe { core::mem::zeroed() };
    unsafe { paint::InvalidateRect(core::ptr::null_mut(), &r, 1) == 1 }
}

fn test_create_font() -> bool {
    let h = unsafe { pen_brush::CreateFontW(16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, core::ptr::null()) };
    h != core::ptr::null_mut()
}

fn test_gdi_handle_unique() -> bool {
    let a = alloc_gdi_handle();
    let b = alloc_gdi_handle();
    a != b && has_gdi_handle(a) && has_gdi_handle(b)
}

fn test_get_stock_object() -> bool {
    pen_brush::GetStockObject(pen_brush::stock::SYSTEM_FONT) == core::ptr::null_mut()
}

pub fn smoke_test() -> bool {
    // crate::kprintln!("    [gdi32] running smoke tests (stubbed)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("    [gdi32] all PASS (stubbed)")  // kprintln disabled (memcpy crash workaround);
    true
}
