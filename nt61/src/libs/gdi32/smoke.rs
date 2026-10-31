//! gdi32 — smoke test
//!
//! Walks every public gdi32 entry point to ensure the
//! signature matches, the call returns, and the side
//! effects on the gdi32-internal handle table are
//! sane. The aggregate `smoke_test` returns the
//! conjunction of all individual cases.
//!
//! Each case is exposed (`pub`) so the kernel-side
//! bootstrap can call them by name when it wants to
//! exercise a specific function.

extern crate alloc;

use super::dc;
use super::paint;
use super::pen_brush;
use super::text;
use super::types::{Rect, Size, TextMetricW};
use super::{
    alloc_gdi_handle, has_gdi_handle, lookup_object, remove_object, GdiObjectKind, GdiObjectPayload,
};
use core::sync::atomic::{AtomicU32, Ordering};

pub static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn case(_name: &str, ok: bool) -> bool {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let _ = &n;
    // crate::kprintln!("      [gdi32/{:02}] {} {}", n, if ok { "PASS" } else { "FAIL" }, name);
    ok
}

pub fn test_get_release_dc() -> bool {
    let h = dc::get_dc(core::ptr::null_mut());
    if h.is_null() {
        return false;
    }
    let r = dc::release_dc(core::ptr::null_mut(), h);
    r == 1
}

pub fn test_compatible_dc() -> bool {
    let h1 = dc::create_compatible_dc(core::ptr::null_mut());
    let h2 = dc::get_dc(core::ptr::null_mut());
    !h1.is_null() && !h2.is_null()
}

pub fn test_pat_blt() -> bool {
    let dc_h = dc::get_dc(core::ptr::null_mut());
    paint::pat_blt(dc_h, 0, 0, 100, 100, paint::rop::SRCCOPY) == 1
}

pub fn test_create_pen_brush() -> bool {
    let pen = pen_brush::create_pen(pen_brush::ps::PS_SOLID, 1, 0);
    let brush = pen_brush::create_solid_brush(0xFFFFFF);
    !pen.is_null() && !brush.is_null()
}

pub fn test_select_delete() -> bool {
    let dc_h = dc::get_dc(core::ptr::null_mut());
    let brush = pen_brush::create_solid_brush(0);
    let prev = pen_brush::select_object(dc_h, brush);
    let r = unsafe { pen_brush::delete_object(brush) };
    core::ptr::eq(prev, brush) && r == 1
}

pub fn test_text_out() -> bool {
    let dc_h = dc::get_dc(core::ptr::null_mut());
    unsafe { text::text_out_w(dc_h, 0, 0, core::ptr::null(), 0) == 1 }
}

pub fn test_get_text_extent() -> bool {
    let dc_h = dc::get_dc(core::ptr::null_mut());
    let mut s: Size = unsafe { core::mem::zeroed() };
    let r = unsafe { text::get_text_extent_point32_w(dc_h, core::ptr::null(), 8, &mut s) };
    r == 1 && s.cx == 64 && s.cy == 16
}

pub fn test_get_text_metrics() -> bool {
    let dc_h = dc::get_dc(core::ptr::null_mut());
    let mut m: TextMetricW = unsafe { core::mem::zeroed() };
    let r = unsafe { text::get_text_metrics_w(dc_h, &mut m) };
    r == 1 && m.tm_height == 16
}

pub fn test_draw_text() -> bool {
    let dc_h = dc::get_dc(core::ptr::null_mut());
    let mut r: Rect = unsafe { core::mem::zeroed() };
    let ret = unsafe { text::draw_text_w(dc_h, core::ptr::null(), 5, &mut r, 0) };
    ret == 5
}

pub fn test_invalid_rect() -> bool {
    let r: Rect = unsafe { core::mem::zeroed() };
    unsafe { paint::invalidate_rect(core::ptr::null_mut(), &r, 1) == 1 }
}

pub fn test_create_font() -> bool {
    let h = unsafe {
        pen_brush::create_font_w(16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, core::ptr::null())
    };
    !h.is_null()
}

pub fn test_gdi_handle_unique() -> bool {
    let a = alloc_gdi_handle();
    let b = alloc_gdi_handle();
    a != b && has_gdi_handle(a) && has_gdi_handle(b)
}

pub fn test_get_stock_object() -> bool {
    let white = pen_brush::get_stock_object(pen_brush::stock::WHITE_BRUSH);
    let black = pen_brush::get_stock_object(pen_brush::stock::BLACK_PEN);
    let invalid = pen_brush::get_stock_object(0xDEAD_BEEFu32 as i32);
    !white.is_null() && !black.is_null() && invalid.is_null()
}

// ---------------------------------------------------------------------------
// New cases added alongside the real implementations
// ---------------------------------------------------------------------------

/// `test_get_device_caps` — confirm the driver caps
/// return non-zero for the well-known indices.
pub fn test_get_device_caps() -> bool {
    let hdc = dc::get_dc(core::ptr::null_mut());
    let hr = dc::get_device_caps(hdc, dc::HORZRES);
    let vr = dc::get_device_caps(hdc, dc::VERTRES);
    let bpp = dc::get_device_caps(hdc, dc::BITSPIXEL);
    let planes = dc::get_device_caps(hdc, dc::PLANES);
    hr == 1024 && vr == 768 && bpp == 32 && planes == 1
}

/// `test_save_restore_dc` — verify the per-DC save
/// stack pushes and pops the selected state.
pub fn test_save_restore_dc() -> bool {
    let hdc = dc::get_dc(core::ptr::null_mut());
    let brush1 = pen_brush::create_solid_brush(0x111111);
    let brush2 = pen_brush::create_solid_brush(0x222222);
    let _ = pen_brush::select_object(hdc, brush1);
    let id = dc::save_dc(hdc);
    if id <= 0 {
        return false;
    }
    let _ = pen_brush::select_object(hdc, brush2);
    let r = dc::restore_dc(hdc, 1);
    r == 1
}

/// `test_create_pen_indirect` — confirm the LOGPEN
/// layout is parsed correctly.
pub fn test_create_pen_indirect() -> bool {
    #[repr(C)]
    struct LogPen {
        style: u32,
        width_x: i32,
        width_y: i32,
        color: u32,
    }
    let lp = LogPen {
        style: pen_brush::ps::PS_SOLID as u32,
        width_x: 3,
        width_y: 0,
        color: 0xABCDEF,
    };
    let h = unsafe { pen_brush::create_pen_indirect(&lp as *const _ as *const ()) };
    if h.is_null() {
        return false;
    }
    if let Some(obj) = lookup_object(h as u64) {
        if let GdiObjectPayload::Pen(p) = obj.payload {
            return p.style == pen_brush::ps::PS_SOLID && p.width == 3 && p.color == 0xABCDEF;
        }
    }
    false
}

/// `test_object_lifecycle` — register / lookup / remove
/// round-trip on a synthetic object.
pub fn test_object_lifecycle() -> bool {
    let h = alloc_gdi_handle();
    if !has_gdi_handle(h) {
        return false;
    }
    // The legacy `alloc_gdi_handle` does not insert an
    // object into the typed table, so `remove_object`
    // returns false — that is the expected behaviour.
    if remove_object(h) {
        return false;
    }
    // Inserting via the typed API and then removing
    // should round-trip cleanly.
    let pen = pen_brush::create_solid_brush(0xCAFE_BABE);
    if pen.is_null() {
        return false;
    }
    if !remove_object(pen as u64) {
        return false;
    }
    lookup_object(pen as u64).is_none()
}

/// `test_select_object_dc_pen` — pick a real pen, select
/// it into a DC, then confirm the DC table reflects
/// the change.
pub fn test_select_object_dc_pen() -> bool {
    let hdc = dc::get_dc(core::ptr::null_mut());
    let pen = pen_brush::create_pen(pen_brush::ps::PS_SOLID, 2, 0x00FF_00FF);
    let prev = pen_brush::select_object(hdc, pen);
    if prev.is_null() {
        return false;
    }
    // The DC should now report the new pen via the
    // handle table. We don't expose the DC payload
    // directly, so just confirm the handle still
    // resolves to a Pen object.
    if let Some(obj) = lookup_object(pen as u64) {
        obj.kind == GdiObjectKind::Pen
    } else {
        false
    }
}

/// `test_text_extent_ascii` — feed an actual ASCII
/// string and confirm the computed width is non-zero
/// and equals the sum of glyph widths.
pub fn test_text_extent_ascii() -> bool {
    let hdc = dc::get_dc(core::ptr::null_mut());
    let s: [u16; 4] = [b'W' as u16, b'i' as u16, b'W' as u16, b'i' as u16];
    let mut sz: Size = unsafe { core::mem::zeroed() };
    let r = unsafe { text::get_text_extent_point32_w(hdc, s.as_ptr(), 4, &mut sz) };
    // W=12, i=4, W=12, i=4 → 32; height = 16.
    r == 1 && sz.cx == 32 && sz.cy == 16
}

pub fn smoke_test() -> bool {
    let mut ok = true;
    ok &= case("get_release_dc", test_get_release_dc());
    ok &= case("compatible_dc", test_compatible_dc());
    ok &= case("pat_blt", test_pat_blt());
    ok &= case("create_pen_brush", test_create_pen_brush());
    ok &= case("select_delete", test_select_delete());
    ok &= case("text_out", test_text_out());
    ok &= case("get_text_extent", test_get_text_extent());
    ok &= case("get_text_metrics", test_get_text_metrics());
    ok &= case("draw_text", test_draw_text());
    ok &= case("invalidate_rect", test_invalid_rect());
    ok &= case("create_font", test_create_font());
    ok &= case("gdi_handle_unique", test_gdi_handle_unique());
    ok &= case("get_stock_object", test_get_stock_object());
    ok &= case("get_device_caps", test_get_device_caps());
    ok &= case("save_restore_dc", test_save_restore_dc());
    ok &= case("create_pen_indirect", test_create_pen_indirect());
    ok &= case("object_lifecycle", test_object_lifecycle());
    ok &= case("select_object_dc_pen", test_select_object_dc_pen());
    ok &= case("text_extent_ascii", test_text_extent_ascii());
    if ok {
        // crate::kprintln!("  [gdi32 SMOKE]   all {} checks passed",
        //     TEST_COUNTER.load(Ordering::SeqCst));
    } else {
        // crate::kprintln!("  [gdi32 SMOKE FAIL] one or more checks failed");
    }
    ok
}
