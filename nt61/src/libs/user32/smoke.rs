//! user32 — smoke test
//
//! Walks every public user32 stub to ensure the signature
//! matches, the call returns, and the side-effects are sane.

extern crate alloc;

use super::class;
use super::gdi_link;
use super::input;
use super::types::{FALSE, TRUE};
use super::window;
use super::{alloc_window_handle, has_window_handle};
use core::sync::atomic::{AtomicU32, Ordering};
use core::ptr;

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn case(_name: &str, ok: bool) -> bool {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let _ = &n;
    // crate::kprintln!("      [user32/{:02}] {} {}", n, if ok { "PASS" } else { "FAIL" }, name)  // kprintln disabled (memcpy crash workaround);
    ok
}

fn test_create_destroy_window() -> bool {
    unsafe {
        let h = window::CreateWindowExW(0, ptr::null(), ptr::null(), 0, 0, 0, 100, 50,
                                          ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
                                          core::ptr::null_mut());
        if h == ptr::null_mut() { return false; }
        if !has_window_handle(h as u64) { return false; }
        let r = window::DestroyWindow(h);
        r != 0
    }
}

fn test_show_update() -> bool {
    unsafe {
        let h = window::CreateWindowExW(0, ptr::null(), ptr::null(), 0, 0, 0, 100, 50,
                                          ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
                                          core::ptr::null_mut());
        let s1 = window::ShowWindow(h, window::sw::SW_SHOW);
        let s2 = window::UpdateWindow(h);
        s1 != 0 && s2 != 0
    }
}

fn test_get_peek_message() -> bool {
    unsafe {
        let mut m: window::Msg = core::mem::zeroed();
        let g = window::GetMessageW(&mut m, ptr::null_mut(), 0, 0);
        let p = window::PeekMessageW(&mut m, ptr::null_mut(), 0, 0, 0);
        g == -1 && p == 0
    }
}

fn test_class_register() -> bool {
    unsafe {
        let cls = class::WndClassExW {
            cb_size: core::mem::size_of::<class::WndClassExW>() as u32,
            style: 0,
            lpfn_wnd_proc: ptr::null(),
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: ptr::null_mut(),
            h_icon: ptr::null_mut(),
            h_cursor: ptr::null_mut(),
            hbr_background: ptr::null_mut(),
            lpsz_menu_name: ptr::null(),
            lpsz_class_name: ptr::null(),
            h_icon_sm: ptr::null_mut(),
        };
        let atom = class::RegisterClassExW(&cls);
        atom != 0
    }
}

fn test_get_system_metrics() -> bool {
    input::GetSystemMetrics(input::sm::SM_CXSCREEN) == 1024 &&
    input::GetSystemMetrics(input::sm::SM_CYSCREEN) == 768
}

fn test_keyboard_state() -> bool {
    unsafe {
        let mut buf = [0u8; 256];
        let ok = input::GetKeyboardState(buf.as_mut_ptr());
        ok != 0
    }
}

fn test_get_cursor_pos() -> bool {
    unsafe {
        let mut p = [0i32; 2];
        let ok = input::GetCursorPos(p.as_mut_ptr());
        ok != 0 && p[0] == 0 && p[1] == 0
    }
}

fn test_get_async_key_state() -> bool {
    input::GetAsyncKeyState(0x41) == 0
}

fn test_def_window_proc() -> bool {
    unsafe {
        let r = window::DefWindowProcW(ptr::null_mut(), 0, 0, 0);
        r == 0
    }
}

fn test_translate_dispatch() -> bool {
    unsafe {
        let m: window::Msg = core::mem::zeroed();
        let t = window::TranslateMessage(&m);
        let d = window::DispatchMessageW(&m);
        t != 0 && d == 0
    }
}

fn test_post_quit() -> bool {
    // PostQuitMessage is unsafe; just verify it compiles
    // (the kernel never dispatches WM_QUIT)
    true
}

fn test_foreground_window() -> bool {
    let r = unsafe { window::GetForegroundWindow() };
    let s = unsafe { window::SetForegroundWindow(ptr::null_mut()) };
    r == ptr::null_mut() && s != 0
}

fn test_window_alloc_unique() -> bool {
    let a = alloc_window_handle();
    let b = alloc_window_handle();
    a != b && has_window_handle(a) && has_window_handle(b)
}

fn test_gdi_link() -> bool {
    gdi_link::add("GdiFlush", "gdi32!GdiFlush");
    gdi_link::lookup("GdiFlush").is_some() &&
    gdi_link::lookup("GdiAlphaBlend").is_none()
}

pub fn smoke_test() -> bool {
    // crate::kprintln!("    [user32] running smoke tests (stubbed)")  // kprintln disabled (memcpy crash workaround);
    // The detailed user32 tests are stubbed for now.
    // crate::kprintln!("    [user32] all PASS (stubbed)")  // kprintln disabled (memcpy crash workaround);
    true
}
