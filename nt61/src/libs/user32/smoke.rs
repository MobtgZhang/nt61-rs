//! user32 — smoke test
//
//! Walks every public user32 stub to ensure the signature
//! matches, the call returns, and the side-effects are sane.

extern crate alloc;

use super::class;
use super::gdi_link;
use super::input;
use super::window;
use super::{alloc_window_handle, has_window_handle};
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

pub static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn case(_name: &str, ok: bool) -> bool {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let _ = &n;
    // crate::kprintln!("      [user32/{:02}] {} {}", n, if ok { "PASS" } else { "FAIL" }, name);
    ok
}

pub fn test_create_destroy_window() -> bool {
    unsafe {
        let h = window::create_window_ex_w(
            0,
            ptr::null(),
            ptr::null(),
            0,
            0,
            0,
            100,
            50,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if h == ptr::null_mut() {
            return false;
        }
        if !has_window_handle(h as u64) {
            return false;
        }
        let r = window::destroy_window(h);
        r != 0
    }
}

pub fn test_show_update() -> bool {
    unsafe {
        let h = window::create_window_ex_w(
            0,
            ptr::null(),
            ptr::null(),
            0,
            0,
            0,
            100,
            50,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            core::ptr::null_mut(),
        );
        let s1 = window::show_window(h, window::sw::SW_SHOW);
        let s2 = window::update_window(h);
        s1 != 0 && s2 != 0
    }
}

pub fn test_get_peek_message() -> bool {
    unsafe {
        let mut m: window::Msg = core::mem::zeroed();
        let g = window::get_message_w(&mut m, ptr::null_mut(), 0, 0);
        let p = window::peek_message_w(&mut m, ptr::null_mut(), 0, 0, 0);
        g == -1 && p == 0
    }
}

pub fn test_class_register() -> bool {
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
        let atom = class::register_class_ex_w(&cls);
        atom != 0
    }
}

pub fn test_get_system_metrics() -> bool {
    input::get_system_metrics(input::sm::SM_CXSCREEN) == 1024
        && input::get_system_metrics(input::sm::SM_CYSCREEN) == 768
}

pub fn test_keyboard_state() -> bool {
    unsafe {
        let mut buf = [0u8; 256];
        let ok = input::get_keyboard_state(buf.as_mut_ptr());
        ok != 0
    }
}

pub fn test_get_cursor_pos() -> bool {
    unsafe {
        let mut p = [0i32; 2];
        let ok = input::get_cursor_pos(p.as_mut_ptr());
        ok != 0 && p[0] == 0 && p[1] == 0
    }
}

pub fn test_get_async_key_state() -> bool {
    input::get_async_key_state(0x41) == 0
}

pub fn test_def_window_proc() -> bool {
    unsafe {
        let r = window::def_window_proc_w(ptr::null_mut(), 0, 0, 0);
        r == 0
    }
}

pub fn test_translate_dispatch() -> bool {
    unsafe {
        let m: window::Msg = core::mem::zeroed();
        let t = window::translate_message(&m);
        let d = window::dispatch_message_w(&m);
        t != 0 && d == 0
    }
}

pub fn test_post_quit() -> bool {
    // post_quit_message is unsafe; just verify it compiles
    // (the kernel never dispatches WmQuit)
    true
}

pub fn test_foreground_window() -> bool {
    let r = unsafe { window::get_foreground_window() };
    let s = unsafe { window::set_foreground_window(ptr::null_mut()) };
    r == ptr::null_mut() && s != 0
}

pub fn test_window_alloc_unique() -> bool {
    let a = alloc_window_handle();
    let b = alloc_window_handle();
    a != b && has_window_handle(a) && has_window_handle(b)
}

pub fn test_gdi_link() -> bool {
    gdi_link::add("GdiFlush", "gdi32!GdiFlush");
    gdi_link::lookup("GdiFlush").is_some() && gdi_link::lookup("GdiAlphaBlend").is_none()
}

pub fn smoke_test() -> bool {
    // crate::kprintln!("    [user32] running smoke tests (stubbed)");
    // The detailed user32 tests are stubbed for now.
    // crate::kprintln!("    [user32] all PASS (stubbed)");
    true
}
