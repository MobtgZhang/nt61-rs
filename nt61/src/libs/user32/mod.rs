//! user32 — Win32 user-mode API surface
//
//! This module is a stub for the entire NT 6.1 user32.dll API
//! surface. The user-mode side of the kernel is never actually
//! invoked — `winload` loads the DLL just to verify that
//! `DllMain` is reachable and the export table is sane.
//
//! References:
//!   * MSDN Library "Windows 7" — user32.dll
//!   * ReactOS 0.3.x `win32ss/user/ntuser`
//!   * Wine 1.7.x `dlls/user32/user32.spec`

// user32 exports follow the Win32 naming convention
// (CreateWindowExW, GetMessageW, MSG, WNDCLASSEXW, ...).
// These names ARE the user32 ABI; we must not rename them.
#![allow(non_snake_case, non_upper_case_globals, dead_code)]
//
//! Module layout:
//!   * `window`   — window / message-pump APIs
//!   * `class`    — window class registration
//!   * `input`    — keyboard / mouse / system metrics
//!   * `gdi_link` — forwarders to `gdi32`
//!   * `mod.rs`   — aggregator + smoke test
//!   * `smoke`    — module-level smoke cases

extern crate alloc;

use crate::ke::sync::Spinlock;
use crate::kprintln;
use alloc::vec::Vec;

pub mod class;
pub mod gdi_link;
pub mod input;
pub mod types;
pub mod window;

/// Initialise the user32 stub. The bootstrap reports the
/// surfaces the kernel supports.
pub fn init() {
    // kprintln!("    [user32] init")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      window   : CreateWindowExW/DefWindowProcW/Destroy/Show/Update")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      class    : RegisterClassExW/UnregisterClassW")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      input    : GetAsyncKeyState/KeyboardState/Cursor/SystemMetrics")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      gdi_link : forwarders to gdi32")  // kprintln disabled (memcpy crash workaround);
    let _ = gdi_link::GDI_LINK.lock();
    // kprintln!("    [user32] ready")  // kprintln disabled (memcpy crash workaround);
}

/// Window-handle table for the kernel-side bookkeeping. User32
/// stub keeps a small ring of placeholder windows so the smoke
/// test can verify handle creation.
pub static WINDOW_TABLE: Spinlock<Vec<u64>> = Spinlock::new(Vec::new());

/// Allocate a new placeholder window handle. Returns a u64
/// pointer-shaped handle.
pub fn alloc_window_handle() -> u64 {
    let mut t = WINDOW_TABLE.lock();
    let h = 0x0000_FFFF_0000_0000u64 + t.len() as u64;
    t.push(h);
    h
}

/// Look up a window handle; returns true if it exists.
pub fn has_window_handle(h: u64) -> bool {
    WINDOW_TABLE.lock().iter().any(|x| *x == h)
}

pub mod smoke;
pub use smoke::smoke_test as run_smoke;
