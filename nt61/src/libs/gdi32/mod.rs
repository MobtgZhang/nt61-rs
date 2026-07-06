//! gdi32 — Win32 graphics device interface stub
//
//! NT 6.1 GDI surface. The actual rendering pipeline is not
//! implemented; the stubs return deterministic values so
//! the smoke test can exercise the call graph.
//
//! References:
//!   * MSDN Library "Windows 7" — gdi32.dll
//!   * ReactOS 0.3.x `win32ss/gdi/eng`
//!   * Wine 1.7.x `dlls/gdi32/gdi32.spec`

// gdi32 names (CreateCompatibleDC, BITMAPINFOHEADER, ...) are
// the GDI ABI and cannot be renamed.
#![allow(non_snake_case, non_upper_case_globals, dead_code)]
//
//! Module layout:
//!   * `types`     — GDI handles / structs
//!   * `dc`        — device context APIs
//!   * `paint`     — PatBlt / FillRect / InvalidateRect
//!   * `text`      — TextOut / DrawText / GetTextExtentPoint32
//!   * `pen_brush` — CreatePen / CreateSolidBrush / Select/DeleteObject
//!   * `smoke`     — module-level smoke test

extern crate alloc;

use crate::ke::sync::Spinlock;
use crate::kprintln;
use alloc::vec::Vec;

pub mod dc;
#[cfg(target_arch = "x86_64")]
pub mod paint;
pub mod pen_brush;
pub mod text;
pub mod types;

/// Object table for GDI handles.
pub static GDI_OBJECTS: Spinlock<Vec<u64>> = Spinlock::new(Vec::new());

/// Allocate a new placeholder GDI handle.
pub fn alloc_gdi_handle() -> u64 {
    let mut t = GDI_OBJECTS.lock();
    let h = 0x0000_DEAD_0000_0000u64 + t.len() as u64;
    t.push(h);
    h
}

/// Look up a GDI handle; returns true if it exists.
pub fn has_gdi_handle(h: u64) -> bool {
    GDI_OBJECTS.lock().iter().any(|x| *x == h)
}

/// Initialise the gdi32 stub.
pub fn init() {
    // kprintln!("    [gdi32] init")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      dc        : GetDC/ReleaseDC/CreateCompatibleDC/DeleteDC")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      paint     : PatBlt/FillRect/InvalidateRect")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      text      : TextOutW/DrawTextW/GetTextExtentPoint32W")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      pen_brush : CreatePen/CreateSolidBrush/SelectObject/DeleteObject")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    [gdi32] ready")  // kprintln disabled (memcpy crash workaround);
}

#[cfg(target_arch = "x86_64")]
pub mod smoke;
#[cfg(target_arch = "x86_64")]
pub use smoke::smoke_test as run_smoke;
