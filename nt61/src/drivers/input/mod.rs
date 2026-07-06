//! Input Driver Stack
//
//! Provides keyboard and mouse input from two sources:
//! 1. The legacy 8042 PS/2 controller (`i8042.rs`).
//! 2. USB HID (the boot keyboard / mouse protocols live in
//!    `drivers::usb::hid`; the input module just consumes the
//!    HID boot reports).
//
//! Clean-room implementation. Spec source: PS/2 controller
//! reference (IBM KB-101 keyboard) and USB HID 1.11. No code is
//! copied from any Microsoft or ReactOS source file.

extern crate alloc;

#[cfg(target_arch = "x86_64")]
pub mod i8042;
pub mod usb_hid_kbd;
pub mod usb_hid_mouse;

#[cfg(target_arch = "x86_64")]
pub mod smoke;

use crate::kprintln;

pub fn init() {
    // kprintln!("    Input drivers: i8042, USB HID keyboard / mouse")  // kprintln disabled (memcpy crash workaround);
    #[cfg(target_arch = "x86_64")]
    i8042::init();
    usb_hid_kbd::init();
    usb_hid_mouse::init();
    // kprintln!("    Input stack ready")  // kprintln disabled (memcpy crash workaround);
}

pub fn smoke_test() -> bool {
    #[cfg(target_arch = "x86_64")]
    { smoke::smoke_test() }
    #[cfg(not(target_arch = "x86_64"))]
    { true }
}
