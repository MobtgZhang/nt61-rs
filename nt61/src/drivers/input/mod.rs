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

pub mod i8042;
pub mod usb_hid_kbd;
pub mod usb_hid_mouse;
pub mod virtio_input;

pub mod smoke;

pub fn init() {
    // kprintln!("    Input drivers: i8042, USB HID keyboard / mouse");
    crate::drivers::arch::init_i8042();
    virtio_input::init();
    usb_hid_kbd::init();
    usb_hid_mouse::init();
    // kprintln!("    Input stack ready");
}

pub fn smoke_test() -> bool {
    crate::drivers::arch::input_smoke_test(
        crate::drivers::input::usb_hid_kbd::smoke_test,
        crate::drivers::input::usb_hid_mouse::smoke_test,
    )
}
