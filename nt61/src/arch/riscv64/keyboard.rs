//! RISC-V 64 keyboard — no-op stub (USB HID not implemented)

pub fn irq_handler() {}
pub fn getc() -> i16 { -1 }
pub fn init() {}
