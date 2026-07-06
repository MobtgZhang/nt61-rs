//! Desktop Module
//
//! Desktop management

pub mod dwm;
pub mod aero;
pub mod applications;

pub fn init() {
    // crate::kprintln!("    Desktop subsystem: initialized")  // kprintln disabled (memcpy crash workaround);
}