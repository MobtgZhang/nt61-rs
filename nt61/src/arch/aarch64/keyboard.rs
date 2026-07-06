//! aarch64 keyboard (PS/2 or USB — placeholder)
//
//! Real implementation requires a HID driver; this is a no-op
//! for the bootstrap.

use core::sync::atomic::{AtomicU8, Ordering};

static BUF: [AtomicU8; 256] = [const { AtomicU8::new(0) }; 256];
static HEAD: AtomicU8 = AtomicU8::new(0);
static TAIL: AtomicU8 = AtomicU8::new(0);

pub fn irq_handler() {
    // No-op: requires HID driver.
    let _ = (&BUF, HEAD.load(Ordering::Relaxed), TAIL.load(Ordering::Relaxed));
}

pub fn getc() -> i16 { -1 }
pub fn init() {}
