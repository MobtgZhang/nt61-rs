//! x86_64 backend for the abstract keyboard / polled-input.
//!
//! Forwards to the existing PS/2 8042 + USB-HID driver in
//! `crate::hal::x86_64::keyboard` (the shared ring buffer that
//! `keyboard_unified` exposes). The SafeBootMode CMD shell runs
//! with interrupts masked, so we use the *polled* PS/2 path —
//! every `try_read_byte` call drains the 8042 status port
//! directly, regardless of whether the IRQ is masked.
//!
//! The 8042 controller has its own byte format (set-2 scancodes)
//! but `keyboard::getc` returns the *decoded ASCII* byte, which
//! is exactly what the SafeBootMode shell wants. Special keys
//! (arrow keys, F1..F12) come through as a small set of escape
//! sequences that the shell recognises.

use core::sync::atomic::Ordering;

/// Initialise the x86_64 polled input backend. Resets the 8042
/// into polled mode (the existing `full_reset_for_poll`
/// sequence) so even with IRQs masked the byte stream is
/// available.
pub fn init() {
    super::READY.store(true, Ordering::Release);
    crate::hal::x86_64::keyboard::full_reset_for_poll();
}

/// Try to read one byte (non-blocking).
pub fn try_read_byte() -> Option<u8> {
    let raw = crate::hal::x86_64::keyboard::getc();
    if raw < 0 { None } else { Some(raw as u8) }
}

/// Coarse "is anything pending?" poll. The PS/2 driver
/// maintains a 16-byte ring buffer; we can't peek without
/// consuming the byte (the existing `getc` API doesn't have
/// a peek primitive), so `peek` returns `false` and the
/// `read_byte` loop just spins until a byte arrives.
pub fn peek() -> bool {
    false
}