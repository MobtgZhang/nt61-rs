//! Unified keyboard input layer
//
//! Combines PS/2 (8042 controller) and USB HID keyboard input into a
//! single read API used by the CMD shell. This module is the
//! **polling path** — it does not depend on IRQs.
//
//! ## Why we need this
//
//! `servers::cmd::read_command()` calls
//! `hal::x86_64::serial::read_char()` which only sees the UART
//! (COM1, port 0x3F8). On a real machine the user types on a
//! keyboard that is wired to either:
//
//!   * the 8042 PS/2 controller (ports 0x60/0x64), or
//!   * a USB HID keyboard behind an xHCI/EHCI/UHCI host controller.
//
//! Both of those transports land on a per-keyboard ring buffer.
//! This module polls both and pushes decoded ASCII bytes into the
//! shared keyboard ring buffer in `hal::x86_64::keyboard`.
//
//! ## Wire format
//
//! PS/2 Set-1 scancodes are decoded by
//! `hal::x86_64::keyboard::scancode_to_ascii` which is the same
//! table the Windows 6.1 `i8042prt` driver uses.
//
//! USB HID boot-protocol reports are 8 bytes long:
//
//!   byte 0: modifier bitmap (LCtrl..RGui, bit per modifier)
//!   byte 1: reserved
//!   byte 2..7: up-to-six concurrent key usage codes (HID Usage Table 0x07)
//
//! The conversion table `hid_usage_to_ascii()` in this file maps a
//! HID usage code to the ASCII glyph produced by its unshifted
//! (or, with shift=true, shifted) key.

#![cfg(target_arch = "x86_64")]

#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::READ_PORT_UCHAR;

const KBD_STATUS_PORT: u16 = 0x64;
const KBD_DATA_PORT: u16 = 0x60;
const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_AUX_OUTPUT_FULL: u8 = 1 << 5;

/// Polled PS/2 keyboard modifier state. The polled path inside the
/// CMD shell does not touch the IRQ-driven path used by Ring-3 user
/// code, so we own a private copy of the modifier bits.
static mut POLLED_SHIFT: bool = false;
static mut POLLED_CAPS: bool = false;

/// Read one decoded ASCII byte from the PS/2 controller using
/// polled I/O. Returns `None` if no key is pending or the key is
/// a modifier / function key.
pub fn ps2_poll_char() -> Option<u8> {
    let status = READ_PORT_UCHAR(KBD_STATUS_PORT);

    // Drain mouse bytes first so they never interleave with
    // keyboard bytes in the return path.
    if status & STATUS_AUX_OUTPUT_FULL != 0 {
        let _ = READ_PORT_UCHAR(KBD_DATA_PORT);
    }

    if status & STATUS_OUTPUT_FULL == 0 {
        return None;
    }

    let sc = READ_PORT_UCHAR(KBD_DATA_PORT);

    // SAFETY: single-threaded polling path; no concurrent access.
    unsafe {
        match sc {
            0x2A | 0x36 => { POLLED_SHIFT = true; return None; }
            0xAA | 0xB6 => { POLLED_SHIFT = false; return None; }
            0x3A => { POLLED_CAPS = !POLLED_CAPS; return None; }
            0xE0 => {
                // Drain the second byte of an extended scancode.
                let mut waited = 0u32;
                loop {
                    let s = READ_PORT_UCHAR(KBD_STATUS_PORT);
                    if s & STATUS_OUTPUT_FULL != 0 {
                        let _ = READ_PORT_UCHAR(KBD_DATA_PORT);
                        break;
                    }
                    waited += 1;
                    if waited > 100000 { break; }
                    core::hint::spin_loop();
                }
                return None;
            }
            _ => {}
        }

        // Drop release codes for non-modifier keys.
        if sc >= 0x80 {
            return None;
        }

        let shift = POLLED_SHIFT;
        let caps = POLLED_CAPS;
        #[cfg(target_arch = "x86_64")]
        if let Some(c) = crate::hal::x86_64::keyboard::scancode_to_ascii(sc, shift, caps) {
            return Some(if c == b'\n' { b'\r' } else { c });
        }
    }

    None
}

/// Inject a raw ASCII byte into the shared keyboard ring buffer
/// (the same buffer `hal::x86_64::keyboard::getc` reads from).
/// This is the entry point used by the USB HID driver once it
/// has decoded a boot-keyboard report.
pub fn inject_byte(c: u8) {
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::keyboard::enqueue_char(c);
}

/// Convert a USB HID Usage Table 0x07 code (keyboard) to an
/// unshifted ASCII byte. Returns `None` for non-printable keys
/// (modifiers, function keys, nav cluster).
pub fn hid_usage_to_ascii(usage: u8) -> Option<u8> {
    // Lookup table for HID usage codes 0x04..0x38 (letters,
    // digits, basic punctuation). The shifted counterparts are
    // computed by the caller using `shifted()`.
    let ascii: u8 = match usage {
        // Letters a..z (usage codes 0x04..0x1D).
        0x04..=0x1D => b'a' + (usage - 0x04),
        // Digits 1..9, 0.
        0x1E => b'1', 0x1F => b'2', 0x20 => b'3', 0x21 => b'4',
        0x22 => b'5', 0x23 => b'6', 0x24 => b'7', 0x25 => b'8',
        0x26 => b'9', 0x27 => b'0',
        // Basic punctuation.
        0x28 => b'\n', // Enter
        0x29 => 0x1B,  // Escape
        0x2A => b'\x08', // Backspace
        0x2B => b'\t', // Tab
        0x2C => b' ',  // Spacebar
        0x2D => b'-', 0x2E => b'=', 0x2F => b'[', 0x30 => b']',
        0x31 => b'\\', 0x32 => b'#', 0x33 => b';', 0x34 => b'\'',
        0x35 => b'`', 0x36 => b',', 0x37 => b'.', 0x38 => b'/',
        // CapsLock — handled as a modifier by the caller.
        0x39 => return None,
        _ => return None,
    };
    Some(ascii)
}

/// Convert a USB HID Usage Table 0x07 code to its shifted
/// counterpart. Returns `None` for keys that have no shifted
/// form (e.g. letter keys — those are handled by upper-casing
/// the unshifted letter).
pub fn hid_usage_shifted(usage: u8) -> Option<u8> {
    Some(match usage {
        0x04..=0x1D => 0, // Letters — caller uppercases.
        0x1E => b'!', 0x1F => b'@', 0x20 => b'#', 0x21 => b'$',
        0x22 => b'%', 0x23 => b'^', 0x24 => b'&', 0x25 => b'*',
        0x26 => b'(', 0x27 => b')',
        0x2D => b'_', 0x2E => b'+', 0x2F => b'{', 0x30 => b'}',
        0x31 => b'|', 0x32 => b'~', 0x33 => b':', 0x34 => b'"',
        0x35 => b'~', 0x36 => b'<', 0x37 => b'>', 0x38 => b'?',
        _ => return None,
    })
}

/// Decode a single HID usage code given the current modifier
/// state and emit it into the shared keyboard ring buffer.
pub fn hid_emit(usage: u8, shift: bool, caps: bool) {
    if usage == 0 { return; } // 0 = no event in the array slot.

    let base = match hid_usage_to_ascii(usage) {
        Some(c) => c,
        None => return,
    };

    let c = if base.is_ascii_alphabetic() {
        let upper = if shift { !caps } else { caps };
        if upper { base.to_ascii_uppercase() } else { base }
    } else if shift {
        hid_usage_shifted(usage).unwrap_or(base)
    } else {
        base
    };

    inject_byte(c);
}

/// Translate the HID modifier byte into the same flags we keep
/// for the polled PS/2 path. The byte layout matches the USB HID
/// spec (boot keyboard report, byte 0):
///
///   bit 0: Left Ctrl       bit 4: Right Ctrl
///   bit 1: Left Shift      bit 5: Right Shift
///   bit 2: Left Alt        bit 6: Right Alt
///   bit 3: Left GUI        bit 7: Right GUI
pub fn hid_shift_state(modifiers: u8) -> bool {
    (modifiers & (0x02 | 0x20)) != 0
}

pub fn hid_caps_from_modifier(modifiers: u8) -> bool {
    // CapsLock is not part of the modifier byte. Drivers that
    // implement it send a separate 0x39 usage code. We default
    // to off here; the caller should track it across reports.
    let _ = modifiers;
    false
}