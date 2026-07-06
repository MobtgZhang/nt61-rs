//! USB HID Keyboard Driver
//
//! Consumes the boot-protocol reports emitted by the USB HID
//! class driver. The boot keyboard report is 8 bytes: modifier,
//! reserved, 6 key codes (see USB HID 1.11 appendix B.1).
//
//! Clean-room implementation. Spec source: USB HID 1.11
//! appendix B ("Boot keyboard / mouse"). No code is copied
//! from any Microsoft or ReactOS source file.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::kprintln;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of a USB HID boot keyboard report.
pub const BOOT_KBD_REPORT_LEN: usize = 8;

/// USB HID boot protocol report structure:
/// - byte 0: modifier keys (ctrl, shift, etc.)
/// - byte 1: reserved
/// - bytes 2-7: up to 6 simultaneous key codes
const REPORT_MOD: usize = 0;
const REPORT_RESERVED: usize = 1;
const REPORT_KEYCODES: usize = 2;

/// Modifier key bits in the modifier byte.
const MOD_LCTRL: u8 = 1 << 0;
const MOD_LSHIFT: u8 = 1 << 1;
const MOD_LALT: u8 = 1 << 2;

const MOD_RCTRL: u8 = 1 << 4;
const MOD_RSHIFT: u8 = 1 << 5;
const MOD_RALT: u8 = 1 << 6;


/// Maximum number of keys that can be simultaneously pressed.
const MAX_KEYS: usize = 6;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single keyboard event: the key code + modifier mask.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyEvent {
    pub modifier: u8,
    pub key_code: u8,
}

/// HID boot protocol keyboard report.
#[derive(Debug, Clone, Default)]
pub struct BootKbdReport {
    pub modifiers: u8,
    pub reserved: u8,
    pub keycodes: [u8; MAX_KEYS],
}

impl BootKbdReport {
    /// Parse a raw 8-byte HID boot keyboard report.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < BOOT_KBD_REPORT_LEN {
            return None;
        }
        let mut report = Self::default();
        report.modifiers = data[REPORT_MOD];
        report.reserved = data[REPORT_RESERVED];
        for i in 0..MAX_KEYS {
            report.keycodes[i] = data[REPORT_KEYCODES + i];
        }
        Some(report)
    }

    /// Check if a specific modifier is active.
    pub fn is_modifier_active(&self, mod_bit: u8) -> bool {
        (self.modifiers & mod_bit) != 0
    }

    /// Check if any shift key is active.
    pub fn is_shift(&self) -> bool {
        self.is_modifier_active(MOD_LSHIFT) || self.is_modifier_active(MOD_RSHIFT)
    }

    /// Check if any control key is active.
    pub fn is_ctrl(&self) -> bool {
        self.is_modifier_active(MOD_LCTRL) || self.is_modifier_active(MOD_RCTRL)
    }

    /// Check if any alt key is active.
    pub fn is_alt(&self) -> bool {
        self.is_modifier_active(MOD_LALT) || self.is_modifier_active(MOD_RALT)
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// USB HID keyboard global state.
static USB_KBD_INITIALIZED: AtomicBool = AtomicBool::new(false);
static USB_KBD_BOOT_PROTOCOL: AtomicBool = AtomicBool::new(false);
static USB_KBD_IDLE_TIMEOUT: AtomicU8 = AtomicU8::new(0);
static USB_KBD_LAST_MODIFIERS: AtomicU8 = AtomicU8::new(0);
static USB_KBD_LAST_KEYCODES: [AtomicU8; MAX_KEYS] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];

/// Get whether the keyboard is initialised.
pub fn is_initialised() -> bool {
    USB_KBD_INITIALIZED.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Translate a USB HID key code to a Windows virtual key code.
/// The mapping covers the standard 104-key set; consumer / media
/// keys are not handled. Based on the USB HID 1.11 usage tables
/// (section 10 "Keyboard/Keypad Page").
pub fn hid_to_vk(code: u8) -> u16 {
    match code {
        // Letters (HID codes 0x04-0x1D = a-z)
        0x04 => 0x41, // a -> A
        0x05 => 0x42, // b
        0x06 => 0x43,
        0x07 => 0x44,
        0x08 => 0x45,
        0x09 => 0x46,
        0x0A => 0x47,
        0x0B => 0x48,
        0x0C => 0x49,
        0x0D => 0x4A,
        0x0E => 0x4B,
        0x0F => 0x4C,
        0x10 => 0x4D,
        0x11 => 0x4E,
        0x12 => 0x4F,
        0x13 => 0x50,
        0x14 => 0x51,
        0x15 => 0x52,
        0x16 => 0x53,
        0x17 => 0x54,
        0x18 => 0x55,
        0x19 => 0x56,
        0x1A => 0x57,
        0x1B => 0x58,
        // Numbers (HID codes 0x1E-0x27 = 1-0)
        0x1E => 0x31, // 1
        0x1F => 0x32,
        0x20 => 0x33,
        0x21 => 0x34,
        0x22 => 0x35,
        0x23 => 0x36,
        0x24 => 0x37,
        0x25 => 0x38,
        0x26 => 0x39,
        0x27 => 0x30, // 0
        // Enter / Escape / Backspace / Tab / Space
        0x28 => 0x0D, // Enter
        0x29 => 0x1B, // Escape
        0x2A => 0x08, // Backspace
        0x2B => 0x09, // Tab
        0x2C => 0x20, // Space
        // Punctuation (HID codes 0x2D-0x38)
        0x2D => 0xBD, // - (minus)
        0x2E => 0xBB, // =
        0x2F => 0xDB, // [
        0x30 => 0xDD, // ]
        0x31 => 0xDC, // backslash
        0x32 => 0xC0, // `
        0x33 => 0xBA, // ;
        0x34 => 0xDE, // '
        0x35 => 0xBF, // /
        0x36 => 0xBC, // ,
        0x37 => 0xBE, // .
        0x38 => 0xBF, // /
        // Function keys
        0x3A => 0x14, // Caps Lock
        0x3B => 0x70, // F1
        0x3C => 0x71, // F2
        0x3D => 0x72, // F3
        0x3E => 0x73, // F4
        0x3F => 0x74, // F5
        0x40 => 0x75, // F6
        0x41 => 0x76, // F7
        0x42 => 0x77, // F8
        0x43 => 0x78, // F9
        0x44 => 0x79, // F10
        0x45 => 0x7A, // F11
        0x46 => 0x7B, // F12
        // Navigation keys
        0x4F => 0x27, // Right Arrow
        0x50 => 0x25, // Left Arrow
        0x51 => 0x28, // Down Arrow
        0x52 => 0x26, // Up Arrow
        0x4A => 0x24, // Home
        0x4D => 0x23, // End
        0x4B => 0x21, // Page Up
        0x4E => 0x22, // Page Down
        0x49 => 0x2D, // Insert
        0x4C => 0x2E, // Delete
        // Keypad
        0x54 => 0x6A, // Keypad /
        0x55 => 0x6D, // Keypad *
        0x56 => 0x6B, // Keypad -
        0x57 => 0x6D, // Keypad +
        0x58 => 0x6D, // Keypad Enter
        0x63 => 0x6D, // Keypad .
        0x59 => 0x61, // Keypad 1 / End
        0x5A => 0x62, // Keypad 2 / Down
        0x5B => 0x63, // Keypad 3 / Page Down
        0x5C => 0x64, // Keypad 4 / Left
        0x5D => 0x65, // Keypad 5
        0x5E => 0x66, // Keypad 6 / Right
        0x5F => 0x67, // Keypad 7 / Home
        0x60 => 0x68, // Keypad 8 / Up
        0x61 => 0x69, // Keypad 9 / Page Up
        0x62 => 0x60, // Keypad 0 / Insert
        _ => 0,
    }
}

/// Convert a virtual key + modifier state to ASCII.
/// Returns None if the key does not produce a character.
fn vk_to_ascii(vk: u16, modifier: u8) -> Option<u8> {
    let shift = (modifier & (MOD_LSHIFT | MOD_RSHIFT)) != 0;
    let ctrl = (modifier & (MOD_LCTRL | MOD_RCTRL)) != 0;

    // Control characters
    if ctrl {
        match vk {
            0x41 => return Some(0x01), // Ctrl+A
            0x42 => return Some(0x02), // Ctrl+B
            0x43 => return Some(0x03), // Ctrl+C
            0x44 => return Some(0x04), // Ctrl+D
            0x45 => return Some(0x05), // Ctrl+E
            0x46 => return Some(0x06), // Ctrl+F
            0x47 => return Some(0x07), // Ctrl+G
            0x48 => return Some(0x08), // Ctrl+H = Backspace
            0x49 => return Some(0x09), // Ctrl+I = Tab
            0x4A => return Some(0x0A), // Ctrl+J = Line Feed
            0x4B => return Some(0x0B), // Ctrl+K
            0x4C => return Some(0x0C), // Ctrl+L
            0x4D => return Some(0x0D), // Ctrl+M = Enter
            0x4E => return Some(0x0E), // Ctrl+N
            0x4F => return Some(0x0F), // Ctrl+O
            0x50 => return Some(0x10), // Ctrl+P
            0x51 => return Some(0x11), // Ctrl+Q
            0x52 => return Some(0x12), // Ctrl+R
            0x53 => return Some(0x13), // Ctrl+S
            0x54 => return Some(0x14), // Ctrl+T
            0x55 => return Some(0x15), // Ctrl+U
            0x56 => return Some(0x16), // Ctrl+V
            0x57 => return Some(0x17), // Ctrl+W
            0x58 => return Some(0x18), // Ctrl+X
            0x59 => return Some(0x19), // Ctrl+Y
            0x5A => return Some(0x1A), // Ctrl+Z
            _ => {}
        }
    }

    // Letter keys
    if (0x41..=0x5A).contains(&vk) {
        let ch = if shift { vk as u8 } else { (vk + 0x20) as u8 };
        return Some(ch);
    }

    // Number and punctuation keys
    match (vk, shift) {
        (0x30, false) => Some(b'0'),
        (0x30, true) => Some(b')'),
        (0x31, false) => Some(b'1'),
        (0x31, true) => Some(b'!'),
        (0x32, false) => Some(b'2'),
        (0x32, true) => Some(b'@'),
        (0x33, false) => Some(b'3'),
        (0x33, true) => Some(b'#'),
        (0x34, false) => Some(b'4'),
        (0x34, true) => Some(b'$'),
        (0x35, false) => Some(b'5'),
        (0x35, true) => Some(b'%'),
        (0x36, false) => Some(b'6'),
        (0x36, true) => Some(b'^'),
        (0x37, false) => Some(b'7'),
        (0x37, true) => Some(b'&'),
        (0x38, false) => Some(b'8'),
        (0x38, true) => Some(b'*'),
        (0x39, false) => Some(b'9'),
        (0x39, true) => Some(b'('),
        // Punctuation
        (0xBD, false) => Some(b'-'),
        (0xBD, true) => Some(b'_'),
        (0xBB, false) => Some(b'='),
        (0xBB, true) => Some(b'+'),
        (0xDB, false) => Some(b'['),
        (0xDB, true) => Some(b'{'),
        (0xDD, false) => Some(b']'),
        (0xDD, true) => Some(b'}'),
        (0xDC, false) => Some(b'\\'),
        (0xDC, true) => Some(b'|'),
        (0xC0, false) => Some(b'`'),
        (0xC0, true) => Some(b'~'),
        (0xBA, false) => Some(b';'),
        (0xBA, true) => Some(b':'),
        (0xDE, false) => Some(b'\''),
        (0xDE, true) => Some(b'"'),
        (0xBF, false) => Some(b'/'),
        (0xBF, true) => Some(b'?'),
        (0xBC, false) => Some(b','),
        (0xBC, true) => Some(b'<'),
        (0xBE, false) => Some(b'.'),
        (0xBE, true) => Some(b'>'),
        // Special
        (0x08, _) => Some(0x08), // Backspace
        (0x09, _) => Some(0x09), // Tab
        (0x0D, _) => Some(b'\n'), // Enter
        (0x20, _) => Some(b' '), // Space
        _ => None,
    }
}

/// Enqueue a character to the system keyboard input queue.
/// This bridges USB keyboard input to the PS/2 keyboard queue.
fn enqueue_usb_char(ch: u8) {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::keyboard::enqueue_char(ch);
}

/// Handle a single key press event.
fn handle_key_event(modifier: u8, key_code: u8) {
    let vk = hid_to_vk(key_code);
    if vk == 0 {
        return;
    }

    if let Some(ch) = vk_to_ascii(vk, modifier) {
        enqueue_usb_char(ch);
    }

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[USB-KBD] key: vk=0x{:02x} mod=0x{:02x} ch={:?}",
//         vk,
//         modifier,
//         vk_to_ascii(vk, modifier).map(|c| c as char)
//     );
}

/// Process an interrupt transfer report from the USB device.
/// This is called from the USB interrupt handler with the 8-byte
/// boot protocol report.
pub fn process_report(data: &[u8]) {
    if !is_initialised() {
        return;
    }

    let report = match BootKbdReport::from_bytes(data) {
        Some(r) => r,
        None => return,
    };

    // Check for newly pressed keys
    for i in 0..MAX_KEYS {
        let key = report.keycodes[i];
        if key == 0 {
            continue;
        }

        // Check if this key was already pressed
        let was_pressed = (0..MAX_KEYS)
            .any(|j| USB_KBD_LAST_KEYCODES[j].load(Ordering::Relaxed) == key);

        if !was_pressed {
            handle_key_event(report.modifiers, key);
        }
    }

    // Store current state for next comparison
    USB_KBD_LAST_MODIFIERS.store(report.modifiers, Ordering::Relaxed);
    for i in 0..MAX_KEYS {
        USB_KBD_LAST_KEYCODES[i].store(report.keycodes[i], Ordering::Relaxed);
    }
}

/// Initialise the USB HID keyboard driver.
pub fn init() {
    USB_KBD_INITIALIZED.store(true, Ordering::SeqCst);
    USB_KBD_BOOT_PROTOCOL.store(true, Ordering::SeqCst);
    // kprintln!("      USB HID keyboard: ready")  // kprintln disabled (memcpy crash workaround);
}

/// Initialise with device parameters.
pub fn init_with_params(endpoint_addr: u8, max_packet_size: u16) {
    let _ = endpoint_addr;
    let _ = max_packet_size;
    init();
}

/// Set the idle timeout (in 4ms units).
pub fn set_idle(timeout: u8) {
    USB_KBD_IDLE_TIMEOUT.store(timeout, Ordering::Relaxed);
}

/// Smoke test the USB HID keyboard driver.
pub fn smoke_test() -> bool {
    // kprintln!("  [HID-KBD SMOKE] testing USB HID keyboard...")  // kprintln disabled (memcpy crash workaround);

    // Test boot report parsing
    let test_report = [
        0x00, // modifiers: none
        0x00, // reserved
        0x04, // keycode: 'a'
        0x00, 0x00, 0x00, 0x00, 0x00, // rest are zero
    ];

    let report = match BootKbdReport::from_bytes(&test_report) {
        Some(r) => r,
        None => {
            // kprintln!("  [HID-KBD SMOKE FAIL] from_bytes failed")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    };

    // Check modifiers
    if report.modifiers != 0x00 {
        // kprintln!("  [HID-KBD SMOKE FAIL] unexpected modifiers: 0x{:02x}", report.modifiers)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Check keycode
    if report.keycodes[0] != 0x04 {
        // kprintln!("  [HID-KBD SMOKE FAIL] unexpected keycode: 0x{:02x}", report.keycodes[0])  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Check VK translation
    let vk = hid_to_vk(0x04);
    if vk != 0x41 {
        // kprintln!("  [HID-KBD SMOKE FAIL] hid_to_vk(0x04) = 0x{:02x}, expected 0x41", vk)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Check ASCII translation
    let ch = vk_to_ascii(vk, 0);
    if ch != Some(b'a') {
        // kprintln!("  [HID-KBD SMOKE FAIL] vk_to_ascii(0x41, 0) = {:?}, expected 'a'", ch)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Check shift translation
    let ch = vk_to_ascii(vk, MOD_LSHIFT);
    if ch != Some(b'A') {
        // kprintln!("  [HID-KBD SMOKE FAIL] vk_to_ascii(0x41, SHIFT) = {:?}, expected 'A'", ch)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Test modifier detection
    let mod_report = BootKbdReport {
        modifiers: MOD_LSHIFT,
        reserved: 0,
        keycodes: [0x1E, 0, 0, 0, 0, 0], // '1' with shift
    };

    if !mod_report.is_shift() {
        // kprintln!("  [HID-KBD SMOKE FAIL] is_shift() returned false")  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Test shifted number key
    let vk = hid_to_vk(0x1E); // '1' key
    let ch = vk_to_ascii(vk, MOD_LSHIFT);
    if ch != Some(b'!') {
        // kprintln!("  [HID-KBD SMOKE FAIL] '1' with shift = {:?}, expected '!'", ch)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // kprintln!("  [HID-KBD SMOKE OK] USB HID keyboard healthy")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    - Boot report parsing: OK")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    - HID to VK mapping: OK")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    - VK to ASCII translation: OK")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    - Modifier key detection: OK")  // kprintln disabled (memcpy crash workaround);
    true
}
