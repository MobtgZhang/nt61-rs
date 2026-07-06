//! USB HID Mouse Driver
//
//! Consumes the boot-protocol reports emitted by the USB HID
//! class driver. The boot mouse report is 3 bytes (buttons, X, Y)
//! or 4 bytes (with wheel). See USB HID 1.11 appendix B.2.
//
//! Clean-room implementation. Spec source: USB HID 1.11
//! appendix B.2. No code is copied from any Microsoft or
//! ReactOS source file.

use core::sync::atomic::{AtomicBool, AtomicI16, AtomicU8, Ordering};

use crate::kprintln;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of a USB HID boot mouse report (buttons + X + Y).
pub const BOOT_MOUSE_REPORT_LEN: usize = 3;

/// Length of a USB HID boot mouse report with wheel (buttons + X + Y + wheel).
pub const BOOT_MOUSE_REPORT_LEN_WHEEL: usize = 4;

/// Button bits in the button byte.
pub const BUTTON_LEFT: u8 = 1 << 0;
pub const BUTTON_RIGHT: u8 = 1 << 1;
pub const BUTTON_MIDDLE: u8 = 1 << 2;
pub const BUTTON_BUTTON_4: u8 = 1 << 3;
pub const BUTTON_BUTTON_5: u8 = 1 << 4;

/// Maximum X/Y delta per report (boot protocol is 8-bit signed).



// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Mouse button state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MouseButtons {
    pub left: bool,
    pub right: bool,
    pub middle: bool,
    pub button_4: bool,
    pub button_5: bool,
}

impl MouseButtons {
    /// Create from button byte.
    pub fn from_u8(byte: u8) -> Self {
        Self {
            left: (byte & BUTTON_LEFT) != 0,
            right: (byte & BUTTON_RIGHT) != 0,
            middle: (byte & BUTTON_MIDDLE) != 0,
            button_4: (byte & BUTTON_BUTTON_4) != 0,
            button_5: (byte & BUTTON_BUTTON_5) != 0,
        }
    }

    /// Convert to button byte.
    pub fn to_u8(&self) -> u8 {
        let mut byte = 0u8;
        if self.left { byte |= BUTTON_LEFT; }
        if self.right { byte |= BUTTON_RIGHT; }
        if self.middle { byte |= BUTTON_MIDDLE; }
        if self.button_4 { byte |= BUTTON_BUTTON_4; }
        if self.button_5 { byte |= BUTTON_BUTTON_5; }
        byte
    }

    /// Check if any button is pressed.
    pub fn any(&self) -> bool {
        self.left || self.right || self.middle || self.button_4 || self.button_5
    }
}

/// Mouse movement event.
#[derive(Debug, Clone, Copy, Default)]
pub struct MouseEvent {
    /// X delta (movement since last report).
    pub dx: i16,
    /// Y delta (movement since last report).
    pub dy: i16,
    /// Wheel delta (typically -1 or +1 per notch).
    pub wheel: i8,
    /// Button state.
    pub buttons: MouseButtons,
    /// Whether this event contains movement.
    pub has_movement: bool,
    /// Whether this event contains button changes.
    pub has_button_change: bool,
}

impl MouseEvent {
    /// Create a new mouse event.
    pub fn new(dx: i16, dy: i16, wheel: i8, buttons: MouseButtons) -> Self {
        let has_movement = dx != 0 || dy != 0 || wheel != 0;
        Self {
            dx,
            dy,
            wheel,
            buttons,
            has_movement,
            has_button_change: false,
        }
    }

    /// Create an event with button change flag.
    pub fn with_button_change(mut self) -> Self {
        self.has_button_change = true;
        self
    }

    /// Check if this is a movement-only event (no button changes).
    pub fn is_movement_only(&self) -> bool {
        self.has_movement && !self.has_button_change
    }

    /// Check if this is a click event (buttons changed).
    pub fn is_click(&self) -> bool {
        self.has_button_change
    }
}

/// Mouse event type for click detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseClickType {
    LeftDown,
    LeftUp,
    RightDown,
    RightUp,
    MiddleDown,
    MiddleUp,
    WheelUp,
    WheelDown,
}

/// Boot mouse report structure.
#[derive(Debug, Clone, Default)]
pub struct BootMouseReport {
    pub buttons: MouseButtons,
    pub dx: i8,
    pub dy: i8,
    pub wheel: Option<i8>,
}

impl BootMouseReport {
    /// Parse a 3-byte boot mouse report.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < BOOT_MOUSE_REPORT_LEN {
            return None;
        }
        Some(Self {
            buttons: MouseButtons::from_u8(data[0]),
            dx: data[1] as i8,
            dy: data[2] as i8,
            wheel: None,
        })
    }

    /// Parse a 4-byte boot mouse report (with wheel).
    pub fn from_bytes_wheel(data: &[u8]) -> Option<Self> {
        if data.len() < BOOT_MOUSE_REPORT_LEN_WHEEL {
            return None;
        }
        Some(Self {
            buttons: MouseButtons::from_u8(data[0]),
            dx: data[1] as i8,
            dy: data[2] as i8,
            wheel: Some(data[3] as i8),
        })
    }
}

// ---------------------------------------------------------------------------
// Global mouse state
// ---------------------------------------------------------------------------

/// Global mouse state for tracking button transitions.
static MOUSE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static MOUSE_BOOT_PROTOCOL: AtomicBool = AtomicBool::new(false);

/// Last seen button state (for click detection).
static LAST_BUTTONS: AtomicU8 = AtomicU8::new(0);

/// Accumulated mouse position (relative mode).
static CURSOR_X: AtomicI16 = AtomicI16::new(0);
static CURSOR_Y: AtomicI16 = AtomicI16::new(0);

/// Screen bounds for cursor clamping.
static SCREEN_WIDTH: AtomicI16 = AtomicI16::new(1920);
static SCREEN_HEIGHT: AtomicI16 = AtomicI16::new(1080);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Get whether the mouse is initialised.
pub fn is_initialised() -> bool {
    MOUSE_INITIALIZED.load(Ordering::Relaxed)
}

/// Initialise the USB HID mouse driver.
pub fn init() {
    MOUSE_INITIALIZED.store(true, Ordering::SeqCst);
    MOUSE_BOOT_PROTOCOL.store(true, Ordering::SeqCst);
    // kprintln!("      USB HID mouse: ready (boot protocol)")  // kprintln disabled (memcpy crash workaround);
}

/// Initialise with parameters.
pub fn init_with_params(endpoint_addr: u8, max_packet_size: u16) {
    let _ = endpoint_addr;
    let _ = max_packet_size;
    init();
}

/// Reset the cursor position.
pub fn reset_position() {
    CURSOR_X.store(0, Ordering::SeqCst);
    CURSOR_Y.store(0, Ordering::SeqCst);
}

/// Set screen bounds for cursor clamping.
pub fn set_screen_bounds(width: i16, height: i16) {
    SCREEN_WIDTH.store(width, Ordering::SeqCst);
    SCREEN_HEIGHT.store(height, Ordering::SeqCst);
}

/// Get current cursor position.
pub fn get_cursor_position() -> (i16, i16) {
    let x = CURSOR_X.load(Ordering::Relaxed);
    let y = CURSOR_Y.load(Ordering::Relaxed);
    (x, y)
}

/// Parse a mouse report and return a MouseEvent.
/// Automatically detects whether the report has wheel data.
pub fn parse_report(data: &[u8]) -> Option<MouseEvent> {
    if !is_initialised() {
        return None;
    }

    // Try wheel format first (4 bytes)
    if let Some(report) = BootMouseReport::from_bytes_wheel(data) {
        return Some(process_report_internal(report));
    }

    // Fall back to basic format (3 bytes)
    if let Some(report) = BootMouseReport::from_bytes(data) {
        return Some(process_report_internal(report));
    }

    None
}

/// Internal function to process a parsed report.
fn process_report_internal(report: BootMouseReport) -> MouseEvent {
    // Get last button state
    let last_buttons = MouseButtons::from_u8(LAST_BUTTONS.load(Ordering::Relaxed));
    let current_buttons = report.buttons;

    // Detect button transitions
    let has_click = current_buttons != last_buttons;

    // Update last buttons
    LAST_BUTTONS.store(current_buttons.to_u8(), Ordering::Relaxed);

    // Accumulate cursor position
    let dx = report.dx as i16;
    let dy = report.dy as i16;

    if dx != 0 || dy != 0 {
        let old_x = CURSOR_X.load(Ordering::SeqCst);
        let old_y = CURSOR_Y.load(Ordering::SeqCst);

        let new_x = old_x.saturating_add(dx)
            .clamp(0, SCREEN_WIDTH.load(Ordering::Relaxed));
        let new_y = old_y.saturating_add(dy)
            .clamp(0, SCREEN_HEIGHT.load(Ordering::SeqCst));

        CURSOR_X.store(new_x, Ordering::SeqCst);
        CURSOR_Y.store(new_y, Ordering::SeqCst);
    }

    MouseEvent {
        dx: report.dx as i16,
        dy: report.dy as i16,
        wheel: report.wheel.unwrap_or(0) as i8,
        buttons: current_buttons,
        has_movement: dx != 0 || dy != 0 || report.wheel.map(|w| w != 0).unwrap_or(false),
        has_button_change: has_click,
    }
}

/// Detect click events from button transitions.
pub fn detect_click(current: &MouseButtons, previous: &MouseButtons) -> Option<MouseClickType> {
    // Left button transitions
    if current.left && !previous.left {
        return Some(MouseClickType::LeftDown);
    }
    if !current.left && previous.left {
        return Some(MouseClickType::LeftUp);
    }

    // Right button transitions
    if current.right && !previous.right {
        return Some(MouseClickType::RightDown);
    }
    if !current.right && previous.right {
        return Some(MouseClickType::RightUp);
    }

    // Middle button transitions
    if current.middle && !previous.middle {
        return Some(MouseClickType::MiddleDown);
    }
    if !current.middle && previous.middle {
        return Some(MouseClickType::MiddleUp);
    }

    None
}

/// Get the last button state.
pub fn get_last_buttons() -> MouseButtons {
    MouseButtons::from_u8(LAST_BUTTONS.load(Ordering::Relaxed))
}

/// Set idle timeout (for power management).
pub fn set_idle(_timeout: u8) {
    // USB HID idle timeout is set via SET_IDLE request
}

/// Get mouse statistics (for debugging).
pub fn get_stats() -> (i16, i16, u8) {
    let x = CURSOR_X.load(Ordering::Relaxed);
    let y = CURSOR_Y.load(Ordering::Relaxed);
    let buttons = LAST_BUTTONS.load(Ordering::Relaxed);
    (x, y, buttons)
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------

/// Run the mouse smoke test.
pub fn smoke_test() -> bool {
    // kprintln!("  [HID-MOUSE SMOKE] testing USB HID mouse...")  // kprintln disabled (memcpy crash workaround);

    // Test basic report parsing (3 bytes)
    let test_report_3 = [0x01, 0x05, 0xFB]; // Left button, dx=5, dy=-5
    match BootMouseReport::from_bytes(&test_report_3) {
        Some(r) => {
            if !r.buttons.left {
                // kprintln!("  [HID-MOUSE SMOKE FAIL] left button not detected")  // kprintln disabled (memcpy crash workaround);
                return false;
            }
            if r.dx != 5 {
                // kprintln!("  [HID-MOUSE SMOKE FAIL] dx != 5")  // kprintln disabled (memcpy crash workaround);
                return false;
            }
            if r.dy != -5 {
                // kprintln!("  [HID-MOUSE SMOKE FAIL] dy != -5")  // kprintln disabled (memcpy crash workaround);
                return false;
            }
            if r.wheel.is_some() {
                // kprintln!("  [HID-MOUSE SMOKE FAIL] unexpected wheel")  // kprintln disabled (memcpy crash workaround);
                return false;
            }
        }
        None => {
            // kprintln!("  [HID-MOUSE SMOKE FAIL] from_bytes failed")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    }

    // Test wheel report parsing (4 bytes)
    let test_report_4 = [0x00, 0x00, 0x00, 0x01]; // Wheel up
    match BootMouseReport::from_bytes_wheel(&test_report_4) {
        Some(r) => {
            if r.wheel != Some(1) {
                // kprintln!("  [HID-MOUSE SMOKE FAIL] wheel != 1")  // kprintln disabled (memcpy crash workaround);
                return false;
            }
        }
        None => {
            // kprintln!("  [HID-MOUSE SMOKE FAIL] from_bytes_wheel failed")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    }

    // Test MouseButtons
    let buttons = MouseButtons::from_u8(BUTTON_LEFT | BUTTON_RIGHT);
    if !buttons.left || !buttons.right || buttons.middle {
        // kprintln!("  [HID-MOUSE SMOKE FAIL] MouseButtons parsing failed")  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Test click detection
    let prev = MouseButtons::from_u8(0);
    let curr = MouseButtons::from_u8(BUTTON_LEFT);
    match detect_click(&curr, &prev) {
        Some(MouseClickType::LeftDown) => {}
        other => {
            let _ = other;
            // kprintln!("  [HID-MOUSE SMOKE FAIL] detect_click returned {:?}, expected LeftDown", other)  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    }

    // kprintln!("  [HID-MOUSE SMOKE OK] USB HID mouse healthy")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    - Basic report parsing: OK")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    - Wheel report parsing: OK")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    - Button parsing: OK")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    - Click detection: OK")  // kprintln disabled (memcpy crash workaround);
    true
}
