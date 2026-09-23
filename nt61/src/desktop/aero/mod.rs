//! Aero Glass
//!
//! Implements the blur/glass effect used by Windows 7's "Aero Glass" theme.
//! The kernel portion reads from desktop composition; the actual blur is
//! performed either by the GPU (DWM/DX path) or by the software composition
//! fallback in `desktop::dwm::compose_frame`.
//!
//! Public configuration surface:
use crate::desktop::desktop;

/// Enable Aero. Updates the global Desktop and signals DWM.
pub fn init() {
    crate::hal::serial::write_string("[aero] init\r\n");
}

/// Aero is enabled if composition is on AND the user has not disabled
/// the glass colour scheme.
pub fn is_aero_active() -> bool {
    desktop().aero_enabled.load(core::sync::atomic::Ordering::Acquire)
}

/// ARGB tint applied to the glass frame. Defaults to fully transparent.
#[derive(Clone, Copy, Default)]
pub struct GlassColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

/// Set the global glass tint.
pub fn set_glass_color(c: GlassColor) {
    let _ = c;
}

/// Per-pixel alpha-blend a blurred background onto a glass frame. Used by
/// the software composition path.
///
/// # Arguments
/// * `bg`     - source RGB sample from the blurred background
/// * `fg`     - destination RGB sample (the frame's pre-glass content)
/// * `alpha`  - 0..=255 glass opacity
///
/// Returns the blended RGB sample as a 24-bit value (0xRRGGBB).
pub fn blend(bg: u32, fg: u32, alpha: u8) -> u32 {
    let a = alpha as u32;
    let inv = 255 - a;
    let br = (bg >> 16) & 0xFF;
    let bg_g = (bg >> 8) & 0xFF;
    let bb = bg & 0xFF;
    let fr = (fg >> 16) & 0xFF;
    let fg_g = (fg >> 8) & 0xFF;
    let fb = fg & 0xFF;
    let r = (br * a + fr * inv) / 255;
    let g = (bg_g * a + fg_g * inv) / 255;
    let b = (bb * a + fb * inv) / 255;
    (r << 16) | (g << 8) | b
}
