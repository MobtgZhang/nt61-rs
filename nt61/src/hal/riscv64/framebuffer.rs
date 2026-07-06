//! RISC-V64 Framebuffer HAL
//
//! This module provides framebuffer support for RISC-V64 platforms.
//
//! On RISC-V, framebuffer information is typically provided by the
//! bootloader (OpenSBI/UEFI) via device tree or firmware tables.
//
//! The framebuffer HAL provides:
//! - Linear framebuffer initialization
//! - Pixel drawing operations
//! - Text mode support (for compatible displays)
//! - Blue screen of death support
//
//! Clean-room implementation based on platform specifications.

#![cfg(target_arch = "riscv64")]

use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

// =====================================================================
// Framebuffer Info
// =====================================================================

/// The LFB info, as passed in by the bootloader.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical address of framebuffer
    pub address: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bits per pixel
    pub bpp: u32,
    /// Bytes per row (stride)
    pub pitch: u32,
}

impl Default for FramebufferInfo {
    fn default() -> Self {
        Self {
            address: 0,
            width: 1024,
            height: 768,
            bpp: 32,
            pitch: 1024 * 4,
        }
    }
}

// =====================================================================
// Static State
// =====================================================================

static FB_ADDR: AtomicU64 = AtomicU64::new(0);
static FB_WIDTH: AtomicU32 = AtomicU32::new(0);
static FB_HEIGHT: AtomicU32 = AtomicU32::new(0);
static FB_PITCH: AtomicU32 = AtomicU32::new(0);
static FB_BPP: AtomicU32 = AtomicU32::new(0);
static FB_INITIALIZED: AtomicU64 = AtomicU64::new(0);
static FB_CURSOR_X: AtomicU32 = AtomicU32::new(0);
static FB_CURSOR_Y: AtomicU32 = AtomicU32::new(0);
static FB_ATTR: AtomicU8 = AtomicU8::new(0x0F); // White on black

// =====================================================================
// Color Utilities
// =====================================================================

/// RGB to packed u32 pixel helper for 32-bit framebuffers.
#[inline]
pub fn color32(r: u8, g: u8, b: u8) -> u32 {
    ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

/// BGRA to packed u32 pixel helper.
#[inline]
pub fn color32_bgra(r: u8, g: u8, b: u8, a: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((g as u32) << 8) | (r as u32)
}

// =====================================================================
// Initialization
// =====================================================================

/// Initialize the framebuffer from bootloader information.
///
/// On RISC-V, the framebuffer is typically set up by OpenSBI or UEFI
/// firmware. The address, dimensions, and format are passed via device
/// tree or firmware tables.
pub fn init(info: Option<FramebufferInfo>) -> FramebufferInfo {
    match info {
        Some(fb) => {
            FB_ADDR.store(fb.address, Ordering::Release);
            FB_WIDTH.store(fb.width, Ordering::Release);
            FB_HEIGHT.store(fb.height, Ordering::Release);
            FB_PITCH.store(fb.pitch, Ordering::Release);
            FB_BPP.store(fb.bpp, Ordering::Release);
            FB_CURSOR_X.store(0, Ordering::Release);
            FB_CURSOR_Y.store(0, Ordering::Release);
            FB_INITIALIZED.store(1, Ordering::Release);
            fb
        }
        None => {
            // Use default values if no info provided
            // This allows development without firmware framebuffer
            let default_info = FramebufferInfo::default();
            FB_ADDR.store(default_info.address, Ordering::Release);
            FB_WIDTH.store(default_info.width, Ordering::Release);
            FB_HEIGHT.store(default_info.height, Ordering::Release);
            FB_PITCH.store(default_info.pitch, Ordering::Release);
            FB_BPP.store(default_info.bpp, Ordering::Release);
            FB_CURSOR_X.store(0, Ordering::Release);
            FB_CURSOR_Y.store(0, Ordering::Release);
            FB_INITIALIZED.store(1, Ordering::Release);
            default_info
        }
    }
}

/// Return the current framebuffer info.
pub fn info() -> FramebufferInfo {
    FramebufferInfo {
        address: FB_ADDR.load(Ordering::Acquire),
        width: FB_WIDTH.load(Ordering::Acquire),
        height: FB_HEIGHT.load(Ordering::Acquire),
        bpp: FB_BPP.load(Ordering::Acquire),
        pitch: FB_PITCH.load(Ordering::Acquire),
    }
}

/// Check if framebuffer is initialized.
pub fn is_initialized() -> bool {
    FB_INITIALIZED.load(Ordering::Acquire) != 0
}

// =====================================================================
// Pixel Operations
// =====================================================================

/// Write a single pixel at (x, y).
///
/// Coordinates are clipped to framebuffer bounds.
/// Color packing depends on active bpp:
/// - 16 bpp: RGB565
/// - 24 bpp: BGR
/// - 32 bpp: XRGB/BGRA
pub fn set_pixel(x: u32, y: u32, color: u32) {
    let w = FB_WIDTH.load(Ordering::Relaxed);
    let h = FB_HEIGHT.load(Ordering::Relaxed);
    if x >= w || y >= h {
        return;
    }
    let pitch = FB_PITCH.load(Ordering::Relaxed) as usize;
    let bpp = FB_BPP.load(Ordering::Relaxed) as usize;
    let addr = FB_ADDR.load(Ordering::Relaxed) as usize;
    let offset = y as usize * pitch + (x as usize * bpp / 8);
    let p = (addr + offset) as *mut u8;

    unsafe {
        match bpp {
            16 => {
                // RGB565 format
                let r = ((color >> 16) & 0xFF) as u16;
                let g = ((color >> 8) & 0xFF) as u16;
                let b = (color & 0xFF) as u16;
                let v: u16 = (r >> 3) << 11 | (g >> 2) << 5 | (b >> 3);
                ptr::write_volatile(p as *mut u16, v);
            }
            24 => {
                // BGR format (little-endian)
                ptr::write_volatile(p, (color >> 0) as u8);
                ptr::write_volatile(p.add(1), (color >> 8) as u8);
                ptr::write_volatile(p.add(2), (color >> 16) as u8);
            }
            32 => {
                // XRGB format (standard for most displays)
                ptr::write_volatile(p as *mut u32, color);
            }
            _ => {}
        }
    }
}

/// Fill the entire framebuffer with a single color.
pub fn clear(color: u32) {
    let w = FB_WIDTH.load(Ordering::Relaxed);
    let h = FB_HEIGHT.load(Ordering::Relaxed);
    let pitch = FB_PITCH.load(Ordering::Relaxed) as usize;
    let bpp = FB_BPP.load(Ordering::Relaxed) as usize;
    let addr = FB_ADDR.load(Ordering::Relaxed) as usize;

    if bpp == 32 {
        // Fast path for 32-bit framebuffers
        let pixels_per_row = pitch / 4;
        let total_pixels = pixels_per_row * h as usize;
        let p = addr as *mut u32;
        unsafe {
            for i in 0..total_pixels {
                ptr::write_volatile(p.add(i), color);
            }
        }
    } else {
        // Slow path for other bit depths
        for y in 0..h {
            for x in 0..w {
                set_pixel(x, y, color);
            }
        }
    }

    FB_CURSOR_X.store(0, Ordering::Relaxed);
    FB_CURSOR_Y.store(0, Ordering::Relaxed);
}

/// Scroll the visible area up by `lines` rows.
pub fn scroll_up(lines: u32) {
    let w = FB_WIDTH.load(Ordering::Relaxed);
    let h = FB_HEIGHT.load(Ordering::Relaxed);
    let pitch = FB_PITCH.load(Ordering::Relaxed) as usize;
    let bpp = FB_BPP.load(Ordering::Relaxed) as usize;
    let addr = FB_ADDR.load(Ordering::Relaxed) as usize;
    let bytes_per_row = (w as usize) * (bpp / 8);
    let line_bytes = bytes_per_row;
    let total_bytes = (h as usize) * line_bytes;

    if (lines as usize) >= h as usize {
        // Clear everything if scrolling past the end
        unsafe {
            ptr::write_bytes(addr as *mut u8, 0, total_bytes);
        }
        return;
    }

    let shift = (lines as usize) * line_bytes;
    unsafe {
        core::ptr::copy(
            (addr + shift) as *const u8,
            addr as *mut u8,
            total_bytes - shift,
        );
        ptr::write_bytes(
            (addr + total_bytes - shift) as *mut u8,
            0,
            shift,
        );
    }
}

// =====================================================================
// Text Mode
// =====================================================================

/// Set the text-mode attribute byte.
pub fn set_text_attribute(fg: u8, bg: u8) {
    FB_ATTR.store((bg << 4) | (fg & 0x0F), Ordering::Relaxed);
}

/// Write a text cell at (x, y) in text mode.
fn text_cell(x: u32, y: u32, ch: u8, attr: u8) {
    let w = FB_WIDTH.load(Ordering::Relaxed);
    let h = FB_HEIGHT.load(Ordering::Relaxed);
    if x >= w || y >= h {
        return;
    }
    let pitch = FB_PITCH.load(Ordering::Relaxed) as usize;
    let addr = FB_ADDR.load(Ordering::Relaxed) as usize;
    let off = y as usize * pitch + (x as usize) * 2;
    let p = (addr + off) as *mut u8;
    unsafe {
        ptr::write_volatile(p, ch);
        ptr::write_volatile(p.add(1), attr);
    }
}

// =====================================================================
// Font (Minimal 8x8)
// =====================================================================

/// 8x8 font for basic text rendering.
/// Each row is 8 bits, columns are LSB-first.
///
/// The 1024-byte font table is stored as a flat array and
/// re-interpreted into a 2-D view at access time so that we
/// don't have to hand-build a `.bin` file that the
/// `include_bytes!` macro can decode into `[[u8; 8]; 128]`
/// directly. The flat form is portable across binutils and
/// the data layout matches a standard 8x8 ASCII font (row-major,
/// 8 bytes per glyph, 128 glyphs).
static FONT_8X8_FLAT: [u8; 128 * 8] = *include_bytes!("font8x8.bin");

#[inline]
fn font_glyph(ch: u8) -> [u8; 8] {
    let idx = (ch as usize).min(127) * 8;
    FONT_8X8_FLAT[idx..idx + 8].try_into().unwrap()
}

/// Draw a glyph using 8x8 font.
fn draw_glyph_8x8(px: u32, py: u32, ch: u8, fg: u32, bg: u32) {
    if ch >= 128 {
        return;
    }
    let glyph = font_glyph(ch);
    for row in 0..8u32 {
        let bits = glyph[row as usize];
        for col in 0..8u32 {
            let on = (bits >> col) & 1 != 0;
            set_pixel(px + col, py + row, if on { fg } else { bg });
        }
    }
}

/// Draw a character at framebuffer coordinates (x, y).
pub fn draw_char(x: u32, y: u32, c: u8, fg: u32, bg: u32) {
    draw_glyph_8x8(x * 8, y * 8, c, fg, bg);
}

/// Advance the cursor one column. Wraps to next row and scrolls if needed.
pub fn put_char(c: u8) {
    let w = FB_WIDTH.load(Ordering::Relaxed) / 8;
    let h = FB_HEIGHT.load(Ordering::Relaxed) / 8;
    let cx = FB_CURSOR_X.load(Ordering::Relaxed);
    let cy = FB_CURSOR_Y.load(Ordering::Relaxed);
    let attr = FB_ATTR.load(Ordering::Relaxed);

    match c {
        b'\n' => {
            FB_CURSOR_X.store(0, Ordering::Relaxed);
            if cy + 1 >= h {
                scroll_up(8);
            } else {
                FB_CURSOR_Y.store(cy + 1, Ordering::Relaxed);
            }
        }
        b'\r' => {
            FB_CURSOR_X.store(0, Ordering::Relaxed);
        }
        b'\t' => {
            let spaces = 8 - (cx % 8);
            for _ in 0..spaces {
                put_char(b' ');
            }
        }
        _ => {
            // Draw the character
            draw_glyph_8x8(cx * 8, cy * 8, c, 0xFFFFFF, 0x000000);

            let nx = cx + 1;
            if nx >= w {
                FB_CURSOR_X.store(0, Ordering::Relaxed);
                if cy + 1 >= h {
                    scroll_up(8);
                } else {
                    FB_CURSOR_Y.store(cy + 1, Ordering::Relaxed);
                }
            } else {
                FB_CURSOR_X.store(nx, Ordering::Relaxed);
            }
        }
    }
}

/// Render a string at the current cursor position.
pub fn put_string(s: &str) {
    for c in s.bytes() {
        put_char(c);
    }
}

// =====================================================================
// Blue Screen of Death
// =====================================================================

/// Display a blue screen with error message.
pub fn bugcheck_screen(title: &str, message: &str) {
    // Blue background
    clear(0xAA0000); // Blue in RGB565-friendly format

    FB_CURSOR_X.store(0, Ordering::Relaxed);
    FB_CURSOR_Y.store(2, Ordering::Relaxed);
    set_text_attribute(0xF, 0x1); // White on blue

    put_string(title);
    put_char(b'\n');
    put_string(message);
}

// =====================================================================
// Framebuffer from Device Tree
// =====================================================================

/// Probe for framebuffer from device tree.
///
/// This function would typically parse the device tree to find
/// the framebuffer configuration. For now, it returns a default
/// configuration for QEMU virt machine.
pub fn probe_from_device_tree() -> Option<FramebufferInfo> {
    // In a real implementation, this would:
    // 1. Read the device tree from memory
    // 2. Find the /chosen node
    // 3. Look for stdout-path or framebuffer node
    // 4. Parse the framebuffer address, width, height, stride

    // For QEMU virt machine, return default values
    // that match the default VGA device
    Some(FramebufferInfo {
        address: 0x0, // Will be set by firmware
        width: 1024,
        height: 768,
        bpp: 32,
        pitch: 1024 * 4,
    })
}

// =====================================================================
// Direct Memory Access Helpers
// =====================================================================

/// Get a mutable pointer to the framebuffer.
pub fn framebuffer_ptr() -> *mut u8 {
    FB_ADDR.load(Ordering::Relaxed) as *mut u8
}

/// Get framebuffer size in bytes.
pub fn framebuffer_size() -> u64 {
    let pitch = FB_PITCH.load(Ordering::Relaxed) as u64;
    let height = FB_HEIGHT.load(Ordering::Relaxed) as u64;
    pitch * height
}

// =====================================================================
// Compatibility with x86_64 HAL
// =====================================================================

/// Compatible function names for cross-platform code.
pub mod compat {
    pub use super::info;
    pub use super::init;
    pub use super::set_pixel;
    pub use super::clear;
    pub use super::scroll_up;
    pub use super::draw_char;
    pub use super::put_char;
    pub use super::put_string;
    pub use super::bugcheck_screen;
    pub use super::color32;
    pub use super::FramebufferInfo;
}
