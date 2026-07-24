//! Linear Framebuffer (LFB) Support
//
//! On the PC there are three relevant framebuffer modes:
//
//! 1. The UEFI / Multiboot graphics framebuffer, which the
//!    bootloader already mapped for us. The base address, pitch,
//!    width, height, and bpp are passed in via `BootInfo`.
//! 2. The legacy VGA text-mode buffer at physical 0xB8000
//!    (80x25, 16 colours, 2 bytes per cell).
//! 3. The OVMF BOCHS VBE aperture at 0xE0_0000_0000 (1024x768x32).
//
//! `init()` prefers the LFB and falls back to the VGA text
//! buffer if no framebuffer info is supplied. The cross-arch
//! LFB writer lives in `hal::common::framebuffer_impl`; this
//! file mirrors its public API and adds the x86_64-only helpers
//! (VGA text-mode and BOCHS aperture detection) on top.

#![cfg(target_arch = "x86_64")]

use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

/// The LFB info, as passed in by the bootloader.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    pub address: u64,
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub pitch: u32,
}

/// VGA text-mode buffer (0xB8000) dimensions. Always 80x25 with
/// 16 colours and 2 bytes per cell.
const VGA_TEXT_WIDTH: u32 = 80;
const VGA_TEXT_HEIGHT: u32 = 25;
const VGA_TEXT_PITCH: u32 = VGA_TEXT_WIDTH * 2;
const VGA_TEXT_BPP: u32 = 16;
const VGA_TEXT_ADDR: u64 = 0xB8000;

static FB_ADDR: AtomicU64 = AtomicU64::new(0);
static FB_WIDTH: AtomicU32 = AtomicU32::new(0);
static FB_HEIGHT: AtomicU32 = AtomicU32::new(0);
static FB_PITCH: AtomicU32 = AtomicU32::new(0);
static FB_BPP: AtomicU32 = AtomicU32::new(0);
static FB_MODE_TEXT: AtomicU32 = AtomicU32::new(0); // 1 = text mode
static FB_CURSOR_X: AtomicU32 = AtomicU32::new(0);
static FB_CURSOR_Y: AtomicU32 = AtomicU32::new(0);
static FB_ATTR: AtomicU8 = AtomicU8::new(0x0F); // white on black

/// RGB → packed `u32` pixel helper for 32-bit framebuffers.
#[inline]
pub fn color32(r: u8, g: u8, b: u8) -> u32 {
    ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

/// Initialise the framebuffer. `info` is the LFB description
/// from the bootloader. If `info` is `None` we fall back to the
/// legacy VGA text-mode buffer.
pub fn init(info: Option<FramebufferInfo>) -> FramebufferInfo {
    match info {
        Some(fb) => {
            FB_ADDR.store(fb.address, Ordering::Release);
            FB_WIDTH.store(fb.width, Ordering::Release);
            FB_HEIGHT.store(fb.height, Ordering::Release);
            FB_PITCH.store(fb.pitch, Ordering::Release);
            FB_BPP.store(fb.bpp, Ordering::Release);
            FB_MODE_TEXT.store(0, Ordering::Release);
            FB_CURSOR_X.store(0, Ordering::Release);
            FB_CURSOR_Y.store(0, Ordering::Release);
            fb
        }
        None => {
            // Fallback to VGA text mode.
            FB_ADDR.store(VGA_TEXT_ADDR, Ordering::Release);
            FB_WIDTH.store(VGA_TEXT_WIDTH, Ordering::Release);
            FB_HEIGHT.store(VGA_TEXT_HEIGHT, Ordering::Release);
            FB_PITCH.store(VGA_TEXT_PITCH, Ordering::Release);
            FB_BPP.store(VGA_TEXT_BPP, Ordering::Release);
            FB_MODE_TEXT.store(1, Ordering::Release);
            FB_CURSOR_X.store(0, Ordering::Release);
            FB_CURSOR_Y.store(0, Ordering::Release);
            FramebufferInfo {
                address: VGA_TEXT_ADDR,
                width: VGA_TEXT_WIDTH,
                height: VGA_TEXT_HEIGHT,
                bpp: VGA_TEXT_BPP,
                pitch: VGA_TEXT_PITCH,
            }
        }
    }
}

/// Initialise the framebuffer from the winload-provided `BootInfo`
/// fields (`framebuffer_base`, `framebuffer_width`, …). Returns the
/// `FramebufferInfo` that was installed so callers can chain it
/// into subsequent setup.
///
/// Layout: the function does no I/O, just copies the relevant
/// fields into the per-CPU atomics used by the LFB backend. The
/// caller is responsible for ensuring the LFB base is mapped into
/// the kernel page tables before any pixels are written to it.
///
/// On x86_64 this also wires the cross-arch common LFB backend so
/// that the bootvid subsystem sees the same address through
/// `crate::hal::common::framebuffer::info()`. This is what lets
/// `crate::hal::framebuffer::*` resolve to the cross-arch impl on
/// non-x86_64 builds while x86_64 keeps its VGA fallback here.
pub fn init_from_bootinfo(
    base: u64,
    width: u32,
    height: u32,
    stride: u32,
    _format: u32,
) -> FramebufferInfo {
    // Mirror into the cross-arch LFB writer so any caller that
    // touches `crate::hal::common::framebuffer::*` (notably the
    // bootvid subsystem) sees the new base/width/height.
    if let Some(common_info) =
        crate::hal::common::framebuffer::init_from_bootinfo(base, width, height, stride, _format)
    {
        // Set default attribute to 0x07 (light grey on black) so
        // bootvid's cursor paint uses the standard colour.
        crate::hal::common::framebuffer::set_attr(0x07);
        return FramebufferInfo {
            address: common_info.address,
            width: common_info.width,
            height: common_info.height,
            bpp: common_info.bpp,
            pitch: common_info.pitch,
        };
    }
    // Only adopt the GOP-provided framebuffer if winload actually
    // published one. A zero `base` means winload failed to find
    // a GOP and we should fall back to the VGA text-mode buffer.
    if base == 0 || width == 0 || height == 0 {
        return init(None);
    }
    let bpp = 32u32;
    init(Some(FramebufferInfo {
        address: base,
        width,
        height,
        bpp,
        pitch: if stride == 0 { width * (bpp / 8) } else { stride },
    }))
}

/// `format` from the winload `BootInfo` blit:
///
/// * 0 = unknown/reserved (default 32 bpp BGRA)
/// * 1 = BGRA (the default OVMF format)
/// * 2 = RGBA
pub fn format_bpp(format: u32) -> u32 {
    match format {
        1 | 2 => 32,
        _ => 32,
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

/// Set the text-mode attribute byte (foreground in low nibble,
/// background in high nibble).
pub fn set_text_attribute(fg: u8, bg: u8) {
    FB_ATTR.store((bg << 4) | (fg & 0x0F), Ordering::Relaxed);
}

/// Write a single pixel. Coordinates are clipped to the
/// framebuffer bounds. Colour packing depends on the active
/// `bpp`:
///   16 bpp: RGB565
///   24 bpp: BGR
///   32 bpp: XRGB
pub fn set_pixel(x: u32, y: u32, color: u32) {
    let w = FB_WIDTH.load(Ordering::Relaxed);
    let h = FB_HEIGHT.load(Ordering::Relaxed);
    if x >= w || y >= h { return; }
    let pitch = FB_PITCH.load(Ordering::Relaxed) as usize;
    let bpp = FB_BPP.load(Ordering::Relaxed) as usize;
    let addr = FB_ADDR.load(Ordering::Relaxed) as usize;
    let offset = y as usize * pitch + (x as usize * bpp / 8);
    let p = (addr + offset) as *mut u8;
    unsafe {
        match bpp {
            16 => {
                let v: u16 = (((color >> 16) & 0xFF) as u16 >> 3) << 11
                           | (((color >> 8) & 0xFF) as u16 >> 2) << 5
                           | ((color & 0xFF) as u16 >> 3);
                ptr::write_volatile(p as *mut u16, v);
            }
            24 => {
                ptr::write_volatile(p,     (color >> 0)  as u8);
                ptr::write_volatile(p.add(1), (color >> 8)  as u8);
                ptr::write_volatile(p.add(2), (color >> 16) as u8);
            }
            32 => {
                ptr::write_volatile(p as *mut u32, color);
            }
            _ => {}
        }
    }
}

/// Fill the entire framebuffer with a single colour.
pub fn clear(color: u32) {
    let w = FB_WIDTH.load(Ordering::Relaxed);
    let h = FB_HEIGHT.load(Ordering::Relaxed);
    for y in 0..h {
        for x in 0..w {
            set_pixel(x, y, color);
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
        unsafe { ptr::write_bytes(addr as *mut u8, 0, total_bytes); }
        return;
    }
    let shift = (lines as usize) * line_bytes;
    unsafe {
        core::ptr::copy((addr + shift) as *const u8,
                        addr as *mut u8,
                        total_bytes - shift);
        ptr::write_bytes((addr + total_bytes - shift) as *mut u8,
                         0, shift);
    }
    let _ = pitch;
}

/// Write a 16-bit `u16` cell at (x, y) in text mode.
fn text_cell(x: u32, y: u32, ch: u8, attr: u8) {
    let w = FB_WIDTH.load(Ordering::Relaxed);
    let h = FB_HEIGHT.load(Ordering::Relaxed);
    if x >= w || y >= h { return; }
    let pitch = FB_PITCH.load(Ordering::Relaxed) as usize;
    let addr = FB_ADDR.load(Ordering::Relaxed) as usize;
    let off = y as usize * pitch + (x as usize) * 2;
    let p = (addr + off) as *mut u8;
    unsafe {
        ptr::write_volatile(p, ch);
        ptr::write_volatile(p.add(1), attr);
    }
}

/// 8x16 VGA font for printable ASCII. Each row is a 16-bit
/// pattern, only the low 8 bits are used per row.
static FONT: [[u8; 16]; 128] = {
    // Hand-built 8x16 font for ASCII 0x20..0x7E. Each character
    // is 16 rows of 8 bits (LSB = leftmost pixel). Rows are
    // stored MSB-first, mirroring the standard VGA ROM font.
    let mut f = [[0u8; 16]; 128];
    f[0x20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]; // space
    f[0x21] = [0x18,0x18,0x18,0x18,0x18,0x18,0x18,0,0x18,0x18,0,0,0,0,0,0]; // !
    f[0x22] = [0x6C,0x6C,0x6C,0x6C,0,0,0,0,0,0,0,0,0,0,0,0]; // "
    f[0x23] = [0x6C,0x6C,0xFE,0x6C,0xFE,0x6C,0x6C,0,0,0,0,0,0,0,0,0]; // #
    f[0x24] = [0x18,0x7E,0xC0,0x7C,0x06,0xFC,0x18,0,0,0,0,0,0,0,0,0]; // $
    f[0x25] = [0xC6,0xCC,0x18,0x30,0x66,0xC6,0,0,0,0,0,0,0,0,0,0]; // %
    f[0x26] = [0x38,0x6C,0x6C,0x38,0x76,0xDC,0xCC,0,0x76,0,0,0,0,0,0,0]; // &
    f[0x27] = [0x18,0x18,0x18,0,0,0,0,0,0,0,0,0,0,0,0,0]; // '
    f[0x28] = [0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0,0,0,0,0,0,0,0,0]; // (
    f[0x29] = [0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0,0,0,0,0,0,0,0,0]; // )
    f[0x2A] = [0,0x66,0x3C,0xFF,0x3C,0x66,0,0,0,0,0,0,0,0,0,0]; // *
    f[0x2B] = [0,0x18,0x18,0x7E,0x18,0x18,0,0,0,0,0,0,0,0,0,0]; // +
    f[0x2C] = [0,0,0,0,0,0x18,0x18,0x30,0,0,0,0,0,0,0,0]; // ,
    f[0x2D] = [0,0,0,0,0x7E,0,0,0,0,0,0,0,0,0,0,0]; // -
    f[0x2E] = [0,0,0,0,0,0,0,0x18,0x18,0,0,0,0,0,0,0]; // .
    f[0x2F] = [0x06,0x0C,0x18,0x30,0x60,0xC0,0,0,0,0,0,0,0,0,0,0]; // /
    f[0x30] = [0x7C,0xC6,0xC6,0xD6,0xD6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0]; // 0
    f[0x31] = [0x18,0x38,0x18,0x18,0x18,0x18,0x18,0x7E,0,0,0,0,0,0,0,0]; // 1
    f[0x32] = [0x7C,0xC6,0x06,0x0C,0x18,0x30,0x60,0xFE,0,0,0,0,0,0,0,0]; // 2
    f[0x33] = [0x7C,0xC6,0x06,0x3C,0x06,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0]; // 3
    f[0x34] = [0x0C,0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x0C,0,0,0,0,0,0,0,0]; // 4
    f[0x35] = [0xFE,0xC0,0xC0,0xFC,0x06,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0]; // 5
    f[0x36] = [0x3C,0x60,0xC0,0xFC,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0]; // 6
    f[0x37] = [0xFE,0x06,0x0C,0x18,0x30,0x30,0x30,0x30,0,0,0,0,0,0,0,0]; // 7
    f[0x38] = [0x7C,0xC6,0xC6,0x7C,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0]; // 8
    f[0x39] = [0x7C,0xC6,0xC6,0xC6,0x7E,0x06,0x0C,0x78,0,0,0,0,0,0,0,0]; // 9
    f[0x3A] = [0,0,0x18,0x18,0,0x18,0x18,0,0,0,0,0,0,0,0,0]; // :
    f[0x3B] = [0,0,0x18,0x18,0,0x18,0x18,0x30,0,0,0,0,0,0,0,0]; // ;
    f[0x3C] = [0x06,0x0C,0x18,0x30,0x18,0x0C,0x06,0,0,0,0,0,0,0,0,0]; // <
    f[0x3D] = [0,0,0x7E,0,0x7E,0,0,0,0,0,0,0,0,0,0,0]; // =
    f[0x3E] = [0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0,0,0,0,0,0,0,0,0]; // >
    f[0x3F] = [0x7C,0xC6,0x0C,0x18,0x18,0,0x18,0,0,0,0,0,0,0,0,0]; // ?
    f[0x40] = [0x7C,0xC6,0xC6,0xDE,0xDE,0xDC,0xC0,0x7C,0,0,0,0,0,0,0,0]; // @
    f[0x41] = [0x38,0x6C,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0]; // A
    f[0x42] = [0xFC,0xC6,0xC6,0xFC,0xC6,0xC6,0xC6,0xFC,0,0,0,0,0,0,0,0]; // B
    f[0x43] = [0x7C,0xC6,0xC0,0xC0,0xC0,0xC0,0xC6,0x7C,0,0,0,0,0,0,0,0]; // C
    f[0x44] = [0xF8,0xCC,0xC6,0xC6,0xC6,0xC6,0xCC,0xF8,0,0,0,0,0,0,0,0]; // D
    f[0x45] = [0xFE,0xC0,0xC0,0xF8,0xC0,0xC0,0xC0,0xFE,0,0,0,0,0,0,0,0]; // E
    f[0x46] = [0xFE,0xC0,0xC0,0xF8,0xC0,0xC0,0xC0,0xC0,0,0,0,0,0,0,0,0]; // F
    f[0x47] = [0x7C,0xC6,0xC0,0xC0,0xDE,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0]; // G
    f[0x48] = [0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0]; // H
    f[0x49] = [0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0,0,0,0,0,0,0,0]; // I
    f[0x4A] = [0x3E,0x0C,0x0C,0x0C,0x0C,0x0C,0xCC,0x78,0,0,0,0,0,0,0,0]; // J
    f[0x4B] = [0xC6,0xCC,0xD8,0xF0,0xE0,0xF0,0xD8,0xCC,0xC6,0,0,0,0,0,0,0]; // K
    f[0x4C] = [0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xFE,0,0,0,0,0,0,0,0]; // L
    f[0x4D] = [0xC6,0xEE,0xFE,0xFE,0xD6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0]; // M
    f[0x4E] = [0xC6,0xE6,0xF6,0xFE,0xDE,0xCE,0xC6,0xC6,0,0,0,0,0,0,0,0]; // N
    f[0x4F] = [0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0]; // O
    f[0x50] = [0xFC,0xC6,0xC6,0xC6,0xFC,0xC0,0xC0,0xC0,0,0,0,0,0,0,0,0]; // P
    f[0x51] = [0x7C,0xC6,0xC6,0xC6,0xC6,0xF6,0xDE,0x7C,0x06,0,0,0,0,0,0,0]; // Q
    f[0x52] = [0xFC,0xC6,0xC6,0xC6,0xFC,0xF0,0xD8,0xCC,0xC6,0,0,0,0,0,0,0]; // R
    f[0x53] = [0x7C,0xC6,0xC0,0x7C,0x06,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0]; // S
    f[0x54] = [0xFF,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0,0,0,0,0,0,0,0]; // T
    f[0x55] = [0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0]; // U
    f[0x56] = [0xC6,0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0,0,0,0,0,0,0,0]; // V
    f[0x57] = [0xC6,0xC6,0xC6,0xD6,0xD6,0xFE,0x6C,0x6C,0,0,0,0,0,0,0,0]; // W
    f[0x58] = [0xC6,0xC6,0x6C,0x38,0x38,0x6C,0xC6,0xC6,0,0,0,0,0,0,0,0]; // X
    f[0x59] = [0xC3,0xC3,0x66,0x3C,0x18,0x18,0x18,0x18,0,0,0,0,0,0,0,0]; // Y
    f[0x5A] = [0xFE,0x06,0x0C,0x18,0x30,0x60,0xC0,0xFE,0,0,0,0,0,0,0,0]; // Z
    f[0x5B] = [0x3C,0x30,0x30,0x30,0x30,0x30,0x30,0x3C,0,0,0,0,0,0,0,0]; // [
    f[0x5C] = [0xC0,0x60,0x30,0x18,0x0C,0x06,0,0,0,0,0,0,0,0,0,0]; // backslash
    f[0x5D] = [0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0,0,0,0,0,0,0,0]; // ]
    f[0x5E] = [0x10,0x38,0x6C,0xC6,0,0,0,0,0,0,0,0,0,0,0,0]; // ^
    f[0x5F] = [0,0,0,0,0,0,0,0,0xFE,0,0,0,0,0,0,0]; // _
    f[0x60] = [0x18,0x18,0x0C,0,0,0,0,0,0,0,0,0,0,0,0,0]; // `
    f[0x61] = [0,0,0x7C,0x06,0x7E,0xC6,0xC6,0x7E,0,0,0,0,0,0,0,0]; // a
    f[0x62] = [0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xC6,0xFC,0,0,0,0,0,0,0,0]; // b
    f[0x63] = [0,0,0x7C,0xC6,0xC0,0xC0,0xC6,0x7C,0,0,0,0,0,0,0,0]; // c
    f[0x64] = [0x06,0x06,0x7E,0xC6,0xC6,0xC6,0xC6,0x7E,0,0,0,0,0,0,0,0]; // d
    f[0x65] = [0,0,0x7C,0xC6,0xFE,0xC0,0xC6,0x7C,0,0,0,0,0,0,0,0]; // e
    f[0x66] = [0x3C,0x66,0x60,0xF8,0x60,0x60,0x60,0xF0,0,0,0,0,0,0,0,0]; // f
    f[0x67] = [0,0,0x7E,0xC6,0xC6,0x7E,0x06,0x7C,0,0,0,0,0,0,0,0]; // g
    f[0x68] = [0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0]; // h
    f[0x69] = [0x18,0,0x38,0x18,0x18,0x18,0x18,0x3C,0,0,0,0,0,0,0,0]; // i
    f[0x6A] = [0x0C,0,0x1C,0x0C,0x0C,0x0C,0xCC,0x78,0,0,0,0,0,0,0,0]; // j
    f[0x6B] = [0xC0,0xC0,0xC6,0xCC,0xF8,0xCC,0xC6,0xC6,0,0,0,0,0,0,0,0]; // k
    f[0x6C] = [0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0,0,0,0,0,0,0,0]; // l
    f[0x6D] = [0,0,0xEC,0xFE,0xFE,0xD6,0xC6,0xC6,0,0,0,0,0,0,0,0]; // m
    f[0x6E] = [0,0,0xFC,0xC6,0xC6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0]; // n
    f[0x6F] = [0,0,0x7C,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0]; // o
    f[0x70] = [0,0,0xFC,0xC6,0xC6,0xFC,0xC0,0xC0,0,0,0,0,0,0,0,0]; // p
    f[0x71] = [0,0,0x7E,0xC6,0xC6,0x7E,0x06,0x06,0,0,0,0,0,0,0,0]; // q
    f[0x72] = [0,0,0xFC,0xC6,0xC0,0xC0,0xC0,0xC0,0,0,0,0,0,0,0,0]; // r
    f[0x73] = [0,0,0x7E,0xC0,0x7C,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0]; // s
    f[0x74] = [0x30,0x30,0xFC,0x30,0x30,0x30,0x36,0x1C,0,0,0,0,0,0,0,0]; // t
    f[0x75] = [0,0,0xC6,0xC6,0xC6,0xC6,0xC6,0x7E,0,0,0,0,0,0,0,0]; // u
    f[0x76] = [0,0,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0,0,0,0,0,0,0,0]; // v
    f[0x77] = [0,0,0xC6,0xC6,0xD6,0xD6,0xFE,0x6C,0,0,0,0,0,0,0,0]; // w
    f[0x78] = [0,0,0xC6,0x6C,0x38,0x38,0x6C,0xC6,0,0,0,0,0,0,0,0]; // x
    f[0x79] = [0,0,0xC6,0xC6,0xC6,0x7E,0x06,0x7C,0,0,0,0,0,0,0,0]; // y
    f[0x7A] = [0,0,0xFE,0x0C,0x38,0x60,0xC0,0xFE,0,0,0,0,0,0,0,0]; // z
    f[0x7B] = [0x0E,0x18,0x18,0x70,0x18,0x18,0x0E,0,0,0,0,0,0,0,0,0]; // {
    f[0x7C] = [0x18,0x18,0x18,0,0x18,0x18,0x18,0,0,0,0,0,0,0,0,0]; // |
    f[0x7D] = [0x70,0x18,0x18,0x0E,0x18,0x18,0x70,0,0,0,0,0,0,0,0,0]; // }
    f[0x7E] = [0x76,0xDC,0,0,0,0,0,0,0,0,0,0,0,0,0,0]; // ~
    f
};

fn draw_glyph_8x16(px: u32, py: u32, ch: u8, fg: u32, bg: u32) {
    if ch >= 128 { return; }
    let glyph = &FONT[ch as usize];
    for row in 0..16u32 {
        let bits = glyph[row as usize];
        for col in 0..8u32 {
            let on = (bits >> (7 - col)) & 1 != 0;
            set_pixel(px + col, py + row, if on { fg } else { bg });
        }
    }
}

/// Draw a single 8x16 character at framebuffer coordinates
/// (x, y) using the supplied foreground / background colours.
pub fn draw_char(x: u32, y: u32, c: u8, fg: u32, bg: u32) {
    if FB_MODE_TEXT.load(Ordering::Relaxed) != 0 {
        text_cell(x, y, c, FB_ATTR.load(Ordering::Relaxed));
    } else {
        draw_glyph_8x16(x * 8, y * 16, c, fg, bg);
    }
}

/// Advance the cursor one column. Wraps to the next row, and
/// scrolls the screen if the cursor leaves the bottom edge.
pub fn put_char(c: u8) {
    let w = FB_WIDTH.load(Ordering::Relaxed) / if FB_MODE_TEXT.load(Ordering::Relaxed) != 0 { 1 } else { 8 };
    let h = FB_HEIGHT.load(Ordering::Relaxed) / if FB_MODE_TEXT.load(Ordering::Relaxed) != 0 { 1 } else { 16 };
    let cx = FB_CURSOR_X.load(Ordering::Relaxed);
    let cy = FB_CURSOR_Y.load(Ordering::Relaxed);
    match c {
        b'\n' => {
            FB_CURSOR_X.store(0, Ordering::Relaxed);
            if cy + 1 >= h {
                scroll_up(1);
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
            if FB_MODE_TEXT.load(Ordering::Relaxed) != 0 {
                let attr = FB_ATTR.load(Ordering::Relaxed);
                text_cell(cx, cy, c, attr);
            } else {
                draw_glyph_8x16(cx * 8, cy * 16, c, 0xFFFFFF, 0);
            }
            let nx = cx + 1;
            if nx >= w {
                FB_CURSOR_X.store(0, Ordering::Relaxed);
                if cy + 1 >= h {
                    scroll_up(1);
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

/// Draw a blue screen with white text. Used by the bugcheck
/// path (`ke::bugcheck` and friends) when the kernel has to halt
/// with a message visible to the user.
pub fn bugcheck_screen(title: &str, message: &str) {
    if FB_MODE_TEXT.load(Ordering::Relaxed) != 0 {
        clear(color32(0x1F, 0x00, 0x00));
        set_text_attribute(0xF, 0x1);
        FB_CURSOR_X.store(0, Ordering::Relaxed);
        FB_CURSOR_Y.store(0, Ordering::Relaxed);
        put_string(title);
        put_char(b'\n');
        put_string(message);
    } else {
        clear(color32(0x00, 0x00, 0xAA));
        FB_CURSOR_X.store(0, Ordering::Relaxed);
        FB_CURSOR_Y.store(2, Ordering::Relaxed);
        set_text_attribute(0xF, 0x1);
        put_string(title);
        put_char(b'\n');
        put_string(message);
    }
}
