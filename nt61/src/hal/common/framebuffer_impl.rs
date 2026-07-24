//! Cross-architecture Linear Framebuffer (LFB) support.
//!
//! Windows 7's BOOTVID.DLL paints pixels into a 32 bpp BGRA framebuffer
//! regardless of which bus the panel hangs off; this module provides the
//! same interface on every architecture.
//!
//! The LFB base / dimensions / pitch are published by `winload.efi`
//! inside `BootInfo.framebuffer_*`. On architectures that don't yet
//! publish a framebuffer (older builds, headless CI) `init_from_bootinfo`
//! returns `None` and every pixel-write function becomes a no-op so
//! callers can stay architecture-agnostic.
//!
//! The 8x16 font is shared with the legacy x86_64 backend. Each glyph
//! is stored as 16 rows of 8 bits, MSB-first (matches the standard VGA
//! ROM font).

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Framebuffer description produced by the bootloader (or by QEMU
/// `-vga none` / `-device ramfb`). 32 bpp BGRA matches the OVMF GOP
/// default; the per-pixel writer below is endian-aware so swapping
/// BGRA ↔ RGBA in firmware is a constant tweak rather than a code
/// change.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    pub address: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
}

impl FramebufferInfo {
    pub const fn empty() -> Self {
        Self { address: 0, width: 0, height: 0, pitch: 0, bpp: 32 }
    }
}

/// Cached framebuffer state. The writers consult these atomics on
/// every call so a later `init()` swap (e.g. UEFI GOP handover to a
/// real GPU driver) takes effect without touching the call sites.
static FB_ADDR: AtomicU64 = AtomicU64::new(0);
static FB_WIDTH: AtomicU32 = AtomicU32::new(0);
static FB_HEIGHT: AtomicU32 = AtomicU32::new(0);
static FB_PITCH: AtomicU32 = AtomicU32::new(0);
static FB_BPP: AtomicU32 = AtomicU32::new(0);
static FB_ACTIVE: AtomicBool = AtomicBool::new(false);
static FB_CURSOR_X: AtomicU32 = AtomicU32::new(0);
static FB_CURSOR_Y: AtomicU32 = AtomicU32::new(0);
static FB_ATTR: AtomicU8 = AtomicU8::new(0x07);

/// RGB → packed `u32` pixel helper for 32-bit framebuffers.
/// Layout is BGRA so the byte stream the VGA writes matches the
/// standard OVMF GOP format byte-for-byte.
#[inline]
pub const fn color32(r: u8, g: u8, b: u8) -> u32 {
    ((b as u32) << 16) | ((g as u32) << 8) | (r as u32)
}

/// Initialise the framebuffer from a `FramebufferInfo`. Returns the
/// info as installed so callers can chain it into further setup.
pub fn init(info: FramebufferInfo) -> FramebufferInfo {
    if info.address == 0 || info.width == 0 || info.height == 0 {
        return info;
    }
    let pitch = if info.pitch == 0 { info.width * (info.bpp / 8) } else { info.pitch };
    FB_ADDR.store(info.address, Ordering::Release);
    FB_WIDTH.store(info.width, Ordering::Release);
    FB_HEIGHT.store(info.height, Ordering::Release);
    FB_PITCH.store(pitch, Ordering::Release);
    FB_BPP.store(info.bpp, Ordering::Release);
    FB_ACTIVE.store(true, Ordering::Release);
    FB_CURSOR_X.store(0, Ordering::Release);
    FB_CURSOR_Y.store(0, Ordering::Release);
    FB_ATTR.store(0x07, Ordering::Release);
    FramebufferInfo {
        address: info.address,
        width: info.width,
        height: info.height,
        pitch,
        bpp: info.bpp,
    }
}

/// Initialise the framebuffer from the winload-provided `BootInfo`
/// fields (`framebuffer_base`, `framebuffer_width`, …). Returns
/// `Some(info)` if a non-zero framebuffer was installed, `None`
/// otherwise so callers can take a default action (e.g. bootvid
/// falls back to the legacy VGA path on x86_64).
pub fn init_from_bootinfo(
    base: u64,
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
) -> Option<FramebufferInfo> {
    if base == 0 || width == 0 || height == 0 {
        return None;
    }
    // BOCHS / OVMF GOP default to 32 bpp. Older EDK2 builds report
    // 24 bpp, which we treat as XRGB so the same writer works.
    let bpp = match format {
        1 | 2 | 4 | 5 => 32,
        _ => 32,
    };
    Some(init(FramebufferInfo {
        address: base,
        width,
        height,
        pitch: if stride == 0 { width * (bpp / 8) } else { stride },
        bpp,
    }))
}

/// Current framebuffer info. Returns zeros when no LFB is wired in.
pub fn info() -> FramebufferInfo {
    FramebufferInfo {
        address: FB_ADDR.load(Ordering::Acquire),
        width: FB_WIDTH.load(Ordering::Acquire),
        height: FB_HEIGHT.load(Ordering::Acquire),
        pitch: FB_PITCH.load(Ordering::Acquire),
        bpp: FB_BPP.load(Ordering::Acquire),
    }
}

/// Returns `true` once `init()` has wired an LFB into the cache.
pub fn is_active() -> bool {
    FB_ACTIVE.load(Ordering::Acquire)
}

/// Set the text attribute used by `put_byte_to_active_console`.
/// The attribute is split as `(bg << 4) | (fg & 0x0F)`.
pub fn set_attr(attr: u8) {
    FB_ATTR.store(attr, Ordering::Relaxed);
}

/// Set foreground / background separately.
pub fn set_text_attribute(fg: u8, bg: u8) {
    FB_ATTR.store((bg << 4) | (fg & 0x0F), Ordering::Relaxed);
}

/// Write a single pixel. Coordinates outside the framebuffer are
/// silently clipped. No-op if the framebuffer isn't active.
pub fn set_pixel(x: u32, y: u32, color: u32) {
    if !FB_ACTIVE.load(Ordering::Relaxed) { return; }
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
                core::ptr::write_volatile(p as *mut u16, v);
            }
            24 => {
                core::ptr::write_volatile(p,     (color >> 0)  as u8);
                core::ptr::write_volatile(p.add(1), (color >> 8)  as u8);
                core::ptr::write_volatile(p.add(2), (color >> 16) as u8);
            }
            32 => {
                core::ptr::write_volatile(p as *mut u32, color);
            }
            _ => {}
        }
    }
}

/// Fill the entire framebuffer with a single colour.
pub fn clear(color: u32) {
    if !FB_ACTIVE.load(Ordering::Relaxed) { return; }
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
    if !FB_ACTIVE.load(Ordering::Relaxed) { return; }
    let w = FB_WIDTH.load(Ordering::Relaxed);
    let h = FB_HEIGHT.load(Ordering::Relaxed);
    let pitch = FB_PITCH.load(Ordering::Relaxed) as usize;
    let bpp = FB_BPP.load(Ordering::Relaxed) as usize;
    let addr = FB_ADDR.load(Ordering::Relaxed) as usize;
    let bytes_per_row = (w as usize) * (bpp / 8);
    let total_bytes = (h as usize) * bytes_per_row;
    if (lines as usize) >= h as usize {
        unsafe { core::ptr::write_bytes(addr as *mut u8, 0, total_bytes); }
        return;
    }
    let shift = (lines as usize) * bytes_per_row;
    unsafe {
        core::ptr::copy((addr + shift) as *const u8, addr as *mut u8, total_bytes - shift);
        core::ptr::write_bytes((addr + total_bytes - shift) as *mut u8, 0, shift);
    }
    let _ = pitch;
}

/// 8x16 VGA font for printable ASCII. Each row is a 16-bit
/// pattern, only the low 8 bits are used per row.
static FONT: [[u8; 16]; 128] = {
    // Hand-built 8x16 font for ASCII 0x20..0x7E. Each character
    // is 16 rows of 8 bits (MSB = leftmost pixel).
    let mut f = [[0u8; 16]; 128];
    f[0x20] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    f[0x21] = [0x18,0x18,0x18,0x18,0x18,0x18,0x18,0,0x18,0x18,0,0,0,0,0,0];
    f[0x22] = [0x6C,0x6C,0x6C,0x6C,0,0,0,0,0,0,0,0,0,0,0,0];
    f[0x23] = [0x6C,0x6C,0xFE,0x6C,0xFE,0x6C,0x6C,0,0,0,0,0,0,0,0,0];
    f[0x24] = [0x18,0x7E,0xC0,0x7C,0x06,0xFC,0x18,0,0,0,0,0,0,0,0,0];
    f[0x25] = [0xC6,0xCC,0x18,0x30,0x66,0xC6,0,0,0,0,0,0,0,0,0,0];
    f[0x26] = [0x38,0x6C,0x6C,0x38,0x76,0xDC,0xCC,0,0x76,0,0,0,0,0,0,0];
    f[0x27] = [0x18,0x18,0x18,0,0,0,0,0,0,0,0,0,0,0,0,0];
    f[0x28] = [0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0,0,0,0,0,0,0,0,0];
    f[0x29] = [0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0,0,0,0,0,0,0,0,0];
    f[0x2A] = [0,0x66,0x3C,0xFF,0x3C,0x66,0,0,0,0,0,0,0,0,0,0];
    f[0x2B] = [0,0x18,0x18,0x7E,0x18,0x18,0,0,0,0,0,0,0,0,0,0];
    f[0x2C] = [0,0,0,0,0,0x18,0x18,0x30,0,0,0,0,0,0,0,0];
    f[0x2D] = [0,0,0,0,0x7E,0,0,0,0,0,0,0,0,0,0,0];
    f[0x2E] = [0,0,0,0,0,0,0,0x18,0x18,0,0,0,0,0,0,0];
    f[0x2F] = [0x06,0x0C,0x18,0x30,0x60,0xC0,0,0,0,0,0,0,0,0,0,0];
    f[0x30] = [0x7C,0xC6,0xC6,0xD6,0xD6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x31] = [0x18,0x38,0x18,0x18,0x18,0x18,0x18,0x7E,0,0,0,0,0,0,0,0];
    f[0x32] = [0x7C,0xC6,0x06,0x0C,0x18,0x30,0x60,0xFE,0,0,0,0,0,0,0,0];
    f[0x33] = [0x7C,0xC6,0x06,0x3C,0x06,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x34] = [0x0C,0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x0C,0,0,0,0,0,0,0,0];
    f[0x35] = [0xFE,0xC0,0xC0,0xFC,0x06,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x36] = [0x3C,0x60,0xC0,0xFC,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x37] = [0xFE,0x06,0x0C,0x18,0x30,0x30,0x30,0x30,0,0,0,0,0,0,0,0];
    f[0x38] = [0x7C,0xC6,0xC6,0x7C,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x39] = [0x7C,0xC6,0xC6,0xC6,0x7E,0x06,0x0C,0x78,0,0,0,0,0,0,0,0];
    f[0x3A] = [0,0,0x18,0x18,0,0x18,0x18,0,0,0,0,0,0,0,0,0];
    f[0x3B] = [0,0,0x18,0x18,0,0x18,0x18,0x30,0,0,0,0,0,0,0,0];
    f[0x3C] = [0x06,0x0C,0x18,0x30,0x18,0x0C,0x06,0,0,0,0,0,0,0,0,0];
    f[0x3D] = [0,0,0x7E,0,0x7E,0,0,0,0,0,0,0,0,0,0,0];
    f[0x3E] = [0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0,0,0,0,0,0,0,0,0];
    f[0x3F] = [0x7C,0xC6,0x0C,0x18,0x18,0,0x18,0,0,0,0,0,0,0,0,0];
    f[0x40] = [0x7C,0xC6,0xC6,0xDE,0xDE,0xDC,0xC0,0x7C,0,0,0,0,0,0,0,0];
    f[0x41] = [0x38,0x6C,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[0x42] = [0xFC,0xC6,0xC6,0xFC,0xC6,0xC6,0xC6,0xFC,0,0,0,0,0,0,0,0];
    f[0x43] = [0x7C,0xC6,0xC0,0xC0,0xC0,0xC0,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x44] = [0xF8,0xCC,0xC6,0xC6,0xC6,0xC6,0xCC,0xF8,0,0,0,0,0,0,0,0];
    f[0x45] = [0xFE,0xC0,0xC0,0xF8,0xC0,0xC0,0xC0,0xFE,0,0,0,0,0,0,0,0];
    f[0x46] = [0xFE,0xC0,0xC0,0xF8,0xC0,0xC0,0xC0,0xC0,0,0,0,0,0,0,0,0];
    f[0x47] = [0x7C,0xC6,0xC0,0xC0,0xDE,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x48] = [0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[0x49] = [0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0,0,0,0,0,0,0,0];
    f[0x4A] = [0x3E,0x0C,0x0C,0x0C,0x0C,0x0C,0xCC,0x78,0,0,0,0,0,0,0,0];
    f[0x4B] = [0xC6,0xCC,0xD8,0xF0,0xE0,0xF0,0xD8,0xCC,0xC6,0,0,0,0,0,0,0];
    f[0x4C] = [0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xFE,0,0,0,0,0,0,0,0];
    f[0x4D] = [0xC6,0xEE,0xFE,0xFE,0xD6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[0x4E] = [0xC6,0xE6,0xF6,0xFE,0xDE,0xCE,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[0x4F] = [0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x50] = [0xFC,0xC6,0xC6,0xC6,0xFC,0xC0,0xC0,0xC0,0,0,0,0,0,0,0,0];
    f[0x51] = [0x7C,0xC6,0xC6,0xC6,0xC6,0xF6,0xDE,0x7C,0x06,0,0,0,0,0,0,0];
    f[0x52] = [0xFC,0xC6,0xC6,0xC6,0xFC,0xF0,0xD8,0xCC,0xC6,0,0,0,0,0,0,0];
    f[0x53] = [0x7C,0xC6,0xC0,0x7C,0x06,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x54] = [0xFF,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0,0,0,0,0,0,0,0];
    f[0x55] = [0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x56] = [0xC6,0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0,0,0,0,0,0,0,0];
    f[0x57] = [0xC6,0xC6,0xC6,0xD6,0xD6,0xFE,0x6C,0x6C,0,0,0,0,0,0,0,0];
    f[0x58] = [0xC6,0xC6,0x6C,0x38,0x38,0x6C,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[0x59] = [0xC3,0xC3,0x66,0x3C,0x18,0x18,0x18,0x18,0,0,0,0,0,0,0,0];
    f[0x5A] = [0xFE,0x06,0x0C,0x18,0x30,0x60,0xC0,0xFE,0,0,0,0,0,0,0,0];
    f[0x5B] = [0x3C,0x30,0x30,0x30,0x30,0x30,0x30,0x3C,0,0,0,0,0,0,0,0];
    f[0x5C] = [0xC0,0x60,0x30,0x18,0x0C,0x06,0,0,0,0,0,0,0,0,0,0];
    f[0x5D] = [0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0,0,0,0,0,0,0,0];
    f[0x5E] = [0x10,0x38,0x6C,0xC6,0,0,0,0,0,0,0,0,0,0,0,0];
    f[0x5F] = [0,0,0,0,0,0,0,0,0xFE,0,0,0,0,0,0,0];
    f[0x60] = [0x18,0x18,0x0C,0,0,0,0,0,0,0,0,0,0,0,0,0];
    f[0x61] = [0,0,0x7C,0x06,0x7E,0xC6,0xC6,0x7E,0,0,0,0,0,0,0,0];
    f[0x62] = [0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xC6,0xFC,0,0,0,0,0,0,0,0];
    f[0x63] = [0,0,0x7C,0xC6,0xC0,0xC0,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x64] = [0x06,0x06,0x7E,0xC6,0xC6,0xC6,0xC6,0x7E,0,0,0,0,0,0,0,0];
    f[0x65] = [0,0,0x7C,0xC6,0xFE,0xC0,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x66] = [0x3C,0x66,0x60,0xF8,0x60,0x60,0x60,0xF0,0,0,0,0,0,0,0,0];
    f[0x67] = [0,0,0x7E,0xC6,0xC6,0x7E,0x06,0x7C,0,0,0,0,0,0,0,0];
    f[0x68] = [0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[0x69] = [0x18,0,0x38,0x18,0x18,0x18,0x18,0x3C,0,0,0,0,0,0,0,0];
    f[0x6A] = [0x0C,0,0x1C,0x0C,0x0C,0x0C,0xCC,0x78,0,0,0,0,0,0,0,0];
    f[0x6B] = [0xC0,0xC0,0xC6,0xCC,0xF8,0xCC,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[0x6C] = [0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0,0,0,0,0,0,0,0];
    f[0x6D] = [0,0,0xEC,0xFE,0xFE,0xD6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[0x6E] = [0,0,0xFC,0xC6,0xC6,0xC6,0xC6,0xC6,0,0,0,0,0,0,0,0];
    f[0x6F] = [0,0,0x7C,0xC6,0xC6,0xC6,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x70] = [0,0,0xFC,0xC6,0xC6,0xFC,0xC0,0xC0,0,0,0,0,0,0,0,0];
    f[0x71] = [0,0,0x7E,0xC6,0xC6,0x7E,0x06,0x06,0,0,0,0,0,0,0,0];
    f[0x72] = [0,0,0xFC,0xC6,0xC0,0xC0,0xC0,0xC0,0,0,0,0,0,0,0,0];
    f[0x73] = [0,0,0x7E,0xC0,0x7C,0x06,0xC6,0x7C,0,0,0,0,0,0,0,0];
    f[0x74] = [0x30,0x30,0xFC,0x30,0x30,0x30,0x36,0x1C,0,0,0,0,0,0,0,0];
    f[0x75] = [0,0,0xC6,0xC6,0xC6,0xC6,0xC6,0x7E,0,0,0,0,0,0,0,0];
    f[0x76] = [0,0,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0,0,0,0,0,0,0,0];
    f[0x77] = [0,0,0xC6,0xC6,0xD6,0xD6,0xFE,0x6C,0,0,0,0,0,0,0,0];
    f[0x78] = [0,0,0xC6,0x6C,0x38,0x38,0x6C,0xC6,0,0,0,0,0,0,0,0];
    f[0x79] = [0,0,0xC6,0xC6,0xC6,0x7E,0x06,0x7C,0,0,0,0,0,0,0,0];
    f[0x7A] = [0,0,0xFE,0x0C,0x38,0x60,0xC0,0xFE,0,0,0,0,0,0,0,0];
    f[0x7B] = [0x0E,0x18,0x18,0x70,0x18,0x18,0x0E,0,0,0,0,0,0,0,0,0];
    f[0x7C] = [0x18,0x18,0x18,0,0x18,0x18,0x18,0,0,0,0,0,0,0,0,0];
    f[0x7D] = [0x70,0x18,0x18,0x0E,0x18,0x18,0x70,0,0,0,0,0,0,0,0,0];
    f[0x7E] = [0x76,0xDC,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    f
};

/// Decode the standard 16-colour attribute into 32-bit BGRA.
pub fn attr_fg(attr: u8) -> u32 {
    // DOS 16-colour palette as BGRA8888.
    match attr & 0x0F {
        0  => 0x000000,
        1  => 0xAA0000,
        2  => 0x00AA00,
        3  => 0xAAAA00,
        4  => 0x0000AA,
        5  => 0xAA00AA,
        6  => 0x00AAAA,
        7  => 0xAAAAAA,
        8  => 0x555555,
        9  => 0xFF5555,
        10 => 0x55FF55,
        11 => 0xFFFF55,
        12 => 0x5555FF,
        13 => 0xFF55FF,
        14 => 0x55FFFF,
        15 => 0xFFFFFF,
        _ => 0xFFFFFF,
    }
}

pub fn attr_bg(attr: u8) -> u32 {
    attr_fg((attr >> 4) & 0x0F)
}

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

/// Render a single 8x16 character at framebuffer coordinates
/// (x, y) in glyph units using the supplied fg/bg colours.
pub fn draw_char(x: u32, y: u32, c: u8, fg: u32, bg: u32) {
    draw_glyph_8x16(x * 8, y * 16, c, fg, bg);
}

/// Advance the cursor one column. Wraps to the next row, and
/// scrolls the screen if the cursor leaves the bottom edge.
pub fn put_char(c: u8) {
    if !FB_ACTIVE.load(Ordering::Relaxed) { return; }
    let w = FB_WIDTH.load(Ordering::Relaxed) / 8;
    let h = FB_HEIGHT.load(Ordering::Relaxed) / 16;
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
            let attr = FB_ATTR.load(Ordering::Relaxed);
            let fg = attr_fg(attr);
            let bg = attr_bg(attr);
            draw_glyph_8x16(cx * 8, cy * 16, c, fg, bg);
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

/// Draw a blue screen with white text. Used by the bugcheck path.
pub fn bugcheck_screen(title: &str, message: &str) {
    if !FB_ACTIVE.load(Ordering::Relaxed) { return; }
    clear(color32(0x00, 0x00, 0xAA));
    FB_CURSOR_X.store(0, Ordering::Relaxed);
    FB_CURSOR_Y.store(2, Ordering::Relaxed);
    set_text_attribute(0xF, 0x1);
    put_string(title);
    put_char(b'\n');
    put_string(message);
}

/// Returns the current cursor position (in glyph units).
pub fn cursor_position() -> (u32, u32) {
    (
        FB_CURSOR_X.load(Ordering::Relaxed),
        FB_CURSOR_Y.load(Ordering::Relaxed),
    )
}

/// Reset cursor to (0, 0) without clearing the screen.
pub fn home_cursor() {
    FB_CURSOR_X.store(0, Ordering::Relaxed);
    FB_CURSOR_Y.store(0, Ordering::Relaxed);
}

/// Helper to log "LFB brought up" using the new common backend. The
/// kernel-side `arch::boot::adopt_bootinfo_framebuffer` calls this
/// after `init_from_bootinfo` succeeds so a single code path applies
/// to every architecture.
pub fn lfb_present() -> bool {
    let info = info();
    info.address != 0 && info.width != 0 && info.height != 0
}

/// Convenience for `boot_println!`-style code paths: write a string
/// to the LFB and translate `\n` → `\r\n`.
pub fn put_line(s: &str) {
    for b in s.bytes() {
        if b == b'\n' { put_char(b'\r'); }
        put_char(b);
    }
}
