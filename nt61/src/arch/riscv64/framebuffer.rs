//! Framebuffer driver for RISC-V 64.
//!
//! On the QEMU `virt` machine the UEFI firmware hands the kernel a
//! GOP framebuffer through `BootInfo.framebuffer_*`. The actual
//! pixel writer is the cross-arch `hal::common::framebuffer`
//! module; this file is just a thin shim that adapts the per-arch
//! `init()` / `put_char` / `clear` / `blit` API to the cross-arch
//! backend.
//!
//! QEMU `-machine virt` for riscv64 supports `-device ramfb` to
//! expose a GOP framebuffer; that is the canonical bring-up.

#![allow(dead_code)]

use crate::hal::common::framebuffer as lfb;

/// Framebuffer information.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    pub address: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
}

impl From<lfb::FramebufferInfo> for FramebufferInfo {
    fn from(c: lfb::FramebufferInfo) -> Self {
        Self {
            address: c.address,
            width: c.width,
            height: c.height,
            pitch: c.pitch,
            bpp: c.bpp,
        }
    }
}

impl FramebufferInfo {
    pub fn new() -> Self {
        Self {
            address: 0,
            width: 0,
            height: 0,
            pitch: 0,
            bpp: 0,
        }
    }
}

/// Initialise the framebuffer from the GOP mailbox in `BootInfo`.
/// Returns the `FramebufferInfo` if winload actually published a
/// framebuffer, or `None` if the firmware didn't expose one.
pub fn init() -> Option<FramebufferInfo> {
    let info = lfb::info();
    if info.address != 0 && info.width != 0 && info.height != 0 {
        Some(info.into())
    } else {
        None
    }
}

/// Put a character at the given position using the supplied
/// foreground / background colours.
pub fn put_char(x: u32, y: u32, c: u8, fg: u32, bg: u32) {
    lfb::draw_char(x, y, c, fg, bg);
}

/// Clear the screen with the supplied colour.
pub fn clear(color: u32) {
    lfb::clear(color);
}

/// Copy a pixel pattern to the framebuffer. The data is interpreted
/// as 32-bit BGRA pixels.
pub fn blit(data: &[u8], x: u32, y: u32, w: u32, h: u32) {
    let info = lfb::info();
    if info.address == 0 { return; }
    let bytes_per_pixel = (info.bpp / 8) as usize;
    for row in 0..h {
        for col in 0..w {
            let idx = ((row * w + col) as usize) * bytes_per_pixel;
            if idx + 3 >= data.len() { return; }
            let r = data[idx + 2];
            let g = data[idx + 1];
            let b = data[idx + 0];
            lfb::set_pixel(x + col, y + row, lfb::color32(r, g, b));
        }
    }
}
