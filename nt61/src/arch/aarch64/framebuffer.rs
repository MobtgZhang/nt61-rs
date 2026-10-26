//! Framebuffer driver for aarch64.
//!
//! On the QEMU `virt` machine the UEFI firmware hands the kernel a
//! GOP framebuffer through `BootInfo.framebuffer_*`. The actual
//! pixel writer is the cross-arch `hal::common::framebuffer`
//! module; this file is just a thin shim that adapts the per-arch
//! `init()` / `put_char` / `clear` / `blit` API to the cross-arch
//! backend.
//!
//! On real hardware (Rockchip, Qualcomm, Kunpeng) the same code
//! path applies once `BootInfo` carries a valid framebuffer
//! description; the firmware DTB / ACPI tables we currently boot
//! on don't expose a built-in panel, so a `-device ramfb` is the
//! canonical way to make QEMU provide one.

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
    if info.address == 0 {
        return;
    }
    let bytes_per_pixel = (info.bpp / 8) as usize;
    // Clamp to the data actually supplied; a short buffer used to make
    // the whole blit bail out at the first truncated row.
    let row_bytes = w as usize * bytes_per_pixel;
    let max_rows = if row_bytes == 0 { 0 } else { data.len() / row_bytes };
    let h = (h as usize).min(max_rows) as u32;
    for row in 0..h {
        for col in 0..w {
            let idx = ((row * w + col) as usize) * bytes_per_pixel;
            // Safety net only; the row clamp above keeps reads in bounds.
            if idx + 2 >= data.len() {
                break;
            }
            let r = data[idx + 2];
            let g = data[idx + 1];
            let b = data[idx + 0];
            lfb::set_pixel(x + col, y + row, lfb::color32(r, g, b));
        }
    }
}
