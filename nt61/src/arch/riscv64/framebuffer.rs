//! Framebuffer driver stub for RISC-V 64
//
//! RISC-V platforms may use platform-specific display drivers.
//! Real implementation: integrate with device tree for framebuffer
//! detection.

use crate::kprintln;

/// Framebuffer info structure.
pub struct FramebufferInfo {
    pub address: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
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

/// Initialize framebuffer (stub).
pub fn init() -> Option<FramebufferInfo> {
    // crate::kprintln!("[TODO] riscv64: framebuffer driver not yet implemented (arch/riscv64/framebuffer.rs)")  // kprintln disabled (memcpy crash workaround);
    None
}

/// Put a character at the given position.
pub fn put_char(_x: u32, _y: u32, _c: u8, _fg: u32, _bg: u32) {}

/// Clear the screen.
pub fn clear(_color: u32) {}

/// Copy a pixel pattern to the framebuffer.
pub fn blit(_data: &[u8], _x: u32, _y: u32, _w: u32, _h: u32) {}
