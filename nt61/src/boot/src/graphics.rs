//! Graphics support for UEFI
//
//! Provides basic graphics functionality for boot interfaces.

/// Framebuffer information
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    pub base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}
