//! Architecture-agnostic framebuffer support.
//
//! On x86_64 this module re-exports the VGA/Framebuffer implementation.
//! On other platforms we provide no-op stubs.

#[cfg(target_arch = "x86_64")]
pub use crate::hal::x86_64::framebuffer::*;

#[cfg(not(target_arch = "x86_64"))]
mod stub {
    /// Framebuffer information stub.
    #[derive(Default)]
    pub struct FramebufferInfo {
        pub address: u64,
        pub width: u32,
        pub height: u32,
        pub bytes_per_line: u32,
        pub bpp: u32,
    }

    /// Get framebuffer info.
    pub fn info() -> FramebufferInfo {
        FramebufferInfo::default()
    }

    /// Initialize framebuffer. Returns false.
    #[allow(dead_code)]
    pub fn init(_bootinfo_fb: Option<u64>) -> bool {
        false
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub use stub::*;
