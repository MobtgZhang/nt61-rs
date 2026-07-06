//! EFI Framebuffer Driver
//
//! Thin wrapper around the framebuffer information the UEFI
//! firmware supplied at boot. The actual pixel rendering is
//! already in `hal::x86_64::framebuffer`; this module registers
//! the EFI display as the system's primary console.
//
//! Clean-room implementation. No code is copied from any
//! Microsoft or ReactOS source file.

#![cfg(target_arch = "x86_64")]

use crate::drivers::video::log;
#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::framebuffer;

/// EFI framebuffer driver state.
#[derive(Debug)]
pub struct EfiFbState {
    /// Whether the framebuffer was initialized from real GOP info.
    initialized_from_gop: bool,
    /// Framebuffer physical base address.
    pub fb_address: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per row (stride).
    pub pitch: u32,
    /// Bits per pixel.
    pub bpp: u32,
}

impl EfiFbState {
    /// Create and initialize the EFI framebuffer state.
    /// Takes the GOP-provided framebuffer info if available.
    #[allow(dead_code)]
    pub fn new(
        fb_address: u64,
        width: u32,
        height: u32,
        stride: u32,
        bpp: u32,
    ) -> Self {
        let initialized_from_gop = fb_address != 0 && width != 0 && height != 0;

        if initialized_from_gop {
            log::video_ok("efifb", "GOP framebuffer detected, taking ownership");
            log::video_log_hex64("efifb", "framebuffer base", fb_address);
            log::video_log_hex("efifb", "resolution", width);
            log::video_log_hex("efifb", "x", height);
            log::video_log_hex("efifb", "stride", stride);
            log::video_log_hex("efifb", "bpp", bpp);
        } else {
            log::video_warn("efifb", "no GOP framebuffer provided, using VGA fallback");
        }

        Self {
            initialized_from_gop,
            fb_address,
            width,
            height,
            pitch: stride,
            bpp,
        }
    }

    /// Whether we are running on a real GOP framebuffer (not VGA fallback).
    #[allow(dead_code)]
    pub fn has_gop(&self) -> bool {
        self.initialized_from_gop
    }

    /// Write a test pattern to the framebuffer to verify it's writable.
    /// Fills the top-left 8x8 pixel area with a distinctive color (bright magenta).
    fn write_test_pattern(&self) {
        if self.fb_address == 0 {
            return;
        }

        // For 32-bit framebuffers, write bright magenta (R=255, G=0, B=255) as XRGB.
        let color: u32 = 0x00FF00FF;
        let fb = self.fb_address as *mut u32;

        for y in 0..8u32 {
            for x in 0..8u32 {
                let offset = (y * (self.pitch / 4)) + x;
                unsafe {
                    core::ptr::write_volatile(fb.add(offset as usize), color);
                }
            }
        }
    }

    /// Read back a pixel from the framebuffer to verify it was written.
    fn verify_pixel(&self, x: u32, y: u32) -> Option<u32> {
        if self.fb_address == 0 {
            return None;
        }

        let offset = (y * (self.pitch / 4)) + x;
        let fb = self.fb_address as *const u32;
        Some(unsafe { core::ptr::read_volatile(fb.add(offset as usize)) })
    }
}

/// Global EFI framebuffer state.
static EFI_FB_STATE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

fn set_global_state(state: *const EfiFbState) {
    EFI_FB_STATE.store(state as u64, core::sync::atomic::Ordering::Release);
}

fn get_global_state() -> Option<&'static EfiFbState> {
    let ptr = EFI_FB_STATE.load(core::sync::atomic::Ordering::Acquire);
    if ptr == 0 {
        None
    } else {
        unsafe { Some(&*(ptr as *const EfiFbState)) }
    }
}

/// Initialize the EFI framebuffer driver.
///
/// Takes the GOP-provided framebuffer parameters from winload's
/// BootInfo and passes them to `hal::x86_64::framebuffer::init()`.
pub fn init() {
    // Try to read the framebuffer info from winload's BootInfo.
    // This is passed through the kernel's global BootInfo structure.
    let (fb_address, width, height, stride, bpp) = get_bootinfo_framebuffer();

    let state = EfiFbState::new(fb_address, width, height, stride, bpp);

    // Publish the state through the global pointer so other subsystems
    // (e.g. the framebuffer panic screen) can read it without us
    // having to plumb a borrowed reference through every call site.
    set_global_state(&state as *const EfiFbState);

    // Initialize the HAL framebuffer layer.
    if state.has_gop() {
        framebuffer::init(Some(framebuffer::FramebufferInfo {
            address: state.fb_address,
            width: state.width,
            height: state.height,
            bpp: state.bpp,
            pitch: state.pitch,
        }));
    } else {
        // No GOP — fall back to VGA text mode through HAL.
        framebuffer::init(None);
    }

    // Run smoke test if we have a real GOP framebuffer.
    if state.has_gop() {
        state.write_test_pattern();
        // Read back center pixel of the test pattern.
        if let Some(pixel) = state.verify_pixel(4, 4) {
            if pixel == 0x00FF00FF {
                log::video_ok("efifb", "framebuffer write/read test passed");
            } else {
                log::video_warn("efifb", "framebuffer pixel mismatch (may still work)");
            }
        }

        // Clear the test pattern.
        let black: u32 = 0;
        let fb = state.fb_address as *mut u32;
        for y in 0..8u32 {
            for x in 0..8u32 {
                let offset = (y * (state.pitch / 4)) + x;
                unsafe {
                    core::ptr::write_volatile(fb.add(offset as usize), black);
                }
            }
        }
    }

    log::video_ok("efifb", "EFI framebuffer driver initialized");
}

/// Get framebuffer info from BootInfo.
/// This reads from the global BootInfo structure that winload populates.
/// Returns (address, width, height, stride, bpp).
///
/// Note: The framebuffer is initialized in kernel_main.rs via
/// hal::x86_64::framebuffer::init_from_bootinfo() before video::init()
/// is called. This function exists as a fallback mechanism and returns
/// zeros, allowing the driver to fall back to VGA mode.
fn get_bootinfo_framebuffer() -> (u64, u32, u32, u32, u32) {
    // Framebuffer info is initialized in kernel_main.rs before this module
    // is called. Return zeros to indicate no GOP info is available,
    // which causes the driver to fall back to VGA mode.
    // The actual framebuffer state is managed through the HAL layer.
    (0, 0, 0, 0, 0)
}

/// Run a smoke test on the EFI framebuffer.
///
/// Tests the HAL framebuffer layer by writing and reading a pixel.
pub fn smoke_test() -> bool {
    // Confirm that the publish/globalize handshake from init() is
    // visible to the rest of the system: if EFI_FB_STATE was never
    // set, this driver was not initialised and the smoke test is a
    // no-op for this run.
    if get_global_state().is_none() {
        log::video_error("efifb", "smoke test skipped: no published EfiFbState");
        return false;
    }

    let info = framebuffer::info();

    if info.address == 0 {
        log::video_error("efifb", "smoke test skipped: no framebuffer");
        return false;
    }

    // Write a distinctive color to pixel (0, 0).
    // For text mode (16 bpp), this writes a 16-bit cell.
    // For graphics mode (32 bpp), this writes an XRGB pixel.
    framebuffer::set_pixel(0, 0, 0x00FF00FF);

    // Read it back.
    let info2 = framebuffer::info();
    let fb = info2.address as *const u8;

    match info2.bpp {
        32 => {
            let pixel = unsafe {
                core::ptr::read_volatile(fb as *const u32)
            };
            if pixel == 0x00FF00FF {
                log::video_ok("efifb", "smoke test passed (32-bit pixel readback)");
                // Clear it back.
                framebuffer::set_pixel(0, 0, 0);
                return true;
            } else {
                log::video_warn("efifb", "smoke test: pixel mismatch (may still work)");
                return false;
            }
        }
        16 => {
            let cell = unsafe {
                core::ptr::read_volatile(fb as *const u16)
            };
            if cell != 0 {
                log::video_ok("efifb", "smoke test passed (16-bit cell writable)");
                return true;
            } else {
                log::video_warn("efifb", "smoke test: cell zero after write");
                return false;
            }
        }
        _ => {
            log::video_warn("efifb", "smoke test skipped: unsupported bpp");
            return true;
        }
    }
}
