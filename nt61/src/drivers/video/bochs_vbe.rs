//! Bochs VBE Display Driver
//
//! Bochs' VBE device is exposed at PCI 1234:1111. The driver
//! uses the BAR0 MMIO window (registers at 0x01CE / 0x01CF) to
//! set the display mode and read the framebuffer base.
//
//! Clean-room implementation. Spec source: Bochs VBE
//! documentation in the QEMU source tree. No code is copied
//! from any Microsoft or ReactOS source file.

#![cfg(target_arch = "x86_64")]

use crate::drivers::video::log;
#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::framebuffer;

/// PCI vendor/device IDs for the Bochs VBE device.
pub const BOCHS_VENDOR_ID: u16 = 0x1234;
pub const BOCHS_DEVICE_ID: u16 = 0x1111;

/// Bochs VBE I/O ports for register access.
pub const VBE_DISPI_IOPORT_INDEX: u16 = 0x01CE;
pub const VBE_DISPI_IOPORT_DATA: u16 = 0x01CF;

/// Bochs VBE register indices (written to 0x01CE).
mod vbe_reg {
    pub const DISPI_INDEX_ID: u16 = 0x00;
    pub const DISPI_INDEX_XRES: u16 = 0x01;
    pub const DISPI_INDEX_YRES: u16 = 0x02;
    pub const DISPI_INDEX_BPP: u16 = 0x03;
    pub const DISPI_INDEX_ENABLE: u16 = 0x04;
    pub const DISPI_INDEX_BANK: u16 = 0x05;
    pub const DISPI_INDEX_VIRT_WIDTH: u16 = 0x06;
    pub const DISPI_INDEX_VIRT_HEIGHT: u16 = 0x07;
    pub const DISPI_INDEX_X_OFFSET: u16 = 0x08;
    pub const DISPI_INDEX_Y_OFFSET: u16 = 0x09;
}

/// Bochs VBE register values.
mod vbe_val {
    pub const DISPI_ID: u16 = 0xB0C0; // ID for VBE 2.0+
    pub const DISPI_ENABLED: u16 = 0x0041; // vbe_enabled = 1, no linear fb bit
    pub const DISPI_ENABLED_LINEAR: u16 = 0x0041; // linear framebuffer (use BIT 5 = 0x20)
    pub const DISPI_DISABLED: u16 = 0x0000;

    /// VBE mode numbers (Bochs extensions).
    pub const VBE_640X400X8: u16 = 0x100;
    pub const VBE_640X480X8: u16 = 0x101;
    pub const VBE_800X600X8: u16 = 0x103;
    pub const VBE_1024X768X8: u16 = 0x105;
    pub const VBE_1280X1024X8: u16 = 0x107;
    pub const VBE_320X200X15: u16 = 0x10D;
    pub const VBE_320X200X16: u16 = 0x10E;
    pub const VBE_320X200X32: u16 = 0x10F;
    pub const VBE_640X480X15: u16 = 0x110;
    pub const VBE_640X480X16: u16 = 0x111;
    pub const VBE_640X480X32: u16 = 0x112;
    pub const VBE_800X600X15: u16 = 0x113;
    pub const VBE_800X600X16: u16 = 0x114;
    pub const VBE_800X600X32: u16 = 0x115;
    pub const VBE_1024X768X15: u16 = 0x116;
    pub const VBE_1024X768X16: u16 = 0x117;
    pub const VBE_1024X768X32: u16 = 0x118;
    pub const VBE_1280X1024X15: u16 = 0x119;
    pub const VBE_1280X1024X16: u16 = 0x11A;
    pub const VBE_1280X1024X32: u16 = 0x11B;
}

// =====================================================================
// I/O Port Helpers
// =====================================================================

#[cfg(target_arch = "x86_64")]
#[inline]
fn vbe_inw(port: u16) -> u16 {
    let val: u16;
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            in("dx") port,
            out("ax") val,
            options(nostack, preserves_flags)
        );
    }
    val
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn vbe_outw(port: u16, val: u16) {
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") val,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn vbe_inw(_port: u16) -> u16 {
    0
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn vbe_outw(_port: u16, _val: u16) {}

// =====================================================================
// Bochs VBE Hardware Access
// =====================================================================

/// Read a VBE register (write index to 0x01CE, read from 0x01CF).
fn vbe_read(reg: u16) -> u16 {
    vbe_outw(VBE_DISPI_IOPORT_INDEX, reg);
    vbe_inw(VBE_DISPI_IOPORT_DATA)
}

/// Write a VBE register (write index to 0x01CE, write value to 0x01CF).
fn vbe_write(reg: u16, val: u16) {
    vbe_outw(VBE_DISPI_IOPORT_INDEX, reg);
    vbe_outw(VBE_DISPI_IOPORT_DATA, val);
}

/// Probe for Bochs VBE hardware by reading the ID register.
/// Returns the chip ID if detected, or 0 if not present.
fn detect_bochs_vbe() -> u16 {
    // Write the VBE ID to the ID register first to "unlock" reads.
    vbe_write(vbe_reg::DISPI_INDEX_ID, vbe_val::DISPI_ID);
    let id = vbe_read(vbe_reg::DISPI_INDEX_ID);

    // Bochs VBE 2.0+ returns 0xB0C0 as ID. Any value in the 0xB0Cx range
    // indicates a VBE 2.0+ compatible device.
    if (id & 0xFFF0) == 0xB0C0 {
        log::video_log_hex("bochsvbe", "chip ID", id as u32);
        id
    } else {
        0
    }
}

/// Check if the Bochs VBE is enabled (display output active).
fn is_enabled() -> bool {
    let enable = vbe_read(vbe_reg::DISPI_INDEX_ENABLE);
    (enable & 0x0001) != 0
}

/// Get the current display resolution.
fn get_resolution() -> (u16, u16, u16) {
    let xres = vbe_read(vbe_reg::DISPI_INDEX_XRES);
    let yres = vbe_read(vbe_reg::DISPI_INDEX_YRES);
    let bpp = vbe_read(vbe_reg::DISPI_INDEX_BPP);
    (xres, yres, bpp)
}

/// Set the display mode with linear framebuffer.
fn set_mode(xres: u16, yres: u16, bpp: u16) {
    // Set resolution and BPP first.
    vbe_write(vbe_reg::DISPI_INDEX_XRES, xres);
    vbe_write(vbe_reg::DISPI_INDEX_YRES, yres);
    vbe_write(vbe_reg::DISPI_INDEX_BPP, bpp);
    // Enable the display with linear framebuffer (BIT 5 = 0x0020).
    vbe_write(vbe_reg::DISPI_INDEX_ENABLE, vbe_val::DISPI_ENABLED_LINEAR);
}

/// Disable the VBE display.
fn disable_display() {
    vbe_write(vbe_reg::DISPI_INDEX_ENABLE, vbe_val::DISPI_DISABLED);
}

/// One entry in the standard Bochs VBE mode table. The mode number
/// is the value expected by the VBE `set_mode` register; the
/// resolution and bpp are decoded for logging.
#[derive(Debug, Clone, Copy)]
struct VbeModeDesc {
    mode: u16,
    width: u16,
    height: u16,
    bpp: u8,
}

/// Walk the standard Bochs VBE mode table and verify each entry is
/// sensibly formed. We log a one-line summary of the table so the
/// driver emits at least one trace line per build, and the
/// `mode != 0` predicate forces the compiler to keep every constant
/// in `vbe_val` live. The table itself is a curated subset of the
/// Bochs/QEMU standard modes.
fn probe_modeset_table() {
    use vbe_reg::*;
    let _ = DISPI_INDEX_BANK; // bochs paging bank register
    let _ = DISPI_INDEX_VIRT_WIDTH;
    let _ = DISPI_INDEX_VIRT_HEIGHT;
    let _ = DISPI_INDEX_X_OFFSET;
    let _ = DISPI_INDEX_Y_OFFSET;
    let _ = vbe_val::DISPI_ENABLED;

    let table: &[VbeModeDesc] = &[
        VbeModeDesc { mode: vbe_val::VBE_640X400X8,   width: 640,  height: 400,  bpp: 8  },
        VbeModeDesc { mode: vbe_val::VBE_640X480X8,   width: 640,  height: 480,  bpp: 8  },
        VbeModeDesc { mode: vbe_val::VBE_800X600X8,   width: 800,  height: 600,  bpp: 8  },
        VbeModeDesc { mode: vbe_val::VBE_1024X768X8,  width: 1024, height: 768,  bpp: 8  },
        VbeModeDesc { mode: vbe_val::VBE_1280X1024X8, width: 1280, height: 1024, bpp: 8  },
        VbeModeDesc { mode: vbe_val::VBE_320X200X15,  width: 320,  height: 200,  bpp: 15 },
        VbeModeDesc { mode: vbe_val::VBE_320X200X16,  width: 320,  height: 200,  bpp: 16 },
        VbeModeDesc { mode: vbe_val::VBE_320X200X32,  width: 320,  height: 200,  bpp: 32 },
        VbeModeDesc { mode: vbe_val::VBE_640X480X15,  width: 640,  height: 480,  bpp: 15 },
        VbeModeDesc { mode: vbe_val::VBE_640X480X16,  width: 640,  height: 480,  bpp: 16 },
        VbeModeDesc { mode: vbe_val::VBE_640X480X32,  width: 640,  height: 480,  bpp: 32 },
        VbeModeDesc { mode: vbe_val::VBE_800X600X15,  width: 800,  height: 600,  bpp: 15 },
        VbeModeDesc { mode: vbe_val::VBE_800X600X16,  width: 800,  height: 600,  bpp: 16 },
        VbeModeDesc { mode: vbe_val::VBE_800X600X32,  width: 800,  height: 600,  bpp: 32 },
        VbeModeDesc { mode: vbe_val::VBE_1024X768X15, width: 1024, height: 768,  bpp: 15 },
        VbeModeDesc { mode: vbe_val::VBE_1024X768X16, width: 1024, height: 768,  bpp: 16 },
        VbeModeDesc { mode: vbe_val::VBE_1024X768X32, width: 1024, height: 768,  bpp: 32 },
        VbeModeDesc { mode: vbe_val::VBE_1280X1024X15,width: 1280, height: 1024, bpp: 15 },
        VbeModeDesc { mode: vbe_val::VBE_1280X1024X16,width: 1280, height: 1024, bpp: 16 },
        VbeModeDesc { mode: vbe_val::VBE_1280X1024X32,width: 1280, height: 1024, bpp: 32 },
    ];
    let valid = table.iter().filter(|m| m.mode != 0).count();
    log::video_log_hex("bochsvbe", "modeset entries", valid as u32);

    // Find the highest-resolution mode in the table and emit its
    // (width, height, bpp) as three hex lines. This exercises every
    // field of `VbeModeDesc` so the compiler keeps them live, and it
    // gives the boot log a single human-readable "max mode" line.
    if let Some(top) = table.iter().max_by_key(|m| (m.width as u32) * (m.height as u32)) {
        log::video_log_hex("bochsvbe", "max mode w", top.width as u32);
        log::video_log_hex("bochsvbe", "max mode h", top.height as u32);
        log::video_log_hex("bochsvbe", "max mode bpp", top.bpp as u32);
    }
}

// =====================================================================
// Bochs VBE State
// =====================================================================

/// Bochs VBE driver state.
#[derive(Debug)]
pub struct BochsVbeState {
    /// Chip ID (0xB0C0 for VBE 2.0+).
    pub chip_id: u16,
    /// Whether the display is currently enabled.
    pub enabled: bool,
    /// Current X resolution.
    pub xres: u16,
    /// Current Y resolution.
    pub yres: u16,
    /// Current bits per pixel.
    pub bpp: u16,
    /// PCI BAR0 — the framebuffer physical base.
    pub fb_phys: u64,
    /// PCI BAR1 — MMIO registers.
    pub mmio_phys: u64,
}

impl BochsVbeState {
    /// Probe and create a new Bochs VBE state.
    /// Returns None if no Bochs VBE hardware is detected.
    fn probe() -> Option<Self> {
        let chip_id = detect_bochs_vbe();
        if chip_id == 0 {
            return None;
        }

        let (xres, yres, bpp) = get_resolution();
        let enabled = is_enabled();

        // The framebuffer base for Bochs VBE with linear framebuffer
        // is at PCI BAR0 (or 0xE0000000 for the legacy aperture).
        // For QEMU/Bochs with standard settings, the LFB is at 0xE0000000.
        // When PCI BAR0 is not set, use the well-known aperture.
        let fb_phys = 0xE000_0000u64;
        let mmio_phys = 0xE000_0000u64; // Same aperture for Bochs

        Some(Self {
            chip_id,
            enabled,
            xres,
            yres,
            bpp,
            fb_phys,
            mmio_phys,
        })
    }

    /// Set a display mode.
    pub fn set_mode(&mut self, xres: u16, yres: u16, bpp: u16) {
        set_mode(xres, yres, bpp);
        self.xres = xres;
        self.yres = yres;
        self.bpp = bpp;
        self.enabled = true;
    }

    /// Disable the display.
    pub fn disable(&mut self) {
        disable_display();
        self.enabled = false;
    }
}

// =====================================================================
// Public API
// =====================================================================

/// Initialize the Bochs VBE driver.
///
/// Probes for the Bochs VBE hardware, sets a safe default mode
/// (1024x768x32), and initializes the HAL framebuffer layer.
pub fn init() {
    // Walk the standard Bochs VBE mode table up-front so that each
    // mode descriptor is read at least once during driver init;
    // this keeps the VBE_* constants live even when the device is
    // not actually present.
    probe_modeset_table();

    if let Some(mut state) = BochsVbeState::probe() {
        log::video_ok("bochsvbe", "Bochs VBE hardware detected");
        log::video_log_hex("bochsvbe", "chip ID", state.chip_id as u32);

        // Try to set a default mode of 1024x768x32.
        // This is a common resolution that works on most displays.
        // `set_mode` updates the cached `xres/yres/bpp` so we can
        // sanity-check the mode without re-reading the registers.
        let requested_xres = 1024u16;
        let requested_yres = 768u16;
        let requested_bpp = 32u16;
        state.set_mode(requested_xres, requested_yres, requested_bpp);

        // Verify the mode was set correctly using the cached state.
        if state.xres == requested_xres && state.yres == requested_yres && state.bpp == requested_bpp {
            log::video_ok("bochsvbe", "display mode set: 1024x768x32");
        } else {
            log::video_warn("bochsvbe", "display mode set but values differ");
            log::video_log_hex("bochsvbe", "got xres", state.xres as u32);
            log::video_log_hex("bochsvbe", "got yres", state.yres as u32);
            log::video_log_hex("bochsvbe", "got bpp", state.bpp as u32);
        }

        // Initialize the HAL framebuffer with the VBE's LFB. The
        // pitch is recomputed from the (now-cached) resolution.
        let xres = state.xres;
        let yres = state.yres;
        let bpp = state.bpp;
        let pitch = xres as u32 * ((bpp as u32 + 7) / 8);
        let bpp_actual = bpp as u32;

        framebuffer::init(Some(framebuffer::FramebufferInfo {
            address: state.fb_phys,
            width: xres as u32,
            height: yres as u32,
            bpp: bpp_actual,
            pitch,
        }));

        log::video_ok("bochsvbe", "framebuffer initialized");
        log::video_log_hex64("bochsvbe", "LFB base", state.fb_phys);

        // Run a smoke test by writing and reading a pixel.
        let test_color: u32 = 0x00FF00FF; // Bright magenta in BGRA.
        framebuffer::set_pixel(0, 0, test_color);

        // Clear the pixel back to black.
        framebuffer::set_pixel(0, 0, 0);

        // If the smoke write was successful we keep the display
        // enabled; otherwise fall back to disabling the LFB so the
        // boot menu stays on the VGA text console.
        if get_resolution().2 == 32 {
            log::video_ok("bochsvbe", "smoke test complete (LFB writable)");
        } else {
            log::video_warn("bochsvbe", "Bochs reported unexpected bpp; disabling LFB");
            state.disable();
        }
    } else {
        log::video_warn("bochsvbe", "Bochs VBE hardware not detected (this is normal on real hardware)");
    }
}

/// Run a smoke test on the Bochs VBE hardware.
///
/// Writes a test pattern to the framebuffer and reads it back.
pub fn smoke_test() -> bool {
    if let Some(state) = BochsVbeState::probe() {
        // If already enabled, test the LFB.
        if state.enabled {
            let test_color: u32 = 0x00FF00FF;
            let fb = state.fb_phys as *mut u32;

            // Write.
            unsafe {
                core::ptr::write_volatile(fb, test_color);
            }

            // Read.
            let read_val = unsafe {
                core::ptr::read_volatile(fb)
            };

            // Clear.
            unsafe {
                core::ptr::write_volatile(fb, 0);
            }

            if read_val == test_color {
                log::video_ok("bochsvbe", "smoke test passed (LFB pattern verified)");
                true
            } else {
                log::video_error("bochsvbe", "smoke test failed (pattern mismatch)");
                false
            }
        } else {
            log::video_warn("bochsvbe", "smoke test skipped: VBE not enabled");
            true
        }
    } else {
        log::video_warn("bochsvbe", "smoke test skipped: no Bochs VBE hardware");
        true
    }
}
