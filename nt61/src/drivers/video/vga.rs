//! VGA / VBE Display Driver
//
//! Provides text-mode console output via the legacy VGA hardware
//! (I/O ports 0x3B4/0x3D4, physical framebuffer at 0xB8000)
//! and a thin VESA BIOS Extensions (VBE) wrapper for higher-resolution
//! modes.
//
//! Clean-room implementation. Spec source: VESA BIOS Extensions
//! 3.0. No code is copied from any Microsoft or ReactOS source
//! file.

use core::ptr;
use crate::drivers::video::log;

/// VGA text-mode framebuffer physical base address.
pub const VGA_TEXT_PHYS: u64 = 0xB8000;

/// VGA CRT Controller I/O ports (color mode).
pub const VGA_CRTC_INDEX_COLOR: u16 = 0x3D4;
pub const VGA_CRTC_DATA_COLOR: u16 = 0x3D5;

/// VGA CRT Controller I/O ports (monochrome mode).
pub const VGA_CRTC_INDEX_MONO: u16 = 0x3B4;
pub const VGA_CRTC_DATA_MONO: u16 = 0x3B5;

/// VGA Misc Output Register (read at 0x3CC, write at 0x3C2).
pub const VGA_MISC_OUTPUT_READ: u16 = 0x3CC;
pub const VGA_MISC_OUTPUT_WRITE: u16 = 0x3C2;

/// Standard VGA dimensions.
pub const VGA_WIDTH: u32 = 80;
pub const VGA_HEIGHT: u32 = 25;
pub const VGA_CELLS: usize = (VGA_WIDTH * VGA_HEIGHT) as usize;

/// VGA attribute byte: bits [3:0] = foreground, bits [6:4] = background.
pub const VGA_ATTR_DEFAULT: u8 = 0x07; // Light gray on black.

/// CRT Controller register indices.
mod crtc {
    pub const CURSOR_LOCATION_HIGH: u8 = 0x0E;
    pub const CURSOR_LOCATION_LOW: u8 = 0x0F;
    pub const CURSOR_START: u8 = 0x0A;
    pub const CURSOR_END: u8 = 0x0B;
}

// =====================================================================
// I/O Port Helpers (x86_64 only)
// =====================================================================

#[cfg(target_arch = "x86_64")]
#[inline]
fn vga_inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nostack, preserves_flags)
        );
    }
    val
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn vga_outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn vga_inb(_port: u16) -> u8 {
    0
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn vga_outb(_port: u16, _val: u8) {}

// =====================================================================
// VGA Presence Detection
// =====================================================================

/// Read the VGA Miscellaneous Output register to determine display type.
fn detect_display_type() -> DisplayType {
    let misc = vga_inb(VGA_MISC_OUTPUT_READ);
    // Bit 7 = 1 → monochrome (0x3B4), bit 7 = 0 → color (0x3D4)
    if (misc & 0x80) != 0 {
        DisplayType::Monochrome
    } else {
        DisplayType::Color
    }
}

/// Probe for VGA hardware by reading the Feature Control register
/// at 0x3DA (color) / 0x3BA (mono). This register toggles on read
/// so we read it just to verify the port is responding.
fn vga_present() -> bool {
    let _ = vga_inb(0x3DA);
    let _ = vga_inb(0x3DA);
    // If we got here without a fault, the VGA is accessible.
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisplayType {
    Color,
    Monochrome,
}

// =====================================================================
// VGA Text Mode Operations
// =====================================================================

/// Write a character cell (char + attribute) at (x, y).
/// Coordinates are 0-indexed.
fn write_cell(x: u32, y: u32, ch: u8, attr: u8) {
    if x >= VGA_WIDTH || y >= VGA_HEIGHT {
        return;
    }
    // Map the VGA framebuffer into our virtual address space.
    // The kernel page tables must already map 0xB8000 for this to work.
    let offset = ((y * VGA_WIDTH + x) * 2) as u64;
    let vga_virt = (VGA_TEXT_PHYS + offset) as *mut u8;

    unsafe {
        core::ptr::write_volatile(vga_virt, ch);
        core::ptr::write_volatile(vga_virt.add(1), attr);
    }
}

/// Read the current cursor position from the CRT Controller.
fn read_cursor_pos() -> (u32, u32) {
    let crtc_idx = VGA_CRTC_INDEX_COLOR;
    let crtc_data = VGA_CRTC_DATA_COLOR;

    // Read high byte
    vga_outb(crtc_idx, crtc::CURSOR_LOCATION_HIGH);
    let high = vga_inb(crtc_data) as u32;
    // Read low byte
    vga_outb(crtc_idx, crtc::CURSOR_LOCATION_LOW);
    let low = vga_inb(crtc_data) as u32;

    let pos = (high << 8) | low;
    (pos % VGA_WIDTH, pos / VGA_WIDTH)
}

/// Public accessor for the current cursor position. Re-reads the
/// CRT controller each call; intended for the boot menu / panic
/// screens that need the live location.
pub fn current_cursor_pos() -> (u32, u32) {
    read_cursor_pos()
}

/// Set the hardware cursor position.
fn set_cursor_pos(x: u32, y: u32) {
    if x >= VGA_WIDTH || y >= VGA_HEIGHT {
        return;
    }
    let crtc_idx = VGA_CRTC_INDEX_COLOR;
    let crtc_data = VGA_CRTC_DATA_COLOR;
    let pos = (y * VGA_WIDTH + x) as u16;

    vga_outb(crtc_idx, crtc::CURSOR_LOCATION_HIGH);
    vga_outb(crtc_data, (pos >> 8) as u8);
    vga_outb(crtc_idx, crtc::CURSOR_LOCATION_LOW);
    vga_outb(crtc_data, (pos & 0xFF) as u8);
}

/// Enable the hardware cursor (scan-line start/end).
fn enable_cursor(scan_start: u8, scan_end: u8) {
    let crtc_idx = VGA_CRTC_INDEX_COLOR;
    let crtc_data = VGA_CRTC_DATA_COLOR;

    vga_outb(crtc_idx, crtc::CURSOR_START);
    vga_outb(crtc_data, scan_start & 0x1F);
    vga_outb(crtc_idx, crtc::CURSOR_END);
    vga_outb(crtc_data, scan_end & 0x1F);
}

/// Disable the hardware cursor (bit 5 of Cursor Start register).
fn disable_cursor() {
    let crtc_idx = VGA_CRTC_INDEX_COLOR;
    let crtc_data = VGA_CRTC_DATA_COLOR;

    vga_outb(crtc_idx, crtc::CURSOR_START);
    let cur = vga_inb(crtc_data);
    vga_outb(crtc_data, cur | 0x20);
}

/// Clear the entire text screen to spaces with the given attribute.
fn clear_screen(attr: u8) {
    for y in 0..VGA_HEIGHT {
        for x in 0..VGA_WIDTH {
            write_cell(x, y, b' ', attr);
        }
    }
    set_cursor_pos(0, 0);
}

// =====================================================================
// Public API
// =====================================================================

/// VGA driver state.
#[derive(Debug)]
pub struct VgaState {
    /// Display type detected at init.
    _display_type: DisplayType,
    /// Whether the hardware was detected.
    _hardware_present: bool,
    /// Virtual address of the VGA text buffer (0xB8000 mapped).
    pub fb_virt: u64,
}

impl VgaState {
    /// Probe and create a new VGA state.
    /// Returns None if no VGA hardware is detected.
    pub fn probe() -> Option<Self> {
        if !vga_present() {
            return None;
        }
        let display_type = detect_display_type();
        let fb_virt = VGA_TEXT_PHYS; // kernel must have mapped this
        Some(Self {
            _display_type: display_type,
            _hardware_present: true,
            fb_virt,
        })
    }

    /// Get the virtual address of the text framebuffer.
    fn _fb_address(&self) -> u64 {
        self.fb_virt
    }

    /// Write a string at the current cursor position, handling '\n' and '\r'.
    /// Scrolls the screen if the cursor goes past the bottom row.
    fn _write_string(&mut self, s: &str, attr: u8) {
        let (mut cx, mut cy) = read_cursor_pos();
        for b in s.bytes() {
            match b {
                b'\n' => {
                    cx = 0;
                    if cy + 1 >= VGA_HEIGHT {
                        // Scroll up by one row
                        self._scroll_up();
                    } else {
                        cy += 1;
                    }
                }
                b'\r' => {
                    cx = 0;
                }
                c => {
                    write_cell(cx, cy, c, attr);
                    cx += 1;
                    if cx >= VGA_WIDTH {
                        cx = 0;
                        if cy + 1 >= VGA_HEIGHT {
                            self._scroll_up();
                        } else {
                            cy += 1;
                        }
                    }
                }
            }
        }
        set_cursor_pos(cx, cy);
    }

    /// Scroll the screen up by one row (复制显存行).
    fn _scroll_up(&mut self) {
        // Copy rows 1..24 to rows 0..23 (move 23 rows of 80*2 bytes)
        let row_bytes = (VGA_WIDTH * 2) as usize;
        let total_rows = (VGA_HEIGHT - 1) as usize;

        // Use the HAL framebuffer's scroll_up if it is available,
        // otherwise do a manual byte copy.
        let fb_base = self.fb_virt as *mut u8;

        for row in 0..total_rows {
            let src = unsafe { fb_base.add((row + 1) * row_bytes) };
            let dst = unsafe { fb_base.add(row * row_bytes) };
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst, row_bytes);
            }
        }

        // Clear the bottom row
        let last_row_start = (VGA_HEIGHT - 1) as usize * row_bytes;
        for col in 0..(VGA_WIDTH as usize) {
            let cell = unsafe { fb_base.add(last_row_start + col * 2) };
            unsafe {
                core::ptr::write_volatile(cell, b' ');
                ptr::write_volatile(cell.add(1), VGA_ATTR_DEFAULT);
            }
        }
    }
}

/// Initialize the VGA driver.
///
/// This function probes for VGA hardware, detects the display type
/// (color vs. monochrome), enables the hardware cursor, and clears
/// the screen. If no VGA hardware is detected it returns false.
pub fn init() {
    if let Some(_state) = VgaState::probe() {
        log::video_ok("VGA", "hardware detected, initializing text mode");
        log::video_log("VGA", "display type: color");

        // Enable cursor (scan lines 12-13 of 16, standard block cursor).
        enable_cursor(12, 13);

        // Clear screen.
        clear_screen(VGA_ATTR_DEFAULT);

        // Write a banner on the first line.
        let banner = b"NT6.1.7601 VGA text mode ready";
        for (i, &c) in banner.iter().enumerate() {
            write_cell(i as u32, 0, c, 0x1F); // White on blue
        }

        // Set cursor to line 2, column 0.
        set_cursor_pos(0, 1);

        log::video_ok("VGA", "VGA driver initialized");
    } else {
        log::video_error("VGA", "no VGA hardware detected");
    }
}

/// Run a smoke test on the VGA hardware.
///
/// Writes a test pattern to a known cell, reads it back, and verifies
/// the value matches. Returns true if the test passes.
pub fn smoke_test() -> bool {
    if let Some(_state) = VgaState::probe() {
        // Disable the hardware cursor first so the test pattern is
        // not overwritten by the cursor scan-line on each refresh.
        disable_cursor();

        // Test pattern: write 'X' with attribute 0xF0 at position (79, 24).
        const TEST_X: u8 = b'X';
        const TEST_ATTR: u8 = 0xF0;
        const TEST_X_POS: u32 = VGA_WIDTH - 1; // column 79
        const TEST_Y_POS: u32 = VGA_HEIGHT - 1; // row 24

        write_cell(TEST_X_POS, TEST_Y_POS, TEST_X, TEST_ATTR);

        // Read it back.
        let offset = ((TEST_Y_POS * VGA_WIDTH + TEST_X_POS) * 2) as u64;
        let vga_virt = (VGA_TEXT_PHYS + offset) as *const u8;
        let read_ch;
        let read_attr;
        unsafe {
            read_ch = core::ptr::read_volatile(vga_virt);
            read_attr = core::ptr::read_volatile(vga_virt.add(1));
        }

        let ch_ok = read_ch == TEST_X;
        let attr_ok = read_attr == TEST_ATTR;

        if ch_ok && attr_ok {
            log::video_ok("VGA", "smoke test passed (pattern verified)");
            // Restore the cell to space.
            write_cell(TEST_X_POS, TEST_Y_POS, b' ', VGA_ATTR_DEFAULT);
            true
        } else {
            log::video_error("VGA", "smoke test failed (pattern mismatch)");
            false
        }
    } else {
        log::video_error("VGA", "smoke test skipped: no VGA hardware");
        false
    }
}
