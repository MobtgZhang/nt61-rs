//! Legacy VGA text-mode console (80×25, 16 colours).
//
//! This is the human-facing text console used during boot, in Safe
//! Mode, and as the emergency shell window when no graphical
//! subsystem is alive yet. The character buffer lives at the
//! legacy physical address `0xB8000` and is mirrored to the boot
//! video LFB so a QEMU `-display gtk` window keeps showing the
//! same content on scan-out.
//
//! # Sinks
//
//! [`put_byte`] and friends fan a single byte out to *three* sinks:
//
//!   1. The serial UART (`hal::x86_64::serial`) — used by
//!      `tail -f serial.log` and by the kernel debugger transport.
//!   2. The 0xB8000 text buffer — drives QEMU `-vga std` and any
//!      real VGA card.
//!   3. The bootvid LFB — drives QEMU `-display gtk` after the
//!      firmware is done drawing.
//
//! All three sinks are gated by [`VGA_READY`]; the byte is dropped
//! if [`init`] has not been called yet. This is required because
//! the very first bytes of kernel output are emitted before the
//! bootvid backend has finished clearing the OVMF "Loading..."
//! splash on the LFB.
//
//! # Why this lives here
//
//! This is fundamentally a peripheral driver for the Super-IO
//! VGA controller, the same kind of thing as the keyboard, PIC,
//! and APIC drivers in this folder. It used to be inlined inside
//! `kernel_main.rs` (590 lines!), but kernel_main should describe
//! the *boot sequence*, not the per-device register tables. Pulling
//! it out makes both sides smaller and lets other call sites
//! (e.g. the new Safe-Mode CMD shell in `servers/cmd.rs`) write
//! to the same console without depending on a 2000-line mod.
//
//! # Public macros
//
//! [`gui_print!`] / [`gui_println!`] and the [`CursorWriter`]
//! `core::fmt::Write` adapter live next to the module so the
//! macro paths resolve cleanly. They are re-exported at the crate
//! root via the `#[macro_export]` definitions in `kernel_main.rs`
//! (which still defines the bootstrap entry points) and at this
//! module path (`crate::hal::x86_64::text_console::gui_print`)
//! for direct callers.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use crate::drivers::bootvid;

/// Has the VGA text console been initialised yet? Used to
/// gate `gui_print!` so it doesn't try to write to 0xB8000
/// before we have finished switching the kernel to a text
/// console.
static VGA_READY: AtomicBool = AtomicBool::new(false);

/// 25-row classic VGA text window. QEMU's `-vga std` exposes
/// the 80×25 text mode (mode 3) by default after POST; we
/// will also program mode 3 ourselves via INT 10 / CRTC if
/// the firmware left a different mode active.
pub const VGA_COLS: usize = 80;
pub const VGA_ROWS: usize = 25;

/// VGA text-mode buffer physical address. The identity-map
/// inherited from UEFI keeps this region writable.
const VGA_TEXT_BASE: u64 = 0xB8000;

/// Current cell attribute (background * 16 + foreground).
/// 0x07 = light grey on black — the canonical Linux / DOS
/// console default.
static ATTR: AtomicU8 = AtomicU8::new(0x07);

/// Initialise the VGA text console. We:
///   1. Program the legacy VGA controller into 80×25
///      16-colour text mode (mode 3) via the standard
///      CRTC / Sequencer / Attribute / Graphics register
///      sequence. This makes QEMU's `-vga std` start
///      scanning the 0xB8000 text buffer instead of the
///      GOP LFB.
///   2. Wipe the 80×25 buffer at 0xB8000 to spaces.
///   3. Park the cursor at (0,0).
///
/// All three steps are mandatory:
///   * step 1 puts the controller in the right state so
///     QEMU actually displays 0xB8000;
///   * step 2 clears the on-screen window;
///   * step 3 starts the prompt at the top-left.
///
/// This function is safe to call from long mode — it only
/// touches the legacy VGA I/O ports (0x3B0–0x3DF range)
/// and memory at 0xB8000. The `int 0x10` BIOS call is
/// intentionally not used; long-mode cannot trap into the
/// real-mode BIOS and OVMF does not provide a runtime
/// INT 10h handler either, so the only way to get a text
/// console back is to program the controller directly.
pub fn init() {
    // 1. Switch the legacy VGA controller into 80×25
    //    16-colour text mode 03h. This makes QEMU's
    //    `-vga std` scan out the 0xB8000 text buffer on
    //    VNC / SDL displays that follow the VGA controller.
    unsafe { program_vga_mode3(); }
    // 2. Clear the VGA text buffer to spaces (attr 0x07) and
    //    park the CRTC cursor at (0,0). Both happen inside
    //    `clear()`; no separate home step is required.
    clear();

    // 4. ALSO paint the linear framebuffer that QEMU's
    //    `-display gtk` keeps scanning out. Without this
    //    the GUI window would continue to display the OVMF
    //    "Loading..." panel even though the kernel has
    //    switched to text mode. We force bootvid onto the
    //    LFB backend, paint the whole framebuffer solid
    //    black to overwrite the stale GOP pixels, reset
    //    the cursor to (0,0), and let the putchar mirror
    //    in `put_byte_vga` keep both surfaces in sync.
    bootvid::force_lfb_console();
    bootvid::VidClearBlack();
    bootvid::VidSetCursorPosition(0, 0);

    VGA_READY.store(true, Ordering::Release);
}

/// Switch the VGA controller to 80×25 16-colour text mode
/// (VGA "mode 3"). This puts the legacy VGA controller into
/// the state expected by every DOS / Windows NT 6.1 text
/// console: a 9×16 cell on a 720×400 raster, 80 columns and
/// 25 rows, 16 foreground / 8 background colours, with the
/// character generator reading glyphs from plane 2 and the
/// text buffer at the legacy `0xB8000` segment. QEMU's
/// `-vga std` (and every real Super-IO video card that
/// emulates the standard VGA register set) scans out exactly
/// that address once this sequence has run.
///
/// We deliberately do NOT issue `int 0x10` here: long mode
/// cannot trap into the real-mode BIOS, and OVMF does not
/// provide a runtime INT 10h handler. The only way to take
/// the controller back from the GOP LFB scanout is to
/// program the I/O registers directly, which is what this
/// function does.
///
/// The register tables below are the canonical values used
/// by VGA BIOS ROMs (IBM VGA BIOS, SeaBIOS, OVMF) when
/// entering mode 3. Values that depend on the cell size
/// (CRTC 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x13) are
/// computed from constants so the same sequence works for
/// any 9-pixel-wide, 16-pixel-tall cell variant.
unsafe fn program_vga_mode3() {
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_UCHAR, WRITE_PORT_UCHAR};

    // ----- Misc Output Register -----
    // 0x67 = colour I/O (0x3Dx), enable video RAM, clock
    //        select bits 11 (28 MHz reference, 25.175 MHz
    //        internal via the divide-by-2 inside the VGA
    //        chip — both spell out the 25.175 MHz pixel
    //        clock needed for the 720×400 text raster),
    //        negative horizontal sync, positive vertical
    //        sync. The exact value matches what SeaBIOS
    //        / OVMF write when programming mode 3.
    const MISC_OUTPUT: u8 = 0x67;

    // ----- Sequencer registers (port 0x3C4 index, 0x3C5 data) -----
    // Reset (synchronous) and enable all four planes.
    // Then program the Clocking Mode to 8-dot character
    // clocks and enable the video.
    const SEQ_RESET: u8 = 0x00;
    const SEQ_CLOCKING_MODE: u8 = 0x01;
    const SEQ_MAP_MASK: u8 = 0x02;
    const SEQ_CHAR_MAP_SELECT: u8 = 0x03;
    const SEQ_MEM_MODE: u8 = 0x04;

    // ----- CRTC registers (port 0x3D4 index, 0x3D5 data) -----
    // Standard 80x25 9x16 text-mode values.
    const CRTC_H_TOTAL: u8 = 0x00;       // 0x5F (95)   = total horizontal chars
    const CRTC_H_DISPLAY_END: u8 = 0x01; // 0x4F (79)   = displayed columns
    const CRTC_H_BLANK_START: u8 = 0x02; // 0x50 (80)   = start of blanking
    const CRTC_H_BLANK_END: u8 = 0x03;   // 0x82       = end-of-blank + skew
    const CRTC_H_RETRACE_START: u8 = 0x04; // 0x55     = start of H retrace
    const CRTC_H_RETRACE_END: u8 = 0x05;   // 0x81     = end of H retrace
    const CRTC_V_TOTAL: u8 = 0x06;       // 0xBF (191)  = total scan lines
    const CRTC_OVERFLOW: u8 = 0x07;      // 0x1F       = overflow bits
    const CRTC_PRESET_ROW_SCAN: u8 = 0x08; // 0x00
    const CRTC_MAX_SCAN_LINE: u8 = 0x09; // 0x0F (15)   = char height in scan lines
    const CRTC_CURSOR_START: u8 = 0x0A;  // 0x0E       = cursor scan-line start
    const CRTC_CURSOR_END: u8 = 0x0B;    // 0x0F       = cursor scan-line end
    const CRTC_START_ADDR_HI: u8 = 0x0C;// 0x00
    const CRTC_START_ADDR_LO: u8 = 0x0D;// 0x00
    const CRTC_CURSOR_LOC_HI: u8 = 0x0E;// 0x00
    const CRTC_CURSOR_LOC_LO: u8 = 0x0F;// 0x00
    const CRTC_V_RETRACE_START: u8 = 0x10; // 0x9C
    const CRTC_V_RETRACE_END: u8 = 0x11;   // 0x8E
    const CRTC_V_DISPLAY_END: u8 = 0x12;   // 0x8F (143)
    const CRTC_OFFSET: u8 = 0x13;       // 0x28 (40)   = logical row width (bytes)
    const CRTC_UNDERLINE_LOC: u8 = 0x14;// 0x1F (31)
    const CRTC_V_BLANK_START: u8 = 0x15;// 0x96
    const CRTC_V_BLANK_END: u8 = 0x16;  // 0xB9
    const CRTC_MODE_CONTROL: u8 = 0x17; // 0xA3
    const CRTC_LINE_COMPARE: u8 = 0x18; // 0xFF

    // ----- Graphics Controller registers (port 0x3CE/0x3CF) -----
    const GFX_SET_RESET: u8 = 0x00;
    const GFX_ENABLE_SET_RESET: u8 = 0x01;
    const GFX_COLOR_COMPARE: u8 = 0x02;
    const GFX_DATA_ROTATE: u8 = 0x03;
    const GFX_READ_MAP_SELECT: u8 = 0x04;
    const GFX_MODE: u8 = 0x05;
    const GFX_MISC: u8 = 0x06;
    const GFX_COLOR_DONT_CARE: u8 = 0x07;
    const GFX_BIT_MASK: u8 = 0x08;

    // ----- Attribute Controller registers (port 0x3C0 index/data flip-flop) -----
    // The palette index loop below writes indexes 0..=15 directly, so we do
    // not need a named constant for index 0 (it would be the same as the
    // loop variable `i` at i==0). The named constants kept here are the
    // Attribute Controller mode/overscan/enable/panning registers that
    // are addressed by fixed indexes from the standard VGA BIOS set.
    const ATTR_MODE_CONTROL: u8 = 0x10;
    const ATTR_OVERSCAN_COLOR: u8 = 0x11;
    const ATTR_COLOR_PLANE_ENABLE: u8 = 0x12;
    const ATTR_H_PEL_PANNING: u8 = 0x13;

    // First, do a synchronous reset of the sequencer so
    // we can change the clocking mode without glitches.
    WRITE_PORT_UCHAR(0x3C4, SEQ_RESET);
    WRITE_PORT_UCHAR(0x3C5, 0x00); // reset (no planes running)
    WRITE_PORT_UCHAR(0x3C4, SEQ_CLOCKING_MODE);
    WRITE_PORT_UCHAR(0x3C5, 0x01); // 8-dot char clock, no load
    WRITE_PORT_UCHAR(0x3C4, SEQ_MAP_MASK);
    WRITE_PORT_UCHAR(0x3C5, 0x03); // enable planes 0 and 1
    WRITE_PORT_UCHAR(0x3C4, SEQ_CHAR_MAP_SELECT);
    WRITE_PORT_UCHAR(0x3C5, 0x00); // map 0 at offset 0
    WRITE_PORT_UCHAR(0x3C4, SEQ_MEM_MODE);
    WRITE_PORT_UCHAR(0x3C5, 0x03); // sequential addressing
    WRITE_PORT_UCHAR(0x3C4, SEQ_RESET);
    WRITE_PORT_UCHAR(0x3C5, 0x03); // release reset, run planes 0/1

    // Now write the CRTC registers. We must unlock the
    // CRTC first by writing to index 0x11 with bit 7
    // clear; otherwise registers 0x00-0x07 are protected.
    WRITE_PORT_UCHAR(0x3D4, 0x11);
    WRITE_PORT_UCHAR(0x3D5, 0x0E); // unlock, end retrace at 0x8E
    const CRTC_REGS: [(u8, u8); 25] = [
        (CRTC_H_TOTAL,         0x5F),
        (CRTC_H_DISPLAY_END,   0x4F),
        (CRTC_H_BLANK_START,   0x50),
        (CRTC_H_BLANK_END,     0x82),
        (CRTC_H_RETRACE_START, 0x55),
        (CRTC_H_RETRACE_END,   0x81),
        (CRTC_V_TOTAL,         0xBF),
        (CRTC_OVERFLOW,        0x1F),
        (CRTC_PRESET_ROW_SCAN, 0x00),
        (CRTC_MAX_SCAN_LINE,   0x0F),
        (CRTC_CURSOR_START,    0x0E),
        (CRTC_CURSOR_END,      0x0F),
        (CRTC_START_ADDR_HI,   0x00),
        (CRTC_START_ADDR_LO,   0x00),
        (CRTC_CURSOR_LOC_HI,   0x00),
        (CRTC_CURSOR_LOC_LO,   0x00),
        (CRTC_V_RETRACE_START, 0x9C),
        (CRTC_V_RETRACE_END,   0x8E),
        (CRTC_V_DISPLAY_END,   0x8F),
        (CRTC_OFFSET,          0x28),
        (CRTC_UNDERLINE_LOC,   0x1F),
        (CRTC_V_BLANK_START,   0x96),
        (CRTC_V_BLANK_END,     0xB9),
        (CRTC_MODE_CONTROL,    0xA3),
        (CRTC_LINE_COMPARE,    0xFF),
    ];
    for &(idx, val) in CRTC_REGS.iter() {
        WRITE_PORT_UCHAR(0x3D4, idx);
        WRITE_PORT_UCHAR(0x3D5, val);
    }

    // Attribute Controller flip-flop starts in index mode.
    // The standard "set palette / mode / plane-enable"
    // dance:
    //   - first read 0x3DA to reset the FF to index mode;
    //   - then write index 0x00..0x0F to load the 16
    //     palette entries with the IBM default
    //     (BG=0, GR=15) ordering;
    //   - then write 0x10..0x13 to set the mode / mask
    //     / overscan / plane-enable bits.
    let _ = READ_PORT_UCHAR(0x3DA); // side-effect: reset AC FF to index mode

    // 16 attribute palette entries, IBM default 16-colour set
    const ATTR_PALETTE: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    ];
    for i in 0..16u8 {
        WRITE_PORT_UCHAR(0x3C0, i);
        WRITE_PORT_UCHAR(0x3C0, ATTR_PALETTE[i as usize]);
    }
    // Mode Control: text-mode attribute, blink disabled,
    // 8-bit video path, internal palette.
    WRITE_PORT_UCHAR(0x3C0, ATTR_MODE_CONTROL);
    WRITE_PORT_UCHAR(0x3C0, 0x0C);
    // Overscan colour: black border.
    WRITE_PORT_UCHAR(0x3C0, ATTR_OVERSCAN_COLOR);
    WRITE_PORT_UCHAR(0x3C0, 0x00);
    // Colour Plane Enable: enable all 4 planes (text mode
    // uses planes 0 and 1; this is the BIOS default).
    WRITE_PORT_UCHAR(0x3C0, ATTR_COLOR_PLANE_ENABLE);
    WRITE_PORT_UCHAR(0x3C0, 0x0F);
    // Horizontal panning = 0.
    WRITE_PORT_UCHAR(0x3C0, ATTR_H_PEL_PANNING);
    WRITE_PORT_UCHAR(0x3C0, 0x00);
    // Re-enable the video output by writing the video
    // enable bit (bit 5) to 0x3C0. The standard way is to
    // write index 0x20 to 0x3C0, which sets the video
    // enable bit in the Attribute Controller.
    WRITE_PORT_UCHAR(0x3C0, 0x20);

    // Graphics Controller: text mode 0 (mode reg = 0),
    // write mode 0, read mode 0, no rotation, host
    // addressing = sequential.
    const GFX_REGS: [(u8, u8); 9] = [
        (GFX_SET_RESET,        0x00),
        (GFX_ENABLE_SET_RESET, 0x00),
        (GFX_COLOR_COMPARE,    0x00),
        (GFX_DATA_ROTATE,      0x00),
        (GFX_READ_MAP_SELECT,  0x00),
        (GFX_MODE,             0x10), // read mode 0, write mode 0
        (GFX_MISC,             0x0E), // A0..A7 = host address, chain odd/even
        (GFX_COLOR_DONT_CARE,  0x00),
        (GFX_BIT_MASK,         0xFF),
    ];
    for &(idx, val) in GFX_REGS.iter() {
        WRITE_PORT_UCHAR(0x3CE, idx);
        WRITE_PORT_UCHAR(0x3CF, val);
    }

    // Finally write the Misc Output Register. This is the
    // "kick" that actually selects the colour text mode
    // (0xB8000 text buffer) on QEMU `-vga std` and every
    // VGA-compatible card. Until this is written the
    // controller stays in whatever mode the GOP / UEFI
    // left it in.
    WRITE_PORT_UCHAR(0x3C2, MISC_OUTPUT);
}

/// Clear the 80×25 text window to spaces and park the
/// CRTC cursor at (0, 0). The cursor reset is part of
/// `clear` because callers used to invoke `home()` right
/// after `clear()`; folding both into one call removes
/// a duplicated CRTC index/data pair write.
pub fn clear() {
    clear_vga_only();
}

/// Pure-VGA clear — wipes the 0xB8000 buffer and re-points
/// the CRTC cursor at (0, 0). The cursor reset writes the
/// CRTC index/data register pair (high byte then low byte
/// of the linear cursor location; row-major offset = 0).
fn clear_vga_only() {
    let attr = ATTR.load(Ordering::Relaxed);
    unsafe {
        let p = VGA_TEXT_BASE as *mut u8;
        for i in 0..(VGA_COLS * VGA_ROWS * 2) {
            let b = if i & 1 == 0 { b' ' } else { attr };
            core::ptr::write_volatile(p.add(i), b);
        }
        set_cursor_raw(0, 0);
    }
}

/// Write a single byte to BOTH the serial port and the VGA
/// text console. Handles '\n', '\r', '\t' and backspace
/// specially. When the cursor falls off the bottom row, the
/// whole window scrolls up by one row.
pub fn put_byte(b: u8) {
    // 1) Serial — always available (COM1 is mapped by UEFI)
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_char(b);

    // 2) VGA text console — only after init
    if VGA_READY.load(Ordering::Acquire) {
        put_byte_vga(b);
    }
}

/// Public wrapper used by `write_uart_str` which has already
/// written the byte to the serial port itself. Routes only to
/// the VGA text console, no-op if it isn't initialised yet.
pub fn put_byte_vga_only(b: u8) {
    if !VGA_READY.load(Ordering::Acquire) { return; }
    put_byte_vga(b);
}

/// Write a single byte to the VGA text buffer at 0xB8000
/// AND mirror it to the bootvid LFB so the QEMU `-display
/// gtk` window (which keeps scanning the GOP LFB) also
/// shows the same content. Performs Linux-style scrolling
/// when the cursor reaches the bottom row.
fn put_byte_vga(b: u8) {
    // Read the current cursor position via a single IN
    // instruction pair against the CRT controller registers.
    let (mut x, mut y) = unsafe { read_cursor() };

    match b {
        b'\n' => {
            // LF — move down one row, scroll if needed
            y += 1;
            if y >= VGA_ROWS as u16 { scroll_up(); y = (VGA_ROWS - 1) as u16; }
            unsafe { set_cursor_raw(0, y); }
        }
        b'\r' => {
            // CR — return to column 0 of the current row
            unsafe { set_cursor_raw(0, y); }
        }
        b'\t' => {
            // Tab — round up to next multiple of 8
            let nx = ((x / 8) + 1) * 8;
            if nx >= VGA_COLS as u16 {
                y += 1;
                if y >= VGA_ROWS as u16 { scroll_up(); y = (VGA_ROWS - 1) as u16; }
                unsafe { set_cursor_raw(0, y); }
            } else {
                unsafe { set_cursor_raw(nx, y); }
            }
        }
        0x08 => {
            // Backspace — move cursor back one column, blank
            // the old cell.
            if x > 0 {
                x -= 1;
                unsafe { write_cell(x as usize, y as usize, b' '); set_cursor_raw(x, y); }
            }
        }
        _ => {
            // Printable / control — write into the cell at
            // (x, y), advance x. Wrap to next row on overflow.
            unsafe { write_cell(x as usize, y as usize, b); }
            x += 1;
            if x >= VGA_COLS as u16 {
                x = 0;
                y += 1;
                if y >= VGA_ROWS as u16 { scroll_up(); y = (VGA_ROWS - 1) as u16; }
            }
            unsafe { set_cursor_raw(x, y); }
        }
    }

    // Mirror the same byte into the bootvid LFB so the
    // QEMU `-display gtk` window (which keeps scanning the
    // GOP LFB) shows the same character on the same row.
    // The bootvid state machine handles '\n', '\r', '\t',
    // and backspace internally; printable bytes are drawn
    // with its 6×12 bitmap font.
    bootvid::put_byte_to_active_console(b);
}

/// Write a byte string to all sinks.
pub fn put_str(s: &[u8]) {
    for &b in s {
        put_byte(b);
    }
}

/// Print a Rust `&str` to all sinks.
pub fn put_rstr(s: &str) {
    for &b in s.as_bytes() {
        put_byte(b);
    }
}

/// VGA-only `&str` sink. Used by the serial/VGA mirror in
/// `rtl::klog::write_serial` so the mirror does NOT loop
/// the bytes back through the serial port. No-op until
/// `init()` has flipped `VGA_READY` to true.
pub fn put_byte_vga_only_str(s: &str) {
    if !VGA_READY.load(Ordering::Acquire) { return; }
    for &b in s.as_bytes() {
        put_byte_vga(b);
    }
}

pub fn is_ready() -> bool {
    VGA_READY.load(Ordering::Acquire)
}

/// Set the text attribute for subsequent writes. The byte
/// layout is `bg << 4 | fg`, matching Windows / Linux
/// conventions. The attribute is stored in the local
/// module shadow; [`put_byte_vga`] reads it on every
/// cell write so this just needs to update the local
/// atomic.
pub fn set_attr(attr: u8) {
    ATTR.store(attr, Ordering::Relaxed);
    // Also mirror the attribute into the bootvid LFB so
    // the mirrored bytes render in the right colour pair
    // on the QEMU `-display gtk` window.
    bootvid::set_attr(attr);
}

// ---------- Low-level helpers (private to this module) ----------

/// Write one 16-bit cell (char + attr) at (x, y).
unsafe fn write_cell(x: usize, y: usize, ch: u8) {
    let off = (y * VGA_COLS + x) * 2;
    let p = (VGA_TEXT_BASE as *mut u8).add(off);
    let attr = ATTR.load(Ordering::Relaxed);
    core::ptr::write_volatile(p, ch);
    core::ptr::write_volatile(p.add(1), attr);
}

/// Read the current cursor position from the legacy CRT
/// controller. Returns (col, row).
unsafe fn read_cursor() -> (u16, u16) {
    // Index register 0x3D4 holds the register selector; data
    // register 0x3D5 returns the selected register value.
    // Register 0x0F = low byte of cursor pos, 0x0E = high
    // byte. (row * 80) + col is encoded in those two bytes.
    let mut pos: u16;
    core::arch::asm!(
        "mov dx, 0x3D4",
        "mov al, 0x0F",
        "out dx, al",
        "inc dx",
        "in al, dx",
        "mov ah, al",       // ah = low byte
        "dec dx",
        "mov al, 0x0E",
        "out dx, al",
        "inc dx",
        "in al, dx",        // al = high byte
        "xchg al, ah",      // ax = pos
        out("ax") pos,
        options(nostack, preserves_flags)
    );
    let col = pos % VGA_COLS as u16;
    let row = pos / VGA_COLS as u16;
    (col, row)
}

/// Programmatically move the hardware cursor.
unsafe fn set_cursor_raw(x: u16, y: u16) {
    let pos = y * VGA_COLS as u16 + x;
    core::arch::asm!(
        "mov dx, 0x3D4",
        "mov al, 0x0F",
        "out dx, al",
        "inc dx",
        "mov al, {lo}",
        "out dx, al",
        "dec dx",
        "mov al, 0x0E",
        "out dx, al",
        "inc dx",
        "mov al, {hi}",
        "out dx, al",
        lo = in(reg_byte) (pos & 0xFF) as u8,
        hi = in(reg_byte) ((pos >> 8) & 0xFF) as u8,
        options(nostack, preserves_flags)
    );
}

/// Public wrapper around `set_cursor_raw` so the unified
/// `hal::text_console` abstract interface (and any external
/// caller) can position the cursor directly without going
/// through `put_byte`. The SafeBootMode CMD shell uses this
/// to paint dividers and the prompt at arbitrary (x, y).
pub fn set_cursor(x: u8, y: u8) {
    let xx = (x as u16).min(VGA_COLS as u16 - 1);
    let yy = (y as u16).min(VGA_ROWS as u16 - 1);
    unsafe { set_cursor_raw(xx, yy); }
}

/// Shift every row up by one and blank the new bottom row.
/// Linux-style scrollback: lost rows are simply discarded,
/// not preserved in a separate ring buffer (the VGA buffer
/// is the ring).
fn scroll_up() {
    let attr = ATTR.load(Ordering::Relaxed);
    unsafe {
        let p = VGA_TEXT_BASE as *mut u8;
        // Copy rows 1..25 → rows 0..24
        let bytes_per_row = VGA_COLS * 2;
        core::ptr::copy(
            p.add(bytes_per_row),
            p,
            bytes_per_row * (VGA_ROWS - 1),
        );
        // Blank the new bottom row
        for i in 0..VGA_COLS {
            let off = ((VGA_ROWS - 1) * VGA_COLS + i) * 2;
            core::ptr::write_volatile(p.add(off),     b' ');
            core::ptr::write_volatile(p.add(off + 1), attr);
        }
    }
}

// ----------------------------------------------------------------------------
// `gui_print!` / `gui_println!` macros + `core::fmt::Write` adapter.
// ----------------------------------------------------------------------------
//
// These used to live in `kernel_main.rs` next to the inline `gui_log`
// module. After splitting that module out, the macros live here as
// well so the `CursorWriter` import doesn't have to reach into another
// file. The macros are still re-exported at the crate root via
// `#[macro_export]` so existing `gui_print!(...)` calls keep
// compiling without a `use` statement.

/// Tiny `core::fmt::Write` adapter that records how many bytes
/// were emitted so we know how much of the stack buffer to send
/// to the sinks.
pub struct CursorWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> CursorWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self { Self { buf, pos: 0 } }
    pub fn pos(&self) -> usize { self.pos }
}

impl<'a> core::fmt::Write for CursorWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let avail = self.buf.len().saturating_sub(self.pos);
        let n = bytes.len().min(avail);
        if n > 0 {
            self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
            self.pos += n;
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! gui_print {
    ($($arg:tt)*) => {{
        // Build a 256-byte stack buffer with the formatted message,
        // then ship it to both the framebuffer and the serial port.
        use core::fmt::Write;
        let mut buf = [0u8; 256];
        #[cfg(target_arch = "x86_64")]
        let mut cursor = $crate::hal::x86_64::text_console::CursorWriter::new(&mut buf);
        let _ = core::fmt::write(&mut cursor, core::format_args!($($arg)*));
        let len = cursor.pos();
        #[cfg(target_arch = "x86_64")]
        $crate::hal::x86_64::text_console::put_str(&buf[..len]);
    }};
}

#[macro_export]
macro_rules! gui_println {
    () => { $crate::gui_print!(core::stringify!()); };
    ($($arg:tt)*) => {{
        $crate::gui_print!($($arg)*);
        #[cfg(target_arch = "x86_64")]
        $crate::hal::x86_64::text_console::put_str(b"\r\n");
    }};
}
