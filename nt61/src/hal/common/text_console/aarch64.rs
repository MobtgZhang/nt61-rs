//! aarch64 backend for the abstract text console.
//!
//! The QEMU virt machine (which is what we boot on) does not
//! expose a text-mode framebuffer to the kernel directly; the
//! only thing the kernel can see at boot time is the PL011
//! UART and, optionally, the EFI GOP framebuffer.
//!
//! This backend implements the unified `hal::text_console` API
//! on top of the PL011 UART plus an in-RAM log ring:
//!
//! - `put_byte` writes the byte to the PL011 and appends it to
//!   a 64-line circular buffer that the SafeBootMode CMD shell
//!   can read back via `read_log_lines` to render a "log
//!   display" pane.
//! - `set_cursor` is a no-op on the serial sink (the console is
//!   line-buffered) and is only meaningful when the kernel also
//!   has a framebuffer set up by the firmware. We treat it as a
//!   no-op here because the QEMU 'virt' machine does not hand
//!   us one for free.
//! - `log_line_count` and `read_log_lines` walk the ring to
//!   recover the most recent `LOG_RING_LINES` for the
//!   SafeBootMode shell's log view.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Lock-free ring index. `next` is the index of the slot that
/// will be written by the next `put_byte`. Lines wrap around
/// once the ring fills up.
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Number of complete lines in the ring (monotonic counter,
/// capped at `LOG_RING_LINES`).
static LINE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// One ring slot. The first `len` bytes are the message bytes
/// (clipped to `COLS`); `attr` is the colour attribute at the
/// time the byte was emitted; `len` is the byte count.
#[repr(C)]
#[derive(Clone, Copy)]
struct Line {
    bytes: [u8; super::COLS],
    attr: u8,
    len: u8,
}

impl Line {
    const fn empty() -> Self {
        Self { bytes: [0u8; super::COLS], attr: super::ATTR_DEFAULT, len: 0 }
    }
}

/// The ring itself. Each line is `COLS + 2` bytes when serialised
/// (for `read_log_lines`).
static mut RING: [Line; super::LOG_RING_LINES] = [const { Line::empty() }; super::LOG_RING_LINES];

/// Current cursor "position" in the half-built line (used to
/// accumulate bytes until we see a `\n`). A real line is
/// committed when the byte stream contains `\r`, `\n`, or the
/// current line length reaches `COLS`.
static mut CUR_BYTES: [u8; super::COLS] = [0u8; super::COLS];
static mut CUR_LEN: u8 = 0;
static mut CUR_ATTR: u8 = super::ATTR_DEFAULT;

/// Initialise the aarch64 backend. The PL011 UART is brought up
/// elsewhere by `hal::aarch64::serial::init`; this function only
/// resets the ring state.
pub fn init() {
    unsafe {
        NEXT.store(0, Ordering::Release);
        LINE_COUNT.store(0, Ordering::Release);
        CUR_LEN = 0;
        CUR_ATTR = super::ATTR_DEFAULT;
    }
}

/// Update the current attribute. Future bytes that are part of
/// the half-built line adopt this attribute.
pub fn set_attr(attr: u8) {
    unsafe { CUR_ATTR = attr; }
}

/// Append a byte to the half-built line. On `\n` / `\r` / ring
/// overflow we commit the line to the ring and start a new one.
pub fn put_byte(b: u8) {
    // 1. Mirror to the cross-arch LFB if it is active. This is
    //    the GUI-visible sink after the serial-suppress gate is
    //    flipped on by `kernel_main`. On QEMU `virt` without a
    //    framebuffer (the canonical aarch64 bring-up before the
    //    LFB driver is wired) this is a no-op.
    if crate::hal::common::framebuffer::is_active() {
        crate::drivers::bootvid::put_byte_to_active_console(b);
    }

    // 2. Mirror to the serial port so headless debug
    //    installations (the canonical aarch64 deployment on
    //    QEMU virt) actually see the byte. The serial gate
    //    is honoured here — once `kernel_main` flips it on, the
    //    byte is silently dropped.
    if !crate::hal::common::serial_disable::is_disabled() {
        crate::hal::aarch64::serial::put_char(b);
    }

    // 3. Accumulate into the half-built line and commit on
    //    newline / line overflow. This is what the SafeBootMode
    //    CMD shell's log display pane reads from when it paints
    //    its scrollback window on shell entry.
    unsafe {
        match b {
            b'\n' | b'\r' => {
                commit_line();
            }
            0x08 | 0x7F => {
                // Backspace — drop the last byte if any.
                if CUR_LEN > 0 {
                    CUR_LEN -= 1;
                }
            }
            b => {
                if (CUR_LEN as usize) < super::COLS {
                    CUR_BYTES[CUR_LEN as usize] = b;
                    CUR_LEN += 1;
                } else {
                    // Line overflow without a newline — commit
                    // and start a new line with this byte.
                    commit_line();
                    CUR_BYTES[0] = b;
                    CUR_LEN = 1;
                }
            }
        }
    }
}

/// Commit the half-built line into the ring.
unsafe fn commit_line() {
    let slot = NEXT.load(Ordering::Acquire);
    let dst = &mut RING[slot];
    let len = CUR_LEN as usize;
    dst.bytes[..len].copy_from_slice(&CUR_BYTES[..len]);
    dst.len = CUR_LEN;
    dst.attr = CUR_ATTR;
    NEXT.store((slot + 1) % super::LOG_RING_LINES, Ordering::Release);
    LINE_COUNT.fetch_add(1, Ordering::Release);
    CUR_LEN = 0;
}

/// Clear the visible window. Emits an ANSI CSI 2J + H sequence
/// so terminals that understand ANSI escape codes redraw the
/// screen from the top-left. A literal `[screen cleared]` marker
/// is also sent so `tail -f` users see the boundary.
pub fn clear() {
    // ANSI: ESC [ 2 J   clear entire screen
    //        ESC [ H     move cursor to (0, 0)
    crate::hal::aarch64::serial::write_string("\x1b[2J\x1b[H\r\n[screen cleared]\r\n");
    unsafe { commit_line(); }
    unsafe { commit_line(); }
}

/// Set the cursor. Emits an ANSI CSI H sequence so terminals
/// that understand ANSI escape codes position the cursor at
/// (1-based) row `y+1`, column `x+1`. Serial terminals that
/// don't speak ANSI will display the escape literally, but the
/// log ring capture still works because the bytes are wrapped
/// between calls.
pub fn set_cursor(x: u8, y: u8) {
    // ANSI: ESC [ <row> ; <col> H
    let mut buf = [0u8; 16];
    let s = format_ansi_cup(&mut buf, x as u32 + 1, y as u32 + 1);
    crate::hal::aarch64::serial::write_string(s);
}

/// Tiny ANSI CSI CUP formatter to avoid pulling in `core::fmt`.
/// Writes `\x1b[<row>;<col>H` into `buf` and returns the slice.
fn format_ansi_cup<'a>(buf: &'a mut [u8; 16], row: u32, col: u32) -> &'a str {
    let mut p = 0;
    buf[p] = 0x1b; p += 1;
    buf[p] = b'['; p += 1;
    // row
    let mut tmp = [0u8; 8];
    let mut n = 0;
    let mut v = row;
    if v == 0 { tmp[n] = b'0'; n += 1; } else {
        while v > 0 { tmp[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
        for i in 0..n/2 { tmp.swap(i, n-1-i); }
    }
    for i in 0..n { buf[p] = tmp[i]; p += 1; }
    buf[p] = b';'; p += 1;
    // col
    n = 0;
    v = col;
    if v == 0 { tmp[n] = b'0'; n += 1; } else {
        while v > 0 { tmp[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
        for i in 0..n/2 { tmp.swap(i, n-1-i); }
    }
    for i in 0..n { buf[p] = tmp[i]; p += 1; }
    buf[p] = b'H'; p += 1;
    // SAFETY: bytes are ASCII.
    unsafe { core::str::from_utf8_unchecked(&buf[..p]) }
}

/// Return the running line counter (saturates at `LOG_RING_LINES`
/// times the number of wraps).
pub fn log_line_count() -> usize {
    LINE_COUNT.load(Ordering::Acquire)
}

/// Copy the most recent ring contents into `buf` in
/// chronological order. Each output slot is `[u8; COLS + 2]`:
/// the first `COLS` bytes are the message bytes, byte `COLS`
/// is the attribute, and byte `COLS + 1` is the message length.
///
/// Returns the number of lines actually written (always equal
/// to `min(buf.len(), LOG_RING_LINES)` on aarch64).
pub fn read_log_lines(buf: &mut [[u8; super::COLS + 2]]) -> usize {
    let n = buf.len().min(super::LOG_RING_LINES);
    let next = NEXT.load(Ordering::Acquire);
    unsafe {
        for i in 0..n {
            // Oldest line first → newest line last.
            // The ring is FIFO with `next` pointing at the slot
            // to be written next, so the oldest line lives at
            // index `next` and the newest at `(next + n - 1) % n`.
            let slot = (next + i) % super::LOG_RING_LINES;
            let src = &RING[slot];
            let dst = &mut buf[i];
            dst[..super::COLS].copy_from_slice(&src.bytes);
            dst[super::COLS] = src.attr;
            dst[super::COLS + 1] = src.len;
        }
    }
    n
}