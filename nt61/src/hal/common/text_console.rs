//! Abstract Text Console (Cross-Architecture Facade)
//!
//! Architecture-independent text console interface used by the
//! SafeBootMode CMD shell, the kernel log view, and the user-facing
//! prompt. The implementation delegates to the per-architecture
//! `text_console` module:
//!
//! - **x86_64** → `crate::hal::x86_64::text_console`
//!   (full VGA 80×25 + bootvid LFB mirror).
//! - **aarch64** → `crate::hal::aarch64::text_console` (log ring
//!   + serial sink, with an optional framebuffer if the firmware
//!   reported one).
//! - **riscv64 / loongarch64** → `crate::hal::riscv64::text_console`
//!   / `crate::hal::loongarch64::text_console` (log ring + serial).
//!
//! The rest of the kernel only uses the names exported here
//! (`init`, `set_attr`, `put_byte`, `clear`, `set_cursor`, ...),
//! so adding a new architecture only requires writing a backend
//! with the same function signatures and re-aliasing below.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// True once the text console has been initialised by `init()`.
/// `put_byte` is a no-op before this flips to true.
pub static READY: AtomicBool = AtomicBool::new(false);

/// Current attribute byte used by `put_byte` for printable
/// characters. The default (0x07) is the canonical DOS / Windows
/// NT 6.1 light-grey on black combination.
pub static ATTR: AtomicU8 = AtomicU8::new(0x07);

/// Width of the text console in characters. All architectures
/// (including the aarch64/riscv64/loongarch64 log ring) use 80
/// so the CMD shell's column wrapping is uniform.
pub const COLS: usize = 80;

/// Height of the text console in lines. All architectures use 25
/// to match the canonical DOS / Windows NT 6.1 / VGA mode 3
/// height.
pub const ROWS: usize = 25;

/// Compile-time capacity of the log ring, in lines. The
/// per-architecture back-ends size their static ring arrays with
/// this constant; `log_ring_set_lines` picks the active window
/// between 1 and this bound. The default is deep enough to hold
/// a full verbose boot plus the Safe-Mode shell session without
/// the oldest lines being overwritten by the newest.
pub const LOG_RING_LINES: usize = 1024;

/// Active log-ring line count (default: `LOG_RING_LINES`).
/// Capped at `LOG_RING_LINES_MAX` by `log_ring_set_lines`.
static LOG_RING_ACTIVE_LINES: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(LOG_RING_LINES);

/// Grow or shrink the active log-ring window. Clamped to
/// `[1, LOG_RING_LINES]`. Takes effect on the next write;
/// existing lines are preserved up to the new limit.
pub fn log_ring_set_lines(n: usize) {
    let clamped = n.clamp(1, LOG_RING_LINES);
    LOG_RING_ACTIVE_LINES.store(clamped, Ordering::Release);
}

/// Current active log-ring line count.
pub fn log_ring_lines() -> usize {
    LOG_RING_ACTIVE_LINES.load(Ordering::Acquire)
}

/// Dump the most recent log-ring lines into `out` (a flat
/// `\r\n`-separated buffer). Returns the number of bytes written.
/// The caller can then persist `out` to a file (e.g. via the
/// NTFS `write_file` API) to create a crash-dump log on disk.
pub fn dump_log_to_buffer(out: &mut alloc::vec::Vec<u8>) -> usize {
    // The ring buffer is heap-allocated: a `[[u8; 82]; 1024]`
    // temporary would blow the kernel stack for the deep ring.
    let active_lines = LOG_RING_ACTIVE_LINES.load(Ordering::Acquire);
    let mut lines_buf = alloc::vec![[0u8; COLS + 2]; active_lines];
    let n = read_log_lines(&mut lines_buf);
    let mut written = 0usize;
    for line in lines_buf.iter().take(n) {
        let len = line
            .iter()
            .position(|&b| b == 0 || b == b'\r' || b == b'\n')
            .unwrap_or(line.len());
        out.extend_from_slice(&line[..len]);
        out.extend_from_slice(b"\r\n");
        written += len + 2;
    }
    written
}

/// Persist the current log-ring window to the VFS.
///
/// Returns the number of bytes written on success. Callers normally use
/// the Windows log path; the HAL does not pick a path because the
/// filesystem backend is already mounted by the time this is called.
pub fn dump_log_to_disk(path: &str) -> Result<usize, ()> {
    let mut bytes = alloc::vec::Vec::new();
    let written = dump_log_to_buffer(&mut bytes);
    if written == 0 {
        return Err(());
    }
    crate::fs::vfs::vfs_write(path, &bytes)
}

/// Standard colour attributes used by the SafeBootMode shell.
pub const ATTR_DEFAULT: u8 = 0x07; // light-grey on black
pub const ATTR_TITLE: u8 = 0x1F; // white on blue
pub const ATTR_PROMPT: u8 = 0x0F; // white on black
pub const ATTR_HR: u8 = 0x0B; // light-cyan on black
pub const ATTR_LOG: u8 = 0x0A; // light-green on black

/// Initialise the architecture-specific text console backend.
///
/// Idempotent — calling more than once is harmless.
pub fn init() {
    if READY.swap(true, Ordering::SeqCst) {
        return;
    }
    backend_init();
}

/// Set the current text attribute.
pub fn set_attr(attr: u8) {
    ATTR.store(attr, Ordering::Release);
    backend_set_attr(attr);
}

/// Get the current text attribute.
pub fn get_attr() -> u8 {
    ATTR.load(Ordering::Acquire)
}

/// write a single byte. Recognises `\n`, `\r`, `\t`, and
/// backspace (`0x08`, `0x7F`); every other byte is treated as
/// a printable character.
pub fn put_byte(b: u8) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    backend_put_byte(b);
}

/// Convenience: write a string.
pub fn put_string(s: &str) {
    for b in s.bytes() {
        put_byte(b);
    }
}

/// Convenience: write a string followed by `\r\n`.
pub fn put_line(s: &str) {
    put_string(s);
    put_byte(b'\r');
    put_byte(b'\n');
}

/// write a centred title bar to the screen with a coloured
/// background. Used by the SafeBootMode CMD shell to render the
/// `C:\Windows\system32\cmd.exe` window title.
pub fn put_title_bar(text: &str, attr: u8) {
    let prev = get_attr();
    set_attr(attr);
    put_byte(b' ');
    let pad_left = (COLS.saturating_sub(text.len() + 2)) / 2;
    for _ in 0..pad_left {
        put_byte(b' ');
    }
    put_string(text);
    let pad_right = COLS.saturating_sub(text.len() + 2 + pad_left);
    for _ in 0..pad_right {
        put_byte(b' ');
    }
    put_byte(b' ');
    set_attr(prev);
}

/// Byte-array variant of `put_title_bar`. Useful for ASCII-safe
/// callers (kernels, boot menus) that want to draw a banner
/// without going through the UTF-8 validator. The text is
/// taken byte-for-byte up to its first NUL.
pub fn put_title_bar_bytes(text: &[u8], attr: u8) {
    let prev = get_attr();
    set_attr(attr);
    put_byte(b' ');
    let len = text.iter().position(|&c| c == 0).unwrap_or(text.len());
    let pad_left = (COLS.saturating_sub(len + 2)) / 2;
    for _ in 0..pad_left {
        put_byte(b' ');
    }
    for &c in &text[..len] {
        put_byte(c);
    }
    let pad_right = COLS.saturating_sub(len + 2 + pad_left);
    for _ in 0..pad_right {
        put_byte(b' ');
    }
    put_byte(b' ');
    set_attr(prev);
}

/// Clear the visible window and home the cursor.
pub fn clear() {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    backend_clear();
}

/// Return the number of lines in the log ring. On x86_64 this
/// returns 0 (the VGA buffer IS the log); on the other
/// architectures it returns the running line counter.
pub fn log_line_count() -> usize {
    backend_log_line_count()
}

/// read up to `buf.len()` lines from the most recent log ring
/// into `buf`. Returns the number of lines actually written.
/// Used by the SafeBootMode CMD shell's "log display" pane on
/// architectures without a real text framebuffer.
pub fn read_log_lines(buf: &mut [[u8; COLS + 2]]) -> usize {
    backend_read_log_lines(buf)
}

/// Position the cursor at (x, y). Coordinates are clamped to
/// the visible window.
pub fn set_cursor(x: u8, y: u8) {
    let xx = x.min((COLS - 1) as u8);
    let yy = y.min((ROWS - 1) as u8);
    backend_set_cursor(xx, yy);
}

// =====================================================================
// LFB glyph-cell metrics (shared by the non-x86_64 back-ends)
// =====================================================================
//
// The bootvid LFB text backend positions its cursor in pixels.
// `FONT_LINE_HEIGHT_PX` matches bootvid's `FONT_HEIGHT`; the cell
// width matches bootvid's fallback metric (3/4 of the font height)
// because bootvid does not yet expose a live-metrics accessor.
// When drivers/bootvid grows that accessor these two constants
// become the single point to re-route through it.

/// Vertical advance of one text row in the bootvid LFB backend,
/// in pixels.
pub const FONT_LINE_HEIGHT_PX: u32 = 16;

/// Horizontal advance of one text cell in the bootvid LFB
/// backend, in pixels.
pub const FONT_CELL_WIDTH_PX: u32 = 12;

// =====================================================================
// x86_64-only helpers
// =====================================================================
//
// These functions exist on the x86_64 backend only (they wrap the
// legacy VGA-only path that pre-dates the unified console). We
// re-export them through the top-level facade so call sites that
// previously referenced `crate::hal::text_console::*` directly
// keep compiling on x86_64; on the other architectures they
// resolve to either `put_byte` (for the print paths) or to `false`
// (for `is_ready`, where no early-boot gating is needed because
// the serial sink is always live).

#[cfg(target_arch = "x86_64")]
pub use crate::hal::x86_64::text_console::{
    is_ready, put_byte_vga_only, put_byte_vga_only_str, put_rstr,
};

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn put_byte_vga_only(b: u8) {
    put_byte(b);
}

/// Write to the serial console and the architecture's visible
/// console exactly once.
///
/// The x86_64 backend has separate serial and VGA sinks, while the
/// UART-backed consoles on the other architectures already mirror
/// every byte to serial and the active framebuffer. Keeping this
/// operation in the HAL lets CMD code drive both consoles without
/// knowing whether the visible console itself is serial-backed.
#[inline(always)]
pub fn put_serial_and_console(b: u8) {
    #[cfg(target_arch = "x86_64")]
    {
        crate::hal::common::serial_disable::with_serial_unmasked(|| {
            crate::hal::x86_64::serial::write_char(b);
        });
        if crate::drivers::bootvid::lfb_active() {
            crate::drivers::bootvid::put_byte_to_active_console(b);
        } else {
            put_byte_vga_only(b);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        put_byte(b);
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn put_byte_vga_only_str(s: &str) {
    for b in s.bytes() {
        put_byte(b);
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn put_rstr(s: &str) {
    for b in s.bytes() {
        put_byte(b);
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Move the cursor to the start of the given row, column 0.
pub fn goto_row(row: u8) {
    set_cursor(0, row);
}

/// write a horizontal divider across the full row.
pub fn write_hr(row: u8, attr: u8) {
    let prev = get_attr();
    set_attr(attr);
    goto_row(row);
    for _ in 0..COLS {
        put_byte(0xC4); // horizontal bar
    }
    set_attr(prev);
}

/// Paint the Safe-Mode Command Prompt layout on any text backend.
///
/// The x86_64 VGA backend has a dedicated optimized implementation;
/// this shared renderer keeps the other architectures on the same
/// 80x25 layout rather than falling back to raw serial output.
pub fn show_safe_mode_console() {
    clear();

    const ATTR_HEAD: u8 = 0x0E;

    put_title_bar("NT6.1.7601 Safe Mode -- Command Prompt", ATTR_TITLE);
    set_attr(ATTR_DEFAULT);
    goto_row(1);
    put_line("Microsoft Windows [Version 6.1.7601]");
    put_line("(C) Copyright (c) 2009 Microsoft Corporation.");
    write_hr(3, ATTR_HR);
    set_attr(ATTR_HEAD);
    goto_row(4);
    put_line("Boot log (most recent lines):");
    write_hr(5, ATTR_HR);
    set_attr(ATTR_DEFAULT);
    goto_row(24);
    write_hr(24, ATTR_HR);
}

// =====================================================================
// Per-architecture backend dispatch
// =====================================================================
//
// Every architecture provides a backend module with the same six
// function signatures. The `cfg` block below aliases the active
// one to the symbols `backend_*` used by this facade.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
use self::x86_64 as b;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
use self::aarch64 as b;

#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "riscv64")]
use self::riscv64 as b;

#[cfg(target_arch = "loongarch64")]
mod loong64;
#[cfg(target_arch = "loongarch64")]
use self::loong64 as b;

fn backend_init() {
    b::init();
}
fn backend_set_attr(attr: u8) {
    b::set_attr(attr);
}
fn backend_put_byte(b: u8) {
    b::put_byte(b);
}
fn backend_clear() {
    b::clear();
}
fn backend_set_cursor(x: u8, y: u8) {
    b::set_cursor(x, y);
}
fn backend_log_line_count() -> usize {
    b::log_line_count()
}
fn backend_read_log_lines(buf: &mut [[u8; COLS + 2]]) -> usize {
    b::read_log_lines(buf)
}
