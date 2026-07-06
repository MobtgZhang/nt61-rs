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

/// Number of lines the log ring keeps around for back-scroll on
/// architectures without a real text framebuffer (aarch64,
/// riscv64, loongarch64).
pub const LOG_RING_LINES: usize = 64;

/// Standard colour attributes used by the SafeBootMode shell.
pub const ATTR_DEFAULT: u8 = 0x07; // light-grey on black
pub const ATTR_TITLE: u8 = 0x1F;   // white on blue
pub const ATTR_PROMPT: u8 = 0x0F;  // white on black
pub const ATTR_HR: u8 = 0x0B;      // light-cyan on black
pub const ATTR_LOG: u8 = 0x0A;     // light-green on black

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

/// Write a single byte. Recognises `\n`, `\r`, `\t`, and
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

/// Write a centred title bar to the screen with a coloured
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

/// Read up to `buf.len()` lines from the most recent log ring
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
    put_byte_vga_only, put_byte_vga_only_str, put_rstr, is_ready,
};

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn put_byte_vga_only(b: u8) { put_byte(b); }

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn put_byte_vga_only_str(s: &str) {
    for b in s.bytes() { put_byte(b); }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn put_rstr(s: &str) {
    for b in s.bytes() { put_byte(b); }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn is_ready() -> bool { READY.load(Ordering::Acquire) }

/// Move the cursor to the start of the given row, column 0.
pub fn goto_row(row: u8) {
    set_cursor(0, row);
}

/// Write a horizontal divider across the full row.
pub fn write_hr(row: u8, attr: u8) {
    let prev = get_attr();
    set_attr(attr);
    goto_row(row);
    for _ in 0..COLS {
        put_byte(0xC4); // horizontal bar
    }
    set_attr(prev);
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

fn backend_init() { b::init(); }
fn backend_set_attr(attr: u8) { b::set_attr(attr); }
fn backend_put_byte(b: u8) { b::put_byte(b); }
fn backend_clear() { b::clear(); }
fn backend_set_cursor(x: u8, y: u8) { b::set_cursor(x, y); }
fn backend_log_line_count() -> usize { b::log_line_count() }
fn backend_read_log_lines(buf: &mut [[u8; COLS + 2]]) -> usize {
    b::read_log_lines(buf)
}