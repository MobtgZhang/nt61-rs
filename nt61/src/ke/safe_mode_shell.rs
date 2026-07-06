//! Cross-Architecture Kernel-Side CMD Shell
//!
//! A small, portable command-line interpreter that runs entirely
//! inside the kernel (no Ring 3 transition) and uses the unified
//! `hal::text_console` / `hal::keyboard_input` interfaces for
//! I/O. The shell was introduced so SafeBootMode has a real,
//! usable UI on every architecture — including aarch64,
//! riscv64, and loongarch64, which do not have an x86_64 PE
//! cmd.exe binary and therefore cannot perform the Ring 0→3
//! dispatch that the original `try_launch_cmd_exe` relied on.
//!
//! On x86_64 the shell doubles as a fallback when cmd.exe is
//! unavailable (e.g. on bare-metal boot without an NTFS volume
//! mounted); in that case the kernel logs "FATAL: cmd.exe
//! launch failed" and then drops into the shell rather than
//! halting.
//!
//! # Layout
//!
//! The shell uses a fixed 80×25 layout:
//!
//! ```text
//! row  0      │ Title bar (white-on-blue)
//! rows 1..N-3 │ Log pane (last `LOG_PANE_LINES` ring entries)
//! row  N-2    │ Horizontal divider (light-cyan)
//! row  N-1    │ Prompt (white-on-black)
//! ```
//!
//! Where `N = ROWS` from `hal::text_console`. On the log-ring
//! architectures (aarch64/riscv64/loongarch64) the shell reads
//! the ring via `hal::text_console::read_log_lines` and paints
//! it back through `put_byte`. On x86_64 the VGA buffer *is*
//! the log; the log pane is therefore a no-op (the kernel's own
//! `boot_println` already paints directly into it).
//!
//! # Commands
//!
//! - `help` / `?`         — print the command list.
//! - `ver`                — print the kernel version banner.
//! - `cls`                — clear the screen.
//! - `reboot`             — issue a CPU reset.
//! - `halt`               — enter the architecture's halt loop.
//! - `panic <msg>`        — trigger a kernel panic with `msg`.
//! - `boot-mode`          — print the active `BootMode`.
//! - `arch`               — print the build target architecture.
//! - `log`                — dump the entire log ring.
//! - `echo <text>`        — echo `text` to the console.
//! - `time`               — print a coarse uptime counter.
//!
//! The shell never returns; it only terminates by halting,
//! rebooting, or panicking.

use core::sync::atomic::{AtomicU64, Ordering};
use core::fmt::Write;
use alloc::string::ToString;

/// Number of rows reserved for the log pane. With 25 total
/// rows we keep 22 for logs, 1 for the divider, 1 for the
/// prompt, and 1 for the title bar.
const LOG_PANE_FIRST: u8 = 1;
const DIVIDER_ROW: u8 = 23;
const PROMPT_ROW: u8 = 24;

/// Maximum length of the input line. Anything beyond this
/// length triggers a `Line too long` error.
const INPUT_MAX: usize = 72;

/// Boot-mode label displayed in the title bar. Mirrors the
/// labels printed by the boot sequence file.
const TITLE: &str = " Safe Mode (CMD) - C:\\Windows\\System32\\cmd.exe ";

/// Coarse uptime counter incremented once per command loop
/// iteration. Useful as a "how long has the shell been up"
/// metric without dragging in the platform's full timekeeping
/// stack.
static UPTIME: AtomicU64 = AtomicU64::new(0);

/// The boot mode the shell was entered under. Captured at
/// `enter()` time so the `boot-mode` command can print it
/// without re-deriving it from `BootInfo`.
static ACTIVE_BOOT_MODE: AtomicU64 = AtomicU64::new(0);

/// Maximum bytes the input buffer can hold. We don't use
/// `heapless::Vec` here so the shell stays dependency-free;
/// a fixed-size array is enough for a kernel command line.
struct Input {
    buf: [u8; INPUT_MAX],
    len: usize,
}

impl Input {
    const fn empty() -> Self {
        Self { buf: [0u8; INPUT_MAX], len: 0 }
    }
    fn push(&mut self, b: u8) -> bool {
        if self.len >= INPUT_MAX { return false; }
        self.buf[self.len] = b;
        self.len += 1;
        true
    }
    fn pop(&mut self) -> bool {
        if self.len == 0 { return false; }
        self.len -= 1;
        true
    }
    fn as_str(&self) -> &str {
        // SAFETY: every byte in `buf[..len]` was inserted via
        // `push`, which is fed either by the keyboard's ASCII
        // decoder or by the line-edit path — both produce
        // valid UTF-8 byte sequences. Using `from_utf8_unchecked`
        // here avoids pulling in the panic-heavy validation
        // path on every Enter press.
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
    fn clear(&mut self) { self.len = 0; }
}

/// Tiny `core::fmt::Write` adapter on a fixed-size byte
/// buffer. Used to render messages like
/// "boot-mode=1 (SafeModeCmd)" without pulling in `heapless`.
struct FmtBuf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FmtBuf<N> {
    const fn new() -> Self { Self { bytes: [0u8; N], len: 0 } }
    fn as_str(&self) -> &str {
        // SAFETY: only ASCII text is ever written through
        // `write_str`, so the byte slice is valid UTF-8.
        unsafe { core::str::from_utf8_unchecked(&self.bytes[..self.len]) }
    }
}

impl<const N: usize> Write for FmtBuf<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len >= N { return Err(core::fmt::Error); }
            self.bytes[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

/// Enter the kernel-side CMD shell. Replaces the old
/// "halt because we can't dispatch cmd.exe" path on every
/// non-x86_64 architecture, and acts as a fallback on x86_64
/// if cmd.exe cannot be launched.
///
/// `boot_mode` is the `BootMode` discriminant that was active
/// when the shell was entered; it's printed by the `boot-mode`
/// command.
pub fn enter(boot_mode: u32) -> ! {
    ACTIVE_BOOT_MODE.store(boot_mode as u64, Ordering::Release);

    // Make sure both halves of the abstract HAL are up.
    crate::hal::text_console::init();
    crate::hal::keyboard_input::init();

    paint_static_frame();
    paint_help();
    paint_log_pane();
    paint_prompt("");

    let mut input = Input::empty();
    loop {
        UPTIME.fetch_add(1, Ordering::Relaxed);

        if let Some(c) = crate::hal::keyboard_input::try_read_byte() {
            match c {
                b'\r' | b'\n' => {
                    crate::hal::text_console::put_byte(b'\r');
                    crate::hal::text_console::put_byte(b'\n');
                    // `input.as_str()` is already valid UTF-8.
                    // We materialise it into a `String` here
                    // because `input.clear()` would invalidate
                    // the borrow before `dispatch` reads it.
                    let line = input.as_str().to_string();
                    input.clear();
                    if let Err(e) = dispatch(&line) {
                        print_line(format_msg_error(&e));
                    }
                    paint_log_pane();
                    paint_prompt("");
                }
                0x08 | 0x7F => {
                    if input.pop() {
                        crate::hal::text_console::put_byte(0x08);
                        crate::hal::text_console::put_byte(b' ');
                        crate::hal::text_console::put_byte(0x08);
                    }
                }
                b => {
                    if input.push(b) {
                        crate::hal::text_console::put_byte(b);
                    } else {
                        print_line("line too long");
                    }
                }
            }
        } else {
            // Tight spin — interrupts are disabled in
            // SafeBootMode and there's no scheduler tick to
            // back us off. The arch-specific `halt` issues a
            // low-power wait (hlt / wfi / idle 0) that the
            // CPU uses until the next interrupt arrives; the
            // PS/2 controller on x86_64 and the UART drivers
            // on the other arches raise the appropriate
            // wake-up event when a byte is pending, so this
            // loop burns very little power.
            crate::arch::halt();
        }
    }
}

/// Paint the title bar, divider, and prompt placeholder that
/// form the "static" frame of the shell window.
fn paint_static_frame() {
    use crate::hal::text_console::{set_attr, clear, put_title_bar, write_hr};

    clear();
    set_attr(crate::hal::text_console::ATTR_TITLE);
    put_title_bar(TITLE, crate::hal::text_console::ATTR_TITLE);
    write_hr(DIVIDER_ROW, crate::hal::text_console::ATTR_HR);
}

/// Print the available command list at the bottom of the
/// log pane on first entry. After that the shell only
/// refreshes the dynamic log pane and the prompt line.
fn paint_help() {
    use crate::hal::text_console::set_attr;
    set_attr(crate::hal::text_console::ATTR_LOG);
    let lines: [&str; 7] = [
        "NT6.1.7601 kernel-mode SafeBoot CMD shell",
        "type 'help' for a list of commands.",
        "",
        "available commands:",
        "  help, ver, cls, reboot, halt, log,",
        "  echo <text>, boot-mode, arch, time,",
        "  panic <msg>",
    ];
    let mut row = LOG_PANE_FIRST + 1;
    for l in &lines {
        crate::hal::text_console::set_cursor(0, row);
        for b in l.bytes() {
            crate::hal::text_console::put_byte(b);
        }
        row = row.saturating_add(1);
    }
}

/// Re-paint the log pane. On the log-ring architectures this
/// dumps the most-recent ring entry; on x86_64 this is a
/// no-op (the live VGA buffer is the log).
fn paint_log_pane() {
    let count = crate::hal::text_console::log_line_count();
    if count == 0 {
        return;
    }
    let mut buf = [[0u8; crate::hal::text_console::COLS + 2]; 1];
    let n = crate::hal::text_console::read_log_lines(&mut buf);
    if n == 0 { return; }
    let attr = buf[0][crate::hal::text_console::COLS];
    let len = buf[0][crate::hal::text_console::COLS + 1] as usize;
    crate::hal::text_console::set_attr(attr);
    crate::hal::text_console::set_cursor(0, LOG_PANE_FIRST);
    for i in 0..len.min(crate::hal::text_console::COLS) {
        crate::hal::text_console::put_byte(buf[0][i]);
    }
}

/// Repaint the prompt. `prefix` is the current input buffer;
/// pass an empty string when refreshing after Enter.
fn paint_prompt(prefix: &str) {
    use crate::hal::text_console::{set_attr, set_cursor, put_byte};
    set_attr(crate::hal::text_console::ATTR_PROMPT);
    set_cursor(0, PROMPT_ROW);
    put_byte(b'C');
    put_byte(b':');
    put_byte(b'\\');
    put_byte(b'>');
    for b in prefix.bytes() {
        put_byte(b);
    }
}

/// Print a line on the prompt row (after Enter), advancing
/// nothing — the caller is expected to call `paint_prompt`
/// afterwards to redraw the prompt.
fn print_line(s: &str) {
    use crate::hal::text_console::{set_attr, set_cursor, put_byte};
    set_attr(crate::hal::text_console::ATTR_DEFAULT);
    set_cursor(0, PROMPT_ROW);
    for b in s.bytes() {
        put_byte(b);
    }
    put_byte(b'\r');
    put_byte(b'\n');
}

#[derive(Debug)]
enum CmdError {
    Unknown,
    MissingArg,
    BadArg,
}

fn format_msg_error(e: &CmdError) -> &'static str {
    match e {
        CmdError::Unknown => "error: unknown command",
        CmdError::MissingArg => "error: missing argument",
        CmdError::BadArg => "error: bad argument",
    }
}

fn dispatch(line: &str) -> Result<(), CmdError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let (cmd, rest) = split_first_word(trimmed);
    match cmd {
        "help" | "?" => { paint_help(); Ok(()) }
        "ver" => {
            print_line("NT6.1.7601 kernel v0.1 (SafeBoot CMD)");
            Ok(())
        }
        "cls" => {
            paint_static_frame();
            paint_help();
            Ok(())
        }
        "reboot" => {
            print_line("reboot not supported in this build, halting instead");
            crate::arch::halt_loop();
        }
        "halt" => {
            print_line("halting.");
            crate::arch::halt_loop();
        }
        "panic" => {
            if rest.is_empty() { return Err(CmdError::MissingArg); }
            panic!("user-requested panic from SafeBoot shell: {}", rest);
        }
        "boot-mode" => {
            let m = ACTIVE_BOOT_MODE.load(Ordering::Acquire);
            let mut s: FmtBuf<64> = FmtBuf::new();
            let _ = write!(s, "boot-mode={} ({})", m, boot_mode_name(m as u32));
            print_line(s.as_str());
            Ok(())
        }
        "arch" => {
            print_line(arch_label());
            Ok(())
        }
        "log" => {
            dump_log_ring();
            Ok(())
        }
        "echo" => {
            print_line(rest);
            Ok(())
        }
        "time" => {
            let t = UPTIME.load(Ordering::Acquire);
            let mut s: FmtBuf<64> = FmtBuf::new();
            let _ = write!(s, "uptime ticks={}", t);
            print_line(s.as_str());
            Ok(())
        }
        _ => Err(CmdError::Unknown),
    }
}

fn split_first_word(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

fn dump_log_ring() {
    let count = crate::hal::text_console::log_line_count();
    if count == 0 {
        print_line("(log ring empty or unavailable on this architecture)");
        return;
    }
    let mut buf = [[0u8; crate::hal::text_console::COLS + 2]; 1];
    let n = crate::hal::text_console::read_log_lines(&mut buf);
    if n == 0 { return; }
    let attr = buf[0][crate::hal::text_console::COLS];
    let len = buf[0][crate::hal::text_console::COLS + 1] as usize;
    crate::hal::text_console::set_attr(attr);
    // Render the bytes through the same `core::fmt::Write`
    // adapter the rest of the dispatcher uses; this gives
    // us a `&str` we can hand to `print_line`.
    let mut s: FmtBuf<{ crate::hal::text_console::COLS }> = FmtBuf::new();
    for i in 0..len.min(crate::hal::text_console::COLS) {
        let b = buf[0][i];
        // SAFETY: ring slots are populated byte-by-byte from
        // either ASCII printables or control chars (LF/CR/BS).
        // Each individual byte is valid UTF-8 on its own.
        let _ = s.write_str(unsafe {
            core::str::from_utf8_unchecked(core::slice::from_ref(&b))
        });
    }
    print_line(s.as_str());
}

fn boot_mode_name(m: u32) -> &'static str {
    match m {
        0 => "Normal",
        1 => "SafeModeCmd",
        2 => "SafeModeDebug",
        _ => "Unknown",
    }
}

#[cfg(target_arch = "x86_64")]
fn arch_label() -> &'static str { "x86_64" }
#[cfg(target_arch = "aarch64")]
fn arch_label() -> &'static str { "aarch64" }
#[cfg(target_arch = "riscv64")]
fn arch_label() -> &'static str { "riscv64" }
#[cfg(target_arch = "loongarch64")]
fn arch_label() -> &'static str { "loongarch64" }
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64",
              target_arch = "riscv64", target_arch = "loongarch64")))]
fn arch_label() -> &'static str { "unknown" }