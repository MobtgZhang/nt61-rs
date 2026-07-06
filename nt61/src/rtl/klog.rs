//! Kernel Logging
//
//! Provides standard Windows 7 NT 6.1.7601 kernel logging.

use core::sync::atomic::{AtomicBool, Ordering};

/// CRITICAL-001 (root cause fix):
/// `LOG_EARLY_READY` flips to `true` once `mm::init()` has run. While
/// it is `false`, the `kprintln!` macro routes output directly to the
/// platform UART — bypassing the buffered `BufferWriter` path that
/// pulls in `memcpy`/`copy_from_slice` and crashed early during the
/// boot sequence (before the MM page-fault handler and zero-page
/// allocator were wired up).
///
/// Once `mm::init()` returns, `mark_post_mm()` flips this flag and
/// the high-throughput `BufferWriter`/`windows_log` path is used.
pub static LOG_EARLY_READY: AtomicBool = AtomicBool::new(false);

/// Called from `mm::init()` once the page-fault handler and PFN
/// database are live. From this point on, the buffered logging path
/// is safe to use.
pub fn mark_post_mm() {
    LOG_EARLY_READY.store(true, Ordering::Release);
}

#[inline(never)]
pub fn write_early(s: &str) {
    let _ = crate::hal::serial::write_string(s);

    // Mirror every early log line to the VGA text console as
    // well. Before `mm::init()` runs, the LFB is still mapped
    // by the UEFI page tables and 0xB8000 is identity-mapped,
    // so writing to the text console is safe. We use the
    // VGA-only helper so the mirror does NOT loop back through
    // the serial port.
    #[cfg(target_arch = "x86_64")]
    if crate::hal::text_console::is_ready() {
        crate::hal::text_console::put_byte_vga_only_str(s);
    }
}

/// Kernel log interface
pub struct KLog;

/// Initialize kernel log - bring up the serial port first.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    crate::hal::serial::init();
    #[cfg(target_arch = "aarch64")]
    crate::hal::aarch64::init();
    #[cfg(target_arch = "riscv64")]
    crate::hal::riscv64::init();
    #[cfg(target_arch = "loongarch64")]
    crate::hal::loongarch64::init();
}

impl KLog {
    pub fn init() {
        init();
    }
}

/// A `Write` adapter that spits bytes to the platform serial port.
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_serial(s);
        Ok(())
    }
}

/// Per-arch serial output.
pub fn write_serial(s: &str) {
    // On architectures without a real text framebuffer
    // (aarch64, riscv64, loongarch64) every byte also has to be
    // mirrored into the in-RAM log ring so the SafeBootMode CMD
    // shell's log display pane has content when it is painted
    // on shell entry. Routing through `text_console::put_string`
    // does this in one place: the per-arch backend's `put_byte`
    // already takes care of writing to the UART and to the ring,
    // so calling `hal::serial::write_string` directly here would
    // produce duplicate serial output (once from `write_serial`,
    // once from the backend's `put_byte`).
    #[cfg(not(target_arch = "x86_64"))]
    {
        use crate::hal::text_console;
        if text_console::is_ready() {
            text_console::put_string(s);
        } else {
            let _ = crate::hal::serial::write_string(s);
        }
        return;
    }

    // x86_64 path: write to serial first, then mirror to VGA
    // text buffer (so the operator sees the boot trace in both
    // the tail-f serial log and the on-screen VGA framebuffer).
    let _ = crate::hal::serial::write_string(s);

    #[cfg(target_arch = "x86_64")]
    if crate::hal::text_console::is_ready() {
        crate::hal::text_console::put_byte_vga_only_str(s);
    }
}

/// Print a single character.
#[allow(dead_code)]
pub fn putchar(c: char) {
    let mut buf = [0u8; 4];
    let s = c.encode_utf8(&mut buf);
    write_serial(s);
}

/// Print a string.
pub fn puts(s: &str) {
    write_serial(s);
}

/// A `core::fmt::Write` adapter that writes into a caller-provided stack buffer.
pub struct BufferWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufferWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
}

impl<'a> core::fmt::Write for BufferWriter<'a> {
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

// ============================================================================
/// Kernel print macro — no trailing newline
///
/// CRITICAL-001 fix: when `LOG_EARLY_READY` is `false` (i.e. before
/// `mm::init()` has run), this dispatches to the early UART-direct
/// path so the macro is safe to call before the buffered
/// `BufferWriter` and `windows_log` infrastructure is reachable.
/// Once `mm::init()` returns and `mark_post_mm()` has been called,
/// the buffered path is used instead.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        if $crate::rtl::klog::LOG_EARLY_READY.load(core::sync::atomic::Ordering::Acquire) {
            #[allow(unused_imports)]
            use core::fmt::Write;
            let mut writer = $crate::rtl::klog::SerialWriter;
            let _ = writer.write_fmt(core::format_args!($($arg)*));
        } else {
            // EARLY PATH: format into a 256-byte stack buffer using
            // a borrowed-slice `core::fmt::Write` adapter (no
            // allocations, no `.bss` dependencies, no PLT-trampoline
            // risk) and then ship the result directly to the UART.
            use core::fmt::Write;
            struct FmtWriter<'a> { buf: &'a mut [u8], pos: usize }
            impl<'a> core::fmt::Write for FmtWriter<'a> {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    let n = s.len().min(self.buf.len() - self.pos);
                    self.buf[self.pos..self.pos + n].copy_from_slice(&s.as_bytes()[..n]);
                    self.pos += n;
                    Ok(())
                }
            }
            let mut buf = [0u8; 256];
            let mut w = FmtWriter { buf: &mut buf, pos: 0 };
            let _ = w.write_fmt(core::format_args!($($arg)*));
            let pos = w.pos;
            // Drop `w` so we no longer borrow `buf` mutably.
            drop(w);
            let s = core::str::from_utf8(&buf[..pos]).unwrap_or("");
            $crate::rtl::klog::write_early(s);
        }
    }};
}

/// Kernel println macro — with CRLF
///
/// CRITICAL-001 fix: dispatches between early and late logging
/// paths based on `LOG_EARLY_READY` (see `kprint!`).
#[macro_export]
macro_rules! kprintln {
    // Level + subsystem + message
    (level: $lvl:expr, subsystem: $sub:expr, $($arg:tt)*) => {{
        if $crate::rtl::klog::LOG_EARLY_READY.load(core::sync::atomic::Ordering::Acquire) {
            #[allow(unused_imports)]
            use ::core::fmt::Write;
            let mut body_buf = [0u8; 256];
            let mut body_writer = $crate::rtl::klog::BufferWriter::new(&mut body_buf);
            let _ = body_writer.write_fmt(::core::format_args!($($arg)*));
            let body_len = body_writer.pos();
            let body_str = ::core::str::from_utf8(&body_buf[..body_len]).unwrap_or("<bad utf8>");
            $crate::rtl::windows_log::write_kdprint($sub, body_str);
        } else {
            // EARLY PATH: emit `[SUBSYS] message\r\n` directly to
            // the UART. Avoids the `windows_log::write_kdprint`
            // dependency, which also relies on the buffered writer.
            $crate::rtl::klog::write_early(concat!("[", $sub, "] "));
            $crate::kprint!($($arg)*);
            $crate::rtl::klog::write_early("\r\n");
        }
    }};
    // Level only + message
    (level: $lvl:expr, $($arg:tt)*) => {{
        $crate::kprintln!(level: $lvl, subsystem: "KERNEL", $($arg)*);
    }};
    // Subsystem only + message
    (subsystem: $sub:expr, $($arg:tt)*) => {{
        if $crate::rtl::klog::LOG_EARLY_READY.load(core::sync::atomic::Ordering::Acquire) {
            $crate::kprintln!(level: $crate::rtl::windows_log::LogLevel::Info, subsystem: $sub, $($arg)*);
        } else {
            $crate::rtl::klog::write_early(concat!("[", $sub, "] "));
            $crate::kprint!($($arg)*);
            $crate::rtl::klog::write_early("\r\n");
        }
    }};
    // No-arg
    () => {{
        $crate::rtl::klog::write_early("\r\n");
    }};
    // With message — default Info/KERNEL
    ($($arg:tt)*) => {{
        $crate::kprintln!(subsystem: "KERNEL", $($arg)*);
    }};
}

// ============================================================================
// Convenience macros
// ============================================================================

#[macro_export]
macro_rules! kprintln_error {
    ($subsys:expr, $fmt:expr) => {{
        $crate::kprintln!(level: $crate::rtl::windows_log::LogLevel::Error, subsystem: $subsys, $fmt);
    }};
    ($subsys:expr, $fmt:expr, $($arg:tt)*) => {{
        $crate::kprintln!(level: $crate::rtl::windows_log::LogLevel::Error, subsystem: $subsys, $fmt, $($arg)*);
    }};
}

#[macro_export]
macro_rules! kprintln_warn {
    ($subsys:expr, $fmt:expr) => {{
        $crate::kprintln!(level: $crate::rtl::windows_log::LogLevel::Warning, subsystem: $subsys, $fmt);
    }};
    ($subsys:expr, $fmt:expr, $($arg:tt)*) => {{
        $crate::kprintln!(level: $crate::rtl::windows_log::LogLevel::Warning, subsystem: $subsys, $fmt, $($arg)*);
    }};
}

#[macro_export]
macro_rules! kprintln_info {
    ($subsys:expr, $fmt:expr) => {{
        $crate::kprintln!(level: $crate::rtl::windows_log::LogLevel::Info, subsystem: $subsys, $fmt);
    }};
    ($subsys:expr, $fmt:expr, $($arg:tt)*) => {{
        $crate::kprintln!(level: $crate::rtl::windows_log::LogLevel::Info, subsystem: $subsys, $fmt, $($arg)*);
    }};
}

#[macro_export]
macro_rules! kprintln_debug {
    ($subsys:expr, $fmt:expr) => {{
        $crate::kprintln!(level: $crate::rtl::windows_log::LogLevel::Debug, subsystem: $subsys, $fmt);
    }};
    ($subsys:expr, $fmt:expr, $($arg:tt)*) => {{
        $crate::kprintln!(level: $crate::rtl::windows_log::LogLevel::Debug, subsystem: $subsys, $fmt, $($arg)*);
    }};
}

// ============================================================================
// SOS-style driver loading
// ============================================================================

#[macro_export]
macro_rules! sos_load {
    ($path:expr) => {{
        $crate::rtl::windows_log::write_sos_loading($path);
    }};
}

// ============================================================================
// ntbtlog.txt driver loading log
// ============================================================================

#[macro_export]
macro_rules! ntbtlog {
    (loaded: $path:expr) => {{
        $crate::rtl::windows_log::write_ntbtlog_line($path, true);
    }};
    (not_loaded: $path:expr) => {{
        $crate::rtl::windows_log::write_ntbtlog_line($path, false);
    }};
}

// ============================================================================
// Kernel Phase Initialization
// ============================================================================

#[macro_export]
macro_rules! phase_header {
    ($phase:expr, $name:expr) => {{
        $crate::rtl::windows_log::write_phase_header($phase);
        $crate::boot_println!("    KERNEL: {}", $name);
    }};
}

#[macro_export]
macro_rules! phase_init {
    ($subsys:expr, $msg:expr) => {{
        $crate::rtl::windows_log::write_phase_item($subsys, $msg);
    }};
}

/// Milestone logging (like phase_init)
#[macro_export]
macro_rules! boot_milestone {
    ($subsys:expr, $msg:expr) => {{
        $crate::phase_init!($subsys, $msg);
    }};
    ($msg:expr) => {{
        $crate::phase_init!("KERNEL", $msg);
    }};
}

/// OK status logging
#[macro_export]
macro_rules! boot_ok {
    ($msg:expr) => {{
        $crate::boot_println!("    OK: {}", $msg);
    }};
}

/// Error status logging
#[macro_export]
macro_rules! boot_err {
    ($msg:expr) => {{
        $crate::boot_println!("    FAIL: {}", $msg);
    }};
}

// ============================================================================
// Boot-time logging (before full logging is initialized)
// ============================================================================

#[macro_export]
macro_rules! boot_print {
    ($($arg:tt)*) => {{
        #[allow(unused_imports)]
        use core::fmt::Write;
        let mut writer = $crate::rtl::klog::SerialWriter;
        let _ = writer.write_fmt(core::format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! boot_println {
    ($($arg:tt)*) => {{
        $crate::boot_print!($($arg)*);
        $crate::boot_print!("\r\n");
    }};
}

#[macro_export]
macro_rules! boot_header {
    ($title:expr) => {{
        $crate::boot_println!("");
        $crate::boot_println!("========================================");
        $crate::boot_println!("  {}", $title);
        $crate::boot_println!("========================================");
    }};
}

/// Emit a phase header using the bare serial facade, bypassing
/// `windows_log::write_phase_header` (which uses a 64-byte on-stack
/// buffer and on some archs/link orders can trigger a stack/layout
/// misbehaviour when called repeatedly after the kernel heap has been
/// brought up). This preserves the `--- Phase NNN ... ---` shape the
/// Windows-7 boot trace uses, while producing two short `write_string`
/// calls that we have empirically verified work in every path on every
/// architecture. Use this in place of `phase_header!` for early-boot
/// phases that come *after* `hal::init()` has run.
#[macro_export]
macro_rules! phase_header_emit {
    ($phase:expr, $name:expr) => {{
        // Emit the header in two parts. Splitting on the phase number
        // avoids needing any decimal formatting on the phase value at
        // this site, which keeps the macro a pure ASCII-literal writer
        // (i.e. it relies only on `write_string` and `boot_println`,
        // both of which are known-good from the rest of the boot trace).
        //
        // Always emit a three-digit phase number (e.g. "007",
        // "012") to match the `windows_log::write_phase_header`
        // formatting used on x86_64 so the boot trace is
        // arch-consistent. Phase 0 prints as "000".
        let p: u32 = $phase;
        let h: u8 = b'0' + ((p / 100) as u8);
        let tens: u8 = b'0' + (((p / 10) % 10) as u8);
        let ones: u8 = b'0' + ((p % 10) as u8);
        // SAFETY: each digit byte is in the ASCII range, so a
        // single-byte `str` constructed from it is always valid.
        let h_s = unsafe { core::str::from_utf8_unchecked(core::slice::from_ref(&h)) };
        let t_s = unsafe { core::str::from_utf8_unchecked(core::slice::from_ref(&tens)) };
        let o_s = unsafe { core::str::from_utf8_unchecked(core::slice::from_ref(&ones)) };
        $crate::hal::serial::write_string("--- Phase ");
        $crate::hal::serial::write_string(h_s);
        $crate::hal::serial::write_string(t_s);
        $crate::hal::serial::write_string(o_s);
        $crate::hal::serial::write_string(" Initialization ---\r\n");
        $crate::hal::serial::write_string("    KERNEL: ");
        $crate::hal::serial::write_string($name);
        $crate::hal::serial::write_string("\r\n");
    }};
}
