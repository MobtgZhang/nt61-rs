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

/// Runtime gate for boot log visibility. Set to `false` by
/// `configure_boot_display()` when the selected `BootMode` is
/// Desktop or Cmd — those modes show only the boot animation with
/// no scrolling log output. Panic / BSOD paths bypass this gate
/// via `boot_print_always!` so critical errors are always visible.
pub static BOOT_LOG_VISIBLE: AtomicBool = AtomicBool::new(true);

/// Enable or disable boot-time log output at runtime.
pub fn set_boot_log_visible(visible: bool) {
    BOOT_LOG_VISIBLE.store(visible, Ordering::Release);
}

/// True when boot-time log output is currently enabled.
#[inline]
pub fn boot_log_visible() -> bool {
    BOOT_LOG_VISIBLE.load(Ordering::Acquire)
}

/// Boot diagnostics: emit a raw-UART phase marker that bypasses
/// every output gate so the boot trace stays observable even when
/// the per-mode display policy silences `boot_println!`.
pub fn phase_trace_marker(phase: u32) {
    #[cfg(feature = "log_level_debug")]
    {
        use core::fmt::Write;
        let mut buffer = [0u8; 16];
        let mut writer = StackTraceWriter {
            bytes: &mut buffer,
            offset: 0,
        };
        let _ = write!(writer, "TRACE:{}\r\n", phase);
        let len = buffer
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(buffer.len());
        let text = unsafe { core::str::from_utf8_unchecked(&buffer[..len]) };
        crate::hal::serial::write_string(text);
    }
}

struct StackTraceWriter<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}

impl core::fmt::Write for StackTraceWriter<'_> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for byte in text.as_bytes() {
            if self.offset < self.bytes.len() {
                self.bytes[self.offset] = *byte;
                self.offset += 1;
            }
        }
        Ok(())
    }
}

/// Set while the CPU is inside a trap handler.
///
/// A `#PF` handler must not touch the linear framebuffer or the VGA
/// text buffer: those pages are only reachable through the low-half
/// identity map, and the mapping that is actually loaded when the
/// handler runs is the *faulting process's* page table. If that table
/// marks the framebuffer read-only (or does not map it at all), the
/// logging call re-faults inside the handler. Intel SDM Vol. 3A: a
/// exception that cannot be delivered because its handler faults
/// escalates to `#DF`, and a faulting `#DF` handler causes a triple
/// fault and a platform reset. Windows 7 `MmAccessFault` and ReactOS
/// `ntoskrnl/ex/exception.c` therefore keep the fault-dispatch path
/// free of anything that can re-fault, so while this flag is set the
/// UART is the only sink.
static FAULT_CONTEXT: AtomicBool = AtomicBool::new(false);

pub fn set_fault_context(active: bool) {
    FAULT_CONTEXT.store(active, Ordering::Release);
}

#[inline]
pub fn in_fault_context() -> bool {
    FAULT_CONTEXT.load(Ordering::Acquire)
}

/// Called from `mm::init()` once the page-fault handler and PFN
/// database are live. From this point on, the buffered logging path
/// is safe to use.
pub fn mark_post_mm() {
    LOG_EARLY_READY.store(true, Ordering::Release);
}

#[inline(never)]
pub fn write_early(s: &str) {
    let _ = crate::hal::serial::write_string(s);

    if in_fault_context() {
        return;
    }

    // Mirror every early log line to the VGA text console as
    // well. Before `mm::init()` runs, the LFB is still mapped
    // by the UEFI page tables and 0xB8000 is identity-mapped,
    // so writing to the text console is safe. We use the
    // VGA-only helper so the mirror does NOT loop back through
    // the serial port.
    if crate::hal::text_console::is_ready() {
        crate::hal::text_console::put_byte_vga_only_str(s);
    }
}

/// Kernel log interface
pub struct KLog;

/// Initialize kernel log - bring up the serial port first.
pub fn init() {
    crate::hal::serial::init();
}

impl KLog {
    pub fn init() {
        init();
    }
}

/// A `write` adapter that spits bytes to the platform serial port.
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_serial(s);
        Ok(())
    }
}

/// Per-arch serial output.
///
/// The boot trace is mirrored to three sinks, in order:
/// 1. The platform's serial UART (COM1 / PL011 / NS16550A / 8250).
///    This sink is gated by `hal::serial::set_disabled`; once
///    `kernel_main` flips it on, all subsequent writes are
///    silently dropped. The panic-path macros use
///    `with_serial_unmasked` to bypass the gate so the operator
///    can still read the panic trace on a host terminal.
/// 2. The cross-arch linear framebuffer (via the bootvid LFB
///    path). This is the only operator-visible sink after
///    `set_disabled(true)`; the boot trace stays visible on the
///    GUI panel even when COM1 is silenced.
/// 3. The per-arch text-console backend (VGA mirror on x86_64,
///    in-RAM log ring on the other architectures). The SafeBootMode
///    CMD shell's log display pane reads from this ring so it has
///    content to paint on shell entry.
pub fn write_serial(s: &str) {
    #[cfg(not(feature = "log_level_debug"))]
    {
        // Release builds still show boot messages on the visible
        // display (bootvid LFB) even though COM1 is silenced. The
        // operator must see the boot log on the QEMU `-display gtk`
        // window; otherwise the screen stays black after
        // `bootvid::init()` paints it.
        // The text-console facade is a diagnostic/legacy mirror. The
        // visible post-GOP console is owned by bootvid; routing through
        // the facade would also poke the legacy VGA CRTC registers on
        // x86_64 and can stall a release build. Keep one authoritative
        // display sink.
        if crate::drivers::bootvid::lfb_active() {
            write_to_lfb(s);
        } else if crate::hal::text_console::is_ready() {
            crate::hal::text_console::put_byte_vga_only_str(s);
        }
    }
    #[cfg(feature = "log_level_debug")]
    {
        // While a trap handler is running, the framebuffer and VGA text
        // buffer are not safe to touch (see `FAULT_CONTEXT` above), so the
        // UART is the only sink. Emit unmasked so the trace still reaches
        // the host even after `set_disabled(true)` has gated normal logging.
        if in_fault_context() {
            crate::hal::common::serial_disable::with_serial_unmasked(|| {
                let _ = crate::hal::serial::write_string_always(s);
            });
            return;
        }

        // Choose one operator-visible sink instead of fanning every
        // boot line to both COM1 and the LFB. The LFB scroll path is
        // a multi-megabyte pixel move on high-resolution GOP modes;
        // doing that for every debug line makes headless QEMU runs
        // look hung. Debug builds keep COM1 alive, while non-debug
        // builds use the on-screen console.
        if !crate::hal::common::serial_disable::is_disabled() {
            let _ = crate::hal::serial::write_string(s);
        } else {
            if crate::hal::text_console::is_ready() {
                crate::hal::text_console::put_byte_vga_only_str(s);
            } else {
                write_to_lfb(s);
            }
        }
    }
}

/// Mirror `s` into the bootvid LFB path. This is the
/// post-Milestone-B sink that the operator sees on the GUI panel.
/// The function is a no-op until the LFB has been wired by
/// `arch::boot::adopt_bootinfo_framebuffer`.
fn write_to_lfb(s: &str) {
    if !crate::hal::common::framebuffer::is_active() {
        return;
    }
    for b in s.bytes() {
        // Translate `\n` to `\r\n` so the LFB cursor returns to
        // column 0 after each line — the standard DOS / Windows
        // convention that the SafeBootMode CMD shell assumes.
        if b == b'\n' {
            crate::drivers::bootvid::put_byte_to_active_console(b'\r');
        }
        crate::drivers::bootvid::put_byte_to_active_console(b);
    }
}

/// Print a single character.
pub fn putchar(c: char) {
    let mut buf = [0u8; 4];
    let s = c.encode_utf8(&mut buf);
    write_serial(s);
}

/// Print a string.
pub fn puts(s: &str) {
    write_serial(s);
}

/// A `core::fmt::write` adapter that writes into a caller-provided stack buffer.
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
            use core::fmt::Write;
            let mut writer = $crate::rtl::klog::SerialWriter;
            let _ = writer.write_fmt(core::format_args!($($arg)*));
        } else {
            // EARLY PATH: format into a 256-byte stack buffer using
            // a borrowed-slice `core::fmt::write` adapter (no
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
            let pos = {
                let mut w = FmtWriter { buf: &mut buf, pos: 0 };
                let _ = w.write_fmt(core::format_args!($($arg)*));
                w.pos
            };
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
        // The `level:` argument used to be accepted and then thrown away,
        // so a `Debug` call still printed when the effective level was
        // `Info`. Filter before formatting: skipping the format is also
        // what makes a muted hot path cheap.
        if $crate::rtl::logging::should_log_severity(
            $lvl.to_severity(),
            $crate::rtl::logging::subsystem_to_bits($sub),
        ) {
        if $crate::rtl::klog::LOG_EARLY_READY.load(core::sync::atomic::Ordering::Acquire) {
            use core::fmt::Write;
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
        {
            let p: u32 = $phase;
            $crate::rtl::klog::phase_trace_marker(p);
            let h: u8 = b'0' + ((p / 100) as u8);
            let tens: u8 = b'0' + (((p / 10) % 10) as u8);
            let ones: u8 = b'0' + ((p % 10) as u8);
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
        }
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
        $crate::boot_print_always!("    FAIL: {}\r\n", $msg);
    }};
}

// ============================================================================
// Boot-time logging (before full logging is initialized)
// ============================================================================

#[macro_export]
macro_rules! boot_print {
    ($($arg:tt)*) => {{
        if $crate::rtl::klog::boot_log_visible() {
            let _ = core::format_args!($($arg)*);
            #[cfg(feature = "log_level_debug")]
            {
                #[cfg(not(test))]
                {
                    use core::fmt::Write;
                    let mut writer = $crate::rtl::klog::SerialWriter;
                    let _ = writer.write_fmt(core::format_args!($($arg)*));
                }
            }
        }
    }};
}

#[macro_export]
macro_rules! boot_print_always {
    ($($arg:tt)*) => {{
        if $crate::rtl::klog::boot_log_visible() {
        #[cfg(not(test))]
        {
            use core::fmt::Write;
            let mut writer = $crate::rtl::klog::SerialWriter;
            let _ = writer.write_fmt(core::format_args!($($arg)*));
        }
        }
    }};
}

#[macro_export]
macro_rules! boot_println {
    ($($arg:tt)*) => {{
        {
            #[cfg(not(feature = "log_level_debug"))]
            let _ = core::format_args!($($arg)*);
            #[cfg(feature = "log_level_debug")]
            {
                $crate::boot_print!($($arg)*);
                $crate::boot_print!("\r\n");
            }
        }
    }};
}

/// Debug-gated boot trace. Compiles to nothing unless the
/// `log_level_debug` Cargo feature is enabled, so release /
/// non-debug builds keep the boot display concise while debug
/// builds retain the full phase-by-phase trace.
#[macro_export]
macro_rules! boot_debug_print {
    ($($arg:tt)*) => {{
        #[cfg(not(feature = "log_level_debug"))]
        let _ = core::format_args!($($arg)*);
        #[cfg(feature = "log_level_debug")]
        $crate::boot_print!($($arg)*);
    }};
}

/// Debug-gated boot trace with CRLF. See [`boot_debug_print!`].
#[macro_export]
macro_rules! boot_debug_println {
    ($($arg:tt)*) => {{
        #[cfg(not(feature = "log_level_debug"))]
        let _ = core::format_args!($($arg)*);
        #[cfg(feature = "log_level_debug")]
        $crate::boot_println!($($arg)*);
    }};
}

#[macro_export]
macro_rules! boot_header {
    ($title:expr) => {{
        $crate::boot_println!("");
        $crate::boot_println!("========================================");
        $crate::boot_println!("========================================");
        $crate::boot_print!("{}\r\n", $title);
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
