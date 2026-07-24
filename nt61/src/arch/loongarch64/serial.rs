//! LoongArch 64 8250/16550 UART
//!
//! Provides the same public surface as `crate::hal::x86_64::serial`
//! so that cross-platform code (`system_image`, `rtl::sac`, etc.) can
//! invoke `crate::hal::serial::*` without per-architecture guards.

use core::arch::asm;
use core::fmt;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

static UART_BASE: AtomicU64 = AtomicU64::new(0);

const UART_THR: u64 = 0;
const UART_LSR: u64 = 5;

/// Initialise the UART. `base == 0` uses the LS7A default at
/// `0x1FE0_0000` (the address the Loongson machines and QEMU
/// virt platform expose).
pub fn init() {
    serial_init(0);
}

/// Architecture-specified base address. Provided for symmetry with
/// the x86_64 driver.
pub fn serial_init(base: u64) {
    let b = if base != 0 { base } else { 0x1FE0_0000 };
    UART_BASE.store(b, Ordering::Release);
    unsafe {
        ptr::write_volatile((b + 1) as *mut u8, 0x00);
        ptr::write_volatile((b + 3) as *mut u8, 0x80);
        ptr::write_volatile((b + 0) as *mut u8, 0x01);
        ptr::write_volatile((b + 1) as *mut u8, 0x00);
        ptr::write_volatile((b + 3) as *mut u8, 0x03);
        ptr::write_volatile((b + 2) as *mut u8, 0xC7);
    }
}

fn base() -> u64 {
    let b = UART_BASE.load(Ordering::Acquire);
    if b == 0 { 0x1FE0_0000 } else { b }
}

/// Write a single character to the UART. Honours the global
/// `hal::common::serial_disable` gate.
pub fn write_char(c: u8) {
    if crate::hal::common::serial_disable::is_disabled() {
        return;
    }
    let b = base();
    unsafe {
        while ptr::read_volatile((b + UART_LSR) as *const u8) & 0x20 == 0 {}
        ptr::write_volatile((b + UART_THR) as *mut u8, c);
    }
}

/// Write a string to the UART. Honours the gate.
pub fn write_string(s: &str) {
    if crate::hal::common::serial_disable::is_disabled() {
        return;
    }
    for c in s.bytes() { write_char(c); }
}

/// Write a string followed by CRLF.
pub fn write_line(s: &str) {
    write_string(s);
    write_string("\r\n");
}

/// Write a `u64` as 16 hex digits.
pub fn write_u64_hex(val: u64) {
    use core::fmt::Write;
    struct HexWriter<'a>(&'a mut [u8]);
    impl<'a> fmt::Write for HexWriter<'a> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.0[..s.len()].copy_from_slice(s.as_bytes());
            Ok(())
        }
    }
    let mut buf = [0u8; 16];
    let _ = write!(HexWriter(&mut buf), "{:016x}", val);
    write_string(unsafe { core::str::from_utf8_unchecked(&buf) });
}

/// Write a `u64` as 16 hex digits.
///
/// Available cross-arch through the unified
/// `crate::hal::serial::write_hex_u64` facade. We deliberately
/// define both the kernel-side alias (`write_hex_u64`) and the
/// boot-side name (`write_u64_hex`) so the cross-arch callers
/// (`mm::pool`, `arch/aarch64/paging`, etc.) link regardless of
/// which side of the build they end up on.
pub fn write_hex_u64(val: u64) {
    write_u64_hex(val);
}

/// Write a `usize` as hex without padding.
pub fn write_usize_hex(val: usize) {
    use core::fmt::Write;
    let mut buf = [0u8; 32];
    let mut s = String::new();
    let _ = write!(s, "{:x}", val);
    let bytes = s.as_bytes();
    buf[..bytes.len()].copy_from_slice(bytes);
    write_string(unsafe { core::str::from_utf8_unchecked(&bytes) });
}

/// Write a `u32` as 8 hex digits.
pub fn write_u32_hex(val: u32) {
    use core::fmt::Write;
    let mut buf = [0u8; 8];
    let _ = write!(WriteToBuf(&mut buf), "{:08x}", val);
    write_string(unsafe { core::str::from_utf8_unchecked(&buf) });
}

struct WriteToBuf<'a>(&'a mut [u8]);
impl<'a> fmt::Write for WriteToBuf<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.0.len());
        self.0[..n].copy_from_slice(&s.as_bytes()[..n]);
        Ok(())
    }
}

/// Read one byte from the UART. Returns `None` if no data is ready.
pub fn read_char() -> Option<u8> {
    let b = base();
    unsafe {
        if ptr::read_volatile((b + UART_LSR) as *const u8) & 0x01 == 0 {
            return None;
        }
        Some(ptr::read_volatile((b + UART_THR) as *const u8))
    }
}

/// Returns true if data is waiting in the receive FIFO.
pub fn data_available() -> bool {
    let b = base();
    unsafe { (ptr::read_volatile((b + UART_LSR) as *const u8) & 0x01) != 0 }
}

/// Legacy alias for `init()`-style entry points.
pub fn serial_putc(b: u8) { write_char(b); }

/// Legacy alias for `write_string`.
pub fn serial_puts(s: &str) { write_string(s); }

/// Legacy alias for `read_char`.
pub fn serial_getc() -> i16 {
    match read_char() {
        Some(b) => b as i16,
        None => -1,
    }
}

/// Light-weight formatter helper, mirrors `crate::hal::x86_64::serial`.
pub struct Stdout;

impl Stdout {
    pub fn new() -> Self { Stdout }
    pub fn write(&self, s: &str) { write_string(s); }
    pub fn write_byte(&self, b: u8) { write_char(b); }
    pub fn flush(&self) { /* MMIO writes are synchronous. */ }
}

extern crate alloc;
use alloc::string::String;

/// Reserved for Phase 2 diagnostics. Kept here so the link order is
/// stable across builds.
#[allow(dead_code)]
fn _keep() {}
