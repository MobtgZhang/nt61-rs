//! RISC-V 64 16550 UART

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

static UART_BASE: AtomicU64 = AtomicU64::new(0);

const UART_THR: u64 = 0;
const UART_LSR: u64 = 5;

pub fn serial_init(base: u64) {
    UART_BASE.store(base, Ordering::Release);
    let b = if base != 0 { base } else { 0x1000_0000 };
    unsafe {
        ptr::write_volatile((b + 1) as *mut u8, 0x00); // disable interrupts
        ptr::write_volatile((b + 3) as *mut u8, 0x80); // DLAB
        ptr::write_volatile((b + 0) as *mut u8, 0x01); // divisor
        ptr::write_volatile((b + 1) as *mut u8, 0x00);
        ptr::write_volatile((b + 3) as *mut u8, 0x03); // 8N1
        ptr::write_volatile((b + 2) as *mut u8, 0xC7); // FIFO
    }
}

pub fn serial_putc(b: u8) {
    let base = UART_BASE.load(Ordering::Acquire);
    if base == 0 { return; }
    unsafe {
        while ptr::read_volatile((base + UART_LSR) as *const u8) & 0x20 == 0 {}
        ptr::write_volatile((base + UART_THR) as *mut u8, b);
    }
}

pub fn serial_puts(s: &str) {
    for c in s.bytes() { serial_putc(c); }
}

pub fn serial_getc() -> i16 {
    let base = UART_BASE.load(Ordering::Acquire);
    if base == 0 { return -1; }
    unsafe {
        if ptr::read_volatile((base + UART_LSR) as *const u8) & 0x01 == 0 { return -1; }
        ptr::read_volatile((base + UART_THR) as *const u8) as i16
    }
}

/// Receive-side interrupt handler stub.
///
/// Phase 1 just drains the UART FIFO into a kernel-internal ring
/// buffer. We don't have a kernel input queue yet, so the bytes
/// are silently dropped — the wiring is in place for Phase 3 to
/// hook up a `kbd` driver.
pub fn handle_rx() {
    let base = UART_BASE.load(Ordering::Acquire);
    if base == 0 { return; }
    unsafe {
        // Drain up to 16 bytes.
        for _ in 0..16 {
            if ptr::read_volatile((base + UART_LSR) as *const u8) & 0x01 == 0 {
                break;
            }
            let _b = ptr::read_volatile((base + UART_THR) as *const u8);
        }
    }
}

/// Write a `u32` as 8 hex digits to the UART. Provided for parity
/// with `hal::serial::write_u32_hex` on other architectures.
pub fn write_u32_hex(v: u32) {
    serial_puts("0x");
    for i in (0..8).rev() {
        let n = ((v >> (i * 4)) & 0xF) as u8;
        let c = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
        serial_putc(c);
    }
}