//! NS16550A UART driver for RISC-V 64
//
//! Targets the SiFive test machine and QEMU 'virt', which both map a
//! 16550a-compatible UART at physical address 0x1000_0000. Same
//! register layout as the PC COM port (offset 0 = data, 1 = IER, ...).

use core::ptr::{read_volatile, write_volatile};

const UART_BASE: u64 = 0x1000_0000;

#[inline]
fn reg(offset: usize) -> *mut u8 {
    (UART_BASE as usize + offset) as *mut u8
}

/// Initialize the 16550a UART.
pub fn init() {
    unsafe {
        // Disable interrupts.
        write_volatile(reg(1), 0x00);
        // Set DLAB.
        write_volatile(reg(3), 0x80);
        // Divisor for 115200 baud (3 = 38400 baud at 1.8432 MHz).
        write_volatile(reg(0), 0x03);
        write_volatile(reg(1), 0x00);
        // 8-N-1.
        write_volatile(reg(3), 0x03);
        // Enable FIFO.
        write_volatile(reg(2), 0x01);
        // RTS/DSR set.
        write_volatile(reg(4), 0x03);
    }
}

/// Write a single byte. Honours the global
/// `hal::common::serial_disable` gate.
pub fn write_char(c: u8) {
    if crate::hal::common::serial_disable::is_disabled() {
        return;
    }
    unsafe {
        while (read_volatile(reg(5)) & 0x20) == 0 {
            core::hint::spin_loop();
        }
        write_volatile(reg(0), c);
    }
}

/// Write a string. Honours the gate.
pub fn write_string(s: &str) {
    if crate::hal::common::serial_disable::is_disabled() {
        return;
    }
    for c in s.bytes() {
        write_char(c);
    }
}

/// Write a `u32` as 8 hex digits to the UART. Provided for parity
/// with `crate::arch::riscv64::serial::write_u32_hex`.
pub fn write_u32_hex(v: u32) {
    write_string("0x");
    for i in (0..8).rev() {
        let n = ((v >> (i * 4)) & 0xF) as u8;
        let c = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
        write_char(c);
    }
}

/// Write a 64-bit value as 16 hex digits (uppercase, no prefix).
/// Provided so that callers using the unified `crate::hal::serial`
/// facade (e.g. `mm::pool`, `mm::mod`) can rely on the same name
/// across every architecture. Mirrors `crate::hal::aarch64::serial`.
pub fn write_hex_u64(v: u64) {
    for i in (0..16).rev() {
        let nibble = ((v >> (i * 4)) & 0xF) as u8;
        let c = if nibble < 10 { b'0' + nibble } else { b'A' + nibble - 10 };
        write_char(c);
    }
}

/// Write a single byte (alias used by HAL callers).
#[inline(always)]
pub fn put_char(c: u8) {
    write_char(c);
}

/// Try to read one byte from the UART. Returns `None` if the FIFO
/// is empty. Mirrors `crate::hal::aarch64::serial::try_get_char` so
/// that call sites in the unified `crate::hal::serial` facade work
/// on every architecture.
pub fn try_get_char() -> Option<u8> {
    // NS16550A LSR[0] = DR (Data Ready) — set when a byte is in
    // the receive FIFO.
    unsafe {
        if (read_volatile(reg(5)) & 0x01) == 0 {
            None
        } else {
            let v = read_volatile(reg(0));
            Some(v)
        }
    }
}
