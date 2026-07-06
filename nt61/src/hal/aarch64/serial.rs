//! PL011 UART driver for AArch64
//
//! Targets the QEMU 'virt' machine where the PL011 is mapped at
//! physical address 0x0900_0000. The reference clock is 24 MHz and
//! we configure for 115200 baud. All register access is volatile.

use core::ptr::{read_volatile, write_volatile};

const UART_BASE: u64 = 0x0900_0000;

const UARTDR: usize = 0x000;
const UARTFR: usize = 0x018;
const UARTIBRD: usize = 0x024;
const UARTFBRD: usize = 0x028;
const UARTLCR_H: usize = 0x02C;
const UARTCR: usize = 0x030;

const FR_TXFF: u32 = 1 << 5;

#[inline]
fn reg(offset: usize) -> *mut u32 {
    (UART_BASE as usize + offset) as *mut u32
}

/// Initialize the PL011 UART.
pub fn init() {
    unsafe {
        // Disable UART.
        write_volatile(reg(UARTCR), 0);
        // 115200 baud from 24 MHz clock: divisor = 24000000 / (16 * 115200) = 13.02
        write_volatile(reg(UARTIBRD), 13);
        write_volatile(reg(UARTFBRD), 1);
        // 8-N-1, FIFO enabled.
        write_volatile(reg(UARTLCR_H), 0x60);
        // Enable UART, TX, RX.
        write_volatile(reg(UARTCR), 0x301);
    }
}

/// Write a single byte.
pub fn write_char(c: u8) {
    unsafe {
        while (read_volatile(reg(UARTFR)) & FR_TXFF) != 0 {
            core::hint::spin_loop();
        }
        write_volatile(reg(UARTDR), c as u32);
    }
}

/// Write a string.
pub fn write_string(s: &str) {
    for c in s.bytes() {
        write_char(c);
    }
}

/// Write a 32-bit value as 8 hex digits (uppercase, no prefix).
/// Mirrors `hal::x86_64::serial::write_u32_hex` so the same
/// boot-time tracing code compiles on every architecture.
pub fn write_u32_hex(val: u32) {
    for i in (0..8).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as u8;
        let c = if nibble < 10 { b'0' + nibble } else { b'A' + nibble - 10 };
        write_char(c);
    }
}

/// Write a 64-bit value as 16 hex digits (uppercase, no prefix).
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
/// is empty. This is used as the backing for SVC #0x19.
pub fn try_get_char() -> Option<u8> {
    unsafe {
        // FR[4] = RXFE — Receive FIFO empty.
        if (read_volatile(reg(UARTFR)) & (1 << 4)) != 0 {
            None
        } else {
            let v = read_volatile(reg(UARTDR)) as u8;
            Some(v)
        }
    }
}
