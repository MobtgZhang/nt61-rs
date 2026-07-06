//! 7A1000 UART driver for LoongArch64
//
//! Targets the QEMU 'virt' LoongArch machine, which maps a
//! 7A1000-compatible UART at physical address 0x1FE0_0000. The
//! 7A1000 is 16550a-compatible.

use core::ptr::{read_volatile, write_volatile};

const UART_BASE: u64 = 0x1FE0_0000;

#[inline]
fn reg(offset: usize) -> *mut u8 {
    (UART_BASE as usize + offset) as *mut u8
}

/// Initialize the UART.
pub fn init() {
    unsafe {
        write_volatile(reg(1), 0x00);
        write_volatile(reg(3), 0x80);
        write_volatile(reg(0), 0x03);
        write_volatile(reg(1), 0x00);
        write_volatile(reg(3), 0x03);
        write_volatile(reg(2), 0x01);
        write_volatile(reg(4), 0x03);
    }
}

/// Write a single byte.
pub fn write_char(c: u8) {
    unsafe {
        while (read_volatile(reg(5)) & 0x20) == 0 {
            core::hint::spin_loop();
        }
        write_volatile(reg(0), c);
    }
}

/// Write a string.
pub fn write_string(s: &str) {
    for c in s.bytes() {
        write_char(c);
    }
}
