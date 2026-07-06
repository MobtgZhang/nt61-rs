//! aarch64 PL011 UART

use core::arch::asm;
use core::ptr;

const UART0: u64 = 0x0900_0000;

pub fn serial_init(base: u64) {
    let b = if base != 0 { base } else { UART0 };
    unsafe {
        ptr::write_volatile((b + 0x24) as *mut u32, 0); // disable
        ptr::write_volatile((b + 0x2C) as *mut u32, 0); // clear
        ptr::write_volatile((b + 0x28) as *mut u32, 0x10); // IBRD
        ptr::write_volatile((b + 0x2C) as *mut u32, 0);  // FBRD
        ptr::write_volatile((b + 0x38) as *mut u32, 0x10); // LCR
        ptr::write_volatile((b + 0x2C) as *mut u32, 0);  // clear
        ptr::write_volatile((b + 0x24) as *mut u32, 1); // enable
    }
}

pub fn serial_putc(base: u64, c: u8) {
    let b = if base != 0 { base } else { UART0 };
    unsafe {
        while ptr::read_volatile((b + 0x18) as *const u32) & 0x20 == 0 { /* spin */ }
        ptr::write_volatile((b + 0x00) as *mut u32, c as u32);
    }
}

pub fn serial_puts(base: u64, s: &str) {
    for c in s.bytes() { serial_putc(base, c); }
}

#[allow(dead_code)]
fn _keep() {
    let _ = unsafe { asm!("nop") };
}
