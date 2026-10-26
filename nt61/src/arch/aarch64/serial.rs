//! aarch64 PL011 UART

use core::arch::asm;
use core::ptr;

const UART0: u64 = 0x0900_0000;

pub fn serial_init(base: u64) {
    let b = if base != 0 { base } else { UART0 };
    unsafe {
        // PL011 register offsets:
        //   UARTCR    = 0x030 (Control)
        //   UARTLCR_H = 0x02C (Line Control)
        //   UARTIBRD  = 0x024 (Integer Baud Rate Divisor)
        //   UARTFBRD  = 0x028 (Fractional Baud Rate Divisor)
        //   UARTICR   = 0x044 (Interrupt Clear)
        // Previously the offsets were shifted by 6, writing the
        // baud-rate divisors into the wrong registers.
        ptr::write_volatile((b + 0x030) as *mut u32, 0); // UARTCR: disable
        ptr::write_volatile((b + 0x044) as *mut u32, 0); // UARTICR: clear
        ptr::write_volatile((b + 0x024) as *mut u32, 13); // UARTIBRD
        ptr::write_volatile((b + 0x028) as *mut u32, 1); // UARTFBRD
        ptr::write_volatile((b + 0x02C) as *mut u32, 0x60); // UARTLCR_H: 8N1, FIFO
        ptr::write_volatile((b + 0x030) as *mut u32, 0x301); // UARTCR: enable TX+RX
    }
}

pub fn serial_putc(base: u64, c: u8) {
    let b = if base != 0 { base } else { UART0 };
    unsafe {
        // Bounded wait: if the UART never becomes ready (e.g. a bad
        // clock setup), drop the character instead of hanging forever.
        let mut spins: u32 = 0;
        while ptr::read_volatile((b + 0x18) as *const u32) & 0x20 == 0 {
            spins += 1;
            if spins > 1_000_000 {
                return;
            }
        }
        ptr::write_volatile((b + 0x00) as *mut u32, c as u32);
    }
}

pub fn serial_puts(base: u64, s: &str) {
    for c in s.bytes() {
        serial_putc(base, c);
    }
}

fn _keep() {
    let _ = unsafe { asm!("nop") };
}
