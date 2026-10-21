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
const UARTIMSC: usize = 0x038;
const UARTICR: usize = 0x044;

const FR_TXFF: u32 = 1 << 5;
/// UARTFR bit 4: RX FIFO empty (0 = data available).
const FR_RXFE: u32 = 1 << 4;
/// UARTIMSC / UARTICR bit 4: receive-interrupt mask / clear.
const INTR_RX: u32 = 1 << 4;

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

/// write a single byte. Honours the global
/// `hal::common::serial_disable` gate.
pub fn write_char(c: u8) {
    if crate::hal::common::serial_disable::is_disabled() {
        return;
    }
    unsafe {
        while (read_volatile(reg(UARTFR)) & FR_TXFF) != 0 {
            core::hint::spin_loop();
        }
        write_volatile(reg(UARTDR), c as u32);
    }
}

/// write a string. Honours the gate; the panic-path macros use
/// `with_serial_unmasked` to escape suppression.
pub fn write_string(s: &str) {
    #[cfg(not(feature = "log_level_debug"))]
    {
        let _ = s;
    }
    #[cfg(feature = "log_level_debug")]
    {
        if !crate::hal::common::serial_disable::is_disabled() {
            for c in s.bytes() {
                write_char(c);
            }
        }
    }
}

/// Writes diagnostic strings even in non-debug builds.
pub fn write_string_always(s: &str) {
    #[cfg(test)]
    {
        let _ = s;
    }
    #[cfg(not(test))]
    {
        for c in s.bytes() {
            write_char(c);
        }
    }
}

/// write a 32-bit value as 8 hex digits (uppercase, no prefix).
/// Mirrors `hal::x86_64::serial::write_u32_hex` so the same
/// boot-time tracing code compiles on every architecture.
pub fn write_u32_hex(val: u32) {
    if !log_level_debug() {
        return;
    }

    for i in (0..8).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as u8;
        let c = if nibble < 10 {
            b'0' + nibble
        } else {
            b'A' + nibble - 10
        };
        write_char(c);
    }
}

/// write a 64-bit value as 16 hex digits (uppercase, no prefix).
pub fn write_hex_u64(v: u64) {
    if !log_level_debug() {
        return;
    }

    for i in (0..16).rev() {
        let nibble = ((v >> (i * 4)) & 0xF) as u8;
        let c = if nibble < 10 {
            b'0' + nibble
        } else {
            b'A' + nibble - 10
        };
        write_char(c);
    }
}

fn log_level_debug() -> bool {
    cfg!(feature = "log_level_debug")
}

/// write a single byte (alias used by HAL callers).
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

/// True when the receive FIFO holds at least one byte. Used by
/// the unified keyboard ring to decide whether a drain pass is
/// worth doing.
#[inline]
pub fn data_available() -> bool {
    unsafe { (read_volatile(reg(UARTFR)) & FR_RXFE) == 0 }
}

/// Arm the PL011 receive interrupt (RXIM in the interrupt mask
/// set/clear register). The corresponding GIC handler must call
/// `crate::hal::common::keyboard_unified::serial_rx_irq` to
/// drain the FIFO into the keyboard ring; the HAL never enables
/// the IRQ on its own because enabling hardware IRQs without a
/// registered handler would storm.
pub fn enable_rx_irq() {
    unsafe {
        let imsc = read_volatile(reg(UARTIMSC));
        write_volatile(reg(UARTIMSC), imsc | INTR_RX);
    }
}

/// Mask the PL011 receive interrupt again.
pub fn disable_rx_irq() {
    unsafe {
        let imsc = read_volatile(reg(UARTIMSC));
        write_volatile(reg(UARTIMSC), imsc & !INTR_RX);
    }
}

/// Clear a latched receive interrupt (write 1 to the RX bit of
/// the interrupt clear register). Needed by level-triggered
/// dispatchers that must acknowledge the peripheral before the
/// GIC EOI.
pub fn clear_rx_irq() {
    unsafe {
        write_volatile(reg(UARTICR), INTR_RX);
    }
}
