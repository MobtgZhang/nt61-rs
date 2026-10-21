//! 7A1000 UART driver for LoongArch64
//
//! Targets the QEMU 'virt' LoongArch machine, which maps a
//! 7A1000-compatible UART at physical address 0x1FE0_01E0. The
//! 7A1000 is 16550a-compatible.

use core::ptr::{read_volatile, write_volatile};

const UART_BASE: u64 = 0x1FE0_01E0;

/// Register offsets (DLAB=0 view) and bit masks used for the
/// receive path. The 7A1000 UART is 16550-compatible.
const REG_DATA: usize = 0;
const REG_IER: usize = 1;
const REG_LSR: usize = 5;
/// IER bit 0: Received Data Available interrupt.
const IER_RX: u8 = 0x01;
/// LSR bit 0: Data Ready — a byte waits in the receive FIFO.
const LSR_DR: u8 = 0x01;

#[inline]
fn reg(offset: usize) -> *mut u8 {
    (UART_BASE as usize + offset) as *mut u8
}

/// Initialize the UART.
pub fn init() {
    let _ = reg(0);
}

/// write a single byte.
pub fn write_char(c: u8) {
    unsafe {
        while (read_volatile(reg(5)) & 0x20) == 0 {
            core::hint::spin_loop();
        }
        write_volatile(reg(0), c);
    }
}

/// write a string.
pub fn write_string(s: &str) {
    #[cfg(not(feature = "log_level_debug"))]
    {
        let _ = s;
    }
    #[cfg(feature = "log_level_debug")]
    {
        for c in s.bytes() {
            write_char(c);
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

/// write a single byte (alias used by HAL callers). Provided for
/// parity with the other architectures' `serial::put_char`.
#[inline(always)]
pub fn put_char(c: u8) {
    write_char(c);
}

/// Try to read one byte from the UART. Returns `None` if the
/// receive FIFO is empty. Mirrors `hal::aarch64::serial` /
/// `hal::riscv64::serial` so the unified keyboard ring works on
/// every architecture.
pub fn try_get_char() -> Option<u8> {
    if !data_available() {
        return None;
    }
    Some(read_data_reg())
}

/// True when the receive FIFO holds at least one byte.
#[inline]
pub fn data_available() -> bool {
    unsafe { (read_volatile(reg(REG_LSR)) & LSR_DR) != 0 }
}

/// Arm the 16550 received-data interrupt (IER bit 0). The
/// corresponding LoongArch EXTIOI / CPU-INT handler must call
/// `crate::hal::common::keyboard_unified::serial_rx_irq` to
/// drain the FIFO into the keyboard ring; the HAL never enables
/// the IRQ on its own because enabling hardware IRQs without a
/// registered handler would storm.
pub fn enable_rx_irq() {
    unsafe {
        let ier = read_volatile(reg(REG_IER));
        write_volatile(reg(REG_IER), ier | IER_RX);
    }
}

/// Mask the 16550 received-data interrupt again.
pub fn disable_rx_irq() {
    unsafe {
        let ier = read_volatile(reg(REG_IER));
        write_volatile(reg(REG_IER), ier & !IER_RX);
    }
}

/// Read one byte unconditionally from the data register. Only
/// valid after `data_available` returned true; used by the
/// unified keyboard ring's FIFO drain loop.
#[inline]
pub fn read_data_reg() -> u8 {
    unsafe { read_volatile(reg(REG_DATA)) }
}
