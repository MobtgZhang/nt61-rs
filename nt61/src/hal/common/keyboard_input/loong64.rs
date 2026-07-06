//! loongarch64 backend for the abstract keyboard / polled-input.
//!
//! The QEMU 'virt' machine on LoongArch (ls7a) does not have a
//! PS/2 controller either. The canonical input path is the
//! 8250/16550 UART, which QEMU wires to the host's stdin/stdout.
//! `arch::loongarch64::serial` exposes `read_char` for
//! non-blocking reads.

use core::sync::atomic::Ordering;

pub fn init() {
    super::READY.store(true, Ordering::Release);
}

pub fn try_read_byte() -> Option<u8> {
    crate::arch::loongarch64::serial::read_char()
}

pub fn peek() -> bool {
    crate::arch::loongarch64::serial::data_available()
}