//! riscv64 backend for the abstract keyboard / polled-input.
//!
//! The QEMU 'virt' machine (SiFive test) does not have a PS/2
//! controller either. The canonical input path is the NS16550A
//! UART at 0x1000_0000, which QEMU wires to the host's
//! stdin/stdout. `hal::riscv64::serial` exposes `try_get_char`
//! for non-blocking reads.

use core::sync::atomic::Ordering;

pub fn init() {
    super::READY.store(true, Ordering::Release);
}

pub fn try_read_byte() -> Option<u8> {
    crate::hal::riscv64::serial::try_get_char()
}

pub fn peek() -> bool {
    false
}