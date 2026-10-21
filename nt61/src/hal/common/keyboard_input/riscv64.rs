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
    crate::drivers::input::virtio_input::init();
}

pub fn try_read_byte() -> Option<u8> {
    crate::hal::common::keyboard_unified::try_read_byte()
}

pub fn peek() -> bool {
    crate::hal::common::keyboard_unified::peek()
}

pub fn poll() {
    crate::hal::common::keyboard_unified::poll();
}
