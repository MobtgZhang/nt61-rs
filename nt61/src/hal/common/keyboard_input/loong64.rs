//! loongarch64 backend for the abstract keyboard / polled-input.
//!
//! The QEMU 'virt' machine on LoongArch (ls7a) does not have a
//! PS/2 controller either. The canonical input path is the
//! 8250/16550 UART, which QEMU wires to the host's stdin/stdout.
//! Reads go through the unified keyboard ring
//! (`hal::common::keyboard_unified`), which drains the
//! `hal::loongarch64::serial` FIFO and the virtio-input device.

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
