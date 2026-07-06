//! LoongArch64 Hardware Abstraction Layer
//
//! LoongArch HAL. The QEMU 'virt' machine for LoongArch maps a
//! 7a1000 UART at 0x1FE0_0000; this driver targets that UART.

pub mod serial;

/// Initialize the HAL - just the serial port for now.
pub fn init() {
    serial::init();
}
