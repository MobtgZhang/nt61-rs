//! RISC-V 64 Hardware Abstraction Layer
//
//! RISC-V64 HAL. Contains the 16550a-style UART driver for QEMU
//! 'virt' (the SiFive test machine maps a 16550a-compatible UART at
//! 0x1000_0000) and stubs for the CLINT/PLIC interrupt controllers.
//
//! Also includes framebuffer support for GPU display output.

pub mod serial;

/// Framebuffer HAL for display output
pub mod framebuffer;

/// Initialize the HAL - serial port and framebuffer.
pub fn init() {
    serial::init();
    // Initialize framebuffer if available
    let _ = framebuffer::init(framebuffer::probe_from_device_tree());
}
