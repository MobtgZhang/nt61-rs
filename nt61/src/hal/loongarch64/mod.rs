//! LoongArch64 Hardware Abstraction Layer
//
//! LoongArch HAL. The QEMU 'virt' machine for LoongArch maps a
//! 7a1000 UART at 0x1FE0_01E0; this driver targets that UART.

pub mod framebuffer;
pub mod keyboard;
pub mod serial;

/// Initialize the HAL — serial port + framebuffer.
pub fn init() {
    serial::init();
    if let Some(info) = crate::arch::loongarch64::framebuffer::init() {
        framebuffer::init(crate::hal::common::framebuffer_impl::FramebufferInfo {
            address: info.address,
            width: info.width,
            height: info.height,
            pitch: info.pitch,
            bpp: info.bpp,
        });
    }
}
