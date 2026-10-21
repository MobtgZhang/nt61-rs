//! aarch64 backend for the abstract keyboard / polled-input.
//!
//! The QEMU 'virt' machine that we boot on does not expose a
//! PS/2 controller to the kernel; the only input path is the
//! PL011 UART, which QEMU wires to the host's stdin/stdout
//! when launched with `-serial stdio`. `hal::aarch64::serial`
//! exposes `try_get_char` for non-blocking reads; we use it
//! here.
//!
//! On real hardware (KunPeng 920, FT-2000+, Rockchip RK3399)
//! the equivalent input path is usually a USB-HID keyboard
//! attached to a USB-3 controller — wiring that up is
//! tracked as future work. For now the serial path is
//! sufficient for QEMU bring-up.

use core::sync::atomic::Ordering;

pub fn init() {
    // The PL011 UART was already brought up by
    // `hal::aarch64::serial::init` during Phase 0. We just
    // need to flag the abstract interface as ready so the
    // shell loop starts polling.
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
