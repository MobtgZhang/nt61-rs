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
}

pub fn try_read_byte() -> Option<u8> {
    crate::hal::aarch64::serial::try_get_char()
}

pub fn peek() -> bool {
    // The PL011 has a status register but `try_get_char`
    // already does the right thing. Callers that want a
    // non-blocking probe can use `try_read_byte().is_some()`;
    // `peek` here is a no-op that always returns false so the
    // shell loop can spin without stalling.
    false
}