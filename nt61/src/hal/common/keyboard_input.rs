//! Abstract keyboard / polled-input interface.
//!
//! Cross-architecture polled-input sink used by the SafeBootMode
//! CMD shell and the kernel-side debug shell. The implementation
//! delegates to the per-architecture backend:
//!
//! - **x86_64** → PS/2 (8042) keyboard controller polled through
//!   `crate::hal::x86_64::keyboard`, plus the unified USB-HID
//!   buffer.
//! - **aarch64 / riscv64 / loongarch64** → polled UART (PL011 /
//!   NS16550A / 8250) via `crate::hal::serial::read_char`. The
//!   QEMU virt machine forwards host keyboard input to the UART
//!   so the operator can still type into the CMD shell even
//!   though there is no PS/2 controller.
//!
//! The interface deliberately returns the *byte* the user
//! typed rather than a fully decoded scan code: on x86_64 the
//! PS/2 driver already returns the ASCII byte after the
//! scancode-to-ASCII translation; on the serial path the byte
//! is exactly what the operator typed.
//!
//! # Polled-input discipline
//!
//! The SafeBootMode CMD shell runs with interrupts masked
//! (see `kernel_main::run_safe_mode_cmd_shell`). This module is
//! therefore *polled* — every call to `read_byte()` blocks
//! until a byte is available. There is no IRQ path, so the
//! shell loop is simple:
//!
//! ```ignore
//! loop {
//!     let b = kbd::read_byte();
//!     // process b ...
//! }
//! ```

use core::sync::atomic::{AtomicBool, Ordering};

use crate::ke::sync::{DispatcherHeader, Event, EventType, Spinlock};

/// True once the keyboard / polled-input backend has been
/// brought up by `init()`. `read_byte` blocks / returns
/// `None` before this flips to true.
pub static READY: AtomicBool = AtomicBool::new(false);

/// Initialise the architecture-specific input backend.
///
/// On x86_64 this resets the 8042 controller into polled mode
/// (`keyboard::full_reset_for_poll`) and arms the PS/2 +
/// USB-HID ring buffer. On the other architectures it just
/// flips the `READY` flag — the UART was already brought up
/// during Phase 0 by `hal::serial::init`.
pub fn init() {
    if READY.swap(true, Ordering::SeqCst) {
        return;
    }
    backend::init();
}

/// Try to read one byte without blocking. Returns `Some(b)` if
/// a byte is available, `None` otherwise.
pub fn try_read_byte() -> Option<u8> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    backend::try_read_byte()
}

/// Block until a byte is available, then return it.
///
/// On x86_64 this spins on `try_read_byte` until the PS/2
/// controller reports a scancode byte. On the serial-path
/// architectures it spins on the UART FIFO. The spin is
/// interruptible by the architecture's normal wfi / hlt
/// instruction if the system is otherwise idle.
pub fn read_byte() -> u8 {
    loop {
        if let Some(b) = try_read_byte() {
            return b;
        }
        // Hint the CPU that we're spinning on a peripheral.
        crate::arch::halt();
    }
}

/// Drain platform-specific keyboard sources into the unified buffer.
pub fn poll() {
    backend::poll();
}

/// read one byte if the underlying backend exposes a
/// non-blocking `data_available` style primitive. Some callers
/// want a coarse "is anything pending?" check without spinning
/// forever — this is a one-shot poll, not a loop.
pub fn peek() -> bool {
    if !READY.load(Ordering::Acquire) {
        return false;
    }
    backend::peek()
}

/// Console-input notification event (the wait block on the console
/// input queue, NT 6.1 style): the input producers - the PS/2
/// keyboard IRQ, the UART RX IRQ and the USB-HID stack - signal the
/// event when bytes are enqueued, and console readers wait on it
/// instead of polling the hardware rings.
static INPUT_EVENT: Spinlock<Option<Event>> = Spinlock::new(None);

/// Thread-safe access to the input event header. The event is
/// created on first use so no init-order dependency exists.
fn input_event_header() -> &'static mut DispatcherHeader {
    let mut guard = INPUT_EVENT.lock();
    if guard.is_none() {
        *guard = Some(Event::new(EventType::Notification));
    }
    // SAFETY: the Event is stored behind a static Spinlock, so the
    // DispatcherHeader outlives the guard. The caller uses the
    // reference immediately to signal / clear / wait and never
    // stores it.
    let event = guard.as_mut().unwrap();
    let header_ptr = &mut event.header as *mut DispatcherHeader;
    drop(guard);
    unsafe { &mut *header_ptr }
}

/// Signal console-input availability: wake every thread waiting for
/// a keystroke. Called by the input producers whenever a byte is
/// enqueued into a keyboard ring.
pub fn signal_input_available() {
    let header = input_event_header();
    header.signal_state = 1;
    crate::ke::sync::wake(header, true);
}

/// Clear the input event signal state. A reader resets the event
/// after draining the rings so a producer that raced the drain
/// re-signals it and no wakeup is lost.
pub fn clear_input_event() {
    input_event_header().signal_state = 0;
}

/// Wait until console input is signaled or the timeout (in ms)
/// expires. Returns true when the event was signaled. The bounded
/// timeout also services polled-only producers: the serial fallback
/// path has no RX interrupt on every architecture, so a console
/// reader re-polls it at the timeout cadence instead of spinning.
pub fn wait_input_event(timeout_ms: u32) -> bool {
    let header = input_event_header();
    matches!(
        crate::ke::sync::wait_single(header, timeout_ms),
        crate::ke::sync::WaitResult::Success
    )
}

// =====================================================================
// Per-architecture backend dispatch
// =====================================================================

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
use self::x86_64 as b;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
use self::aarch64 as b;

#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "riscv64")]
use self::riscv64 as b;

#[cfg(target_arch = "loongarch64")]
mod loong64;
#[cfg(target_arch = "loongarch64")]
use self::loong64 as b;

mod backend {
    pub use super::b::*;
}
