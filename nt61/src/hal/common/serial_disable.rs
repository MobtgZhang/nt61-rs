//! Runtime gate for the serial sink.
//!
//! On every architecture `hal::serial::write_*` is the canonical
//! debug sink during boot. The cross-arch plan requires us to
//! turn it OFF once the LFB is alive so the operator sees only
//! the GUI panel (`make run-<arch>-gtk` runs QEMU with `-serial
//! null`, but we still need to suppress accidental writes from
//! the kernel so that a panic path doesn't leak serial output
//! to a host terminal that the user has redirected to a file).
//!
//! The gate is a single `AtomicBool`; the per-arch `write_char` /
//! `write_string` helpers check it on every call and short-circuit
//! when it is `true`. The exceptions are:
//!
//! * `boot_header!` / `boot_milestone!` / `boot_err!` / `boot_ok!`
//!   — these are panic-path macros that explicitly opt back in by
//!   flipping the gate to `false` for the duration of their write.
//!   The early `boot_println!` uses the same path because it
//!   runs before any user-mode interaction.
//! * `arch::boot::early_write_byte` / `early_write_str` — these
//!   run BEFORE `mm::init()` and never consult the gate; they
//!   bypass it deliberately so the firmware can leave a trail on
//!   the UART even when the rest of the kernel has gone silent.

use core::sync::atomic::{AtomicBool, Ordering};

/// Master gate for the serial sink. Default is `false` (serial
/// is enabled). `kernel_main` flips it to `true` once the LFB
/// is wired so the operator only sees the GUI.
static DISABLED: AtomicBool = AtomicBool::new(false);

/// Suppress every subsequent `hal::serial::write_*` call until
/// `set_disabled(false)` is invoked. Idempotent.
pub fn set_disabled(b: bool) {
    DISABLED.store(b, Ordering::Release);
}

/// Returns `true` when the serial sink is currently suppressed.
pub fn is_disabled() -> bool {
    DISABLED.load(Ordering::Acquire)
}

/// Convenience guard for call sites that want to express "if
/// serial is enabled, write these bytes". Returns `true` when
/// the bytes were actually written.
#[inline]
pub fn if_enabled<F: FnOnce() -> R, R>(f: F) -> Option<R> {
    if is_disabled() { None } else { Some(f()) }
}

/// Panic-path re-enable. Wrap a multi-line diagnostic in this
/// scope so the bytes actually reach the UART even when the
/// serial sink has been globally disabled.
///
/// ```ignore
/// boot_println::with_serial_unmasked(|| {
///     hal::serial::write_string("[KERNEL PANIC]\r\n");
/// });
/// ```
#[inline]
pub fn with_serial_unmasked<F: FnOnce() -> R, R>(f: F) -> R {
    let prev = DISABLED.swap(false, Ordering::AcqRel);
    let result = f();
    DISABLED.store(prev, Ordering::Release);
    result
}
