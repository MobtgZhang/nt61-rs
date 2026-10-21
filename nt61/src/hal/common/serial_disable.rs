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
//! The gate is **per-CPU**: each tracked CPU carries its own
//! override slot, and the global flag only supplies the default
//! for CPUs that have not taken an explicit per-CPU setting (and
//! for the pre-per-CPU bootstrap window, where every CPU reads
//! as CPU 0). A panic path running on CPU 1 therefore re-enables
//! the UART for CPU 1 only — CPUs 0/2/3 keep their suppressed
//! state and never see the window open, which is what the old
//! single-global-flag design got wrong.
//!
//! The exceptions are:
//!
//! * `boot_header!` / `boot_milestone!` / `boot_err!` / `boot_ok!`
//!   — these are panic-path macros that explicitly opt back in by
//!   wrapping their write in `with_serial_unmasked`. Only the
//!   current CPU's slot is flipped, so concurrent serial writes
//!   from other CPUs stay suppressed for the duration.
//! * `arch::boot::early_write_byte` / `early_write_str` — these
//!   run BEFORE `mm::init()` and never consult the gate; they
//!   bypass it deliberately so the firmware can leave a trail on
//!   the UART even when the rest of the kernel has gone silent.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Maximum CPUs tracked by the per-CPU override table.
/// Must match `crate::arch::smp::MAX_CPUS` (currently 4 in this kernel).
const MAX_TRACKED_CPUS: usize = 4;

/// Per-CPU override slot value: follow the global default gate.
const OVERRIDE_FOLLOW_GLOBAL: u8 = 0;
/// Per-CPU override slot value: force the serial sink enabled.
const OVERRIDE_FORCE_ENABLED: u8 = 1;
/// Per-CPU override slot value: force the serial sink disabled.
const OVERRIDE_FORCE_DISABLED: u8 = 2;

/// Per-CPU override slots. Slot semantics:
/// 0 = follow the global default, 1 = force-enabled (panic path),
/// 2 = force-disabled (debugging).
static CPU_OVERRIDE: [AtomicU8; MAX_TRACKED_CPUS] = [
    AtomicU8::new(OVERRIDE_FOLLOW_GLOBAL),
    AtomicU8::new(OVERRIDE_FOLLOW_GLOBAL),
    AtomicU8::new(OVERRIDE_FOLLOW_GLOBAL),
    AtomicU8::new(OVERRIDE_FOLLOW_GLOBAL),
];

/// Master default gate for the serial sink. Default is `false`
/// (serial is enabled). `kernel_main` flips it to `true` once the
/// LFB is wired so the operator only sees the GUI; every CPU that
/// has not taken an explicit per-CPU override inherits this value.
///
/// In libtest (`#[cfg(test)]`) the default becomes `true`
/// because user-mode `out` instructions fault and would crash
/// the libtest binary. Tests that exercise the serial output
/// path must explicitly call `set_disabled(false)`.
static DISABLED: AtomicBool = AtomicBool::new(cfg!(test));

/// Logical CPU id of the caller, clamped to the tracked range.
/// Before the per-CPU area is installed every architecture's
/// implementation falls back to CPU 0, which is exactly the
/// bootstrap behaviour we want.
#[inline]
fn current_cpu_slot() -> Option<usize> {
    let cpu = crate::arch::common::percpu::get_current_cpu_id() as usize;
    (cpu < MAX_TRACKED_CPUS).then_some(cpu)
}

/// Disable (or re-enable) the serial sink for the current CPU.
///
/// The current CPU's slot always takes priority over the global
/// default, so a subsequent panic-path unmask on another CPU can
/// never reopen (or close) this CPU's gate as a side effect. The
/// global default is updated as well so that CPUs with no explicit
/// per-CPU setting (APs before their scheduler entry) keep the
/// machine-wide suppression intent of the caller.
pub fn set_disabled(b: bool) {
    let slot = if b {
        OVERRIDE_FORCE_DISABLED
    } else {
        OVERRIDE_FORCE_ENABLED
    };
    if let Some(cpu) = current_cpu_slot() {
        CPU_OVERRIDE[cpu].store(slot, Ordering::Release);
    }
    DISABLED.store(b, Ordering::Release);
}

/// Returns `true` when the serial sink is suppressed for the
/// current CPU. The per-CPU override takes priority; when no
/// override is set the global default decides.
pub fn is_disabled() -> bool {
    if let Some(cpu) = current_cpu_slot() {
        match CPU_OVERRIDE[cpu].load(Ordering::Acquire) {
            OVERRIDE_FORCE_ENABLED => return false,
            OVERRIDE_FORCE_DISABLED => return true,
            _ => {}
        }
    }
    DISABLED.load(Ordering::Acquire)
}

/// Convenience guard for call sites that want to express "if
/// serial is enabled, write these bytes". Returns `true` when
/// the bytes were actually written.
#[inline]
pub fn if_enabled<F: FnOnce() -> R, R>(f: F) -> Option<R> {
    if is_disabled() {
        None
    } else {
        Some(f())
    }
}

/// Panic-path re-enable. Wrap a multi-line diagnostic in this
/// scope so the bytes actually reach the UART even when the
/// serial sink has been disabled. Only the CURRENT CPU's slot is
/// flipped for the duration of the scope; every other CPU keeps
/// its gate untouched.
///
/// ```ignore
/// boot_println::with_serial_unmasked(|| {
///     hal::serial::write_string("[KERNEL PANIC]\r\n");
/// });
/// ```
#[inline]
pub fn with_serial_unmasked<F: FnOnce() -> R, R>(f: F) -> R {
    if let Some(cpu) = current_cpu_slot() {
        // Only unmask this CPU; other CPUs keep their gate.
        let prev = CPU_OVERRIDE[cpu].swap(OVERRIDE_FORCE_ENABLED, Ordering::AcqRel);
        let result = f();
        CPU_OVERRIDE[cpu].store(prev, Ordering::Release);
        result
    } else {
        // CPU id outside the tracked range: fall back to the
        // legacy global-gate swap (bootstrap before SMP init).
        let prev = DISABLED.swap(false, Ordering::AcqRel);
        let result = f();
        DISABLED.store(prev, Ordering::Release);
        result
    }
}

/// Mark the current CPU as the panic CPU so that the panic
/// handler's serial writes are always visible regardless of the
/// global gate. Call once at the top of the panic path.
pub fn enter_panic_cpu() {
    if let Some(cpu) = current_cpu_slot() {
        CPU_OVERRIDE[cpu].store(OVERRIDE_FORCE_ENABLED, Ordering::Release);
    }
}

/// Clear the panic-CPU override once the panic path has finished.
pub fn exit_panic_cpu() {
    if let Some(cpu) = current_cpu_slot() {
        CPU_OVERRIDE[cpu].store(OVERRIDE_FOLLOW_GLOBAL, Ordering::Release);
    }
}
