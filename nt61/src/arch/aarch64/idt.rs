//! aarch64 exception vector install.
//!
//! The actual 2 KiB vector table lives in `exception.rs`. This module
//! is kept as a thin shim so that callers (e.g. `arch::init_hardware`)
//! can refer to `arch::aarch64::idt::init()` regardless of where the
//! real implementation lives.

/// Install the exception vector table at EL1.
///
/// Loads the address of the `exception_vector` label into
/// `VBAR_EL1`. Must be called once per CPU at boot, before any
/// exception class is unmasked.
pub fn init() {
    super::exception::init();
}
