//! Microsoft System Management BIOS driver.

use core::sync::atomic::{AtomicBool, Ordering};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    INITIALIZED.store(true, Ordering::Release);
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}
