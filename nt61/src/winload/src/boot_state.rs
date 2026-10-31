//! Single-threaded boot-state storage for winload.
//!
//! The OS loader runs on one CPU with boot services active, so its
//! global state never needs real synchronisation — but `static mut`
//! is unsound under shared references and every accessor had to carry
//! its own unsafe block. These small wrappers keep the same addresses
//! and initialisation semantics while making the accessors safe.

use core::cell::UnsafeCell;

/// Interior-mutable static storage. `#[repr(transparent)]` keeps the
/// inner value at offset zero, so the address of the cell is the
/// address of the value it holds.
#[repr(transparent)]
pub struct StaticCell<T> {
    value: UnsafeCell<T>,
}

// SAFETY: the UEFI boot flow is single-threaded; the cell is only
// accessed from the BSP before `ExitBootServices`.
unsafe impl<T> Sync for StaticCell<T> {}

impl<T> StaticCell<T> {
    pub const fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(value),
        }
    }

    /// Borrow the value mutably for the duration of the caller's
    /// use. Two overlapping borrows would violate the borrow rules,
    /// which the single-threaded boot flow never does.
    pub fn get(&self) -> &mut T {
        unsafe { &mut *self.value.get() };
    }

    /// Address of the inner value, for handing raw pointers to the
    /// kernel or firmware.
    pub fn ptr(&self) -> *mut T {
        self.value.get()
    }
}
