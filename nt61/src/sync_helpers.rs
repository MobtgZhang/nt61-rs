use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};


use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, AtomicBool, AtomicPtr, Ordering};

pub struct SyncArray<T, const N: usize> {
    data: Mutex<[T; N]>,
}

impl<T: Copy + Default, const N: usize> SyncArray<T, N> {
    pub const fn new() -> Self {
        Self {
            data: Mutex::new([T::default(); N]),
        }
    }

    pub fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut [T; N]) -> R,
    {
        let mut guard = self.data.lock();
        f(&mut *guard)
    }
}

pub struct SyncOption<T> {
    data: Mutex<Option<T>>,
}

impl<T> SyncOption<T> {
    pub const fn new() -> Self {
        Self {
            data: Mutex::new(None),
        }
    }

    pub fn set(&self, value: T) {
        *self.data.lock() = Some(value);
    }

    pub fn take(&self) -> Option<T> {
        self.data.lock().take()
    }

    pub fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Option<T>) -> R,
    {
        let mut guard = self.data.lock();
        f(&mut *guard)
    }
}
