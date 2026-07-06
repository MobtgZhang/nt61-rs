//! Spinlock Implementation
//
//! Low-level synchronization primitives
//
//! NOTE: This module is NOT used by the kernel. The kernel uses
//! `ke::sync::Spinlock` instead. This module is kept for reference
//! and compatibility.

use core::sync::atomic::{AtomicU8, Ordering};

/// Spinlock structure
pub struct Spinlock {
    locked: AtomicU8,
}

impl Spinlock {
    pub const fn new() -> Self {
        Self { locked: AtomicU8::new(0) }
    }

    /// Acquire spinlock
    pub fn lock(&mut self) {
        // Use the atomic directly via references
        while self.locked.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            // Spin with a hint to the CPU that we're waiting.
            // The unified `arch::cpu_relax()` maps to `pause` on
            // x86_64, `yield` on aarch64, and `nop` elsewhere.
            crate::arch::cpu_relax();
        }
    }

    /// Try to acquire spinlock without blocking
    pub fn try_acquire(&mut self) -> Result<(), ()> {
        if self.locked.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Release spinlock
    pub fn unlock(&mut self) {
        self.locked.store(0, Ordering::Release);
    }
}

impl Default for Spinlock {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for spinlock
pub struct SpinlockGuard<'a> {
    lock: &'a mut Spinlock,
}

impl<'a> SpinlockGuard<'a> {
    pub fn new(lock: &'a mut Spinlock) -> Self {
        lock.lock();
        Self { lock }
    }
}

impl<'a> Drop for SpinlockGuard<'a> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}
