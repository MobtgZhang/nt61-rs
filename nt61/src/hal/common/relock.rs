//! Reentrant spin lock for low-level kernel sinks.
//!
//! Logging sinks (UART, text-console rings) can be re-entered from a
//! fault handler on the same CPU while the faulting context already
//! holds the lock; a plain spin lock would then spin against itself
//! and hang the machine. This lock tracks the owning CPU and a depth
//! counter so nested acquisitions on the owning CPU pass through.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct ReentrantLock {
    lock: AtomicBool,
    owner: AtomicUsize,
    depth: AtomicUsize,
}

pub struct ReentrantGuard<'a> {
    lock: &'a ReentrantLock,
}

impl ReentrantLock {
    pub const fn new() -> Self {
        Self {
            lock: AtomicBool::new(false),
            owner: AtomicUsize::new(usize::MAX),
            depth: AtomicUsize::new(0),
        }
    }

    pub fn lock(&self) -> ReentrantGuard<'_> {
        let cpu = crate::arch::common::percpu::get_current_cpu_id() as usize;
        if self.depth.load(Ordering::Relaxed) > 0 && self.owner.load(Ordering::Relaxed) == cpu {
            self.depth.fetch_add(1, Ordering::Relaxed);
            return ReentrantGuard { lock: self };
        }
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        self.owner.store(cpu, Ordering::Relaxed);
        self.depth.store(1, Ordering::Relaxed);
        ReentrantGuard { lock: self }
    }
}

impl Drop for ReentrantGuard<'_> {
    fn drop(&mut self) {
        if self.lock.depth.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.lock.owner.store(usize::MAX, Ordering::Relaxed);
            self.lock.lock.store(false, Ordering::Release);
        }
    }
}
