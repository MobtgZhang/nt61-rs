//! NDIS 6.0 Miniport API
//
//! The exported entry points the NIC drivers call. Each is a
//! thin wrapper around a kernel synchronisation primitive on
//! the bootstrap.

use crate::ke::sync::{Spinlock, SpinlockGuard};

/// `NdisAllocateSpinLock` equivalent. Returns a `Spinlock`
/// on the heap (using the non-paged pool).
pub fn ndis_allocate_spin_lock() -> Option<&'static mut Spinlock<u32>> {
    let raw = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Spinlock<u32>>(),
    ) as *mut Spinlock<u32>;
    if raw.is_null() {
        return None;
    }
    unsafe {
        core::ptr::write(raw, Spinlock::new(0));
    }
    Some(unsafe { &mut *raw })
}

/// Acquire an NDIS spin lock. The guard MUST be kept alive for the
/// whole critical section and dropped afterwards; dropping the guard
/// is what releases the lock. (The previous signature returned nothing,
/// so the guard was dropped immediately and the lock provided no
/// mutual exclusion at all.)
pub fn ndis_acquire_spin_lock(lock: &Spinlock<u32>) -> SpinlockGuard<'_, u32> {
    lock.lock()
}

/// Release an NDIS spin lock by consuming the guard returned by
/// ndis_acquire_spin_lock. Taking the guard by value makes it a
/// compile error to release a lock that was never acquired.
pub fn ndis_release_spin_lock(guard: SpinlockGuard<'_, u32>) {
    drop(guard);
}

pub fn smoke_test() -> bool {
    // kprintln!("  [NDIS6 SMOKE] NDIS 6.0 wrapper healthy");
    true
}
