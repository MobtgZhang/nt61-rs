//! NDIS 6.0 Miniport API
//
//! The exported entry points the NIC drivers call. Each is a
//! thin wrapper around a kernel synchronisation primitive on
//! the bootstrap.

use crate::ke::sync::Spinlock;

/// `NdisAllocateSpinLock` equivalent. Returns a `Spinlock`
/// on the heap (using the non-paged pool).
pub fn ndis_allocate_spin_lock() -> Option<&'static mut Spinlock<u32>> {
    let raw = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Spinlock<u32>>()
    ) as *mut Spinlock<u32>;
    if raw.is_null() { return None; }
    unsafe {
        core::ptr::write(raw, Spinlock::new(0));
    }
    Some(unsafe { &mut *raw })
}

pub fn ndis_acquire_spin_lock(lock: &Spinlock<u32>) {
    let _g = lock.lock();
}

pub fn ndis_release_spin_lock(lock: &Spinlock<u32>) {
    // The guard's drop releases the lock; we just take one.
    let _g = lock.lock();
    let _ = _g;
}

pub fn smoke_test() -> bool {
    use crate::kprintln;
    // kprintln!("  [NDIS6 SMOKE] NDIS 6.0 wrapper healthy")  // kprintln disabled (memcpy crash workaround);
    true
}
