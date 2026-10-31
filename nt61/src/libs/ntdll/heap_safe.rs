use core::sync::atomic::{AtomicPtr, Ordering};

use core::ptr;

pub struct Heap {
    _private: [u8; 0],
}

static PROCESS_HEAP: AtomicPtr<Heap> = AtomicPtr::new(ptr::null_mut());

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn init_process_heap(heap: *mut Heap) {
    PROCESS_HEAP.store(heap, Ordering::Release);
}

pub fn get_process_heap() -> *mut Heap {
    PROCESS_HEAP.load(Ordering::Acquire)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn rtl_get_process_heap() -> *mut Heap {
    get_process_heap()
}

pub fn is_process_heap_initialized() -> bool {
    !get_process_heap().is_null()
}
