use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};


use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

pub struct Heap {
    _private: [u8; 0],
}

static PROCESS_HEAP: AtomicPtr<Heap> = AtomicPtr::new(ptr::null_mut());

pub unsafe fn init_process_heap(heap: *mut Heap) {
    PROCESS_HEAP.store(heap, Ordering::Release);
}

pub fn get_process_heap() -> *mut Heap {
    PROCESS_HEAP.load(Ordering::Acquire)
}

#[no_mangle]
pub unsafe extern "C" fn RtlGetProcessHeap() -> *mut Heap {
    get_process_heap()
}

pub fn is_process_heap_initialized() -> bool {
    !get_process_heap().is_null()
}
