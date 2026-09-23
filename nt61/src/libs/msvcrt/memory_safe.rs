use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, AtomicI32, AtomicI64, AtomicPtr, Ordering};

use super::types::*;
use core::sync::atomic::{AtomicI32, Ordering};

// In a real implementation, this would use proper TLS
const MAX_THREAD_ERRNO: usize = 256;

struct ThreadErrnoTable {
    entries: [AtomicI32; MAX_THREAD_ERRNO],
}

impl ThreadErrnoTable {
    const fn new() -> Self {
        const INIT: AtomicI32 = AtomicI32::new(0);
        Self {
            entries: [INIT; MAX_THREAD_ERRNO],
        }
    }

    fn get_errno(&self, thread_id: usize) -> c_int {
        self.entries[thread_id % MAX_THREAD_ERRNO].load(Ordering::Relaxed)
    }

    fn set_errno(&self, thread_id: usize, value: c_int) {
        self.entries[thread_id % MAX_THREAD_ERRNO].store(value, Ordering::Relaxed);
    }
}

static THREAD_ERRNO: ThreadErrnoTable = ThreadErrnoTable::new();

fn get_current_thread_id() -> usize {
    // For now, use 0 as a placeholder
    0
}

#[no_mangle]
pub unsafe extern "C" fn _errno() -> *mut c_int {
    static ERRNO_STORAGE: AtomicI32 = AtomicI32::new(0);
    &ERRNO_STORAGE as *const AtomicI32 as *mut c_int
}

#[no_mangle]
pub unsafe extern "C" fn _get_errno(value: *mut c_int) -> errno_t {
    if value.is_null() {
        return super::EINVAL;
    }

    let thread_id = get_current_thread_id();
    *value = THREAD_ERRNO.get_errno(thread_id);
    0
}

#[no_mangle]
pub unsafe extern "C" fn _set_errno(value: c_int) -> errno_t {
    let thread_id = get_current_thread_id();
    THREAD_ERRNO.set_errno(thread_id, value);
    0
}
