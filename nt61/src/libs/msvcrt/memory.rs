//! Memory Management Functions
//!
//! Implements malloc, free, calloc, realloc, and aligned memory operations.
//! This is a proper implementation with metadata tracking for each allocation.

use super::types::*;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

extern crate alloc;
use alloc::alloc::{alloc, alloc_zeroed, dealloc, realloc as alloc_realloc};

static ERRNO: AtomicI32 = 0;

#[repr(C)]
struct AllocHeader {
    size: usize,
    alignment: usize,
    magic: u32,  // For validation
}

const ALLOC_MAGIC: u32 = 0xDEADBEEF;
const HEADER_SIZE: usize = core::mem::size_of::<AllocHeader>();

/// Get header from user pointer
unsafe fn get_header(ptr: *mut c_void) -> *mut AllocHeader {
    (ptr as usize - HEADER_SIZE) as *mut AllocHeader
}

/// Get user pointer from header
unsafe fn get_user_ptr(header: *mut AllocHeader) -> *mut c_void {
    (header as usize + HEADER_SIZE) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn malloc(size: size_t) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }

    let total_size = size + HEADER_SIZE;
    let layout = match Layout::from_size_align(total_size, DEFAULT_ALIGNMENT) {
        Ok(l) => l,
        Err(_) => {
            ERRNO = ENOMEM;
            return ptr::null_mut();
        }
    };

    let ptr = alloc(layout);
    if ptr.is_null() {
        ERRNO = ENOMEM;
        return ptr::null_mut();
    }

    let header = ptr as *mut AllocHeader;
    (*header).size = size;
    (*header).alignment = DEFAULT_ALIGNMENT;
    (*header).magic = ALLOC_MAGIC;

    get_user_ptr(header)
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    let header = get_header(ptr);

    if (*header).magic != ALLOC_MAGIC {
        ERRNO = EINVAL;
        return;
    }

    let size = (*header).size + HEADER_SIZE;
    let align = (*header).alignment;

    (*header).magic = 0;

    if let Ok(layout) = Layout::from_size_align(size, align) {
        dealloc(header as *mut u8, layout);
    }
}

#[no_mangle]
pub unsafe extern "C" fn calloc(count: size_t, size: size_t) -> *mut c_void {
    let total_size = match count.checked_mul(size) {
        Some(s) => s,
        None => {
            ERRNO = ENOMEM;
            return ptr::null_mut();
        }
    };

    if total_size == 0 {
        return ptr::null_mut();
    }

    let alloc_size = total_size + HEADER_SIZE;
    let layout = match Layout::from_size_align(alloc_size, DEFAULT_ALIGNMENT) {
        Ok(l) => l,
        Err(_) => {
            ERRNO = ENOMEM;
            return ptr::null_mut();
        }
    };

    let ptr = alloc_zeroed(layout);
    if ptr.is_null() {
        ERRNO = ENOMEM;
        return ptr::null_mut();
    }

    let header = ptr as *mut AllocHeader;
    (*header).size = total_size;
    (*header).alignment = DEFAULT_ALIGNMENT;
    (*header).magic = ALLOC_MAGIC;

    get_user_ptr(header)
}

#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, new_size: size_t) -> *mut c_void {
    if ptr.is_null() {
        return malloc(new_size);
    }

    if new_size == 0 {
        free(ptr);
        return ptr::null_mut();
    }

    let header = get_header(ptr);

    if (*header).magic != ALLOC_MAGIC {
        ERRNO = EINVAL;
        return ptr::null_mut();
    }

    let old_size = (*header).size;
    let align = (*header).alignment;
    let old_total = old_size + HEADER_SIZE;
    let new_total = new_size + HEADER_SIZE;

    let old_layout = match Layout::from_size_align(old_total, align) {
        Ok(l) => l,
        Err(_) => {
            ERRNO = EINVAL;
            return ptr::null_mut();
        }
    };

    let new_ptr = alloc_realloc(header as *mut u8, old_layout, new_total);
    if new_ptr.is_null() {
        ERRNO = ENOMEM;
        return ptr::null_mut();
    }

    let new_header = new_ptr as *mut AllocHeader;
    (*new_header).size = new_size;
    (*new_header).alignment = align;
    (*new_header).magic = ALLOC_MAGIC;

    get_user_ptr(new_header)
}

#[no_mangle]
pub unsafe extern "C" fn _aligned_malloc(size: size_t, alignment: size_t) -> *mut c_void {
    if size == 0 || alignment == 0 || !alignment.is_power_of_two() {
        ERRNO = EINVAL;
        return ptr::null_mut();
    }

    if alignment > MAX_ALIGNMENT {
        ERRNO = EINVAL;
        return ptr::null_mut();
    }

    let total_size = size + HEADER_SIZE;
    let layout = match Layout::from_size_align(total_size, alignment) {
        Ok(l) => l,
        Err(_) => {
            ERRNO = ENOMEM;
            return ptr::null_mut();
        }
    };

    let ptr = alloc(layout);
    if ptr.is_null() {
        ERRNO = ENOMEM;
        return ptr::null_mut();
    }

    let header = ptr as *mut AllocHeader;
    (*header).size = size;
    (*header).alignment = alignment;
    (*header).magic = ALLOC_MAGIC;

    get_user_ptr(header)
}

#[no_mangle]
pub unsafe extern "C" fn _aligned_free(ptr: *mut c_void) {
    free(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn _aligned_realloc(
    ptr: *mut c_void,
    new_size: size_t,
    alignment: size_t,
) -> *mut c_void {
    if alignment == 0 || !alignment.is_power_of_two() {
        ERRNO = EINVAL;
        return ptr::null_mut();
    }

    if ptr.is_null() {
        return _aligned_malloc(new_size, alignment);
    }

    if new_size == 0 {
        _aligned_free(ptr);
        return ptr::null_mut();
    }

    let header = get_header(ptr);

    if (*header).magic != ALLOC_MAGIC {
        ERRNO = EINVAL;
        return ptr::null_mut();
    }

    let old_size = (*header).size;
    let old_align = (*header).alignment;

    if old_align != alignment {
        let new_ptr = _aligned_malloc(new_size, alignment);
        if !new_ptr.is_null() {
            let copy_size = if old_size < new_size { old_size } else { new_size };
            ptr::copy_nonoverlapping(ptr as *const u8, new_ptr as *mut u8, copy_size);
            _aligned_free(ptr);
        }
        return new_ptr;
    }

    // Same alignment, can use realloc
    let old_total = old_size + HEADER_SIZE;
    let new_total = new_size + HEADER_SIZE;

    let old_layout = match Layout::from_size_align(old_total, alignment) {
        Ok(l) => l,
        Err(_) => {
            ERRNO = EINVAL;
            return ptr::null_mut();
        }
    };

    let new_ptr = alloc_realloc(header as *mut u8, old_layout, new_total);
    if new_ptr.is_null() {
        ERRNO = ENOMEM;
        return ptr::null_mut();
    }

    let new_header = new_ptr as *mut AllocHeader;
    (*new_header).size = new_size;
    (*new_header).alignment = alignment;
    (*new_header).magic = ALLOC_MAGIC;

    get_user_ptr(new_header)
}

#[no_mangle]
pub unsafe extern "C" fn _malloc_dbg(
    size: size_t,
    _block_type: c_int,
    _filename: *const c_char,
    _line: c_int,
) -> *mut c_void {
    malloc(size)
}

#[no_mangle]
pub unsafe extern "C" fn _free_dbg(ptr: *mut c_void, _block_type: c_int) {
    free(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn _calloc_dbg(
    count: size_t,
    size: size_t,
    _block_type: c_int,
    _filename: *const c_char,
    _line: c_int,
) -> *mut c_void {
    calloc(count, size)
}

#[no_mangle]
pub unsafe extern "C" fn _realloc_dbg(
    ptr: *mut c_void,
    new_size: size_t,
    _block_type: c_int,
    _filename: *const c_char,
    _line: c_int,
) -> *mut c_void {
    realloc(ptr, new_size)
}

#[no_mangle]
pub unsafe extern "C" fn _expand(ptr: *mut c_void, new_size: size_t) -> *mut c_void {
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn _msize(ptr: *mut c_void) -> size_t {
    if ptr.is_null() {
        return 0;
    }

    let header = get_header(ptr);

    if (*header).magic != ALLOC_MAGIC {
        return 0;
    }

    (*header).size
}

#[no_mangle]
pub unsafe extern "C" fn _heapchk() -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn _heapmin() -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn _set_new_handler(_handler: *const c_void) -> *const c_void {
    ptr::null()
}

#[no_mangle]
pub unsafe extern "C" fn _query_new_handler() -> *const c_void {
    ptr::null()
}
