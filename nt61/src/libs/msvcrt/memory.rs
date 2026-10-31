//! Memory Management Functions
//!
//! Implements malloc, free, calloc, realloc, and aligned memory operations.
//! This is a proper implementation with metadata tracking for each allocation.

use super::types::*;
use core::alloc::Layout;
use core::ptr;

extern crate alloc;
use alloc::alloc::{alloc, alloc_zeroed, dealloc, realloc as alloc_realloc};

fn set_errno(value: ErrnoT) {
    unsafe { super::tls_errno_safe::_set_errno(value) };
}

#[repr(C)]
struct AllocHeader {
    size: usize,
    alignment: usize,
    magic: u32, // For validation
}

const ALLOC_MAGIC: u32 = 0xDEADBEEF;
const HEADER_SIZE: usize = core::mem::size_of::<AllocHeader>();

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Get header from user pointer
unsafe fn get_header(ptr: *mut c_void) -> *mut AllocHeader {
    (ptr as usize - HEADER_SIZE) as *mut AllocHeader
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Get user pointer from header
unsafe fn get_user_ptr(header: *mut AllocHeader) -> *mut c_void {
    (header as usize + HEADER_SIZE) as *mut c_void
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn malloc(size: SizeT) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }

    let total_size = size + HEADER_SIZE;
    let layout = match Layout::from_size_align(total_size, DEFAULT_ALIGNMENT) {
        Ok(l) => l,
        Err(_) => {
            set_errno(ENOMEM);
            return ptr::null_mut();
        }
    };

    let ptr = alloc(layout);
    if ptr.is_null() {
        set_errno(ENOMEM);
        return ptr::null_mut();
    }

    let header = ptr as *mut AllocHeader;
    (*header).size = size;
    (*header).alignment = DEFAULT_ALIGNMENT;
    (*header).magic = ALLOC_MAGIC;

    get_user_ptr(header)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    let header = get_header(ptr);

    if (*header).magic != ALLOC_MAGIC {
        set_errno(EINVAL);
        return;
    }

    let size = (*header).size + HEADER_SIZE;
    let align = (*header).alignment;

    (*header).magic = 0;

    if let Ok(layout) = Layout::from_size_align(size, align) {
        dealloc(header as *mut u8, layout);
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn calloc(count: SizeT, size: SizeT) -> *mut c_void {
    let total_size = match count.checked_mul(size) {
        Some(s) => s,
        None => {
            set_errno(ENOMEM);
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
            set_errno(ENOMEM);
            return ptr::null_mut();
        }
    };

    let ptr = alloc_zeroed(layout);
    if ptr.is_null() {
        set_errno(ENOMEM);
        return ptr::null_mut();
    }

    let header = ptr as *mut AllocHeader;
    (*header).size = total_size;
    (*header).alignment = DEFAULT_ALIGNMENT;
    (*header).magic = ALLOC_MAGIC;

    get_user_ptr(header)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, new_size: SizeT) -> *mut c_void {
    if ptr.is_null() {
        return malloc(new_size);
    }

    if new_size == 0 {
        free(ptr);
        return ptr::null_mut();
    }

    let header = get_header(ptr);

    if (*header).magic != ALLOC_MAGIC {
        set_errno(EINVAL);
        return ptr::null_mut();
    }

    let old_size = (*header).size;
    let align = (*header).alignment;
    let old_total = old_size + HEADER_SIZE;
    let new_total = new_size + HEADER_SIZE;

    let old_layout = match Layout::from_size_align(old_total, align) {
        Ok(l) => l,
        Err(_) => {
            set_errno(EINVAL);
            return ptr::null_mut();
        }
    };

    let new_ptr = alloc_realloc(header as *mut u8, old_layout, new_total);
    if new_ptr.is_null() {
        set_errno(ENOMEM);
        return ptr::null_mut();
    }

    let new_header = new_ptr as *mut AllocHeader;
    (*new_header).size = new_size;
    (*new_header).alignment = align;
    (*new_header).magic = ALLOC_MAGIC;

    get_user_ptr(new_header)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _aligned_malloc(size: SizeT, alignment: SizeT) -> *mut c_void {
    if size == 0 || alignment == 0 || !alignment.is_power_of_two() {
        set_errno(EINVAL);
        return ptr::null_mut();
    }

    if alignment > MAX_ALIGNMENT {
        set_errno(EINVAL);
        return ptr::null_mut();
    }

    let total_size = size + HEADER_SIZE;
    let layout = match Layout::from_size_align(total_size, alignment) {
        Ok(l) => l,
        Err(_) => {
            set_errno(ENOMEM);
            return ptr::null_mut();
        }
    };

    let ptr = alloc(layout);
    if ptr.is_null() {
        set_errno(ENOMEM);
        return ptr::null_mut();
    }

    let header = ptr as *mut AllocHeader;
    (*header).size = size;
    (*header).alignment = alignment;
    (*header).magic = ALLOC_MAGIC;

    get_user_ptr(header)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _aligned_free(ptr: *mut c_void) {
    free(ptr);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _aligned_realloc(
    ptr: *mut c_void,
    new_size: SizeT,
    alignment: SizeT,
) -> *mut c_void {
    if alignment == 0 || !alignment.is_power_of_two() {
        set_errno(EINVAL);
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
        set_errno(EINVAL);
        return ptr::null_mut();
    }

    let old_size = (*header).size;
    let old_align = (*header).alignment;

    if old_align != alignment {
        let new_ptr = _aligned_malloc(new_size, alignment);
        if !new_ptr.is_null() {
            let copy_size = if old_size < new_size {
                old_size
            } else {
                new_size
            };
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
            set_errno(EINVAL);
            return ptr::null_mut();
        }
    };

    let new_ptr = alloc_realloc(header as *mut u8, old_layout, new_total);
    if new_ptr.is_null() {
        set_errno(ENOMEM);
        return ptr::null_mut();
    }

    let new_header = new_ptr as *mut AllocHeader;
    (*new_header).size = new_size;
    (*new_header).alignment = alignment;
    (*new_header).magic = ALLOC_MAGIC;

    get_user_ptr(new_header)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _malloc_dbg(
    size: SizeT,
    _block_type: CInt,
    _filename: *const CChar,
    _line: CInt,
) -> *mut c_void {
    malloc(size)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _free_dbg(ptr: *mut c_void, _block_type: CInt) {
    free(ptr);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _calloc_dbg(
    count: SizeT,
    size: SizeT,
    _block_type: CInt,
    _filename: *const CChar,
    _line: CInt,
) -> *mut c_void {
    calloc(count, size)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _realloc_dbg(
    ptr: *mut c_void,
    new_size: SizeT,
    _block_type: CInt,
    _filename: *const CChar,
    _line: CInt,
) -> *mut c_void {
    realloc(ptr, new_size)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _expand(_ptr: *mut c_void, _new_size: SizeT) -> *mut c_void {
    ptr::null_mut()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _msize(ptr: *mut c_void) -> SizeT {
    if ptr.is_null() {
        return 0;
    }

    let header = get_header(ptr);

    if (*header).magic != ALLOC_MAGIC {
        return 0;
    }

    (*header).size
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _heapchk() -> CInt {
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _heapmin() -> CInt {
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _set_new_handler(_handler: *const c_void) -> *const c_void {
    ptr::null()
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _query_new_handler() -> *const c_void {
    ptr::null()
}
