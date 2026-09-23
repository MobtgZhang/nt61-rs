use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, AtomicI32, AtomicI64, AtomicPtr, Ordering};

use super::types::*;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

static STRTOK_NEXT: AtomicPtr<c_char> = AtomicPtr::new(ptr::null_mut());

#[no_mangle]
pub unsafe extern "C" fn strtok(str: *mut c_char, delim: *const c_char) -> *mut c_char {
    if str.is_null() {
        let saved = STRTOK_NEXT.load(Ordering::Relaxed);
        if saved.is_null() {
            return ptr::null_mut();
        }
        strtok_r(saved, delim, &mut STRTOK_NEXT as *mut AtomicPtr<c_char> as *mut *mut c_char)
    } else {
        strtok_r(str, delim, &mut STRTOK_NEXT as *mut AtomicPtr<c_char> as *mut *mut c_char)
    }
}

#[no_mangle]
pub unsafe extern "C" fn strtok_r(
    str: *mut c_char,
    delim: *const c_char,
    saveptr: *mut *mut c_char,
) -> *mut c_char {
    if delim.is_null() || saveptr.is_null() {
        return ptr::null_mut();
    }

    let mut token_start = if str.is_null() {
        *saveptr
    } else {
        str
    };

    if token_start.is_null() {
        return ptr::null_mut();
    }

    while *token_start != 0 && is_delimiter(*token_start, delim) {
        token_start = token_start.add(1);
    }

    if *token_start == 0 {
        *saveptr = ptr::null_mut();
        return ptr::null_mut();
    }

    let mut token_end = token_start;
    while *token_end != 0 && !is_delimiter(*token_end, delim) {
        token_end = token_end.add(1);
    }

    if *token_end == 0 {
        *saveptr = ptr::null_mut();
    } else {
        *token_end = 0;
        *saveptr = token_end.add(1);
    }

    token_start
}

unsafe fn is_delimiter(c: c_char, delim: *const c_char) -> bool {
    let mut d = delim;
    while *d != 0 {
        if *d == c {
            return true;
        }
        d = d.add(1);
    }
    false
}
