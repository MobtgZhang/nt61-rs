use core::sync::atomic::{AtomicPtr, Ordering};

use super::types::*;
use core::ptr;

static STRTOK_NEXT: AtomicPtr<CChar> = AtomicPtr::new(ptr::null_mut());

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strtok(str: *mut CChar, delim: *const CChar) -> *mut CChar {
    if str.is_null() {
        let saved = STRTOK_NEXT.load(Ordering::Relaxed);
        if saved.is_null() {
            return ptr::null_mut();
        }
        let mut saved_ptr = saved;
        let result = strtok_r(saved, delim, &mut saved_ptr);
        STRTOK_NEXT.store(saved_ptr, Ordering::Relaxed);
        result
    } else {
        let mut saved_ptr = STRTOK_NEXT.load(Ordering::Relaxed);
        let result = strtok_r(str, delim, &mut saved_ptr);
        STRTOK_NEXT.store(saved_ptr, Ordering::Relaxed);
        result
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strtok_r(
    str: *mut CChar,
    delim: *const CChar,
    saveptr: *mut *mut CChar,
) -> *mut CChar {
    if delim.is_null() || saveptr.is_null() {
        return ptr::null_mut();
    }

    let mut token_start = if str.is_null() { *saveptr } else { str };

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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn is_delimiter(c: CChar, delim: *const CChar) -> bool {
    let mut d = delim;
    while *d != 0 {
        if *d == c {
            return true;
        }
        d = d.add(1);
    }
    false
}
