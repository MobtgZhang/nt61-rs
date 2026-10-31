//! ntdll — RTL memory utilities
//
//! Additional memory manipulation functions beyond heap allocation:
//! rtl_compare_memory, rtl_fill_memory, rtl_zero_memory, rtl_move_memory,
//! rtl_copy_memory, rtl_secure_zero_memory.
//
//! References: MSDN Library "Windows 7" — RTL Memory functions.

use super::types::PVOID;
use core::ptr;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn rtl_compare_memory(
    source1: PVOID,
    source2: PVOID,
    length: usize,
) -> usize {
    if source1.is_null() || source2.is_null() || length == 0 {
        return 0;
    }
    let s1 = core::slice::from_raw_parts(source1 as *const u8, length);
    let s2 = core::slice::from_raw_parts(source2 as *const u8, length);
    for i in 0..length {
        if s1[i] != s2[i] {
            return i;
        }
    }
    length
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn rtl_equal_memory(source1: PVOID, source2: PVOID, length: usize) -> u8 {
    if rtl_compare_memory(source1, source2, length) == length {
        1
    } else {
        0
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn rtl_fill_memory(destination: PVOID, length: usize, fill: u8) {
    if destination.is_null() || length == 0 {
        return;
    }
    ptr::write_bytes(destination as *mut u8, fill, length);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn rtl_zero_memory(destination: PVOID, length: usize) {
    rtl_fill_memory(destination, length, 0);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn rtl_secure_zero_memory(ptr: PVOID, cnt: usize) {
    if ptr.is_null() || cnt == 0 {
        return;
    }
    let p = ptr as *mut u8;
    for i in 0..cnt {
        ptr::write_volatile(p.add(i), 0);
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn rtl_move_memory(destination: PVOID, source: PVOID, length: usize) {
    if destination.is_null() || source.is_null() || length == 0 {
        return;
    }
    ptr::copy(source as *const u8, destination as *mut u8, length);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn rtl_copy_memory(destination: PVOID, source: PVOID, length: usize) {
    if destination.is_null() || source.is_null() || length == 0 {
        return;
    }
    ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, length);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn rtl_copy_bytes(destination: PVOID, source: PVOID, length: usize) {
    rtl_copy_memory(destination, source, length);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn rtl_fill_bytes(destination: PVOID, length: usize, fill: u8) {
    rtl_fill_memory(destination, length, fill);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn rtl_zero_bytes(destination: PVOID, length: usize) {
    rtl_zero_memory(destination, length);
}
