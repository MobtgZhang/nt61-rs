//! ntdll — RTL memory utilities
//
//! Additional memory manipulation functions beyond heap allocation:
//! RtlCompareMemory, RtlFillMemory, RtlZeroMemory, RtlMoveMemory,
//! RtlCopyMemory, RtlSecureZeroMemory.
//
//! References: MSDN Library "Windows 7" — RTL Memory functions.

use super::types::PVOID;
use core::ptr;

pub unsafe extern "C" fn RtlCompareMemory(
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

pub unsafe extern "C" fn RtlEqualMemory(
    source1: PVOID,
    source2: PVOID,
    length: usize,
) -> u8 {
    if RtlCompareMemory(source1, source2, length) == length {
        1
    } else {
        0
    }
}

pub unsafe extern "C" fn RtlFillMemory(
    destination: PVOID,
    length: usize,
    fill: u8,
) {
    if destination.is_null() || length == 0 {
        return;
    }
    ptr::write_bytes(destination as *mut u8, fill, length);
}

pub unsafe extern "C" fn RtlZeroMemory(destination: PVOID, length: usize) {
    RtlFillMemory(destination, length, 0);
}

pub unsafe extern "C" fn RtlSecureZeroMemory(ptr: PVOID, cnt: usize) {
    if ptr.is_null() || cnt == 0 {
        return;
    }
    let p = ptr as *mut u8;
    for i in 0..cnt {
        ptr::write_volatile(p.add(i), 0);
    }
}

pub unsafe extern "C" fn RtlMoveMemory(
    destination: PVOID,
    source: PVOID,
    length: usize,
) {
    if destination.is_null() || source.is_null() || length == 0 {
        return;
    }
    ptr::copy(source as *const u8, destination as *mut u8, length);
}

pub unsafe extern "C" fn RtlCopyMemory(
    destination: PVOID,
    source: PVOID,
    length: usize,
) {
    if destination.is_null() || source.is_null() || length == 0 {
        return;
    }
    ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, length);
}

pub unsafe extern "C" fn RtlCopyBytes(
    destination: PVOID,
    source: PVOID,
    length: usize,
) {
    RtlCopyMemory(destination, source, length);
}

pub unsafe extern "C" fn RtlFillBytes(
    destination: PVOID,
    length: usize,
    fill: u8,
) {
    RtlFillMemory(destination, length, fill);
}

pub unsafe extern "C" fn RtlZeroBytes(destination: PVOID, length: usize) {
    RtlZeroMemory(destination, length);
}
