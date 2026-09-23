//! ntdll — Thread Local Storage (TLS) support
//
//! Implements the TLS allocation and access functions:
//! RtlAllocateThreadLocalStorageIndex, RtlFreeThreadLocalStorageIndex,
//! TlsGetValue, TlsSetValue.
//
//! References: MSDN Library "Windows 7" — Thread Local Storage.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

use super::status::{STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS};
use super::types::{NTSTATUS, PVOID};
use crate::ke::sync::Spinlock;
use core::ptr;

const TLS_MINIMUM_AVAILABLE: usize = 64;
const TLS_EXPANSION_SLOTS: usize = 1024;
const TLS_TOTAL_SLOTS: usize = TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS;

struct TlsState {
    allocated: [bool; TLS_TOTAL_SLOTS],
    next_free: usize,
}

static TLS_LOCK: Spinlock<TlsState> = Spinlock::new(TlsState {
    allocated: [false; TLS_TOTAL_SLOTS],
    next_free: 0,
});

static TLS_DATA: Lazy<Mutex<[usize; TLS_MINIMUM_AVAILABLE]>> = Lazy::new(|| Mutex::new([0; TLS_MINIMUM_AVAILABLE]));
static TLS_EXPANSION: Lazy<Mutex<[usize; TLS_EXPANSION_SLOTS]>> = Lazy::new(|| Mutex::new([0; TLS_EXPANSION_SLOTS]));

pub unsafe extern "C" fn TlsAlloc() -> u32 {
    let mut state = TLS_LOCK.lock();

    for i in state.next_free..TLS_TOTAL_SLOTS {
        if !state.allocated[i] {
            state.allocated[i] = true;
            state.next_free = i + 1;
            return i as u32;
        }
    }

    for i in 0..state.next_free {
        if !state.allocated[i] {
            state.allocated[i] = true;
            state.next_free = i + 1;
            return i as u32;
        }
    }

    0xFFFF_FFFF // TLS_OUT_OF_INDEXES
}

pub unsafe extern "C" fn RtlAllocateThreadLocalStorageIndex(index: *mut u32) -> NTSTATUS {
    if index.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let idx = TlsAlloc();
    if idx == 0xFFFF_FFFF {
        return STATUS_NO_MEMORY;
    }
    *index = idx;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn TlsFree(index: u32) -> u32 {
    if index as usize >= TLS_TOTAL_SLOTS {
        return 0;
    }
    let mut state = TLS_LOCK.lock();
    if !state.allocated[index as usize] {
        return 0;
    }
    state.allocated[index as usize] = false;
    if (index as usize) < state.next_free {
        state.next_free = index as usize;
    }
    1
}

pub unsafe extern "C" fn RtlFreeThreadLocalStorageIndex(index: u32) -> NTSTATUS {
    if TlsFree(index) != 0 {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

pub unsafe extern "C" fn TlsGetValue(index: u32) -> PVOID {
    if index as usize >= TLS_TOTAL_SLOTS {
        return ptr::null_mut();
    }

    // Get thread ID (simplified - use slot 0 for bootstrap)
    let thread_id = 0usize;
    if thread_id >= 8 {
        return ptr::null_mut();
    }

    if (index as usize) < TLS_MINIMUM_AVAILABLE {
        TLS_DATA[thread_id][index as usize] as PVOID
    } else {
        let expansion_idx = (index as usize) - TLS_MINIMUM_AVAILABLE;
        TLS_EXPANSION[thread_id][expansion_idx] as PVOID
    }
}

pub unsafe extern "C" fn TlsSetValue(index: u32, value: PVOID) -> u32 {
    if index as usize >= TLS_TOTAL_SLOTS {
        return 0;
    }

    // Get thread ID (simplified - use slot 0 for bootstrap)
    let thread_id = 0usize;
    if thread_id >= 8 {
        return 0;
    }

    if (index as usize) < TLS_MINIMUM_AVAILABLE {
        TLS_DATA[thread_id][index as usize] = value as usize;
    } else {
        let expansion_idx = (index as usize) - TLS_MINIMUM_AVAILABLE;
        TLS_EXPANSION[thread_id][expansion_idx] = value as usize;
    }
    1
}

pub unsafe extern "C" fn RtlFlsAlloc(
    _callback: PVOID,
    index: *mut u32,
) -> NTSTATUS {
    RtlAllocateThreadLocalStorageIndex(index)
}

pub unsafe extern "C" fn RtlFlsFree(index: u32) -> NTSTATUS {
    RtlFreeThreadLocalStorageIndex(index)
}
