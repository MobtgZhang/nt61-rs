//! ntdll — Thread Local Storage (TLS) support
//
//! Implements the TLS allocation and access functions:
//! rtl_allocate_thread_local_storage_index, rtl_free_thread_local_storage_index,
//! tls_get_value, tls_set_value.
//
//! References: MSDN Library "Windows 7" — Thread Local Storage.

use super::status::{STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS};
use super::types::{NTSTATUS, PVOID};
use crate::ke::sync::Spinlock;
use core::ptr;
use spin::{Lazy, Mutex};

extern crate alloc;
use alloc::vec::Vec;

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

/// Per-thread TLS storage.
///
/// `tls_get_value`/`tls_set_value` are per-thread by definition (Win32 DDI:
/// "the value is stored in the calling thread's TLS array"), so the table
/// must be keyed by the calling thread rather than shared process-wide.
/// Expansion slots are allocated lazily, matching the Windows behaviour
/// where slots 64..1087 only exist once the thread has used them.
struct TlsThreadState {
    thread_id: usize,
    base: [usize; TLS_MINIMUM_AVAILABLE],
    expansion: Vec<usize>,
}

static TLS_THREADS: Lazy<Mutex<Vec<TlsThreadState>>> = Lazy::new(|| Mutex::new(Vec::new()));

fn current_thread_id() -> usize {
    match crate::arch::common::percpu::try_get_current() {
        Some(area) if !area.current_thread.is_null() => area.current_thread as usize,
        _ => 0,
    }
}

pub unsafe extern "C" fn tls_alloc() -> u32 {
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

pub unsafe extern "C" fn rtl_allocate_thread_local_storage_index(index: *mut u32) -> NTSTATUS {
    if index.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let idx = tls_alloc();
    if idx == 0xFFFF_FFFF {
        return STATUS_NO_MEMORY;
    }
    *index = idx;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn tls_free(index: u32) -> u32 {
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

pub unsafe extern "C" fn rtl_free_thread_local_storage_index(index: u32) -> NTSTATUS {
    if tls_free(index) != 0 {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

pub unsafe extern "C" fn tls_get_value(index: u32) -> PVOID {
    if index as usize >= TLS_TOTAL_SLOTS {
        return ptr::null_mut();
    }

    let thread_id = current_thread_id();
    let table = TLS_THREADS.lock();
    let entry = match table.iter().find(|entry| entry.thread_id == thread_id) {
        Some(entry) => entry,
        None => return ptr::null_mut(),
    };
    if (index as usize) < TLS_MINIMUM_AVAILABLE {
        entry.base[index as usize] as PVOID
    } else {
        let expansion_idx = (index as usize) - TLS_MINIMUM_AVAILABLE;
        entry.expansion.get(expansion_idx).copied().unwrap_or(0) as PVOID
    }
}

pub unsafe extern "C" fn tls_set_value(index: u32, value: PVOID) -> u32 {
    if index as usize >= TLS_TOTAL_SLOTS {
        return 0;
    }

    let thread_id = current_thread_id();
    let mut table = TLS_THREADS.lock();
    let entry_index = match table.iter().position(|entry| entry.thread_id == thread_id) {
        Some(entry_index) => entry_index,
        None => {
            table.push(TlsThreadState {
                thread_id,
                base: [0; TLS_MINIMUM_AVAILABLE],
                expansion: Vec::new(),
            });
            table.len() - 1
        }
    };
    let entry = &mut table[entry_index];
    if (index as usize) < TLS_MINIMUM_AVAILABLE {
        entry.base[index as usize] = value as usize;
    } else {
        let expansion_idx = (index as usize) - TLS_MINIMUM_AVAILABLE;
        if entry.expansion.len() <= expansion_idx {
            entry.expansion.resize(expansion_idx + 1, 0);
        }
        entry.expansion[expansion_idx] = value as usize;
    }
    1
}

pub unsafe extern "C" fn rtl_fls_alloc(_callback: PVOID, index: *mut u32) -> NTSTATUS {
    rtl_allocate_thread_local_storage_index(index)
}

pub unsafe extern "C" fn rtl_fls_free(index: u32) -> NTSTATUS {
    rtl_free_thread_local_storage_index(index)
}
