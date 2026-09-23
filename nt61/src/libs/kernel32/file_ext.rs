//! Thread-safe kernel32 file handle management
//!
//! Replaces unsafe static mut FIND_HANDLES with synchronized access

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

use super::types::*;

const MAX_FIND_HANDLES: usize = 16;

#[derive(Clone)]
pub struct FindHandle {
    pub handle: HANDLE,
    pub pattern: [u16; 260], // MAX_PATH
    pub current_index: usize,
    pub in_use: bool,
}

impl FindHandle {
    const fn new() -> Self {
        Self {
            handle: 0 as HANDLE,
            pattern: [0; 260],
            current_index: 0,
            in_use: false,
        }
    }
}

struct FindHandleTable {
    handles: [FindHandle; MAX_FIND_HANDLES],
}

impl FindHandleTable {
    const fn new() -> Self {
        const INIT: FindHandle = FindHandle::new();
        Self {
            handles: [INIT; MAX_FIND_HANDLES],
        }
    }

    fn allocate(&mut self) -> Option<usize> {
        for (i, handle) in self.handles.iter_mut().enumerate() {
            if !handle.in_use {
                handle.in_use = true;
                return Some(i);
            }
        }
        None
    }

    fn free(&mut self, index: usize) {
        if index < MAX_FIND_HANDLES {
            self.handles[index].in_use = false;
            self.handles[index].handle = 0 as HANDLE;
        }
    }

    fn get(&mut self, index: usize) -> Option<&mut FindHandle> {
        if index < MAX_FIND_HANDLES && self.handles[index].in_use {
            Some(&mut self.handles[index])
        } else {
            None
        }
    }
}

static FIND_HANDLES: Lazy<Mutex<FindHandleTable>> = Lazy::new(|| {
    Mutex::new(FindHandleTable::new())
});

pub fn alloc_find_handle() -> Option<usize> {
    FIND_HANDLES.lock().allocate()
}

pub fn free_find_handle(index: usize) {
    FIND_HANDLES.lock().free(index);
}

pub fn get_find_handle(index: usize) -> Option<FindHandle> {
    FIND_HANDLES.lock().get(index).cloned()
}

pub fn update_find_handle<F>(index: usize, f: F) -> bool
where
    F: FnOnce(&mut FindHandle),
{
    let mut table = FIND_HANDLES.lock();
    if let Some(handle) = table.get(index) {
        f(handle);
        true
    } else {
        false
    }
}
