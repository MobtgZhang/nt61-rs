//! Thread-safe TLS (Thread Local Storage) errno management
//!
//! Provides proper thread-local errno storage

use super::types::*;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

const MAX_THREADS: usize = 256;

#[derive(Copy, Clone)]
struct ThreadErrno {
    tid: usize,
    errno_val: i32,
    doserrno_val: u32,
}

struct TlsErrnoTable {
    entries: [Mutex<ThreadErrno>; MAX_THREADS],
    initialized: AtomicBool,
}

impl TlsErrnoTable {
    const fn new() -> Self {
        const INIT: Mutex<ThreadErrno> = Mutex::new(ThreadErrno {
            tid: 0,
            errno_val: 0,
            doserrno_val: 0,
        });
        Self {
            entries: [INIT; MAX_THREADS],
            initialized: AtomicBool::new(false),
        }
    }

    fn get_entry(&self, tid: usize) -> &Mutex<ThreadErrno> {
        &self.entries[tid % MAX_THREADS]
    }
}

static TLS_ERRNO: TlsErrnoTable = TlsErrnoTable::new();

fn get_current_tid() -> usize {
    // TODO: Get actual thread ID from kernel
    0
}

#[no_mangle]
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let mut locked = entry.lock();
    &mut locked.errno_val as *mut c_int
}

#[no_mangle]
pub unsafe extern "C" fn __doserrno() -> *mut c_ulong {
    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let mut locked = entry.lock();
    &mut locked.doserrno_val as *mut c_ulong as *mut c_ulong
}

#[no_mangle]
pub unsafe extern "C" fn _get_errno(value: *mut c_int) -> errno_t {
    if value.is_null() {
        return super::EINVAL;
    }

    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let locked = entry.lock();
    *value = locked.errno_val;
    0
}

#[no_mangle]
pub unsafe extern "C" fn _set_errno(value: c_int) -> errno_t {
    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let mut locked = entry.lock();
    locked.errno_val = value;
    0
}

#[no_mangle]
pub unsafe extern "C" fn _get_doserrno(value: *mut c_ulong) -> errno_t {
    if value.is_null() {
        return super::EINVAL;
    }

    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let locked = entry.lock();
    *value = locked.doserrno_val;
    0
}

#[no_mangle]
pub unsafe extern "C" fn _set_doserrno(value: c_ulong) -> errno_t {
    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let mut locked = entry.lock();
    locked.doserrno_val = value;
    0
}

#[no_mangle]
pub unsafe extern "C" fn strerror(errnum: c_int) -> *const c_char {
    static BUFFER: Mutex<[c_char; 64]> = Mutex::new([0; 64]);

    let mut buf = BUFFER.lock();
    let msg = match errnum {
        0 => b"Success\0",
        _ => b"Unknown error\0",
    };

    for (i, &byte) in msg.iter().enumerate() {
        if i >= 64 {
            break;
        }
        buf[i] = byte as c_char;
    }

    buf.as_ptr()
}
