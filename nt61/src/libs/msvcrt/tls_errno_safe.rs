//! Thread-safe TLS (Thread Local Storage) errno management
//!
//! Provides proper thread-local errno storage

use super::types::*;
use core::sync::atomic::AtomicBool;
use spin::Mutex;

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const ESRCH: i32 = 3;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const ENXIO: i32 = 6;
pub const E2BIG: i32 = 7;
pub const ENOEXEC: i32 = 8;
pub const EBADF: i32 = 9;
pub const ECHILD: i32 = 10;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EFAULT: i32 = 14;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENODEV: i32 = 19;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const ENFILE: i32 = 23;
pub const EMFILE: i32 = 24;
pub const ENOTTY: i32 = 25;
pub const EFBIG: i32 = 27;
pub const ENOSPC: i32 = 28;
pub const ESPIPE: i32 = 29;
pub const EROFS: i32 = 30;
pub const EMLINK: i32 = 31;
pub const EPIPE: i32 = 32;
pub const EDOM: i32 = 33;
pub const ERANGE: i32 = 34;
pub const EDEADLK: i32 = 36;
pub const ENAMETOOLONG: i32 = 38;
pub const ENOLCK: i32 = 39;
pub const ENOSYS: i32 = 40;
pub const ENOTEMPTY: i32 = 41;
pub const EILSEQ: i32 = 42;
pub const STRUNCATE: i32 = 80;

const MAX_THREADS: usize = 256;

#[derive(Copy, Clone)]
struct ThreadErrno {
    tid: usize,
    errno_val: i32,
    doserrno_val: u32,
}

pub struct TlsErrnoTable {
    entries: [Mutex<ThreadErrno>; MAX_THREADS],
    pub initialized: AtomicBool,
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
    // Per-thread errno must be keyed by the running thread. Before any thread
    // context exists (early boot) the table falls back to entry 0; once the
    // per-CPU area publishes the current ETHREAD, that identity is used as the
    // table key so concurrent threads no longer share one errno slot.
    let thread = crate::arch::common::percpu::get_current_thread();
    if thread.is_null() {
        return 0;
    }
    thread as usize
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn __errno_location() -> *mut CInt {
    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let mut locked = entry.lock();
    &mut locked.errno_val as *mut CInt
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn __doserrno() -> *mut CUlong {
    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let mut locked = entry.lock();
    &mut locked.doserrno_val as *mut CUlong as *mut CUlong
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _get_errno(value: *mut CInt) -> ErrnoT {
    if value.is_null() {
        return EINVAL;
    }

    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let locked = entry.lock();
    *value = locked.errno_val;
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _set_errno(value: CInt) -> ErrnoT {
    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let mut locked = entry.lock();
    locked.errno_val = value;
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _get_doserrno(value: *mut CUlong) -> ErrnoT {
    if value.is_null() {
        return EINVAL;
    }

    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let locked = entry.lock();
    *value = locked.doserrno_val;
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _set_doserrno(value: CUlong) -> ErrnoT {
    let tid = get_current_tid();
    let entry = TLS_ERRNO.get_entry(tid);
    let mut locked = entry.lock();
    locked.doserrno_val = value;
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strerror(errnum: CInt) -> *const CChar {
    static BUFFER: Mutex<[CChar; 64]> = Mutex::new([0; 64]);

    let mut buf = BUFFER.lock();
    let msg: &[u8] = match errnum {
        0 => b"Success\0",
        EPERM => b"Operation not permitted\0",
        ENOENT => b"No such file or directory\0",
        ESRCH => b"No such process\0",
        EINTR => b"Interrupted system call\0",
        EIO => b"Input/output error\0",
        ENXIO => b"No such device or address\0",
        E2BIG => b"Argument list too long\0",
        ENOEXEC => b"Exec format error\0",
        EBADF => b"Bad file descriptor\0",
        ECHILD => b"No child processes\0",
        EAGAIN => b"Resource temporarily unavailable\0",
        ENOMEM => b"Cannot allocate memory\0",
        EACCES => b"Permission denied\0",
        EFAULT => b"Bad address\0",
        EBUSY => b"Device or resource busy\0",
        EEXIST => b"File exists\0",
        EXDEV => b"Invalid cross-device link\0",
        ENODEV => b"No such device\0",
        ENOTDIR => b"Not a directory\0",
        EISDIR => b"Is a directory\0",
        EINVAL => b"Invalid argument\0",
        ENFILE => b"Too many open files in system\0",
        EMFILE => b"Too many open files\0",
        ENOTTY => b"Inappropriate ioctl for device\0",
        EFBIG => b"File too large\0",
        ENOSPC => b"No space left on device\0",
        ESPIPE => b"Illegal seek\0",
        EROFS => b"Read-only file system\0",
        EMLINK => b"Too many links\0",
        EPIPE => b"Broken pipe\0",
        EDOM => b"Numerical argument out of domain\0",
        ERANGE => b"Numerical result out of range\0",
        EDEADLK => b"Resource deadlock avoided\0",
        ENAMETOOLONG => b"File name too long\0",
        ENOLCK => b"No locks available\0",
        ENOSYS => b"Function not implemented\0",
        ENOTEMPTY => b"Directory not empty\0",
        EILSEQ => b"Invalid or incomplete multibyte or wide character\0",
        STRUNCATE => b"String was truncated\0",
        _ => b"Unknown error\0",
    };

    for (i, &byte) in msg.iter().enumerate() {
        if i >= 64 {
            break;
        }
        buf[i] = byte as CChar;
    }

    buf.as_ptr()
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _errno() -> *mut CInt {
    __errno_location()
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _doserrno() -> *mut CUlong {
    __doserrno()
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn __tls_cleanup_thread(thread_id: usize) {
    let entry = TLS_ERRNO.get_entry(thread_id);
    let mut locked = entry.lock();
    if locked.tid == thread_id {
        locked.tid = 0;
        locked.errno_val = 0;
        locked.doserrno_val = 0;
    }
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn strerror_s(
    buffer: *mut CChar,
    size_in_bytes: SizeT,
    errnum: CInt,
) -> ErrnoT {
    if buffer.is_null() || size_in_bytes == 0 {
        return EINVAL;
    }

    let msg = strerror(errnum);
    let mut i = 0;

    while i < size_in_bytes - 1 && *msg.add(i) != 0 {
        *buffer.add(i) = *msg.add(i);
        i += 1;
    }
    *buffer.add(i) = 0;

    if i < size_in_bytes - 1 {
        return STRUNCATE;
    }

    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn perror(s: *const CChar) {
    let errnum = *_errno();
    let stderr = super::stdio_safe::__get_stderr();

    if !s.is_null() && *s != 0 {
        super::stdio::fputs(s, stderr);
        super::stdio::fputs(b": \0".as_ptr() as *const CChar, stderr);
    }

    let msg = strerror(errnum);
    super::stdio::fputs(msg as *const CChar, stderr);
    super::stdio::fputc(b'\n' as CInt, stderr);
}
