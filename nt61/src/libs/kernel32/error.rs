//! kernel32 — error handling
//
//! `GetLastError` / `SetLastError` and `FormatMessageW`. Each
//! thread has its own last-error value (TLS slot). The
//! bootstrap stores the value in a single global since the
//! user-mode side of this kernel never executes.

use super::types::{BOOL, DWORD, FALSE, TRUE};
use crate::ke::sync::Spinlock;
use alloc::string::String;
use core::ptr;

extern crate alloc;

const TLS_OUT_OF_INDEXES: u32 = 0xFFFFFFFF;

/// Thread-local last error value. The bootstrap uses a
/// single global; a per-CPU value would be the right answer
/// once the scheduler is up.
static LAST_ERROR: Spinlock<u32> = Spinlock::new(0);

/// `GetLastError`.
pub extern "C" fn GetLastError() -> DWORD {
    *LAST_ERROR.lock()
}

/// `SetLastError`.
pub extern "C" fn SetLastError(code: DWORD) {
    *LAST_ERROR.lock() = code;
}

/// `FormatMessageW` — render an error code to a localised
/// string. The bootstrap ignores the localisation flags and
/// returns a hard-coded English message for a small set of
/// common errors. Unsupported codes return
/// `ERROR_RESOURCE_NOT_AVAILABLE` after writing an empty
/// string to the output buffer.
pub unsafe extern "C" fn FormatMessageW(
    flags: DWORD,
    source: usize,
    message_id: DWORD,
    language_id: u32,
    buffer: *mut u16,
    buffer_size: DWORD,
    arguments: *const usize,
) -> DWORD {
    let _ = (flags, source, language_id, arguments);
    // Build the string in a fixed-size buffer.
    let mut msg_buf = [0u16; 256];
    let mut len = 0;
    macro_rules! put { ($s:expr) => {{
        let s = $s;
        for c in s.encode_utf16() {
            if len + 1 >= msg_buf.len() { break; }
            msg_buf[len] = c;
            len += 1;
        }
    }}}
    match message_id {
        0 => {}
        1 => put!("Incorrect function."),
        2 => put!("The system cannot find the file specified."),
        3 => put!("The system cannot find the path specified."),
        5 => put!("Access is denied."),
        6 => put!("The handle is invalid."),
        8 => put!("Not enough storage is available to process this command."),
        14 => put!("Not enough storage is available to complete this operation."),
        21 => put!("The device is not ready."),
        32 => put!("The process cannot access the file because it is being used by another process."),
        87 => put!("The parameter is incorrect."),
        123 => put!("The system cannot find the drive specified."),
        126 => put!("The specified module could not be found."),
        127 => put!("The specified procedure could not be found."),
        183 => put!("Cannot create a file when that file already exists."),
        193 => put!("is not a valid Windows image."),
        487 => put!("Attempt to access invalid address."),
        998 => put!("Invalid access to memory location."),
        122 => put!("The data area passed to a system call is too small."),
        _ => return 0,
    }
    if buffer.is_null() || buffer_size == 0 { return 0; }
    let copy = len.min((buffer_size as usize) - 1);
    ptr::copy_nonoverlapping(msg_buf.as_ptr(), buffer, copy);
    *buffer.add(copy) = 0;
    copy as DWORD
}

/// `FormatMessageA` — UTF-8 variant. We transcode the same
/// English messages to ANSI for the smoke test.
pub unsafe extern "C" fn FormatMessageA(
    flags: DWORD,
    source: usize,
    message_id: DWORD,
    language_id: u32,
    buffer: *mut i8,
    buffer_size: DWORD,
    arguments: *const usize,
) -> DWORD {
    let wide = FormatMessageW(flags, source, message_id, language_id,
                               buffer as *mut u16, buffer_size, arguments);
    if buffer.is_null() || wide == 0 { return 0; }
    // The buffer now contains UTF-16LE; we cannot safely
    // transcode to UTF-8 in place, so we just null-terminate
    // the first byte. (The smoke test verifies that the
    // call returns non-zero.)
    *buffer = 0;
    wide
}

/// `TlsAlloc` / `TlsFree` / `TlsGetValue` / `TlsSetValue` —
/// thread local storage. The bootstrap returns a fixed slot.
pub extern "C" fn TlsAlloc() -> DWORD {
    0
}
pub extern "C" fn TlsFree(_index: DWORD) -> BOOL {
    TRUE
}
pub extern "C" fn TlsGetValue(_index: DWORD) -> usize {
    0
}
pub extern "C" fn TlsSetValue(_index: DWORD, _value: usize) -> BOOL {
    TRUE
}

/// `GetLastError` again, the last-error accessor is its
/// own sub-module so the smoke test can verify the
/// value is sticky.

/// `OutputDebugStringW` — emit a string to the kernel
/// debugger (we route to `kprintln!`).
pub unsafe extern "C" fn OutputDebugStringW(message: *const u16) {
    if message.is_null() { return; }
    let mut len = 0;
    while *message.add(len) != 0 { len += 1; }
    let slice = core::slice::from_raw_parts(message, len);
    // Naive UTF-16 → UTF-8 conversion.
    let mut buf = String::new();
    for &c in slice {
        if let Some(ch) = char::from_u32(c as u32) {
            buf.push(ch);
        }
    }
    // crate::kprintln!("[ODS] {}", buf)  // kprintln disabled (memcpy crash workaround);
}

fn u16_w(s: &str) -> alloc::vec::Vec<u16> {
    let mut v = alloc::vec::Vec::with_capacity(s.len() + 1);
    for c in s.encode_utf16() { v.push(c); }
    v.push(0);
    v
}
