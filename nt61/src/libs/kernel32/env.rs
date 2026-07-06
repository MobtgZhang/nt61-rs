//! kernel32 — environment, paths, command line
//
//! `GetEnvironmentVariableW`, `SetEnvironmentVariableW`,
//! `GetCurrentDirectoryW`, `SetCurrentDirectoryW`,
//! `GetCommandLineW`. The bootstrap holds a fixed
//! environment; the calls are accepted and return the
//! canonical `C:\Windows\System32` for directory queries.

use super::error::GetLastError;
use super::error::SetLastError;
use super::types::DWORD;
use crate::ke::sync::Spinlock;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;

extern crate alloc;

const ENV_CAP: usize = 16;
const ENV_KEY: usize = 32;
const ENV_VAL: usize = 256;

struct EnvEntry {
    in_use: bool,
    key: [u16; ENV_KEY],
    value: [u16; ENV_VAL],
}

impl EnvEntry {
    const fn new() -> Self {
        Self { in_use: false, key: [0; ENV_KEY], value: [0; ENV_VAL] }
    }
}

static ENV: Spinlock<[EnvEntry; ENV_CAP]> = Spinlock::new([
    EnvEntry::new(), EnvEntry::new(), EnvEntry::new(), EnvEntry::new(),
    EnvEntry::new(), EnvEntry::new(), EnvEntry::new(), EnvEntry::new(),
    EnvEntry::new(), EnvEntry::new(), EnvEntry::new(), EnvEntry::new(),
    EnvEntry::new(), EnvEntry::new(), EnvEntry::new(), EnvEntry::new(),
]);

const DEFAULT_DIR: &[u16] = &[
    b'C' as u16, b':' as u16, b'\\' as u16, b'W' as u16, b'i' as u16, b'n' as u16, b'd' as u16,
    b'o' as u16, b'w' as u16, b's' as u16, b'\\' as u16, b'S' as u16, b'y' as u16, b's' as u16,
    b't' as u16, b'e' as u16, b'm' as u16, b'3' as u16, b'2' as u16, 0,
];

const COMMAND_LINE: &[u16] = &[
    b'C' as u16, b':' as u16, b'\\' as u16, b'W' as u16, b'i' as u16, b'n' as u16, b'd' as u16,
    b'o' as u16, b'w' as u16, b's' as u16, b'\\' as u16, b'S' as u16, b'y' as u16, b's' as u16,
    b't' as u16, b'e' as u16, b'm' as u16, b'3' as u16, b'2' as u16, b'\\' as u16, b's' as u16,
    b'm' as u16, b's' as u16, b's' as u16, b'.' as u16, b'e' as u16, b'x' as u16, b'e' as u16, 0,
];

/// `GetEnvironmentVariableW`.
pub unsafe extern "C" fn GetEnvironmentVariableW(
    name: *const u16,
    buffer: *mut u16,
    buffer_size: DWORD,
) -> DWORD {
    if name.is_null() { return 0; }
    let n = wide_to_string(name).unwrap_or_default();
    if n.is_empty() { return 0; }
    let env = ENV.lock();
    for entry in env.iter() {
        if !entry.in_use { continue; }
        let key = wide_slice_to_string(&entry.key);
        if key.eq_ignore_ascii_case(&n) {
            let val = wide_slice_to_string(&entry.value);
            let bytes = (val.len() + 1) * 2;
            if (buffer_size as usize) < bytes {
                return bytes as DWORD;
            }
            if !buffer.is_null() {
                copy_wide(&val, unsafe { core::slice::from_raw_parts_mut(buffer, (val.len() + 1) * 2) });
            }
            return val.len() as DWORD;
        }
    }
    0
}

/// `SetEnvironmentVariableW`.
pub unsafe extern "C" fn SetEnvironmentVariableW(
    name: *const u16,
    value: *const u16,
) -> BOOL {
    if name.is_null() { SetLastError(87); return 0; }
    let n = match wide_to_string(name) { Some(s) => s, None => { SetLastError(87); return 0; } };
    let v = if value.is_null() { String::new() } else { wide_to_string(value).unwrap_or_default() };
    let mut env = ENV.lock();
    // First, try to find an existing entry to update.
    for entry in env.iter_mut() {
        if entry.in_use && wide_slice_to_string(&entry.key).eq_ignore_ascii_case(&n) {
            if v.is_empty() {
                entry.in_use = false;
            } else {
                copy_wide(&v, &mut entry.value);
            }
            return 1;
        }
    }
    // Not found; insert.
    for entry in env.iter_mut() {
        if !entry.in_use {
            copy_wide(&n, &mut entry.key);
            copy_wide(&v, &mut entry.value);
            entry.in_use = true;
            return 1;
        }
    }
    SetLastError(8); // ERROR_NOT_ENOUGH_MEMORY
    0
}

/// `GetCurrentDirectoryW`.
pub unsafe extern "C" fn GetCurrentDirectoryW(
    buffer_length: DWORD,
    buffer: *mut u16,
) -> DWORD {
    let len = (DEFAULT_DIR.len() as DWORD) - 1; // exclude NUL
    if (buffer_length as usize) < (DEFAULT_DIR.len()) {
        return len + 1;
    }
    if !buffer.is_null() {
        ptr::copy_nonoverlapping(DEFAULT_DIR.as_ptr(), buffer, DEFAULT_DIR.len());
    }
    len
}

/// `SetCurrentDirectoryW` — accept the call and ignore the
/// directory (the bootstrap has no real current directory).
pub unsafe extern "C" fn SetCurrentDirectoryW(_path: *const u16) -> BOOL {
    1
}

/// `GetCommandLineW` — return the static command line.
pub unsafe extern "C" fn GetCommandLineW() -> *const u16 {
    COMMAND_LINE.as_ptr()
}

/// `GetSystemDirectoryW` / `GetWindowsDirectoryW`.
pub unsafe extern "C" fn GetSystemDirectoryW(buffer: *mut u16, buffer_size: DWORD) -> DWORD {
    if buffer.is_null() || buffer_size < 40 { return 40; }
    let p = &DEFAULT_DIR[..];
    ptr::copy_nonoverlapping(p.as_ptr(), buffer, p.len());
    p.len() as DWORD
}

pub unsafe extern "C" fn GetWindowsDirectoryW(buffer: *mut u16, buffer_size: DWORD) -> DWORD {
    GetSystemDirectoryW(buffer, buffer_size)
}

/// `ExpandEnvironmentStringsW` — substitute `%FOO%` with the
/// matching environment variable. We only do exact matches
/// and a single pass.
pub unsafe extern "C" fn ExpandEnvironmentStringsW(
    source: *const u16,
    destination: *mut u16,
    destination_size: DWORD,
) -> DWORD {
    if source.is_null() { return 0; }
    let src = wide_to_string(source).unwrap_or_default();
    let expanded = expand_env(&src);
    let need = (expanded.len() + 1) * 2;
    if (destination_size as usize) < need { return need as DWORD; }
    if !destination.is_null() {
        let mut sl = [0u16; 256];
        let bytes = (expanded.len() + 1) * 2;
        for (i, c) in expanded.encode_utf16().enumerate() {
            if i + 1 >= sl.len() { break; }
            sl[i] = c;
        }
        sl[expanded.len()] = 0;
        ptr::copy_nonoverlapping(sl.as_ptr(), destination, bytes.min(sl.len()));
        if (bytes as usize) < sl.len() {
            *destination.add(bytes - 1) = 0;
        }
    }
    expanded.len() as DWORD
}

fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(end) = s[i+1..].find('%') {
                let name = &s[i+1..i+1+end];
                let val = lookup_env(name);
                out.push_str(&val);
                i += 1 + end + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn lookup_env(name: &str) -> String {
    let env = ENV.lock();
    for entry in env.iter() {
        if !entry.in_use { continue; }
        if wide_slice_to_string(&entry.key).eq_ignore_ascii_case(name) {
            return wide_slice_to_string(&entry.value);
        }
    }
    String::new()
}

fn wide_to_string(p: *const u16) -> Option<String> {
    if p.is_null() { return None; }
    let mut len = 0;
    unsafe {
        while *p.add(len) != 0 { len += 1; }
        let slice = core::slice::from_raw_parts(p, len);
        let mut out = String::new();
        for &c in slice {
            if let Some(ch) = char::from_u32(c as u32) { out.push(ch); }
        }
        Some(out)
    }
}

fn wide_slice_to_string(s: &[u16]) -> String {
    let mut out = String::new();
    for &c in s {
        if c == 0 { break; }
        if let Some(ch) = char::from_u32(c as u32) { out.push(ch); }
    }
    out
}

fn copy_wide(s: &str, dst: &mut [u16]) {
    for (i, c) in s.encode_utf16().enumerate() {
        if i + 1 >= dst.len() { break; }
        dst[i] = c;
    }
    dst[s.len()] = 0;
}

use super::types::BOOL;
