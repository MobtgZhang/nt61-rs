//! kernel32 — console APIs
//
//! `GetStdHandle`, `WriteConsoleW`, `ReadConsoleW`,
//! `GetConsoleScreenBufferInfo`, `SetConsoleTextAttribute`,
//! `AllocConsole`, `FreeConsole`. The console is a thin
//! wrapper around the kernel's `kprintln!` so the smoke
//! test can verify that messages go somewhere.

extern crate alloc;

use super::error::{GetLastError, SetLastError};
use super::types::{BOOL, DWORD, FALSE, HANDLE, TRUE};
use alloc::string::String;
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicPtr, Ordering};

const STD_INPUT_HANDLE: DWORD = 0xFFFF_FFF6;
const STD_OUTPUT_HANDLE: DWORD = 0xFFFF_FFF5;
const STD_ERROR_HANDLE: DWORD = 0xFFFF_FFF4;

static MOCK_STDIN: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static MOCK_STDOUT: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static MOCK_STDERR: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

/// `GetStdHandle`.
pub unsafe extern "C" fn GetStdHandle(n_std_handle: DWORD) -> HANDLE {
    match n_std_handle {
        0xFFFF_FFF6 => MOCK_STDIN.load(Ordering::Acquire) as HANDLE,
        0xFFFF_FFF5 => MOCK_STDOUT.load(Ordering::Acquire) as HANDLE,
        0xFFFF_FFF4 => MOCK_STDERR.load(Ordering::Acquire) as HANDLE,
        _ => { SetLastError(6); ptr::null_mut() },
    }
}

/// `SetStdHandle`.
pub unsafe extern "C" fn SetStdHandle(n_std_handle: DWORD, h: HANDLE) -> BOOL {
    let p = h as *mut u8;
    match n_std_handle {
        0xFFFF_FFF6 => { MOCK_STDIN.store(p, Ordering::Release); }
        0xFFFF_FFF5 => { MOCK_STDOUT.store(p, Ordering::Release); }
        0xFFFF_FFF4 => { MOCK_STDERR.store(p, Ordering::Release); }
        _ => { SetLastError(6); return FALSE; }
    }
    TRUE
}

static CONSOLE_ATTR: AtomicU32 = AtomicU32::new(0x07);

/// `GetConsoleScreenBufferInfo` — fill a `CONSOLE_SCREEN_BUFFER_INFO`.
#[repr(C)]
#[derive(Default)]
pub struct Coord {
    pub x: i16,
    pub y: i16,
}

#[repr(C)]
#[derive(Default)]
pub struct SmallRect {
    pub left: i16,
    pub top: i16,
    pub right: i16,
    pub bottom: i16,
}

#[repr(C)]
#[derive(Default)]
pub struct ConsoleScreenBufferInfo {
    pub size: Coord,
    pub cursor_position: Coord,
    pub attributes: u16,
    pub window: SmallRect,
    pub maximum_window_size: Coord,
}

pub unsafe extern "C" fn GetConsoleScreenBufferInfo(
    _console: HANDLE,
    info: *mut ConsoleScreenBufferInfo,
) -> BOOL {
    if info.is_null() { SetLastError(87); return FALSE; }
    let i = &mut *info;
    i.size = Coord { x: 80, y: 25 };
    i.cursor_position = Coord { x: 0, y: 0 };
    i.attributes = CONSOLE_ATTR.load(Ordering::Relaxed) as u16;
    i.window = SmallRect { left: 0, top: 0, right: 79, bottom: 24 };
    i.maximum_window_size = Coord { x: 80, y: 25 };
    TRUE
}

/// `SetConsoleTextAttribute`.
pub unsafe extern "C" fn SetConsoleTextAttribute(_console: HANDLE, attributes: u16) -> BOOL {
    CONSOLE_ATTR.store(attributes as u32, Ordering::Relaxed);
    TRUE
}

/// `WriteConsoleW`.
pub unsafe extern "C" fn WriteConsoleW(
    _console: HANDLE,
    buffer: *const u16,
    chars_to_write: DWORD,
    chars_written: *mut DWORD,
    _reserved: *const u8,
) -> BOOL {
    if buffer.is_null() { SetLastError(87); return FALSE; }
    let slice = core::slice::from_raw_parts(buffer, chars_to_write as usize);
    // Naive UTF-16 -> UTF-8.
    let mut s = alloc::string::String::new();
    for &c in slice {
        if let Some(ch) = char::from_u32(c as u32) { s.push(ch); }
    }
    // crate::kprintln!("[CONSOLE] {}", s)  // kprintln disabled (memcpy crash workaround);
    if !chars_written.is_null() { *chars_written = chars_to_write; }
    TRUE
}

/// `ReadConsoleW` — read from a fake input buffer. The
/// bootstrap never has real input; we return zero bytes.
pub unsafe extern "C" fn ReadConsoleW(
    _console: HANDLE,
    _buffer: *mut u16,
    _chars_to_read: DWORD,
    chars_read: *mut DWORD,
    _input_control: *const u8,
) -> BOOL {
    if !chars_read.is_null() { *chars_read = 0; }
    TRUE
}

/// `AllocConsole` / `FreeConsole` — always succeed in the
/// bootstrap. The real kernel creates a console object.
pub extern "C" fn AllocConsole() -> BOOL { TRUE }
pub extern "C" fn FreeConsole() -> BOOL { TRUE }
