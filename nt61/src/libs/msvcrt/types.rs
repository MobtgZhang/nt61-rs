//! C Runtime Library Types
//!
//! Defines C types, structures, and constants used throughout msvcrt.

pub use core::ffi::c_void;

// Standard C types
pub type c_char = i8;
pub type c_uchar = u8;
pub type c_short = i16;
pub type c_ushort = u16;
pub type c_int = i32;
pub type c_uint = u32;
pub type c_long = i32;
pub type c_ulong = u32;
pub type c_longlong = i64;
pub type c_ulonglong = u64;
pub type c_float = f32;
pub type c_double = f64;

pub type size_t = usize;
pub type ssize_t = isize;
pub type ptrdiff_t = isize;
pub type intptr_t = isize;
pub type uintptr_t = usize;

pub type wchar_t = u16;
pub type errno_t = c_int;
pub type time_t = i64;
pub type clock_t = i64;

// File types
pub const EOF: c_int = -1;
pub const SEEK_SET: c_int = 0;
pub const SEEK_CUR: c_int = 1;
pub const SEEK_END: c_int = 2;

pub const BUFSIZ: usize = 512;
pub const FILENAME_MAX: usize = 260;
pub const FOPEN_MAX: usize = 20;

// Error codes
pub const EINVAL: c_int = 22;
pub const ENOMEM: c_int = 12;
pub const ERANGE: c_int = 34;
pub const EBADF: c_int = 9;
pub const EIO: c_int = 5;

// Math constants
pub const HUGE_VAL: f64 = f64::INFINITY;

/// FILE structure for stream operations

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FILE {
    pub handle: usize,
    pub buffer: *mut u8,
    pub buffer_size: usize,
    pub position: usize,
    pub flags: u32,
    pub eof: bool,
    pub error: bool,
}

impl FILE {
    pub const fn new() -> Self {
        FILE {
            handle: 0,
            buffer: core::ptr::null_mut(),
            buffer_size: 0,
            position: 0,
            flags: 0,
            eof: false,
            error: false,
        }
    }
}

// FILE flags
pub const _IOFBF: c_int = 0; // Full buffering
pub const _IOLBF: c_int = 1; // Line buffering
pub const _IONBF: c_int = 2; // No buffering

/// Time structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct tm {
    pub tm_sec: c_int,    // seconds after the minute [0, 60]
    pub tm_min: c_int,    // minutes after the hour [0, 59]
    pub tm_hour: c_int,   // hours since midnight [0, 23]
    pub tm_mday: c_int,   // day of the month [1, 31]
    pub tm_mon: c_int,    // months since January [0, 11]
    pub tm_year: c_int,   // years since 1900
    pub tm_wday: c_int,   // days since Sunday [0, 6]
    pub tm_yday: c_int,   // days since January 1 [0, 365]
    pub tm_isdst: c_int,  // Daylight Saving Time flag
}

impl tm {
    pub const fn new() -> Self {
        tm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 1,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: -1,
        }
    }
}

/// Division result structures
#[repr(C)]
pub struct div_t {
    pub quot: c_int,
    pub rem: c_int,
}

#[repr(C)]
pub struct ldiv_t {
    pub quot: c_long,
    pub rem: c_long,
}

/// Memory allocation alignment
pub const DEFAULT_ALIGNMENT: usize = 16;
pub const MAX_ALIGNMENT: usize = 4096;
