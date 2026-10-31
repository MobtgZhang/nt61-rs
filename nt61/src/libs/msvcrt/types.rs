//! C Runtime Library Types
//!
//! Defines C types, structures, and constants used throughout msvcrt.

pub use core::ffi::c_void;

// Standard C types
pub type CChar = i8;
pub type CUchar = u8;
pub type CShort = i16;
pub type CUshort = u16;
pub type CInt = i32;
pub type CUint = u32;
pub type CLong = i32;
pub type CUlong = u32;
pub type CLonglong = i64;
pub type CUlonglong = u64;
pub type CFloat = f32;
pub type CDouble = f64;

pub type SizeT = usize;
pub type SsizeT = isize;
pub type PtrdiffT = isize;
pub type IntptrT = isize;
pub type UintptrT = usize;

pub type WcharT = u16;
pub type ErrnoT = CInt;
pub type TimeT = i64;
pub type ClockT = i64;

// File types
pub const EOF: CInt = -1;
pub const SEEK_SET: CInt = 0;
pub const SEEK_CUR: CInt = 1;
pub const SEEK_END: CInt = 2;

pub const BUFSIZ: usize = 512;
pub const FILENAME_MAX: usize = 260;
pub const FOPEN_MAX: usize = 20;

// Error codes
pub const EINVAL: CInt = 22;
pub const ENOMEM: CInt = 12;
pub const ERANGE: CInt = 34;
pub const EBADF: CInt = 9;
pub const EIO: CInt = 5;

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

// FILE objects are only reachable through the mutex-guarded pools that own
// them, so sharing them across threads is sound as long as access goes
// through the guard.
unsafe impl Send for FILE {}

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

impl Default for FILE {
    fn default() -> Self {
        Self::new()
    }
}

// FILE flags
pub const _IOFBF: CInt = 0; // Full buffering
pub const _IOLBF: CInt = 1; // Line buffering
pub const _IONBF: CInt = 2; // No buffering

/// Time structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct tm {
    pub tm_sec: CInt,   // seconds after the minute [0, 60]
    pub tm_min: CInt,   // minutes after the hour [0, 59]
    pub tm_hour: CInt,  // hours since midnight [0, 23]
    pub tm_mday: CInt,  // day of the month [1, 31]
    pub tm_mon: CInt,   // months since January [0, 11]
    pub tm_year: CInt,  // years since 1900
    pub tm_wday: CInt,  // days since Sunday [0, 6]
    pub tm_yday: CInt,  // days since January 1 [0, 365]
    pub tm_isdst: CInt, // Daylight Saving Time flag
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

impl Default for tm {
    fn default() -> Self {
        Self::new()
    }
}

/// Division result structures
#[repr(C)]
pub struct div_t {
    pub quot: CInt,
    pub rem: CInt,
}

#[repr(C)]
pub struct ldiv_t {
    pub quot: CLong,
    pub rem: CLong,
}

/// Memory allocation alignment
pub const DEFAULT_ALIGNMENT: usize = 16;
pub const MAX_ALIGNMENT: usize = 4096;
