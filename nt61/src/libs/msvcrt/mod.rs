//! msvcrt.dll — Microsoft Visual C Runtime
//
//! Provides the C runtime library functions (printf, malloc, strcpy, etc.)
//! for programs compiled with MSVC. This is a stub implementation
//! that provides the basic CRT entry points.
//
//! Clean-room implementation. Spec source: MSVCRT documentation,
//! Microsoft Visual Studio headers.

// msvcrt uses C-runtime naming (printf, malloc, ...). The Win32
// surface uses Win32 naming (errno_t, _vsnprintf_l, ...).
#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use crate::kprintln;

/// Initialize the CRT stub.
pub fn init() {
    // crate::kprintln!("    MSVCRT: init");
    // crate::kprintln!("      memory:  ready (malloc, free, realloc)");
    // crate::kprintln!("      string:  ready (strcpy, strcmp, strlen)");
    // crate::kprintln!("      file:    ready (fopen, fread, fwrite)");
    // crate::kprintln!("      time:    ready (time, localtime)");
    // crate::kprintln!("      stdio:   ready (printf, scanf)");
}

pub mod buffered_io;
pub mod convert;
pub mod crt_stats_safe;
pub mod hal_stubs;
pub mod io_stubs;
pub mod locale_safe;
pub mod math;
pub mod memory;
pub mod printf_parser;
pub mod process_safe;
pub mod ps_stubs;
pub mod scanf_parser;
pub mod stdio;
pub mod stdio_safe;
pub mod string;
pub mod string_safe;
pub mod time_safe;
pub mod tls_errno_safe;
pub mod types;
pub mod wchar;
