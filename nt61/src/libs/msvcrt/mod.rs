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
    // crate::kprintln!("    MSVCRT: init")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      memory:  ready (malloc, free, realloc)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      string:  ready (strcpy, strcmp, strlen)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      file:    ready (fopen, fread, fwrite)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      time:    ready (time, localtime)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      stdio:   ready (printf, scanf)")  // kprintln disabled (memcpy crash workaround);
}
