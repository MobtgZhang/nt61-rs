//! C runtime support — what's needed to bring up `main`-style
//! programs without dragging in an external CRT.

#![allow(dead_code)]

/// Entry-point shim: simplest possible equivalent of CRTStartup.
#[no_mangle]
pub extern "system" fn __crt_startup(
    main: extern "system" fn(i32, *mut *mut u8) -> i32,
    argc: i32,
    argv: *mut *mut u8,
) -> i32 {
    main(argc, argv)
}

/// TLS / atexit slot allocation stubs — Phase 3 fills these in.
pub fn _initterm(_table: *const unsafe extern "system" fn()) {}
pub fn _initterm_e(_table: *const unsafe extern "system" fn() -> i32) -> i32 { 0 }

/// SEH trampoline — Phase 3 implements the Win7 SEH4 setup.
pub fn _set_app_type(_app_type: i32) {}

/// Guard check callback list (Phase 3).
pub fn _guard_check_icall_fptr() {}

/// /GS stack-cookie (also defined in `stack.rs`).
#[cfg(target_arch = "x86_64")]
pub fn __security_cookie() -> u64 {
    crate::userspace::stack::__security_cookie()
}

#[cfg(target_arch = "x86_64")]
pub fn __security_check_cookie(cookie: u64) {
    crate::userspace::stack::__security_check_cookie(cookie)
}

// Stubs for non-x86_64 builds.
#[cfg(not(target_arch = "x86_64"))]
pub fn __security_cookie() -> u64 { 0 }

#[cfg(not(target_arch = "x86_64"))]
pub fn __security_check_cookie(_cookie: u64) {}
