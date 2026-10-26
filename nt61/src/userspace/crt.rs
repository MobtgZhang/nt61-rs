//! C runtime support — what's needed to bring up `main`-style
//! programs without dragging in an external CRT.

/// Entry-point shim: simplest possible equivalent of CRTStartup.
#[no_mangle]
pub extern "system" fn __crt_startup(
    main: extern "system" fn(i32, *mut *mut u8) -> i32,
    argc: i32,
    argv: *mut *mut u8,
) -> i32 {
    main(argc, argv)
}

/// Walk a null-terminated table of C initializers and invoke each one,
/// matching the MSVC _initterm contract used by CRT startup code.
pub fn _initterm(table: *const unsafe extern "system" fn()) {
    if table.is_null() {
        return;
    }
    let mut i = 0usize;
    loop {
        let init = unsafe { *table.add(i) };
        if init as usize == 0 {
            break;
        }
        // SAFETY: each entry was emitted by the toolchain as an
        // initializer that runs once, at startup, on the current
        // thread. The table is linker-produced user-mode data.
        unsafe { init() };
        i += 1;
    }
}

/// Walk a null-terminated table of CRT initializers that return an
/// NTSTATUS-style status; abort on the first failure and propagate it,
/// matching the MSVC _initterm_e contract.
pub fn _initterm_e(table: *const unsafe extern "system" fn() -> i32) -> i32 {
    if table.is_null() {
        return 0;
    }
    let mut i = 0usize;
    loop {
        let init = unsafe { *table.add(i) };
        if init as usize == 0 {
            break;
        }
        // SAFETY: same toolchain-emitted-initializer contract as
        // _initterm above.
        let status = unsafe { init() };
        if status != 0 {
            return status;
        }
        i += 1;
    }
    0
}

/// SEH trampoline — Phase 3 implements the Win7 SEH4 setup.
pub fn _set_app_type(_app_type: i32) {}

/// Guard check callback list (Phase 3).
pub fn _guard_check_icall_fptr() {}

pub fn __security_cookie() -> u64 {
    crate::userspace::stack::__security_cookie()
}

pub fn __security_check_cookie(cookie: u64) {
    crate::userspace::stack::__security_check_cookie(cookie)
}
