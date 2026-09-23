use crate::kprintln;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};


use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, AtomicBool, AtomicPtr, Ordering};
use super::types::*;
use super::string::*;
use core::ptr;

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

const ATEXIT_MAX: usize = 32;

static mut ATEXIT_HANDLERS: [Option<extern "C" fn()>; ATEXIT_MAX] = [None; ATEXIT_MAX];
static ATEXIT_COUNT: AtomicUsize = AtomicUsize::new(0);

static mut AT_QUICK_EXIT_HANDLERS: [Option<extern "C" fn()>; ATEXIT_MAX] = [None; ATEXIT_MAX];
static AT_QUICK_EXIT_COUNT: AtomicUsize = AtomicUsize::new(0);

pub const EXIT_SUCCESS: c_int = 0;
pub const EXIT_FAILURE: c_int = 1;

pub const SIGINT: c_int = 2;   // Interrupt
pub const SIGILL: c_int = 4;   // Illegal instruction
pub const SIGFPE: c_int = 8;   // Floating point exception
pub const SIGSEGV: c_int = 11; // Segmentation fault
pub const SIGTERM: c_int = 15; // Termination request
pub const SIGABRT: c_int = 22; // Abort

pub type SignalHandler = extern "C" fn(c_int);

pub static SIG_DFL: SignalHandler = default_signal_handler;
pub static SIG_IGN: SignalHandler = ignore_signal_handler;

static SIGNAL_HANDLERS: Lazy<Mutex<[SignalHandler; 32]>> = Lazy::new(|| Mutex::new([default_signal_handler; 32]));

extern "C" fn default_signal_handler(sig: c_int) {
    unsafe {
        abort();
    }
}

extern "C" fn ignore_signal_handler(_sig: c_int) {
}

#[no_mangle]
pub unsafe extern "C" fn atexit(func: extern "C" fn()) -> c_int {
    if ATEXIT_COUNT >= ATEXIT_MAX {
        return -1; // Too many handlers
    }

    ATEXIT_HANDLERS[ATEXIT_COUNT] = Some(func);
    ATEXIT_COUNT += 1;
    0
}

#[no_mangle]
pub unsafe extern "C" fn at_quick_exit(func: extern "C" fn()) -> c_int {
    if AT_QUICK_EXIT_COUNT >= ATEXIT_MAX {
        return -1;
    }

    AT_QUICK_EXIT_HANDLERS[AT_QUICK_EXIT_COUNT] = Some(func);
    AT_QUICK_EXIT_COUNT += 1;
    0
}

unsafe fn call_atexit_handlers() {
    for i in (0..ATEXIT_COUNT).rev() {
        if let Some(handler) = ATEXIT_HANDLERS[i] {
            handler();
        }
    }
}

unsafe fn call_quick_exit_handlers() {
    for i in (0..AT_QUICK_EXIT_COUNT).rev() {
        if let Some(handler) = AT_QUICK_EXIT_HANDLERS[i] {
            handler();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn exit(status: c_int) -> ! {
    call_atexit_handlers();

    super::stdio::fflush(ptr::null_mut());


    super::ps_stubs::exit_process(status);
}

#[no_mangle]
pub unsafe extern "C" fn quick_exit(status: c_int) -> ! {
    call_quick_exit_handlers();

    super::ps_stubs::exit_process(status);
}

#[no_mangle]
pub unsafe extern "C" fn _exit(status: c_int) -> ! {
    super::ps_stubs::exit_process(status);
}

#[no_mangle]
pub unsafe extern "C" fn abort() -> ! {
    raise(SIGABRT);

    super::ps_stubs::terminate_process(3); // STATUS_ABORTED
}

#[no_mangle]
pub unsafe extern "C" fn raise(sig: c_int) -> c_int {
    if sig < 0 || sig >= 32 {
        return -1;
    }

    let handler = SIGNAL_HANDLERS[sig as usize];
    handler(sig);

    0
}

#[no_mangle]
pub unsafe extern "C" fn signal(sig: c_int, handler: SignalHandler) -> SignalHandler {
    if sig < 0 || sig >= 32 {
        return SIG_DFL;
    }

    let old_handler = SIGNAL_HANDLERS[sig as usize];
    SIGNAL_HANDLERS[sig as usize] = handler;
    old_handler
}

#[no_mangle]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    if name.is_null() {
        return ptr::null_mut();
    }

    match super::ps_stubs::get_environment_variable(name) {
        Some(value) => value.as_ptr() as *mut c_char,
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn getenv_s(
    len: *mut size_t,
    value: *mut c_char,
    maxsize: size_t,
    name: *const c_char,
) -> errno_t {
    if name.is_null() {
        return EINVAL;
    }

    match super::ps_stubs::get_environment_variable(name) {
        Some(val) => {
            let val_len = strlen(val.as_ptr() as *const c_char);

            if !len.is_null() {
                *len = val_len + 1;
            }

            if !value.is_null() && maxsize > 0 {
                if val_len >= maxsize {
                    *value = 0;
                    return ERANGE;
                }
                strcpy(value, val.as_ptr() as *const c_char);
            }

            0
        }
        None => {
            if !len.is_null() {
                *len = 0;
            }
            if !value.is_null() && maxsize > 0 {
                *value = 0;
            }
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn putenv(string: *mut c_char) -> c_int {
    if string.is_null() {
        return -1;
    }

    let mut i = 0;
    while *string.add(i) != 0 && *string.add(i) != b'=' as c_char {
        i += 1;
    }

    if *string.add(i) != b'=' as c_char {
        return -1; // No '=' found
    }

    let name_end = i;
    let value_start = i + 1;

    let separator = *string.add(name_end);
    *string.add(name_end) = 0;

    let name = string;
    let value = string.add(value_start);

    let result = super::ps_stubs::set_environment_variable(name, value);

    *string.add(name_end) = separator;

    if result { 0 } else { -1 }
}

#[no_mangle]
pub unsafe extern "C" fn system(command: *const c_char) -> c_int {
    if command.is_null() {
        return 1;
    }

    match super::ps_stubs::execute_command(command) {
        Ok(exit_code) => exit_code,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn _get_pgmptr(value: *mut *mut c_char) -> errno_t {
    use alloc::boxed::Box;

    if value.is_null() {
        return EINVAL;
    }

    static PROGRAM_NAME_STORAGE: Lazy<Mutex<Option<Box<alloc::string::String>> = None;
    static mut PROGRAM_NAME: *mut c_char = ptr::null_mut();

    if PROGRAM_NAME.is_null() {
        let name_string = Box::new(super::ps_stubs::get_program_name());
        PROGRAM_NAME = name_string.as_ptr() as *mut c_char;
        PROGRAM_NAME_STORAGE = Some(name_string);
    }

    *value = PROGRAM_NAME;
    0
}

#[no_mangle]
pub unsafe extern "C" fn _getpid() -> c_int {
    super::ps_stubs::get_current_pid() as c_int
}

#[no_mangle]
pub unsafe extern "C" fn _getcwd(buffer: *mut c_char, maxlen: c_int) -> *mut c_char {
    if buffer.is_null() || maxlen <= 0 {
        return ptr::null_mut();
    }

    match super::ps_stubs::get_current_directory() {
        Some(cwd) => {
            let cwd_len = cwd.len();
            if cwd_len >= maxlen as usize {
                return ptr::null_mut();
            }

            for i in 0..cwd_len {
                *buffer.add(i) = cwd.as_bytes()[i] as c_char;
            }
            *buffer.add(cwd_len) = 0;

            buffer
        }
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn _chdir(path: *const c_char) -> c_int {
    if path.is_null() {
        return -1;
    }

    match super::ps_stubs::change_directory(path) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn _wassert(
    message: *const wchar_t,
    file: *const wchar_t,
    line: c_uint,
) -> ! {
    crate::kprintln!("\nAssertion failed!");
    crate::kprintln!("  File: (wide string)");
    crate::kprintln!("  Line: {}", line);

    abort()
}

#[no_mangle]
pub unsafe extern "C" fn _assert(
    message: *const c_char,
    file: *const c_char,
    line: c_uint,
) -> ! {
    if !message.is_null() {
        crate::kprint!("\nAssertion failed: ");
        let mut i = 0;
        while *message.add(i) != 0 {
            crate::kprint!("{}", *message.add(i) as u8 as char);
            i += 1;
        }
        kprintln!(});

    if !file.is_null() {
        crate::kprint!("  File: ");
        let mut i = 0;
        while *file.add(i) != 0 {
            crate::kprint!("{}", *file.add(i) as u8 as char);
            i += 1;
        }
        kprintln!(});

    crate::kprintln!("  Line: {}", line);

    abort()
}

#[no_mangle]
pub unsafe extern "C" fn _set_error_mode(mode: c_int) -> c_int {
    mode
}

#[no_mangle]
pub unsafe extern "C" fn _get_cmdline() -> *mut c_char {

    static CMDLINE_STORAGE: Lazy<Mutex<Option<Box<alloc::string::String>> = None;
    static mut CMDLINE: *mut c_char = ptr::null_mut();

    if CMDLINE.is_null() {
        let cmdline_string = Box::new(super::ps_stubs::get_command_line());
        CMDLINE = cmdline_string.as_ptr() as *mut c_char;
        CMDLINE_STORAGE = Some(cmdline_string);
    }

    CMDLINE
}

#[no_mangle]
pub unsafe extern "C" fn terminate() -> ! {
    abort();
}

#[no_mangle]
pub unsafe extern "C" fn unexpected() -> ! {
    abort();
}

#[no_mangle]
pub unsafe extern "C" fn set_terminate(_handler: extern "C" fn() -> !) -> extern "C" fn() -> ! {
    extern "C" fn dummy_terminate() -> ! {
        unsafe { abort(); }
    }
    dummy_terminate
}

#[no_mangle]
pub unsafe extern "C" fn set_unexpected(_handler: extern "C" fn() -> !) -> extern "C" fn() -> ! {
    extern "C" fn dummy_unexpected() -> ! {
        unsafe { abort(); }
    }
    dummy_unexpected
}

#[no_mangle]
pub unsafe extern "C" fn Sleep(dwMilliseconds: c_ulong) {
    super::hal_stubs::sleep(dwMilliseconds as u64);
}

#[repr(C)]
pub struct timespec {
    pub tv_sec: time_t,
    pub tv_nsec: c_long,
}

#[no_mangle]
pub unsafe extern "C" fn nanosleep(req: *const timespec, rem: *mut timespec) -> c_int {
    if req.is_null() {
        return -1;
    }

    let request = &*req;
    let total_ms = (request.tv_sec * 1000) + (request.tv_nsec as i64 / 1_000_000);

    super::hal_stubs::sleep(total_ms as u64);

    if !rem.is_null() {
        (*rem).tv_sec = 0;
        (*rem).tv_nsec = 0;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn sleep(seconds: c_uint) -> c_uint {
    super::hal_stubs::sleep((seconds as u64) * 1000);
    0
}

#[no_mangle]
pub unsafe extern "C" fn usleep(usec: c_uint) -> c_int {
    let ms = (usec + 999) / 1000; // Round up
    super::hal_stubs::sleep(ms as u64);
    0
}
