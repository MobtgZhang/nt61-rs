//! Thread-safe process globals
//!
//! Replaces unsafe static mut with synchronized access

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, AtomicI32, AtomicI64, AtomicPtr, Ordering};
use super::types::*;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;

struct ProgramNameStorage {
    name: Option<Box<String>>,
    ptr: *mut c_char,
}

unsafe impl Send for ProgramNameStorage {}
unsafe impl Sync for ProgramNameStorage {}

static PROGRAM_NAME: Lazy<Mutex<ProgramNameStorage>> = Lazy::new(|| {
    Mutex::new(ProgramNameStorage {
        name: None,
        ptr: ptr::null_mut(),
    })
});

static CMDLINE: Lazy<Mutex<ProgramNameStorage>> = Lazy::new(|| {
    Mutex::new(ProgramNameStorage {
        name: None,
        ptr: ptr::null_mut(),
    })
});

const ATEXIT_MAX: usize = 128;

struct ExitHandlers {
    handlers: [Option<extern "C" fn()>; ATEXIT_MAX],
    count: usize,
}

static ATEXIT_HANDLERS: Lazy<Mutex<ExitHandlers>> = Lazy::new(|| {
    Mutex::new(ExitHandlers {
        handlers: [None; ATEXIT_MAX],
        count: 0,
    })
});

static AT_QUICK_EXIT_HANDLERS: Lazy<Mutex<ExitHandlers>> = Lazy::new(|| {
    Mutex::new(ExitHandlers {
        handlers: [None; ATEXIT_MAX],
        count: 0,
    })
});

type SignalHandler = extern "C" fn(c_int);

struct SignalHandlers {
    handlers: [SignalHandler; 32],
}

unsafe impl Send for SignalHandlers {}
unsafe impl Sync for SignalHandlers {}

fn default_signal_handler(_sig: c_int) {
}

static SIGNAL_HANDLERS: Lazy<Mutex<SignalHandlers>> = Lazy::new(|| {
    Mutex::new(SignalHandlers {
        handlers: [default_signal_handler; 32],
    })
});

#[no_mangle]
pub unsafe extern "C" fn atexit(func: extern "C" fn()) -> c_int {
    let mut handlers = ATEXIT_HANDLERS.lock();
    if handlers.count >= ATEXIT_MAX {
        return -1;
    }
    handlers.handlers[handlers.count] = Some(func);
    handlers.count += 1;
    0
}

#[no_mangle]
pub unsafe extern "C" fn signal(sig: c_int, handler: SignalHandler) -> SignalHandler {
    if sig < 0 || sig >= 32 {
        return default_signal_handler;
    }

    let mut handlers = SIGNAL_HANDLERS.lock();
    let old_handler = handlers.handlers[sig as usize];
    handlers.handlers[sig as usize] = handler;
    old_handler
}

pub unsafe fn get_program_name_safe() -> *mut c_char {
    let mut storage = PROGRAM_NAME.lock();

    if storage.ptr.is_null() {
        let name_string = Box::new(super::ps_stubs::get_program_name());
        storage.ptr = name_string.as_ptr() as *mut c_char;
        storage.name = Some(name_string);
    }

    storage.ptr
}

pub unsafe fn get_cmdline_safe() -> *mut c_char {
    let mut storage = CMDLINE.lock();

    if storage.ptr.is_null() {
        let cmdline_string = Box::new(super::ps_stubs::get_command_line());
        storage.ptr = cmdline_string.as_ptr() as *mut c_char;
        storage.name = Some(cmdline_string);
    }

    storage.ptr
}
