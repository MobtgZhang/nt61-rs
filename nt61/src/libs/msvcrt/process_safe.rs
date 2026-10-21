use spin::{Lazy, Mutex};

use super::types::*;
use core::ptr;

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;

struct ProgramNameStorage {
    name: Option<Box<String>>,
    ptr: *mut CChar,
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

pub struct ExitHandlers {
    handlers: [Option<extern "C" fn()>; ATEXIT_MAX],
    count: usize,
}

static ATEXIT_HANDLERS: Lazy<Mutex<ExitHandlers>> = Lazy::new(|| {
    Mutex::new(ExitHandlers {
        handlers: [None; ATEXIT_MAX],
        count: 0,
    })
});

pub static AT_QUICK_EXIT_HANDLERS: Lazy<Mutex<ExitHandlers>> = Lazy::new(|| {
    Mutex::new(ExitHandlers {
        handlers: [None; ATEXIT_MAX],
        count: 0,
    })
});

type SignalHandler = extern "C" fn(CInt);

struct SignalHandlers {
    handlers: [SignalHandler; 32],
}

unsafe impl Send for SignalHandlers {}
unsafe impl Sync for SignalHandlers {}

extern "C" fn default_signal_handler(_sig: CInt) {}

static SIGNAL_HANDLERS: Lazy<Mutex<SignalHandlers>> = Lazy::new(|| {
    Mutex::new(SignalHandlers {
        handlers: [default_signal_handler; 32],
    })
});

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn atexit(func: extern "C" fn()) -> CInt {
    let mut handlers = ATEXIT_HANDLERS.lock();
    if handlers.count >= ATEXIT_MAX {
        return -1;
    }
    let index = handlers.count;
    handlers.handlers[index] = Some(func);
    handlers.count += 1;
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn signal(sig: CInt, handler: SignalHandler) -> SignalHandler {
    if sig < 0 || sig >= 32 {
        return default_signal_handler;
    }

    let mut handlers = SIGNAL_HANDLERS.lock();
    let old_handler = handlers.handlers[sig as usize];
    handlers.handlers[sig as usize] = handler;
    old_handler
}

pub unsafe fn get_program_name_safe() -> *mut CChar {
    let mut storage = PROGRAM_NAME.lock();

    if storage.ptr.is_null() {
        let name_string = Box::new(super::ps_stubs::get_program_name());
        storage.ptr = name_string.as_ptr() as *mut CChar;
        storage.name = Some(name_string);
    }

    storage.ptr
}

pub unsafe fn get_cmdline_safe() -> *mut CChar {
    let mut storage = CMDLINE.lock();

    if storage.ptr.is_null() {
        let cmdline_string = Box::new(super::ps_stubs::get_command_line());
        storage.ptr = cmdline_string.as_ptr() as *mut CChar;
        storage.name = Some(cmdline_string);
    }

    storage.ptr
}
