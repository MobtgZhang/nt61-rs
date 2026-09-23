//! Protected stdio globals using once_cell
//!
//! This module provides thread-safe initialization of stdio streams

use super::types::*;
use core::ptr;

extern crate alloc;
use alloc::vec::Vec;

const FILE_POOL_SIZE: usize = 64;

struct FilePool {
    files: [FILE; FILE_POOL_SIZE],
    initialized: bool,
}

impl FilePool {
    const fn new() -> Self {
        Self {
            files: [FILE::new(); FILE_POOL_SIZE],
            initialized: false,
        }
    }
}

static FILE_POOL: Lazy<Mutex<FilePool>> = Lazy::new(|| {
    Mutex::new(FilePool::new())
});

static STDIN: Lazy<Mutex<FILE>> = Lazy::new(|| {
    let mut file = FILE::new();
    file.handle = 0;
    Mutex::new(file)
});

static STDOUT: Lazy<Mutex<FILE>> = Lazy::new(|| {
    let mut file = FILE::new();
    file.handle = 1;
    Mutex::new(file)
});

static STDERR: Lazy<Mutex<FILE>> = Lazy::new(|| {
    let mut file = FILE::new();
    file.handle = 2;
    Mutex::new(file)
});

#[no_mangle]
pub unsafe extern "C" fn __get_stdin() -> *mut FILE {
    // For now, return null and let callers use file descriptors 0/1/2
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn __get_stdout() -> *mut FILE {
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn __get_stderr() -> *mut FILE {
    ptr::null_mut()
}
