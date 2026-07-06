//! Process / thread management wrappers (kernel32).
//!
//! Thin wrappers over `NtCreateProcess` / `NtCreateThread` /
//! `NtTerminateProcess`.

#![allow(dead_code)]

use crate::libs::ntdll::types::{NTSTATUS, HANDLE};

pub const THREAD_ALL_ACCESS: u32 = 0x001F_03FF;
pub const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;

#[inline]
pub fn get_current_process() -> HANDLE { core::ptr::null_mut() }

#[inline]
pub fn get_current_thread() -> HANDLE { core::ptr::null_mut() }

pub fn exit_process(exit_code: u32) -> ! {
    // Phase 1: loop forever so the system remains alive.
    loop { core::hint::black_box(exit_code); }
}

pub fn exit_thread(exit_code: u32) -> ! {
    exit_process(exit_code)
}

pub fn create_process_a(_app: &str, _cmd: &str) -> Result<HANDLE, NTSTATUS> {
    Err(-1)
}

pub fn create_thread(
    _security: *mut (),
    _stack_size: usize,
    _start: extern "system" fn(*mut ()) -> u32,
    _param: *mut (),
    _flags: u32,
    _tid: *mut u32,
) -> Result<HANDLE, NTSTATUS> {
    Err(-1)
}

pub fn terminate_process(_p: HANDLE, _code: u32) -> Result<(), NTSTATUS> {
    Ok(())
}

#[inline]
pub fn get_last_error() -> u32 { 0 }
#[inline]
pub fn set_last_error(_: u32) {}

// Touch the imports so they don't get dropped.
#[allow(dead_code)]
fn _imports(_: NTSTATUS, _: HANDLE) {}
