//! DLL loading (kernel32).

#![allow(dead_code)]

use crate::libs::ntdll::types::{HANDLE, NTSTATUS};

pub fn load_library_w(_name: &[u16]) -> Result<HANDLE, NTSTATUS> {
    Err(-1)
}

pub fn get_proc_address(_module: HANDLE, _name: &[u8]) -> Option<unsafe extern "system" fn() -> isize> {
    None
}

pub fn free_library(_h: HANDLE) -> Result<(), NTSTATUS> { Ok(()) }
