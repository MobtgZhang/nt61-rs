//! Console I/O wrappers (kernel32).

#![allow(dead_code)]

use crate::libs::ntdll::types::{HANDLE, NTSTATUS};

pub const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;

pub fn write_console_w(
    _h: HANDLE,
    _buf: &[u16],
    _chars_written: *mut u32,
    _reserved: *mut (),
) -> Result<(), NTSTATUS> {
    Err(-1)
}

pub fn write_console_a(
    _h: HANDLE,
    _buf: &[u8],
    _chars_written: *mut u32,
    _reserved: *mut (),
) -> Result<(), NTSTATUS> {
    Err(-1)
}

pub fn read_console_w(
    _h: HANDLE,
    _buf: &mut [u16],
    _chars_read: *mut u32,
    _input_control: *mut (),
) -> Result<(), NTSTATUS> {
    Err(-1)
}

pub fn set_console_title_w(_title: &[u16]) -> Result<(), NTSTATUS> {
    Err(-1)
}
