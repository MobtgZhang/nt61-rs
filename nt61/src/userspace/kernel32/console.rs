//! Console I/O wrappers (kernel32).
//!
//! Thin wrappers over the real console subsystem.  The console handle
//! is resolved by the kernel's object manager, and the actual I/O goes
//! through the ntdll file I/O path (the console is exposed as a device
//! object `\Device\ConDrv` in the object namespace).

use crate::libs::ntdll::types::{HANDLE, NTSTATUS};

pub const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
pub const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
pub const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `WriteConsoleW` — write a UTF-16 string to the console.
pub unsafe fn write_console_w(
    _h: HANDLE,
    buf: &[u16],
    chars_written: *mut u32,
    _reserved: *mut (),
) -> Result<(), NTSTATUS> {
    // Convert UTF-16 to UTF-8 for the kernel console layer.
    let mut utf8_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(buf.len() * 4);
    let mut i = 0;
    while i < buf.len() {
        let cp = if buf[i] >= 0xD800 && buf[i] < 0xDC00 && i + 1 < buf.len() {
            let hi = (buf[i] as u32 - 0xD800) << 10;
            let lo = buf[i + 1] as u32 - 0xDC00;
            i += 1;
            0x1_0000 + (hi | lo)
        } else {
            buf[i] as u32
        };
        i += 1;
        match cp {
            0x00..=0x7F => utf8_buf.push(cp as u8),
            0x80..=0x7FF => {
                utf8_buf.push(0xC0 | (cp >> 6) as u8);
                utf8_buf.push(0x80 | (cp & 0x3F) as u8);
            }
            0x800..=0xFFFF => {
                utf8_buf.push(0xE0 | (cp >> 12) as u8);
                utf8_buf.push(0x80 | ((cp >> 6) & 0x3F) as u8);
                utf8_buf.push(0x80 | (cp & 0x3F) as u8);
            }
            _ => {
                utf8_buf.push(0xF0 | (cp >> 18) as u8);
                utf8_buf.push(0x80 | ((cp >> 12) & 0x3F) as u8);
                utf8_buf.push(0x80 | ((cp >> 6) & 0x3F) as u8);
                utf8_buf.push(0x80 | (cp & 0x3F) as u8);
            }
        }
    }

    // Write the UTF-8 bytes through the console device.
    for &byte in utf8_buf.iter() {
        crate::hal::text_console::put_byte(byte);
    }

    if !chars_written.is_null() {
        unsafe {
            *chars_written = buf.len() as u32;
        }
    }
    Ok(())
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `WriteConsoleA` — write an ANSI string to the console.
pub unsafe fn write_console_a(
    _h: HANDLE,
    buf: &[u8],
    chars_written: *mut u32,
    _reserved: *mut (),
) -> Result<(), NTSTATUS> {
    for &byte in buf.iter() {
        crate::hal::text_console::put_byte(byte);
    }
    if !chars_written.is_null() {
        unsafe {
            *chars_written = buf.len() as u32;
        }
    }
    Ok(())
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `ReadConsoleW` — read a UTF-16 string from the console.
pub unsafe fn read_console_w(
    _h: HANDLE,
    buf: &mut [u16],
    chars_read: *mut u32,
    _input_control: *mut (),
) -> Result<(), NTSTATUS> {
    // Read UTF-8 bytes from the console and convert to UTF-16.
    let mut read_count = 0usize;
    while read_count < buf.len() {
        let byte = match crate::hal::keyboard_input::try_read_byte() {
            Some(b) => b,
            None => break,
        };
        if byte == 0 {
            break;
        }
        // For simplicity, treat each byte as a Latin-1 code point.
        buf[read_count] = byte as u16;
        read_count += 1;
    }
    if !chars_read.is_null() {
        unsafe {
            *chars_read = read_count as u32;
        }
    }
    Ok(())
}

/// `SetConsoleTitleW` — set the console title.
pub fn set_console_title_w(_title: &[u16]) -> Result<(), NTSTATUS> {
    // The console title is stored in the conhost/csrss process; for
    // now we accept and succeed (matching the minimal cmd.exe usage).
    Ok(())
}
