//! Per-process startup parameter packaging.
//!
//! `RTL_USER_PROCESS_PARAMETERS` contains copies of the command line, image
//! path, current working directory, DLL search path, and environment.  The
//! strings are allocated in the same block as the structure so that callers can
//! hand the block to the process creator without exposing dangling temporaries.

extern crate alloc;

use crate::libs::ntdll::types::NTSTATUS;
use crate::ps::process::UnicodeString;
use crate::userspace::peb_teb::{peb, RtlUserProcessParameters};
use alloc::alloc::{alloc, Layout};
use core::ptr;

/// Convert a UTF-8 Rust string into a NUL-terminated UTF-16 vector.
pub fn utf8_to_utf16(s: &str) -> alloc::vec::Vec<u16> {
    let mut out: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(s.len() + 1);
    out.extend(s.encode_utf16());
    out.push(0);
    out
}

fn aligned_size(bytes: usize) -> usize {
    (bytes + 7) & !7
}

unsafe fn place_string(target: &mut UnicodeString, text: &[u16], cursor: &mut *mut u16) {
    let length = text.len().min(0x7FFF);
    let maximum_length = (length + 1).min(0x8000);
    let buffer = *cursor;
    for (index, value) in text.iter().take(length).enumerate() {
        buffer.add(index).write(*value);
    }
    buffer.add(length).write(0);
    target.length = (length * 2) as u16;
    target.maximum_length = (maximum_length * 2) as u16;
    target.buffer = buffer;
    *cursor = buffer.add(maximum_length);
}

fn required_size(
    image_path: &[u16],
    command_line: &[u16],
    current_dir: &[u16],
    env_block: &[u16],
) -> usize {
    let string_bytes =
        (image_path.len() + command_line.len() + current_dir.len() + env_block.len() + 4) * 2;
    core::mem::size_of::<RtlUserProcessParameters>() + aligned_size(string_bytes)
}

/// Build an `RTL_USER_PROCESS_PARAMETERS` block and its backing strings.
pub fn build_process_parameters(
    image_path: &[u16],
    command_line: &[u16],
    current_dir: &[u16],
    env_block: &[u16],
) -> Result<*mut RtlUserProcessParameters, NTSTATUS> {
    let size = required_size(image_path, command_line, current_dir, env_block);
    let layout = Layout::from_size_align(size, 8).map_err(|_| STATUS_NO_MEMORY)?;
    let raw = unsafe { alloc(layout) } as *mut RtlUserProcessParameters;
    if raw.is_null() {
        return Err(STATUS_NO_MEMORY);
    }

    unsafe {
        ptr::write_bytes(raw as *mut u8, 0, size);
        ptr::write(raw, RtlUserProcessParameters::new());
        let mut cursor = raw.add(1) as *mut u16;

        (*raw).length = core::mem::size_of::<RtlUserProcessParameters>() as u32;
        (*raw).flags = 0x200000;
        place_string(
            &mut (*raw).current_directory.dos_path,
            current_dir,
            &mut cursor,
        );
        place_string(&mut (*raw).image_path_name, image_path, &mut cursor);
        place_string(&mut (*raw).command_line, command_line, &mut cursor);

        let env_length = env_block.len().min(0x7FFF);
        (*raw).environment = cursor as u64;
        for (index, value) in env_block.iter().take(env_length).enumerate() {
            cursor.add(index).write(*value);
        }
        cursor.add(env_length).write(0);
        (*raw).environment_size = ((env_length + 1) * 2) as u32;
    }

    Ok(raw)
}

/// Install a process parameter block in the current process PEB.
pub fn install_process_parameters(
    peb: *mut peb,
    params: *mut RtlUserProcessParameters,
) -> NTSTATUS {
    if peb.is_null() || params.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        (*peb).process_parameters = params;
    }
    0
}

const STATUS_NO_MEMORY: NTSTATUS = -0x0FFF_FFFFi32 as NTSTATUS;
const STATUS_INVALID_PARAMETER: NTSTATUS = -0x0FFF_FFF9i32 as NTSTATUS;
