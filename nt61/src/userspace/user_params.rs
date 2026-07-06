//! Per-process startup parameter packaging.
//!
//! `RTL_USER_PROCESS_PARAMETERS` is a sizeable structure containing
//! Unicode copies of the command line, image path, current working
//! directory, DLL search path, and environment. SMSS builds the
//! initial block; `peb::ProcessParameters` holds the pointer.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

extern crate alloc;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;

use crate::libs::ntdll::types::{
    NTSTATUS, UNICODE_STRING, WCHAR,
};
#[cfg(target_arch = "x86_64")]
use crate::userspace::peb_teb::{Peb, RtlUserProcessParameters};

/// Convert a UTF-8 Rust string into a UTF-16 `u16` vector and zero-
/// terminate it.
pub fn utf8_to_utf16(s: &str) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::with_capacity(s.len() + 1);
    for c in s.encode_utf16() {
        out.push(c);
    }
    out.push(0);
    out
}

/// Stub for `alloc::vec::Vec` — when the `alloc` crate is not linked
/// we use the heap stub defined in `userspace::kernel32::heap`.
pub use crate::userspace::kernel32::heap::HeapVec as Vec;

/// Build a `RTL_USER_PROCESS_PARAMETERS` block in kernel memory and
/// return its virtual pointer.
pub fn build_process_parameters(
    image_path: &[u16],
    cmd_line: &[u16],
    current_dir: &[u16],
    env_block: &[u16],
) -> Result<*mut RtlUserProcessParameters, NTSTATUS> {
    let params = RtlUserProcessParameters {
        MaximumLength: size_of::<RtlUserProcessParameters>() as u32,
        Length: size_of::<RtlUserProcessParameters>() as u32,
        Flags: 0,
        DebugFlags: 0,
        ConsoleHandle: ptr::null_mut(),
        ConsoleFlags: 0,
        StandardInput: ptr::null_mut(),
        StandardOutput: ptr::null_mut(),
        StandardError: ptr::null_mut(),
        CurrentDirectory: crate::userspace::peb_teb::CURDIR {
            Handle: ptr::null_mut(),
            DosPath: UNICODE_STRING {
                Length: (current_dir.len() * 2) as u16,
                MaximumLength: ((current_dir.len() + 1) * 2) as u16,
                Buffer: current_dir.as_ptr() as *mut WCHAR,
            },
        },
        DllPath: UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: ptr::null_mut(),
        },
        ImagePathName: UNICODE_STRING {
            Length: (image_path.len() * 2) as u16,
            MaximumLength: ((image_path.len() + 1) * 2) as u16,
            Buffer: image_path.as_ptr() as *mut WCHAR,
        },
        CommandLine: UNICODE_STRING {
            Length: (cmd_line.len() * 2) as u16,
            MaximumLength: ((cmd_line.len() + 1) * 2) as u16,
            Buffer: cmd_line.as_ptr() as *mut WCHAR,
        },
        Environment: env_block.as_ptr() as *mut c_void,
        EnvironmentSize: (env_block.len() * 2) as u32,
        StartingX: 0,
        StartingY: 0,
        CountX: 0,
        CountY: 0,
        CountCharsX: 0,
        CountCharsY: 0,
        FillAttribute: 0,
        WindowFlags: 0,
        ShowWindowFlags: 0,
        WindowTitle: UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: ptr::null_mut(),
        },
        DesktopInfo: UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: ptr::null_mut(),
        },
        ShellInfo: UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: ptr::null_mut(),
        },
        RuntimeData: UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: ptr::null_mut(),
        },
        CurrentDirectories: [crate::userspace::peb_teb::RTL_DRIVE_LETTER_CURDIR {
            Flags: 0, Length: 0, TimeStamp: 0,
            DosPath: UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: ptr::null_mut(),
            },
        }; 32],
        EnvironmentVersion: 0,
        PackageDependencyList: ptr::null_mut(),
    };
    // Heap-allocate the block and hand the raw pointer back to the
    // caller (which will write it into PEB.ProcessParameters).
    use alloc::alloc::{alloc, Layout};
    let layout = Layout::new::<RtlUserProcessParameters>();
    let raw = unsafe { alloc(layout) as *mut RtlUserProcessParameters };
    if raw.is_null() { return Err(-0x0FFF_FFFFi32 as NTSTATUS); }
    unsafe { ptr::write(raw, params); }
    Ok(raw)
}

/// Update PEB.ProcessParameters with a fresh block.
pub fn install_process_parameters(
    peb: *mut Peb,
    params: *mut RtlUserProcessParameters,
) -> NTSTATUS {
    if peb.is_null() || params.is_null() { return -1i32; }
    unsafe { (*peb).ProcessParameters = params; }
    0
}

// Keep the unused-import warning at bay when minimal_stub is removed.
#[allow(dead_code)]
fn _silence(_: *mut RtlUserProcessParameters) {}
