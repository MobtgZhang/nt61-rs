//! kernel32 — module loading
//
//! `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryW`,
//! `FreeLibrary`, `GetModuleFileNameW`, `EnumProcessModules`.
//! Wraps `ntdll!Ldr*`.

extern crate alloc;

use super::error::{GetLastError, SetLastError};
use super::types::{BOOL, DWORD, FALSE, HANDLE, HMODULE, LPCSTR, LPCWSTR, TRUE};
use crate::libs::ntdll::ldr as ntdll_ldr;
use crate::libs::ntdll::status::{STATUS_NOT_FOUND, STATUS_SUCCESS};
use crate::libs::ntdll::types::{UnicodeString};
use alloc::string::String;
use core::ptr;

unsafe fn wide_to_string(p: *const u16) -> Option<String> {
    if p.is_null() { return None; }
    let mut len = 0;
    while *p.add(len) != 0 { len += 1; }
    let slice = core::slice::from_raw_parts(p, len);
    let mut out = String::new();
    for &c in slice {
        if let Some(ch) = char::from_u32(c as u32) { out.push(ch); }
    }
    Some(out)
}

fn build_us(name: &str) -> UnicodeString {
    let mut buf: [u16; 256] = [0; 256];
    let mut i = 0;
    for c in name.encode_utf16() {
        if i + 1 >= buf.len() { break; }
        buf[i] = c;
        i += 1;
    }
    buf[i] = 0;
    UnicodeString {
        Length: (i * 2) as u16,
        MaximumLength: ((i + 1) * 2) as u16,
        Buffer: buf.as_mut_ptr(),
    }
}

fn map_status(s: i32) -> u32 {
    if s == STATUS_SUCCESS { return 0; }
    let code = match s {
        STATUS_NOT_FOUND => 126, // ERROR_MOD_NOT_FOUND
        _ => 0xDEAD_BEEF,
    };
    SetLastError(code);
    code
}

/// `GetModuleHandleW`.
pub unsafe extern "C" fn GetModuleHandleW(module_name: LPCWSTR) -> HMODULE {
    if module_name.is_null() {
        // Return the address of the calling image's base.
        return crate::loader::get_self_image_base() as HMODULE;
    }
    let name = match wide_to_string(module_name) {
        Some(s) => s,
        None => { SetLastError(123); return ptr::null_mut(); },
    };
    let mut us = build_us(&name);
    let mut h: HANDLE = ptr::null_mut();
    let status = ntdll_ldr::LdrGetDllHandle(0, ptr::null_mut(), &mut us, &mut h);
    if status != STATUS_SUCCESS {
        map_status(status);
        return ptr::null_mut();
    }
    h as HMODULE
}

/// `GetProcAddress`.
pub unsafe extern "C" fn GetProcAddress(module: HMODULE, proc_name: LPCSTR) -> super::types::FARPROC {
    if module.is_null() || proc_name.is_null() {
        SetLastError(87);
        return core::mem::transmute(ptr::null::<u8>())
    }
    // Read the name.
    let mut len = 0;
    while *proc_name.add(len) != 0 { len += 1; }
    let name_bytes = core::slice::from_raw_parts(proc_name as *const u8, len);
    let name_str = String::from_utf8_lossy(name_bytes).into_owned();
    let mut us = build_us(&name_str);
    let mut p = ptr::null_mut::<core::ffi::c_void>();
    let status = ntdll_ldr::LdrGetProcedureAddress(module as *mut core::ffi::c_void, &mut us, 0, &mut p);
    if status != STATUS_SUCCESS {
        map_status(status);
        return core::mem::transmute(ptr::null::<u8>())
    }
    core::mem::transmute(p)
}

/// `LoadLibraryW`.
pub unsafe extern "C" fn LoadLibraryW(file_name: LPCWSTR) -> HMODULE {
    if file_name.is_null() { SetLastError(87); return ptr::null_mut(); }
    let name = match wide_to_string(file_name) {
        Some(s) => s,
        None => { SetLastError(123); return ptr::null_mut(); },
    };
    let mut us = build_us(&name);
    let mut h: HANDLE = ptr::null_mut();
    let status = ntdll_ldr::LdrLoadDll(0, ptr::null_mut(), &mut us, &mut h);
    if status != STATUS_SUCCESS {
        map_status(status);
        return ptr::null_mut();
    }
    h as HMODULE
}

/// `FreeLibrary` — unloads the module. The bootstrap does
/// not really unload anything; we just remove the LDR entry.
pub unsafe extern "C" fn FreeLibrary(module: HMODULE) -> BOOL {
    let status = ntdll_ldr::LdrUnloadDll(module as HANDLE);
    if status == STATUS_SUCCESS { TRUE } else {
        map_status(status);
        FALSE
    }
}

/// `GetModuleFileNameW`.
pub unsafe extern "C" fn GetModuleFileNameW(
    module: HMODULE,
    buffer: *mut u16,
    buffer_size: DWORD,
) -> DWORD {
    let _ = module;
    if buffer.is_null() || buffer_size == 0 { return 0; }
    let path: [u16; 28] = [
        b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16,
        b'C' as u16, b':' as u16, b'\\' as u16, b'W' as u16, b'i' as u16, b'n' as u16, b'd' as u16,
        b'o' as u16, b'w' as u16, b's' as u16, b'\\' as u16, b'S' as u16, b'y' as u16, b's' as u16,
        b't' as u16, b'e' as u16, b'm' as u16, b'3' as u16, b'2' as u16, b'\\' as u16,
        b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16,
    ];
    let copy = path.len().min(buffer_size as usize);
    ptr::copy_nonoverlapping(path.as_ptr(), buffer, copy);
    copy as DWORD
}

/// `EnumProcessModules` — we only have one loaded module
/// (the calling process image).
pub unsafe extern "C" fn EnumProcessModules(
    process: HANDLE,
    modules: *mut HMODULE,
    buffer_size: DWORD,
    bytes_needed: *mut DWORD,
) -> BOOL {
    let _ = process;
    if modules.is_null() { SetLastError(87); return FALSE; }
    if buffer_size < 8 { SetLastError(122); return FALSE; }
    let p = crate::loader::get_self_image_base() as HMODULE;
    ptr::write(modules, p);
    if !bytes_needed.is_null() { *bytes_needed = 8; }
    TRUE
}

/// `GetCurrentProcess` — pseudo-handle.
pub extern "C" fn GetCurrentProcess() -> HANDLE {
    super::types::HANDLE_CURRENT_PROCESS
}

/// `GetCurrentThread` — pseudo-handle.
pub extern "C" fn GetCurrentThread() -> HANDLE {
    super::types::HANDLE_CURRENT_THREAD
}

/// `GetCurrentProcessId` — return the kernel's idea of
/// the current PID.
pub extern "C" fn GetCurrentProcessId() -> DWORD {
    crate::ps::process::PID_SYSTEM as u32
}

/// `GetCurrentThreadId` — return the kernel's idea of the
/// current TID.
pub extern "C" fn GetCurrentThreadId() -> DWORD {
    crate::ps::process::PID_SYSTEM.wrapping_add(1) as u32
}
