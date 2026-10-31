//! DLL loading (kernel32).
//!
//! Thin wrappers over `LdrLoadDll` / `LdrGetDllHandle` /
//! `LdrGetProcedureAddress` / `LdrUnloadDll` in ntdll.  The LDR layer
//! tracks loaded images in the PEB's InLoadOrderModuleList, so these
//! functions simply forward and convert types.

use crate::libs::ntdll::types::{HANDLE, NTSTATUS};

/// `LoadLibraryW` — load a DLL by name.
pub fn load_library_w(name: &[u16]) -> Result<HANDLE, NTSTATUS> {
    // Build a null-terminated wide string.
    let mut wbuf: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(name.len() + 1);
    wbuf.extend_from_slice(name);
    wbuf.push(0);

    let mut us = crate::libs::ntdll::types::UnicodeString::default();
    unsafe {
        crate::libs::ntdll::string::rtl_init_unicode_string(&mut us, wbuf.as_ptr());
    }

    let mut handle: HANDLE = core::ptr::null_mut();
    let status = unsafe {
        crate::libs::ntdll::ldr::ldr_load_dll(0, core::ptr::null_mut(), &mut us, &mut handle)
    };

    if status >= 0 {
        Ok(handle)
    } else {
        Err(status)
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `GetProcAddress` — resolve an export by name.
pub unsafe fn get_proc_address(
    module: HANDLE,
    name: &[u8],
) -> Option<unsafe extern "system" fn() -> isize> {
    // Build a null-terminated ANSI string and wrap in a UnicodeString
    // (the LDR layer expects a wide string; we upcast ASCII → UTF-16).
    let mut wbuf: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(name.len() + 1);
    for &b in name.iter() {
        wbuf.push(b as u16);
    }
    wbuf.push(0);

    let mut us = crate::libs::ntdll::types::UnicodeString::default();
    unsafe {
        crate::libs::ntdll::string::rtl_init_unicode_string(&mut us, wbuf.as_ptr());
    }

    let mut addr: crate::libs::ntdll::types::PVOID = core::ptr::null_mut();
    let status = unsafe {
        crate::libs::ntdll::ldr::ldr_get_procedure_address(
            module, &mut us, 0, // ordinal (unused when name is provided)
            &mut addr,
        )
    };

    if status >= 0 && !addr.is_null() {
        // Safety: the caller assumes the resolved address points at a
        // function with the declared signature (matching real Windows).
        Some(unsafe {
            core::mem::transmute::<*mut core::ffi::c_void, unsafe extern "system" fn() -> isize>(
                addr,
            )
        })
    } else {
        None
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `FreeLibrary` — unload a DLL.
pub unsafe fn free_library(h: HANDLE) -> Result<(), NTSTATUS> {
    let status = unsafe { crate::libs::ntdll::ldr::ldr_unload_dll(h) };
    if status >= 0 {
        Ok(())
    } else {
        Err(status)
    }
}
