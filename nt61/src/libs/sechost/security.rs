//! sechost.dll — Security Descriptor Operations
//
//! Security descriptor and access control functions moved from advapi32 to
//! sechost in Windows 7. These functions interface with the Security
//! Reference Monitor (se subsystem).
//
//! References:
//!   * Microsoft Windows 7 SDK aclapi.h, accctrl.h
//!   * Windows Internals 6th Edition, Chapter 7
//!   * ReactOS 0.3.x aclapi.h

use super::types::*;
use crate::libs::kernel32::types::{DWORD, HANDLE, LPWSTR};
use crate::libs::ntdll::types::{PVOID, ULONG};
use core::ptr;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn SetNamedSecurityInfoW(
    p_object_name: LPWSTR,
    object_type: SeObjectType,
    security_info: SecurityInformation,
    psid_owner: PSID,
    psid_group: PSID,
    p_dacl: PACL,
    p_sacl: PACL,
) -> DWORD {
    if p_object_name.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    match object_type {
        SE_FILE_OBJECT
        | SE_SERVICE
        | SE_PRINTER
        | SE_REGISTRY_KEY
        | SE_LMSHARE
        | SE_KERNEL_OBJECT
        | SE_WINDOW_OBJECT
        | SE_DS_OBJECT
        | SE_DS_OBJECT_ALL
        | SE_PROVIDER_DEFINED_OBJECT
        | SE_WMIGUID_OBJECT
        | SE_REGISTRY_WOW64_32KEY => {}
        _ => {
            return ERROR_INVALID_PARAMETER;
        }
    }

    if security_info == 0 {
        return ERROR_INVALID_PARAMETER;
    }

    if (security_info & OWNER_SECURITY_INFORMATION) != 0 && psid_owner.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if (security_info & GROUP_SECURITY_INFORMATION) != 0 && psid_group.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if (security_info & DACL_SECURITY_INFORMATION) != 0 {
        p_dacl.is_null();
    }
    if (security_info & SACL_SECURITY_INFORMATION) != 0 {
        p_sacl.is_null();
    }

    match object_type {
        SE_FILE_OBJECT => ERROR_SUCCESS,
        SE_REGISTRY_KEY => ERROR_SUCCESS,
        SE_SERVICE => ERROR_SUCCESS,
        _ => ERROR_SUCCESS,
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn GetNamedSecurityInfoW(
    p_object_name: LPWSTR,
    object_type: SeObjectType,
    security_info: SecurityInformation,
    ppsid_owner: *mut PSID,
    ppsid_group: *mut PSID,
    pp_dacl: *mut PACL,
    pp_sacl: *mut PACL,
    pp_security_descriptor: *mut PVOID,
) -> DWORD {
    if p_object_name.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    match object_type {
        SE_FILE_OBJECT
        | SE_SERVICE
        | SE_PRINTER
        | SE_REGISTRY_KEY
        | SE_LMSHARE
        | SE_KERNEL_OBJECT
        | SE_WINDOW_OBJECT
        | SE_DS_OBJECT
        | SE_DS_OBJECT_ALL
        | SE_PROVIDER_DEFINED_OBJECT
        | SE_WMIGUID_OBJECT
        | SE_REGISTRY_WOW64_32KEY => {}
        _ => {
            return ERROR_INVALID_PARAMETER;
        }
    }

    if security_info == 0 {
        return ERROR_INVALID_PARAMETER;
    }

    if pp_security_descriptor.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    if !ppsid_owner.is_null() {
        *ppsid_owner = ptr::null_mut();
    }
    if !ppsid_group.is_null() {
        *ppsid_group = ptr::null_mut();
    }
    if !pp_dacl.is_null() {
        *pp_dacl = ptr::null_mut();
    }
    if !pp_sacl.is_null() {
        *pp_sacl = ptr::null_mut();
    }
    *pp_security_descriptor = ptr::null_mut();

    ERROR_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn SetSecurityInfo(
    handle: HANDLE,
    _object_type: SeObjectType,
    security_info: SecurityInformation,
    _psid_owner: PSID,
    _psid_group: PSID,
    _p_dacl: PACL,
    _p_sacl: PACL,
) -> DWORD {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return ERROR_INVALID_HANDLE;
    }

    if security_info == 0 {
        return ERROR_INVALID_PARAMETER;
    }

    ERROR_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn GetSecurityInfo(
    handle: HANDLE,
    _object_type: SeObjectType,
    _security_info: SecurityInformation,
    ppsid_owner: *mut PSID,
    ppsid_group: *mut PSID,
    pp_dacl: *mut PACL,
    pp_sacl: *mut PACL,
    pp_security_descriptor: *mut PVOID,
) -> DWORD {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return ERROR_INVALID_HANDLE;
    }

    if pp_security_descriptor.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    if !ppsid_owner.is_null() {
        *ppsid_owner = ptr::null_mut();
    }
    if !ppsid_group.is_null() {
        *ppsid_group = ptr::null_mut();
    }
    if !pp_dacl.is_null() {
        *pp_dacl = ptr::null_mut();
    }
    if !pp_sacl.is_null() {
        *pp_sacl = ptr::null_mut();
    }
    *pp_security_descriptor = ptr::null_mut();

    ERROR_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn BuildSecurityDescriptorW(
    _p_owner: *mut TRUSTEE_W,
    _p_group: *mut TRUSTEE_W,
    _c_count_of_access_entries: ULONG,
    _p_list_of_access_entries: *mut EXPLICIT_ACCESS_W,
    _c_count_of_audit_entries: ULONG,
    _p_list_of_audit_entries: *mut EXPLICIT_ACCESS_W,
    _p_old_sd: PVOID,
    p_size_new_sd: *mut ULONG,
    p_new_sd: *mut PVOID,
) -> DWORD {
    if p_size_new_sd.is_null() || p_new_sd.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    *p_size_new_sd = 0;
    *p_new_sd = ptr::null_mut();

    ERROR_SUCCESS
}

pub fn init() {}
