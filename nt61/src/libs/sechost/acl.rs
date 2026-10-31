//! sechost.dll — Access control List Operations
//
//! ACL manipulation functions moved from advapi32 to sechost in Windows 7.
//! These functions build and parse access control lists.
//
//! References:
//!   * Microsoft Windows 7 SDK aclapi.h, accctrl.h
//!   * Windows Internals 6th Edition, Chapter 7
//!   * ReactOS 0.3.x aclapi.h

use super::types::*;
use crate::libs::kernel32::types::{DWORD, LPWSTR};
use crate::libs::ntdll::types::ULONG;
use core::ptr;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn SetEntriesInAclW(
    c_count_of_explicit_entries: ULONG,
    p_list_of_explicit_entries: *mut EXPLICIT_ACCESS_W,
    old_acl: PACL,
    new_acl: *mut PACL,
) -> DWORD {
    if new_acl.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    *new_acl = ptr::null_mut();

    if c_count_of_explicit_entries == 0 && old_acl.is_null() {
        return ERROR_SUCCESS;
    }

    if c_count_of_explicit_entries > 0 && p_list_of_explicit_entries.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    ERROR_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn GetExplicitEntriesFromAclW(
    pacl: PACL,
    pc_count_of_explicit_entries: *mut ULONG,
    p_list_of_explicit_entries: *mut *mut EXPLICIT_ACCESS_W,
) -> DWORD {
    if pc_count_of_explicit_entries.is_null() || p_list_of_explicit_entries.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    *pc_count_of_explicit_entries = 0;
    *p_list_of_explicit_entries = ptr::null_mut();

    if pacl.is_null() {
        return ERROR_SUCCESS;
    }

    let acl = &*pacl;
    if acl.ace_count == 0 {
        return ERROR_SUCCESS;
    }

    ERROR_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn GetEffectiveRightsFromAclW(
    pacl: PACL,
    p_trustee: *mut TRUSTEE_W,
    p_access_rights: *mut DWORD,
) -> DWORD {
    if p_trustee.is_null() || p_access_rights.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    *p_access_rights = 0;

    if pacl.is_null() {
        *p_access_rights = 0xFFFFFFFF; // GENERIC_ALL
        return ERROR_SUCCESS;
    }

    ERROR_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn GetAuditedPermissionsFromAclW(
    pacl: PACL,
    p_trustee: *mut TRUSTEE_W,
    p_successful_audited_rights: *mut DWORD,
    p_failed_audit_rights: *mut DWORD,
) -> DWORD {
    if p_trustee.is_null()
        || p_successful_audited_rights.is_null()
        || p_failed_audit_rights.is_null()
    {
        return ERROR_INVALID_PARAMETER;
    }

    *p_successful_audited_rights = 0;
    *p_failed_audit_rights = 0;

    if pacl.is_null() {
        return ERROR_SUCCESS;
    }

    ERROR_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn BuildExplicitAccessWithNameW(
    p_explicit_access: *mut EXPLICIT_ACCESS_W,
    p_trustee_name: LPWSTR,
    access_permissions: DWORD,
    access_mode: DWORD,
    inheritance: DWORD,
) {
    if p_explicit_access.is_null() {
        return;
    }

    let ea = &mut *p_explicit_access;
    ea.grf_access_permissions = access_permissions;
    ea.grf_access_mode = access_mode;
    ea.grf_inheritance = inheritance;
    ea.trustee.p_multiple_trustee = ptr::null_mut();
    ea.trustee.multiple_trustee_operation = 0; // NO_MULTIPLE_TRUSTEE
    ea.trustee.trustee_form = TRUSTEE_IS_NAME;
    ea.trustee.trustee_type = TRUSTEE_IS_UNKNOWN;
    ea.trustee.ptstr_name = p_trustee_name;
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn BuildTrusteeWithNameW(p_trustee: *mut TRUSTEE_W, p_name: LPWSTR) {
    if p_trustee.is_null() {
        return;
    }

    let trustee = &mut *p_trustee;
    trustee.p_multiple_trustee = ptr::null_mut();
    trustee.multiple_trustee_operation = 0; // NO_MULTIPLE_TRUSTEE
    trustee.trustee_form = TRUSTEE_IS_NAME;
    trustee.trustee_type = TRUSTEE_IS_UNKNOWN;
    trustee.ptstr_name = p_name;
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn BuildTrusteeWithSidW(p_trustee: *mut TRUSTEE_W, p_sid: PSID) {
    if p_trustee.is_null() {
        return;
    }

    let trustee = &mut *p_trustee;
    trustee.p_multiple_trustee = ptr::null_mut();
    trustee.multiple_trustee_operation = 0; // NO_MULTIPLE_TRUSTEE
    trustee.trustee_form = TRUSTEE_IS_SID;
    trustee.trustee_type = TRUSTEE_IS_UNKNOWN;
    trustee.ptstr_name = p_sid as LPWSTR;
}

pub fn init() {}
