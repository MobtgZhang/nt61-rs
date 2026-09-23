//! sechost.dll — Access Control List Operations
//
//! ACL manipulation functions moved from advapi32 to sechost in Windows 7.
//! These functions build and parse access control lists.
//
//! References:
//!   * Microsoft Windows 7 SDK aclapi.h, accctrl.h
//!   * Windows Internals 6th Edition, Chapter 7
//!   * ReactOS 0.3.x aclapi.h

#![allow(non_snake_case, dead_code)]

use super::types::*;
use crate::libs::kernel32::types::{DWORD, BOOL, TRUE, FALSE, LPWSTR};
use crate::libs::ntdll::types::{PVOID, NTSTATUS, ULONG};
use core::ptr;

#[no_mangle]
pub unsafe extern "C" fn SetEntriesInAclW(
    cCountOfExplicitEntries: ULONG,
    pListOfExplicitEntries: *mut EXPLICIT_ACCESS_W,
    OldAcl: PACL,
    NewAcl: *mut PACL,
) -> DWORD {
    if NewAcl.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    *NewAcl = ptr::null_mut();

    if cCountOfExplicitEntries == 0 && OldAcl.is_null() {
        return ERROR_SUCCESS;
    }

    if cCountOfExplicitEntries > 0 && pListOfExplicitEntries.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn GetExplicitEntriesFromAclW(
    pacl: PACL,
    pcCountOfExplicitEntries: *mut ULONG,
    pListOfExplicitEntries: *mut *mut EXPLICIT_ACCESS_W,
) -> DWORD {
    if pcCountOfExplicitEntries.is_null() || pListOfExplicitEntries.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    *pcCountOfExplicitEntries = 0;
    *pListOfExplicitEntries = ptr::null_mut();

    if pacl.is_null() {
        return ERROR_SUCCESS;
    }

    let acl = &*pacl;
    if acl.AceCount == 0 {
        return ERROR_SUCCESS;
    }

    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn GetEffectiveRightsFromAclW(
    pacl: PACL,
    pTrustee: *mut TRUSTEE_W,
    pAccessRights: *mut DWORD,
) -> DWORD {
    if pTrustee.is_null() || pAccessRights.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    *pAccessRights = 0;

    if pacl.is_null() {
        *pAccessRights = 0xFFFFFFFF; // GENERIC_ALL
        return ERROR_SUCCESS;
    }

    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn GetAuditedPermissionsFromAclW(
    pacl: PACL,
    pTrustee: *mut TRUSTEE_W,
    pSuccessfulAuditedRights: *mut DWORD,
    pFailedAuditRights: *mut DWORD,
) -> DWORD {
    if pTrustee.is_null() ||
       pSuccessfulAuditedRights.is_null() ||
       pFailedAuditRights.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    *pSuccessfulAuditedRights = 0;
    *pFailedAuditRights = 0;

    if pacl.is_null() {
        return ERROR_SUCCESS;
    }

    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn BuildExplicitAccessWithNameW(
    pExplicitAccess: *mut EXPLICIT_ACCESS_W,
    pTrusteeName: LPWSTR,
    AccessPermissions: DWORD,
    AccessMode: DWORD,
    Inheritance: DWORD,
) {
    if pExplicitAccess.is_null() {
        return;
    }

    let ea = &mut *pExplicitAccess;
    ea.grfAccessPermissions = AccessPermissions;
    ea.grfAccessMode = AccessMode;
    ea.grfInheritance = Inheritance;
    ea.Trustee.pMultipleTrustee = ptr::null_mut();
    ea.Trustee.MultipleTrusteeOperation = 0; // NO_MULTIPLE_TRUSTEE
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea.Trustee.ptstrName = pTrusteeName;
}

#[no_mangle]
pub unsafe extern "C" fn BuildTrusteeWithNameW(
    pTrustee: *mut TRUSTEE_W,
    pName: LPWSTR,
) {
    if pTrustee.is_null() {
        return;
    }

    let trustee = &mut *pTrustee;
    trustee.pMultipleTrustee = ptr::null_mut();
    trustee.MultipleTrusteeOperation = 0; // NO_MULTIPLE_TRUSTEE
    trustee.TrusteeForm = TRUSTEE_IS_NAME;
    trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    trustee.ptstrName = pName;
}

#[no_mangle]
pub unsafe extern "C" fn BuildTrusteeWithSidW(
    pTrustee: *mut TRUSTEE_W,
    pSid: PSID,
) {
    if pTrustee.is_null() {
        return;
    }

    let trustee = &mut *pTrustee;
    trustee.pMultipleTrustee = ptr::null_mut();
    trustee.MultipleTrusteeOperation = 0; // NO_MULTIPLE_TRUSTEE
    trustee.TrusteeForm = TRUSTEE_IS_SID;
    trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    trustee.ptstrName = pSid as LPWSTR;
}

pub fn init() {
}
