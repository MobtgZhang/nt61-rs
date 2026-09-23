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

#![allow(non_snake_case, dead_code)]

use super::types::*;
use crate::libs::kernel32::types::{DWORD, BOOL, HANDLE, TRUE, FALSE, LPCWSTR, LPWSTR};
use crate::libs::ntdll::types::{PVOID, NTSTATUS, ULONG};
use core::ptr;

#[no_mangle]
pub unsafe extern "C" fn SetNamedSecurityInfoW(
    pObjectName: LPWSTR,
    ObjectType: SE_OBJECT_TYPE,
    SecurityInfo: SECURITY_INFORMATION,
    psidOwner: PSID,
    psidGroup: PSID,
    pDacl: PACL,
    pSacl: PACL,
) -> DWORD {
    if pObjectName.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    match ObjectType {
        SE_FILE_OBJECT |
        SE_SERVICE |
        SE_PRINTER |
        SE_REGISTRY_KEY |
        SE_LMSHARE |
        SE_KERNEL_OBJECT |
        SE_WINDOW_OBJECT |
        SE_DS_OBJECT |
        SE_DS_OBJECT_ALL |
        SE_PROVIDER_DEFINED_OBJECT |
        SE_WMIGUID_OBJECT |
        SE_REGISTRY_WOW64_32KEY => {}
        _ => {
            return ERROR_INVALID_PARAMETER;
        }
    }

    if SecurityInfo == 0 {
        return ERROR_INVALID_PARAMETER;
    }

    if (SecurityInfo & OWNER_SECURITY_INFORMATION) != 0 && psidOwner.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if (SecurityInfo & GROUP_SECURITY_INFORMATION) != 0 && psidGroup.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if (SecurityInfo & DACL_SECURITY_INFORMATION) != 0 && pDacl.is_null() {
    }
    if (SecurityInfo & SACL_SECURITY_INFORMATION) != 0 && pSacl.is_null() {
    }

    match ObjectType {
        SE_FILE_OBJECT => {
            ERROR_SUCCESS
        }
        SE_REGISTRY_KEY => {
            ERROR_SUCCESS
        }
        SE_SERVICE => {
            ERROR_SUCCESS
        }
        _ => {
            ERROR_SUCCESS
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn GetNamedSecurityInfoW(
    pObjectName: LPWSTR,
    ObjectType: SE_OBJECT_TYPE,
    SecurityInfo: SECURITY_INFORMATION,
    ppsidOwner: *mut PSID,
    ppsidGroup: *mut PSID,
    ppDacl: *mut PACL,
    ppSacl: *mut PACL,
    ppSecurityDescriptor: *mut PVOID,
) -> DWORD {
    if pObjectName.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    match ObjectType {
        SE_FILE_OBJECT |
        SE_SERVICE |
        SE_PRINTER |
        SE_REGISTRY_KEY |
        SE_LMSHARE |
        SE_KERNEL_OBJECT |
        SE_WINDOW_OBJECT |
        SE_DS_OBJECT |
        SE_DS_OBJECT_ALL |
        SE_PROVIDER_DEFINED_OBJECT |
        SE_WMIGUID_OBJECT |
        SE_REGISTRY_WOW64_32KEY => {}
        _ => {
            return ERROR_INVALID_PARAMETER;
        }
    }

    if SecurityInfo == 0 {
        return ERROR_INVALID_PARAMETER;
    }

    if ppSecurityDescriptor.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    if !ppsidOwner.is_null() {
        *ppsidOwner = ptr::null_mut();
    }
    if !ppsidGroup.is_null() {
        *ppsidGroup = ptr::null_mut();
    }
    if !ppDacl.is_null() {
        *ppDacl = ptr::null_mut();
    }
    if !ppSacl.is_null() {
        *ppSacl = ptr::null_mut();
    }
    *ppSecurityDescriptor = ptr::null_mut();

    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn SetSecurityInfo(
    handle: HANDLE,
    ObjectType: SE_OBJECT_TYPE,
    SecurityInfo: SECURITY_INFORMATION,
    psidOwner: PSID,
    psidGroup: PSID,
    pDacl: PACL,
    pSacl: PACL,
) -> DWORD {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return ERROR_INVALID_HANDLE;
    }

    if SecurityInfo == 0 {
        return ERROR_INVALID_PARAMETER;
    }

    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn GetSecurityInfo(
    handle: HANDLE,
    ObjectType: SE_OBJECT_TYPE,
    SecurityInfo: SECURITY_INFORMATION,
    ppsidOwner: *mut PSID,
    ppsidGroup: *mut PSID,
    ppDacl: *mut PACL,
    ppSacl: *mut PACL,
    ppSecurityDescriptor: *mut PVOID,
) -> DWORD {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return ERROR_INVALID_HANDLE;
    }

    if ppSecurityDescriptor.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    if !ppsidOwner.is_null() {
        *ppsidOwner = ptr::null_mut();
    }
    if !ppsidGroup.is_null() {
        *ppsidGroup = ptr::null_mut();
    }
    if !ppDacl.is_null() {
        *ppDacl = ptr::null_mut();
    }
    if !ppSacl.is_null() {
        *ppSacl = ptr::null_mut();
    }
    *ppSecurityDescriptor = ptr::null_mut();

    ERROR_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn BuildSecurityDescriptorW(
    pOwner: *mut TRUSTEE_W,
    pGroup: *mut TRUSTEE_W,
    cCountOfAccessEntries: ULONG,
    pListOfAccessEntries: *mut EXPLICIT_ACCESS_W,
    cCountOfAuditEntries: ULONG,
    pListOfAuditEntries: *mut EXPLICIT_ACCESS_W,
    pOldSD: PVOID,
    pSizeNewSD: *mut ULONG,
    pNewSD: *mut PVOID,
) -> DWORD {
    if pSizeNewSD.is_null() || pNewSD.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    *pSizeNewSD = 0;
    *pNewSD = ptr::null_mut();

    ERROR_SUCCESS
}

pub fn init() {
}
