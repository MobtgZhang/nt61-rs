//! sechost.dll — Token Operations
//
//! Token security functions moved from advapi32 to sechost in Windows 7.
//! These functions check token properties and group membership.
//
//! References:
//!   * Microsoft Windows 7 SDK winbase.h, securitybaseapi.h
//!   * Windows Internals 6th Edition, Chapter 7
//!   * ReactOS 0.3.x winbase.h

#![allow(non_snake_case, dead_code)]

use super::types::*;
use crate::libs::kernel32::types::{DWORD, BOOL, HANDLE, TRUE, FALSE, LPVOID};
use crate::libs::ntdll::types::{PVOID, NTSTATUS};
use core::ptr;

#[no_mangle]
pub unsafe extern "C" fn CheckTokenMembership(
    TokenHandle: HANDLE,
    SidToCheck: PSID,
    IsMember: *mut BOOL,
) -> BOOL {
    if SidToCheck.is_null() || IsMember.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *IsMember = FALSE;

    let token = if TokenHandle.is_null() {
        1 as HANDLE
    } else {
        TokenHandle
    };



    *IsMember = FALSE;
    TRUE
}

#[no_mangle]
pub unsafe extern "C" fn IsTokenRestricted(TokenHandle: HANDLE) -> BOOL {
    if TokenHandle.is_null() || TokenHandle == INVALID_HANDLE_VALUE {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    // Restricted tokens are created by CreateRestrictedToken and used


    FALSE
}

#[no_mangle]
pub unsafe extern "C" fn GetTokenInformation(
    TokenHandle: HANDLE,
    TokenInformationClass: DWORD,
    TokenInformation: LPVOID,
    TokenInformationLength: DWORD,
    ReturnLength: *mut DWORD,
) -> BOOL {
    if TokenHandle.is_null() || TokenHandle == INVALID_HANDLE_VALUE {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if ReturnLength.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // - TokenUser (1): Gets token's user SID

    *ReturnLength = 0;
    crate::libs::kernel32::error::SetLastError(ERROR_INSUFFICIENT_BUFFER);
    FALSE
}

#[no_mangle]
pub unsafe extern "C" fn CheckTokenCapability(
    TokenHandle: HANDLE,
    CapabilitySidToCheck: PSID,
    HasCapability: *mut BOOL,
) -> BOOL {
    if TokenHandle.is_null() || TokenHandle == INVALID_HANDLE_VALUE {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if CapabilitySidToCheck.is_null() || HasCapability.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *HasCapability = FALSE;

    TRUE
}

#[no_mangle]
pub unsafe extern "C" fn IsWellKnownSid(
    pSid: PSID,
    WellKnownSidType: DWORD,
) -> BOOL {
    if pSid.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }


    FALSE
}

#[no_mangle]
pub unsafe extern "C" fn CreateWellKnownSid(
    WellKnownSidType: DWORD,
    DomainSid: PSID,
    pSid: PSID,
    cbSid: *mut DWORD,
) -> BOOL {
    if cbSid.is_null() {
        crate::libs::kernel32::error::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *cbSid = 0;
    crate::libs::kernel32::error::SetLastError(ERROR_INSUFFICIENT_BUFFER);
    FALSE
}

pub fn init() {
}
