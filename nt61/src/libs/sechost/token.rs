//! sechost.dll — Token Operations
//
//! Token security functions moved from advapi32 to sechost in Windows 7.
//! These functions check token properties and group membership.
//
//! References:
//!   * Microsoft Windows 7 SDK winbase.h, securitybaseapi.h
//!   * Windows Internals 6th Edition, Chapter 7
//!   * ReactOS 0.3.x winbase.h

use super::types::*;
use crate::libs::kernel32::types::{BOOL, DWORD, FALSE, HANDLE, LPVOID, TRUE};

#[no_mangle]
pub unsafe extern "C" fn CheckTokenMembership(
    token_handle: HANDLE,
    sid_to_check: PSID,
    is_member: *mut BOOL,
) -> BOOL {
    if sid_to_check.is_null() || is_member.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *is_member = FALSE;

    let _token = if token_handle.is_null() {
        1 as HANDLE
    } else {
        token_handle
    };

    *is_member = FALSE;
    TRUE
}

#[no_mangle]
pub unsafe extern "C" fn IsTokenRestricted(token_handle: HANDLE) -> BOOL {
    if token_handle.is_null() || token_handle == INVALID_HANDLE_VALUE {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    // Restricted tokens are created by CreateRestrictedToken and used

    FALSE
}

#[no_mangle]
pub unsafe extern "C" fn GetTokenInformation(
    token_handle: HANDLE,
    _token_information_class: DWORD,
    _token_information: LPVOID,
    _token_information_length: DWORD,
    return_length: *mut DWORD,
) -> BOOL {
    if token_handle.is_null() || token_handle == INVALID_HANDLE_VALUE {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if return_length.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // - TOKEN_USER (1): Gets token's user SID

    *return_length = 0;
    crate::libs::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
    FALSE
}

#[no_mangle]
pub unsafe extern "C" fn CheckTokenCapability(
    token_handle: HANDLE,
    capability_sid_to_check: PSID,
    has_capability: *mut BOOL,
) -> BOOL {
    if token_handle.is_null() || token_handle == INVALID_HANDLE_VALUE {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if capability_sid_to_check.is_null() || has_capability.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *has_capability = FALSE;

    TRUE
}

#[no_mangle]
pub unsafe extern "C" fn IsWellKnownSid(p_sid: PSID, _well_known_sid_type: DWORD) -> BOOL {
    if p_sid.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    FALSE
}

#[no_mangle]
pub unsafe extern "C" fn CreateWellKnownSid(
    _well_known_sid_type: DWORD,
    _domain_sid: PSID,
    _p_sid: PSID,
    cb_sid: *mut DWORD,
) -> BOOL {
    if cb_sid.is_null() {
        crate::libs::kernel32::error::set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *cb_sid = 0;
    crate::libs::kernel32::error::set_last_error(ERROR_INSUFFICIENT_BUFFER);
    FALSE
}

pub fn init() {}
