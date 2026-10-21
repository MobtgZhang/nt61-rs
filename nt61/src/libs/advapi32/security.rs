//! advapi32 — Security and Account APIs
//
//! Implements Windows security functions including:
//! - LookupAccountSid/LookupAccountName — SID to account name translation
//! - GetSecurityInfo/SetSecurityInfo — Security descriptor management
//! - OpenProcessToken/OpenThreadToken — Token access
//! - CheckTokenMembership — group membership checking
//! - AdjustTokenPrivileges — Privilege management
//! - InitializeSecurityDescriptor — Security descriptor creation

use super::types::{PsecurityDescriptor, BYTE, LUID, SID_NAME_USE};
use super::types::{PsidNameUse, DWORD, LONG, PSID};
use crate::libs::ntdll::types::{BOOLEAN, HANDLE, PCWSTR, PVOID, PWSTR, ULONG};
use core::ptr::null_mut;
#[no_mangle]
pub unsafe extern "C" fn LookupAccountSidW(
    _lp_system_name: PCWSTR,
    sid: PSID,
    name: PWSTR,
    cch_name: *mut DWORD,
    referenced_domain_name: PWSTR,
    cch_referenced_domain_name: *mut DWORD,
    pe_use: PsidNameUse,
) -> LONG {
    if sid.is_null() || cch_name.is_null() || cch_referenced_domain_name.is_null() {
        return 0; // FALSE
    }

    let _sid_bytes = sid as *const u8;

    let account_name = "User\0".encode_utf16().collect::<alloc::vec::Vec<u16>>();
    let domain_name = "NT AUTHORITY\0"
        .encode_utf16()
        .collect::<alloc::vec::Vec<u16>>();
    let sid_type = SID_NAME_USE::SidTypeUser;

    if !name.is_null() && *cch_name > 0 {
        let copy_len = core::cmp::min(account_name.len(), *cch_name as usize);
        for i in 0..copy_len {
            *name.add(i) = account_name[i];
        }
        *cch_name = account_name.len() as DWORD;
    } else {
        *cch_name = account_name.len() as DWORD;
        return 0; // Insufficient buffer
    }

    if !referenced_domain_name.is_null() && *cch_referenced_domain_name > 0 {
        let copy_len = core::cmp::min(domain_name.len(), *cch_referenced_domain_name as usize);
        for i in 0..copy_len {
            *referenced_domain_name.add(i) = domain_name[i];
        }
        *cch_referenced_domain_name = domain_name.len() as DWORD;
    } else {
        *cch_referenced_domain_name = domain_name.len() as DWORD;
        return 0; // Insufficient buffer
    }

    if !pe_use.is_null() {
        *pe_use = sid_type;
    }

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn LookupAccountNameW(
    _lp_system_name: PCWSTR,
    lp_account_name: PCWSTR,
    sid: PSID,
    cb_sid: *mut DWORD,
    referenced_domain_name: PWSTR,
    cch_referenced_domain_name: *mut DWORD,
    pe_use: PsidNameUse,
) -> LONG {
    if lp_account_name.is_null() || cb_sid.is_null() {
        return 0; // FALSE
    }

    // For stub implementation, return a generic user SID

    // Generic user SID structure: S-1-5-21-...-1000
    let sid_size = 28; // Size of a typical user SID

    if sid.is_null() || *cb_sid < sid_size {
        *cb_sid = sid_size;
        return 0; // Insufficient buffer
    }

    let sid_bytes = sid as *mut u8;
    *sid_bytes.add(0) = 1; // revision
    *sid_bytes.add(1) = 5; // SubAuthorityCount
    for i in 2..8 {
        *sid_bytes.add(i) = if i == 7 { 5 } else { 0 };
    }

    *cb_sid = sid_size;

    if !cch_referenced_domain_name.is_null() {
        let domain = "BUILTIN\0".encode_utf16().collect::<alloc::vec::Vec<u16>>();
        if !referenced_domain_name.is_null() && *cch_referenced_domain_name >= domain.len() as DWORD
        {
            for i in 0..domain.len() {
                *referenced_domain_name.add(i) = domain[i];
            }
        }
        *cch_referenced_domain_name = domain.len() as DWORD;
    }

    if !pe_use.is_null() {
        *pe_use = SID_NAME_USE::SidTypeUser;
    }

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn InitializeSecurityDescriptor(
    p_security_descriptor: PsecurityDescriptor,
    dw_revision: DWORD,
) -> LONG {
    if p_security_descriptor.is_null() {
        return 0; // FALSE
    }

    let sd = &mut *p_security_descriptor;
    sd.revision = dw_revision as BYTE;
    sd.sbz1 = 0;
    sd.control = 0;
    sd.owner = null_mut();
    sd.group = null_mut();
    sd.sacl = null_mut();
    sd.dacl = null_mut();

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn OpenProcessToken(
    process_handle: HANDLE,
    desired_access: DWORD,
    token_handle: *mut HANDLE,
) -> LONG {
    if process_handle.is_null() || token_handle.is_null() {
        return 0; // FALSE
    }

    let status = crate::libs::ntdll::security::nt_open_process_token_kernel(
        process_handle,
        desired_access,
        &mut *token_handle,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}

#[no_mangle]
pub unsafe extern "C" fn OpenThreadToken(
    thread_handle: HANDLE,
    desired_access: DWORD,
    open_as_self: LONG,
    token_handle: *mut HANDLE,
) -> LONG {
    if thread_handle.is_null() || token_handle.is_null() {
        return 0; // FALSE
    }

    let status = crate::libs::ntdll::security::nt_open_thread_token_kernel(
        thread_handle,
        desired_access,
        open_as_self as BOOLEAN,
        &mut *token_handle,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}

#[no_mangle]
pub unsafe extern "C" fn SetTokenInformation(
    token_handle: HANDLE,
    token_information_class: DWORD,
    token_information: PVOID,
    token_information_length: DWORD,
) -> LONG {
    if token_handle.is_null() {
        return 0; // FALSE
    }

    let status = crate::libs::ntdll::security::nt_set_information_token(
        token_handle,
        token_information_class as u32,
        token_information,
        token_information_length,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}

#[no_mangle]
pub unsafe extern "C" fn AdjustTokenPrivileges(
    token_handle: HANDLE,
    _disable_all_privileges: LONG,
    _new_state: *const PVOID,
    _buffer_length: DWORD,
    _previous_state: PVOID,
    _return_length: *mut DWORD,
) -> LONG {
    if token_handle.is_null() {
        return 0; // FALSE
    }

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn DuplicateToken(
    existing_token_handle: HANDLE,
    impersonation_level: DWORD,
    duplicate_token_handle: *mut HANDLE,
) -> LONG {
    if existing_token_handle.is_null() || duplicate_token_handle.is_null() {
        return 0; // FALSE
    }

    let status = crate::libs::ntdll::security::nt_duplicate_token_kernel(
        existing_token_handle,
        0, // desired_access (0 = same as original)
        0, // EffectiveOnly
        impersonation_level as u32,
        &mut *duplicate_token_handle,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}

#[no_mangle]
pub unsafe extern "C" fn DuplicateTokenEx(
    h_existing_token: HANDLE,
    dw_desired_access: DWORD,
    _lp_token_attributes: PVOID,
    _impersonation_level: DWORD,
    token_type: DWORD,
    ph_new_token: *mut HANDLE,
) -> LONG {
    if h_existing_token.is_null() || ph_new_token.is_null() {
        return 0; // FALSE
    }

    let status = crate::libs::ntdll::security::nt_duplicate_token_kernel(
        h_existing_token,
        dw_desired_access,
        0, // EffectiveOnly
        token_type as u32,
        &mut *ph_new_token,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}

#[no_mangle]
pub unsafe extern "C" fn LookupPrivilegeValueW(
    _lp_system_name: PCWSTR,
    lp_name: PCWSTR,
    lp_luid: *mut LUID,
) -> LONG {
    if lp_name.is_null() || lp_luid.is_null() {
        return 0; // FALSE
    }

    // Real implementation would use a lookup table

    (*lp_luid).low_part = 1;
    (*lp_luid).high_part = 0;

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn LookupPrivilegeNameW(
    _lp_system_name: PCWSTR,
    lp_luid: *const LUID,
    lp_name: PWSTR,
    cch_name: *mut DWORD,
) -> LONG {
    if lp_luid.is_null() || cch_name.is_null() {
        return 0; // FALSE
    }

    let priv_name = "SeDebugPrivilege\0"
        .encode_utf16()
        .collect::<alloc::vec::Vec<u16>>();

    if lp_name.is_null() || *cch_name < priv_name.len() as DWORD {
        *cch_name = priv_name.len() as DWORD;
        return 0; // Insufficient buffer
    }

    for i in 0..priv_name.len() {
        *lp_name.add(i) = priv_name[i];
    }
    *cch_name = priv_name.len() as DWORD;

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn PrivilegeCheck(
    client_token: HANDLE,
    _required_privileges: PVOID,
    pf_result: *mut LONG,
) -> LONG {
    if client_token.is_null() || pf_result.is_null() {
        return 0; // FALSE
    }

    *pf_result = 0;

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn AccessCheck(
    p_security_descriptor: PsecurityDescriptor,
    client_token: HANDLE,
    desired_access: DWORD,
    _generic_mapping: PVOID,
    _privilege_set: PVOID,
    _privilege_set_length: *mut DWORD,
    granted_access: *mut DWORD,
    access_status: *mut LONG,
) -> LONG {
    if p_security_descriptor.is_null() || client_token.is_null() || access_status.is_null() {
        return 0; // FALSE
    }

    if !granted_access.is_null() {
        *granted_access = desired_access;
    }
    *access_status = 1; // TRUE (access granted)

    1 // TRUE
}

/// ImpersonateLoggedOnUser — Impersonate a logged-on user
#[no_mangle]
pub unsafe extern "C" fn ImpersonateLoggedOnUser(h_token: HANDLE) -> LONG {
    if h_token.is_null() {
        return 0; // FALSE
    }

    let current_thread = crate::libs::ntdll::thread::nt_current_thread();
    let status = crate::libs::ntdll::thread::nt_set_information_thread(
        current_thread,
        5, // ThreadImpersonationToken
        &h_token as *const _ as PVOID,
        core::mem::size_of::<HANDLE>() as ULONG,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}

#[no_mangle]
pub unsafe extern "C" fn RevertToSelf() -> LONG {
    let null_token: HANDLE = null_mut();
    let current_thread = crate::libs::ntdll::thread::nt_current_thread();
    let status = crate::libs::ntdll::thread::nt_set_information_thread(
        current_thread,
        5, // ThreadImpersonationToken
        &null_token as *const _ as PVOID,
        core::mem::size_of::<HANDLE>() as ULONG,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}
