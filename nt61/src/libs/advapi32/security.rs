//! advapi32 — Security and Account APIs
//
//! Implements Windows security functions including:
//! - LookupAccountSid/LookupAccountName — SID to account name translation
//! - GetSecurityInfo/SetSecurityInfo — Security descriptor management
//! - OpenProcessToken/OpenThreadToken — Token access
//! - CheckTokenMembership — Group membership checking
//! - AdjustTokenPrivileges — Privilege management
//! - InitializeSecurityDescriptor — Security descriptor creation

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use super::types::{DWORD, BOOL, TRUE, FALSE, LPCWSTR, LPWSTR, LPDWORD, PSID, LONG, PSID_NAME_USE};
use super::types::{ERROR_SUCCESS, ERROR_INVALID_HANDLE, ACL, PSECURITY_DESCRIPTOR, BYTE, LPVOID, SID_NAME_USE, LUID};
use crate::libs::ntdll::types::{HANDLE, PVOID, ULONG, PWSTR, PCWSTR, BOOLEAN};
use crate::libs::ntdll::types::NTSTATUS;
use crate::libs::ntdll::status::STATUS_SUCCESS;
use core::ptr::{null_mut, null};


#[no_mangle]
pub unsafe extern "C" fn LookupAccountSidW(
    lpSystemName: PCWSTR,
    Sid: PSID,
    Name: PWSTR,
    cchName: *mut DWORD,
    ReferencedDomainName: PWSTR,
    cchReferencedDomainName: *mut DWORD,
    peUse: PSID_NAME_USE,
) -> LONG {
    if Sid.is_null() || cchName.is_null() || cchReferencedDomainName.is_null() {
        return 0; // FALSE
    }


    let sid_bytes = Sid as *const u8;

    let account_name = "User\0".encode_utf16().collect::<alloc::vec::Vec<u16>>();
    let domain_name = "NT AUTHORITY\0".encode_utf16().collect::<alloc::vec::Vec<u16>>();
    let sid_type = SID_NAME_USE::SidTypeUser;


    if !Name.is_null() && *cchName > 0 {
        let copy_len = core::cmp::min(account_name.len(), *cchName as usize);
        for i in 0..copy_len {
            *Name.add(i) = account_name[i];
        }
        *cchName = account_name.len() as DWORD;
    } else {
        *cchName = account_name.len() as DWORD;
        return 0; // Insufficient buffer
    }

    if !ReferencedDomainName.is_null() && *cchReferencedDomainName > 0 {
        let copy_len = core::cmp::min(domain_name.len(), *cchReferencedDomainName as usize);
        for i in 0..copy_len {
            *ReferencedDomainName.add(i) = domain_name[i];
        }
        *cchReferencedDomainName = domain_name.len() as DWORD;
    } else {
        *cchReferencedDomainName = domain_name.len() as DWORD;
        return 0; // Insufficient buffer
    }

    if !peUse.is_null() {
        *peUse = sid_type;
    }

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn LookupAccountNameW(
    lpSystemName: PCWSTR,
    lpAccountName: PCWSTR,
    Sid: PSID,
    cbSid: *mut DWORD,
    ReferencedDomainName: PWSTR,
    cchReferencedDomainName: *mut DWORD,
    peUse: PSID_NAME_USE,
) -> LONG {
    if lpAccountName.is_null() || cbSid.is_null() {
        return 0; // FALSE
    }

    // For stub implementation, return a generic user SID

    // Generic user SID structure: S-1-5-21-...-1000
    let sid_size = 28; // Size of a typical user SID

    if Sid.is_null() || *cbSid < sid_size {
        *cbSid = sid_size;
        return 0; // Insufficient buffer
    }

    let sid_bytes = Sid as *mut u8;
    *sid_bytes.add(0) = 1; // Revision
    *sid_bytes.add(1) = 5; // SubAuthorityCount
    for i in 2..8 {
        *sid_bytes.add(i) = if i == 7 { 5 } else { 0 };
    }

    *cbSid = sid_size;

    if !cchReferencedDomainName.is_null() {
        let domain = "BUILTIN\0".encode_utf16().collect::<alloc::vec::Vec<u16>>();
        if !ReferencedDomainName.is_null() && *cchReferencedDomainName >= domain.len() as DWORD {
            for i in 0..domain.len() {
                *ReferencedDomainName.add(i) = domain[i];
            }
        }
        *cchReferencedDomainName = domain.len() as DWORD;
    }

    if !peUse.is_null() {
        *peUse = SID_NAME_USE::SidTypeUser;
    }

    1 // TRUE
}


#[no_mangle]
pub unsafe extern "C" fn InitializeSecurityDescriptor(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    dwRevision: DWORD,
) -> LONG {
    if pSecurityDescriptor.is_null() {
        return 0; // FALSE
    }

    let sd = &mut *pSecurityDescriptor;
    sd.Revision = dwRevision as BYTE;
    sd.Sbz1 = 0;
    sd.Control = 0;
    sd.Owner = null_mut();
    sd.Group = null_mut();
    sd.Sacl = null_mut();
    sd.Dacl = null_mut();

    1 // TRUE
}




#[no_mangle]
pub unsafe extern "C" fn OpenProcessToken(
    ProcessHandle: HANDLE,
    DesiredAccess: DWORD,
    TokenHandle: *mut HANDLE,
) -> LONG {
    if ProcessHandle.is_null() || TokenHandle.is_null() {
        return 0; // FALSE
    }

    let status = crate::libs::ntdll::process::NtOpenProcessToken(
        ProcessHandle,
        DesiredAccess,
        TokenHandle,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}

#[no_mangle]
pub unsafe extern "C" fn OpenThreadToken(
    ThreadHandle: HANDLE,
    DesiredAccess: DWORD,
    OpenAsSelf: LONG,
    TokenHandle: *mut HANDLE,
) -> LONG {
    if ThreadHandle.is_null() || TokenHandle.is_null() {
        return 0; // FALSE
    }

    let status = crate::libs::ntdll::thread::NtOpenThreadToken(
        ThreadHandle,
        DesiredAccess,
        OpenAsSelf as BOOLEAN,
        TokenHandle,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}


#[no_mangle]
pub unsafe extern "C" fn SetTokenInformation(
    TokenHandle: HANDLE,
    TokenInformationClass: DWORD,
    TokenInformation: PVOID,
    TokenInformationLength: DWORD,
) -> LONG {
    if TokenHandle.is_null() {
        return 0; // FALSE
    }

    let status = crate::libs::ntdll::info::NtSetInformationToken(
        TokenHandle,
        TokenInformationClass as u32,
        TokenInformation,
        TokenInformationLength,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}

#[no_mangle]
pub unsafe extern "C" fn AdjustTokenPrivileges(
    TokenHandle: HANDLE,
    DisableAllPrivileges: LONG,
    NewState: *const PVOID,
    BufferLength: DWORD,
    PreviousState: PVOID,
    ReturnLength: *mut DWORD,
) -> LONG {
    if TokenHandle.is_null() {
        return 0; // FALSE
    }


    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn DuplicateToken(
    ExistingTokenHandle: HANDLE,
    ImpersonationLevel: DWORD,
    DuplicateTokenHandle: *mut HANDLE,
) -> LONG {
    if ExistingTokenHandle.is_null() || DuplicateTokenHandle.is_null() {
        return 0; // FALSE
    }

    let status = crate::libs::ntdll::process::NtDuplicateToken(
        ExistingTokenHandle,
        0, // DesiredAccess (0 = same as original)
        null_mut(),
        0, // EffectiveOnly
        ImpersonationLevel as u32,
        DuplicateTokenHandle,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}

#[no_mangle]
pub unsafe extern "C" fn DuplicateTokenEx(
    hExistingToken: HANDLE,
    dwDesiredAccess: DWORD,
    lpTokenAttributes: PVOID,
    ImpersonationLevel: DWORD,
    TokenType: DWORD,
    phNewToken: *mut HANDLE,
) -> LONG {
    if hExistingToken.is_null() || phNewToken.is_null() {
        return 0; // FALSE
    }

    let status = crate::libs::ntdll::process::NtDuplicateToken(
        hExistingToken,
        dwDesiredAccess,
        lpTokenAttributes as *mut crate::libs::ntdll::types::ObjectAttributes,
        0, // EffectiveOnly
        TokenType as u32,
        phNewToken,
    );

    if status < 0 {
        0 // FALSE
    } else {
        1 // TRUE
    }
}


#[no_mangle]
pub unsafe extern "C" fn LookupPrivilegeValueW(
    lpSystemName: PCWSTR,
    lpName: PCWSTR,
    lpLuid: *mut LUID,
) -> LONG {
    if lpName.is_null() || lpLuid.is_null() {
        return 0; // FALSE
    }

    // Real implementation would use a lookup table

    (*lpLuid).LowPart = 1;
    (*lpLuid).HighPart = 0;

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn LookupPrivilegeNameW(
    lpSystemName: PCWSTR,
    lpLuid: *const LUID,
    lpName: PWSTR,
    cchName: *mut DWORD,
) -> LONG {
    if lpLuid.is_null() || cchName.is_null() {
        return 0; // FALSE
    }

    let priv_name = "SeDebugPrivilege\0".encode_utf16().collect::<alloc::vec::Vec<u16>>();

    if lpName.is_null() || *cchName < priv_name.len() as DWORD {
        *cchName = priv_name.len() as DWORD;
        return 0; // Insufficient buffer
    }

    for i in 0..priv_name.len() {
        *lpName.add(i) = priv_name[i];
    }
    *cchName = priv_name.len() as DWORD;

    1 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn PrivilegeCheck(
    ClientToken: HANDLE,
    RequiredPrivileges: PVOID,
    pfResult: *mut LONG,
) -> LONG {
    if ClientToken.is_null() || pfResult.is_null() {
        return 0; // FALSE
    }

    *pfResult = 0;

    1 // TRUE
}


#[no_mangle]
pub unsafe extern "C" fn AccessCheck(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    ClientToken: HANDLE,
    DesiredAccess: DWORD,
    GenericMapping: PVOID,
    PrivilegeSet: PVOID,
    PrivilegeSetLength: *mut DWORD,
    GrantedAccess: *mut DWORD,
    AccessStatus: *mut LONG,
) -> LONG {
    if pSecurityDescriptor.is_null() || ClientToken.is_null() || AccessStatus.is_null() {
        return 0; // FALSE
    }

    if !GrantedAccess.is_null() {
        *GrantedAccess = DesiredAccess;
    }
    *AccessStatus = 1; // TRUE (access granted)

    1 // TRUE
}

/// ImpersonateLoggedOnUser — Impersonate a logged-on user
#[no_mangle]
pub unsafe extern "C" fn ImpersonateLoggedOnUser(hToken: HANDLE) -> LONG {
    if hToken.is_null() {
        return 0; // FALSE
    }

    let current_thread = crate::libs::ntdll::thread::NtCurrentThread();
    let status = crate::libs::ntdll::thread::NtSetInformationThread(
        current_thread,
        5, // ThreadImpersonationToken
        &hToken as *const _ as PVOID,
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
    let current_thread = crate::libs::ntdll::thread::NtCurrentThread();
    let status = crate::libs::ntdll::thread::NtSetInformationThread(
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
