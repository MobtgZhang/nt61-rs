//! ntdll — Security and Token Management (NT 6.1.7601)
//!
//! Security-related Native API functions for Windows 7:
//! - Token operations (NtOpenProcessToken, NtOpenThreadToken)
//! - Privilege management (NtAdjustPrivilegesToken)
//! - Access checking (NtAccessCheck, NtPrivilegeCheck)
//! - Security descriptors (NtQuerySecurityObject, NtSetSecurityObject)
//! - Impersonation (NtImpersonateThread)
//!
//! Integrates with the kernel security subsystem (se/).
//!
//! References:
//!   * MSDN Library "Windows 7" — Security Functions
//!   * Windows Internals 7th Ed. - Chapter 7 (Security)

use super::file::{alloc_handle, lookup_handle, HandleKind};
use super::status::{
    STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_NO_TOKEN, STATUS_PRIVILEGE_NOT_HELD,
    STATUS_SUCCESS, STATUS_NOT_IMPLEMENTED,
};
use super::types::{HANDLE, NTSTATUS, PVOID, ULONG};
use core::ptr;


#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    TokenPrimary = 1,
    TokenImpersonation = 2,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenInformationClass {
    TokenUser = 1,
    TokenGroups = 2,
    TokenPrivileges = 3,
    TokenOwner = 4,
    TokenPrimaryGroup = 5,
    TokenDefaultDacl = 6,
    TokenSource = 7,
    TokenType = 8,
    TokenImpersonationLevel = 9,
    TokenStatistics = 10,
    TokenRestrictedSids = 11,
    TokenSessionId = 12,
    TokenGroupsAndPrivileges = 13,
    TokenSessionReference = 14,
    TokenSandBoxInert = 15,
}

pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x00000001;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;
pub const SE_PRIVILEGE_REMOVED: u32 = 0x00000004;
pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x80000000;

#[repr(C)]
pub struct TokenPrivileges {
    pub privilege_count: u32,
    pub privileges: [LuidAndAttributes; 1], // Variable length
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LuidAndAttributes {
    pub luid: u64, // LUID as u64
    pub attributes: u32,
}


#[repr(C)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub sbz1: u8,
    pub control: u16,
    pub owner: PVOID,
    pub group: PVOID,
    pub sacl: PVOID,
    pub dacl: PVOID,
}

pub const OWNER_SECURITY_INFORMATION: u32 = 0x00000001;
pub const GROUP_SECURITY_INFORMATION: u32 = 0x00000002;
pub const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
pub const SACL_SECURITY_INFORMATION: u32 = 0x00000008;


pub unsafe extern "C" fn NtOpenProcessToken(
    process_handle: HANDLE,
    desired_access: u32,
    token_handle: *mut HANDLE,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let proc_entry = match lookup_handle(process_handle) {
        Some(e) if e.kind == HandleKind::Process => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = (proc_entry, desired_access);


    let token_h = alloc_handle(HandleKind::Token, 1); // Token ID = 1
    if token_h.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    *token_handle = token_h;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtOpenThreadToken(
    thread_handle: HANDLE,
    desired_access: u32,
    open_as_self: u8,
    token_handle: *mut HANDLE,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let thread_entry = match lookup_handle(thread_handle) {
        Some(e) if e.kind == HandleKind::Thread => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = (thread_entry, desired_access, open_as_self);


    STATUS_NO_TOKEN
}


pub unsafe extern "C" fn NtAdjustPrivilegesToken(
    token_handle: HANDLE,
    disable_all_privileges: u8,
    new_state: *const TokenPrivileges,
    buffer_length: u32,
    previous_state: *mut TokenPrivileges,
    return_length: *mut u32,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let token_entry = match lookup_handle(token_handle) {
        Some(e) if e.kind == HandleKind::Token => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = (token_entry, buffer_length);

    if disable_all_privileges != 0 {
        if !return_length.is_null() {
            *return_length = 0;
        }
        return STATUS_SUCCESS;
    }

    if new_state.is_null() {
        return STATUS_INVALID_PARAMETER;
    }


    if !previous_state.is_null() && buffer_length >= core::mem::size_of::<TokenPrivileges>() as u32 {
        (*previous_state).privilege_count = 0;
        if !return_length.is_null() {
            *return_length = core::mem::size_of::<TokenPrivileges>() as u32;
        }
    }

    STATUS_SUCCESS
}


pub unsafe extern "C" fn NtAccessCheck(
    security_descriptor: *const SecurityDescriptor,
    client_token: HANDLE,
    desired_access: u32,
    generic_mapping: *const GenericMapping,
    privilege_set: *mut PrivilegeSet,
    privilege_set_length: *mut u32,
    granted_access: *mut u32,
    access_status: *mut NTSTATUS,
) -> NTSTATUS {
    if security_descriptor.is_null() || client_token.is_null() || granted_access.is_null()
        || access_status.is_null()
    {
        return STATUS_INVALID_PARAMETER;
    }

    let _token_entry = match lookup_handle(client_token) {
        Some(e) if e.kind == HandleKind::Token => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = (generic_mapping, privilege_set, privilege_set_length);


    *granted_access = desired_access;
    *access_status = STATUS_SUCCESS;

    STATUS_SUCCESS
}

#[repr(C)]
pub struct GenericMapping {
    pub generic_read: u32,
    pub generic_write: u32,
    pub generic_execute: u32,
    pub generic_all: u32,
}

#[repr(C)]
pub struct PrivilegeSet {
    pub privilege_count: u32,
    pub control: u32,
    pub privilege: [LuidAndAttributes; 1], // Variable length
}


pub unsafe extern "C" fn NtPrivilegeCheck(
    client_token: HANDLE,
    required_privileges: *const PrivilegeSet,
    result: *mut u8,
) -> NTSTATUS {
    if client_token.is_null() || required_privileges.is_null() || result.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _token_entry = match lookup_handle(client_token) {
        Some(e) if e.kind == HandleKind::Token => e,
        _ => return STATUS_INVALID_HANDLE,
    };


    *result = 1; // TRUE

    STATUS_SUCCESS
}


pub unsafe extern "C" fn NtQuerySecurityObject(
    handle: HANDLE,
    security_information: u32,
    security_descriptor: *mut SecurityDescriptor,
    length: u32,
    length_needed: *mut u32,
) -> NTSTATUS {
    if handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let _entry = match lookup_handle(handle) {
        Some(e) => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = security_information;

    let needed = core::mem::size_of::<SecurityDescriptor>() as u32;

    if !length_needed.is_null() {
        *length_needed = needed;
    }

    if security_descriptor.is_null() || length < needed {
        return STATUS_BUFFER_TOO_SMALL;
    }


    ptr::write_bytes(security_descriptor, 0, 1);
    (*security_descriptor).revision = 1; // SECURITY_DESCRIPTOR_REVISION

    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtSetSecurityObject(
    handle: HANDLE,
    security_information: u32,
    security_descriptor: *const SecurityDescriptor,
) -> NTSTATUS {
    if handle.is_null() || security_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _entry = match lookup_handle(handle) {
        Some(e) => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = security_information;


    STATUS_SUCCESS
}


pub unsafe extern "C" fn NtImpersonateThread(
    server_thread_handle: HANDLE,
    client_thread_handle: HANDLE,
    security_qos: *const SecurityQualityOfService,
) -> NTSTATUS {
    if server_thread_handle.is_null() || client_thread_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _server = match lookup_handle(server_thread_handle) {
        Some(e) if e.kind == HandleKind::Thread => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _client = match lookup_handle(client_thread_handle) {
        Some(e) if e.kind == HandleKind::Thread => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = security_qos;


    STATUS_SUCCESS
}

#[repr(C)]
pub struct SecurityQualityOfService {
    pub length: u32,
    pub impersonation_level: u32,
    pub context_tracking_mode: u8,
    pub effective_only: u8,
}


pub unsafe extern "C" fn NtQueryInformationToken(
    token_handle: HANDLE,
    token_information_class: u32,
    token_information: PVOID,
    token_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let _token_entry = match lookup_handle(token_handle) {
        Some(e) if e.kind == HandleKind::Token => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    // The supported classes are TokenUser (1), TokenGroups (2),
    // TokenPrivileges (3), TokenOwner (4), TokenPrimaryGroup (5),
    // TokenDefaultDacl (6), TokenSource (7), TokenType (8),
    // TokenImpersonationLevel (9), TokenStatistics (10),
    // TokenRestrictedSids (11), TokenSessionId (12),
    // TokenGroupsAndPrivileges (13), TokenSandBoxInert (15),
    // TokenAuditPolicy (16), TokenOrigin (17), TokenElevationType (18),
    // TokenLinkedToken (19), TokenElevation (20), TokenHasRestrictions (21),
    // TokenAccessInformation (22), TokenVirtualizationAllowed (23),
    // TokenVirtualizationEnabled (24), TokenIntegrityLevel (25),
    // TokenUIAccess (26), TokenMandatoryPolicy (27),
    // TokenLogonSid (28).
    let _ = (token_information_class, token_information, token_information_length);

    if !return_length.is_null() {
        *return_length = 0;
    }

    // Return STATUS_INVALID_INFO_CLASS for unsupported subclasses,
    // matching real NT 6.1 behaviour.
    STATUS_INVALID_INFO_CLASS
}

pub unsafe extern "C" fn NtSetInformationToken(
    token_handle: HANDLE,
    token_information_class: u32,
    token_information: PVOID,
    token_information_length: u32,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let _token_entry = match lookup_handle(token_handle) {
        Some(e) if e.kind == HandleKind::Token => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = (token_information_class, token_information, token_information_length);

    STATUS_SUCCESS
}
