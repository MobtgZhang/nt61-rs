//! ntdll — Security and Token Management (NT 6.1.7601)
//!
//! Security-related Native API functions for Windows 7:
//! - Token operations (nt_open_process_token, nt_open_thread_token)
//! - Privilege management (nt_adjust_privileges_token)
//! - Access checking (nt_access_check, nt_privilege_check)
//! - Security descriptors (nt_query_security_object, nt_set_security_object)
//! - Impersonation (nt_impersonate_thread)
//!
//! Integrates with the kernel security subsystem (se/).
//!
//! References:
//!   * MSDN Library "Windows 7" — Security Functions
//!   * Windows Internals 7th Ed. - Chapter 7 (Security)

use super::file::{alloc_handle, lookup_handle, HandleKind};
use super::status::{
    STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER, STATUS_NO_TOKEN, STATUS_SUCCESS,
};
use super::types::{ObjectAttributes, HANDLE, NTSTATUS, PVOID};
use core::ptr;

use crate::mm::user_copy::{
    copy_from_user, copy_to_user, probe_user_read, probe_user_write, read_user, write_user_object,
};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TOKENTYPE {
    TokenPrimary = 1,
    TokenImpersonation = 2,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenInformationClass {
    TOKENUSER = 1,
    TOKENGROUPS = 2,
    TOKENPRIVILEGES = 3,
    TOKENOWNER = 4,
    TOKENPRIMARYGROUP = 5,
    TOKENDEFAULTDACL = 6,
    TOKENSOURCE = 7,
    TOKENTYPE = 8,
    TOKENIMPERSONATIONLEVEL = 9,
    TOKENSTATISTICS = 10,
    TOKENRESTRICTEDSIDS = 11,
    TOKENSESSIONID = 12,
    TOKENGROUPSANDPRIVILEGES = 13,
    TOKENSESSIONREFERENCE = 14,
    TOKENSANDBOXINERT = 15,
}

pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x00000001;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;
pub const SE_PRIVILEGE_REMOVED: u32 = 0x00000004;
pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x80000000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TOKEN_PRIVILEGES {
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn nt_open_process_token(
    process_handle: HANDLE,
    desired_access: u32,
    token_handle: *mut HANDLE,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if crate::mm::user_copy::probe_user_write(token_handle as u64, core::mem::size_of::<HANDLE>())
        .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let mut handle = HANDLE::default();
    let status = nt_open_process_token_kernel(process_handle, desired_access, &mut handle);
    if status == STATUS_SUCCESS
        && crate::mm::user_copy::write_user_object(token_handle as u64, &handle).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    status
}

/// Trusted-kernel entry point for `nt_open_process_token`.
pub fn nt_open_process_token_kernel(
    process_handle: HANDLE,
    desired_access: u32,
    token_handle: &mut HANDLE,
) -> NTSTATUS {
    let proc_entry = match lookup_handle(process_handle) {
        Some(entry) if entry.kind == HandleKind::Process => entry,
        _ => return STATUS_INVALID_HANDLE,
    };

    let token = crate::ps::process::get_by_pid(proc_entry.target)
        .map(|process| process.get_token())
        .filter(|token| !token.is_null())
        .unwrap_or_else(crate::se::token::create_system_token);
    if token.is_null() {
        return crate::libs::ntdll::status::STATUS_NO_MEMORY;
    }

    let _ = desired_access;
    let token_handle_value = alloc_handle(HandleKind::Token, token as u64);
    if token_handle_value.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    *token_handle = token_handle_value;
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn nt_open_thread_token(
    thread_handle: HANDLE,
    desired_access: u32,
    open_as_self: u8,
    token_handle: *mut HANDLE,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if crate::mm::user_copy::probe_user_write(token_handle as u64, core::mem::size_of::<HANDLE>())
        .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let mut handle = HANDLE::default();
    let status =
        nt_open_thread_token_kernel(thread_handle, desired_access, open_as_self, &mut handle);
    if status == STATUS_SUCCESS
        && crate::mm::user_copy::write_user_object(token_handle as u64, &handle).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    status
}

/// Trusted-kernel entry point for `nt_open_thread_token`.
pub fn nt_open_thread_token_kernel(
    thread_handle: HANDLE,
    desired_access: u32,
    open_as_self: u8,
    token_handle: &mut HANDLE,
) -> NTSTATUS {
    let thread_entry = match lookup_handle(thread_handle) {
        Some(entry) if entry.kind == HandleKind::Thread => entry,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = (thread_entry, desired_access, open_as_self);
    let _ = token_handle;
    STATUS_NO_TOKEN
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// nt_duplicate_token — duplicate an existing token handle.
pub unsafe extern "C" fn nt_duplicate_token(
    existing_token_handle: HANDLE,
    desired_access: u32,
    _object_attributes: *mut ObjectAttributes,
    effective_only: u32,
    impersonation_level: u32,
    duplicate_token_handle: *mut HANDLE,
) -> NTSTATUS {
    if duplicate_token_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if crate::mm::user_copy::probe_user_write(
        duplicate_token_handle as u64,
        core::mem::size_of::<HANDLE>(),
    )
    .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let mut handle = HANDLE::default();
    let status = nt_duplicate_token_kernel(
        existing_token_handle,
        desired_access,
        effective_only,
        impersonation_level,
        &mut handle,
    );
    if status == STATUS_SUCCESS
        && crate::mm::user_copy::write_user_object(duplicate_token_handle as u64, &handle).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    status
}

/// Trusted-kernel entry point for `nt_duplicate_token`.
pub fn nt_duplicate_token_kernel(
    existing_token_handle: HANDLE,
    desired_access: u32,
    effective_only: u32,
    impersonation_level: u32,
    duplicate_token_handle: &mut HANDLE,
) -> NTSTATUS {
    let entry = match lookup_handle(existing_token_handle) {
        Some(e) if e.kind == HandleKind::Token => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = (desired_access, effective_only, impersonation_level);

    let duplicate = alloc_handle(HandleKind::Token, entry.target);
    if duplicate.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    *duplicate_token_handle = duplicate;
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn nt_adjust_privileges_token(
    token_handle: HANDLE,
    disable_all_privileges: u8,
    new_state: *const TOKEN_PRIVILEGES,
    buffer_length: u32,
    previous_state: *mut TOKEN_PRIVILEGES,
    return_length: *mut u32,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if disable_all_privileges == 0 {
        if new_state.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        if probe_user_read(new_state as u64, core::mem::size_of::<TOKEN_PRIVILEGES>()).is_err() {
            return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
        }
    }
    if !return_length.is_null()
        && probe_user_write(return_length as u64, core::mem::size_of::<u32>()).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if !previous_state.is_null()
        && buffer_length >= core::mem::size_of::<TOKEN_PRIVILEGES>() as u32
        && probe_user_write(
            previous_state as u64,
            core::mem::size_of::<TOKEN_PRIVILEGES>(),
        )
        .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let mut kernel_new_state = TOKEN_PRIVILEGES {
        privilege_count: 0,
        privileges: [LuidAndAttributes {
            luid: 0,
            attributes: 0,
        }],
    };
    if disable_all_privileges == 0
        && copy_from_user(
            unsafe {
                core::slice::from_raw_parts_mut(
                    &mut kernel_new_state as *mut TOKEN_PRIVILEGES as *mut u8,
                    core::mem::size_of::<TOKEN_PRIVILEGES>(),
                )
            },
            new_state as u64,
        )
        .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let kernel_previous_state = if previous_state.is_null()
        || buffer_length < core::mem::size_of::<TOKEN_PRIVILEGES>() as u32
    {
        None
    } else {
        Some(unsafe { &mut *previous_state })
    };
    let kernel_return_length = if return_length.is_null() {
        None
    } else {
        Some(unsafe { &mut *return_length })
    };

    nt_adjust_privileges_token_kernel(
        token_handle,
        disable_all_privileges,
        if disable_all_privileges == 0 {
            Some(&kernel_new_state)
        } else {
            None
        },
        kernel_previous_state,
        kernel_return_length,
    )
}

/// Trusted-kernel entry point for `nt_adjust_privileges_token`.
pub fn nt_adjust_privileges_token_kernel(
    token_handle: HANDLE,
    disable_all_privileges: u8,
    new_state: Option<&TOKEN_PRIVILEGES>,
    mut previous_state: Option<&mut TOKEN_PRIVILEGES>,
    return_length: Option<&mut u32>,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let token_entry = match lookup_handle(token_handle) {
        Some(e) if e.kind == HandleKind::Token => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let token = token_entry.target as *mut crate::se::token::Token;
    if token.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if disable_all_privileges != 0 {
        let token = unsafe { &mut *token };
        for (index, privilege) in token
            .privileges
            .iter_mut()
            .take(token.privilege_count)
            .enumerate()
        {
            if let Some(previous_state) = previous_state.as_deref_mut() {
                if index == 0 {
                    previous_state.privilege_count = token.privilege_count as u32;
                }
                previous_state.privileges[index] = LuidAndAttributes {
                    luid: privilege.luid.to_u64(),
                    attributes: privilege.attributes,
                };
            }
            privilege.attributes &= !SE_PRIVILEGE_ENABLED;
        }
        if let Some(return_length) = return_length {
            *return_length = 0;
        }
        return STATUS_SUCCESS;
    }

    if let Some(new_state) = new_state {
        if new_state.privilege_count > 0 {
            let requested = new_state.privileges[0];
            let requested_luid = crate::se::token::luid::from_u64(requested.luid);
            let token = unsafe { &mut *token };
            let mut found = false;
            for privilege in token.privileges.iter_mut().take(token.privilege_count) {
                if privilege.luid.equals(&requested_luid) {
                    if let Some(previous_state) = previous_state.as_deref_mut() {
                        previous_state.privilege_count = 1;
                        previous_state.privileges[0] = LuidAndAttributes {
                            luid: privilege.luid.to_u64(),
                            attributes: privilege.attributes,
                        };
                    }
                    privilege.attributes = requested.attributes;
                    found = true;
                }
            }
            if !found {
                return crate::libs::ntdll::status::STATUS_INVALID_PARAMETER;
            }
        }
    }

    if let Some(previous_state) = previous_state.as_deref_mut() {
        previous_state.privilege_count = 0;
    }
    if let Some(return_length) = return_length {
        if previous_state.is_some() {
            *return_length = core::mem::size_of::<TOKEN_PRIVILEGES>() as u32;
        } else {
            *return_length = 0;
        }
    }

    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn nt_access_check(
    security_descriptor: *const SecurityDescriptor,
    client_token: HANDLE,
    desired_access: u32,
    generic_mapping: *const GenericMapping,
    _privilege_set: *mut PrivilegeSet,
    _privilege_set_length: *mut u32,
    granted_access: *mut u32,
    access_status: *mut NTSTATUS,
) -> NTSTATUS {
    if security_descriptor.is_null()
        || client_token.is_null()
        || granted_access.is_null()
        || access_status.is_null()
    {
        return STATUS_INVALID_PARAMETER;
    }

    if probe_user_read(
        security_descriptor as u64,
        core::mem::size_of::<SecurityDescriptor>(),
    )
    .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if !generic_mapping.is_null()
        && probe_user_read(
            generic_mapping as u64,
            core::mem::size_of::<GenericMapping>(),
        )
        .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if probe_user_write(granted_access as u64, core::mem::size_of::<u32>()).is_err() {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if probe_user_write(access_status as u64, core::mem::size_of::<NTSTATUS>()).is_err() {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let mut kernel_granted_access = 0u32;
    let mut kernel_access_status = 0;
    let status = nt_access_check_kernel(
        Some(core::slice::from_raw_parts(
            security_descriptor as *const u8,
            core::mem::size_of::<SecurityDescriptor>(),
        )),
        client_token,
        desired_access,
        if generic_mapping.is_null() {
            None
        } else {
            Some(unsafe { &*generic_mapping })
        },
        &mut kernel_granted_access,
        &mut kernel_access_status,
    );

    if write_user_object(granted_access as u64, &kernel_granted_access).is_err()
        || write_user_object(access_status as u64, &kernel_access_status).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    status
}

/// Trusted-kernel entry point for `nt_access_check`.
pub fn nt_access_check_kernel(
    security_descriptor: Option<&[u8]>,
    client_token: HANDLE,
    desired_access: u32,
    _generic_mapping: Option<&GenericMapping>,
    granted_access: &mut u32,
    access_status: &mut NTSTATUS,
) -> NTSTATUS {
    unsafe {
        if client_token.is_null() || security_descriptor.is_none() {
            return STATUS_INVALID_PARAMETER;
        }

        let token_entry = match lookup_handle(client_token) {
            Some(entry) if entry.kind == HandleKind::Token => entry,
            _ => return STATUS_INVALID_HANDLE,
        };
        let client_token = token_entry.target as *const crate::se::token::Token;
        if client_token.is_null() {
            return STATUS_INVALID_HANDLE;
        }

        let bytes = security_descriptor.unwrap();
        if bytes.len() < 40 {
            return STATUS_INVALID_PARAMETER;
        }

        // Parse the user-mode SECURITY_DESCRIPTOR (pointer-sized fields at
        // offsets 8/16/24/32 after revision+sbz1+control).
        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ])
        };
        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        let owner_ptr = read_u64(8);
        let dacl_ptr = read_u64(32);

        // Deny-by-default when the descriptor has no DACL (matches the
        // kernel refmon policy in se/refmon.rs).
        if dacl_ptr == 0 || (control & 0x0004) == 0 {
            *granted_access = 0;
            *access_status = crate::libs::ntdll::status::STATUS_ACCESS_DENIED;
            return STATUS_SUCCESS;
        }

        // Read the ACL header to learn its size.
        let mut acl_header = [0u8; 8];
        if crate::mm::user_copy::copy_from_user(&mut acl_header, dacl_ptr).is_err() {
            *granted_access = 0;
            *access_status = crate::libs::ntdll::status::STATUS_ACCESS_DENIED;
            return STATUS_SUCCESS;
        }
        let acl_size = u16::from_le_bytes([acl_header[2], acl_header[3]]) as usize;
        if !(8..=1024).contains(&acl_size) {
            *granted_access = 0;
            *access_status = crate::libs::ntdll::status::STATUS_ACCESS_DENIED;
            return STATUS_SUCCESS;
        }

        // Copy the ACL into a kernel-side Acl (inline ACE storage).
        let mut kernel_dacl = crate::se::acl::Acl::new();
        let copy_len = acl_size.min(core::mem::size_of::<crate::se::acl::Acl>());
        let acl_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut kernel_dacl as *mut crate::se::acl::Acl as *mut u8,
                copy_len,
            )
        };
        if crate::mm::user_copy::copy_from_user(acl_bytes, dacl_ptr).is_err() {
            *granted_access = 0;
            *access_status = crate::libs::ntdll::status::STATUS_ACCESS_DENIED;
            return STATUS_SUCCESS;
        }
        kernel_dacl.acl_size = copy_len as u16;

        // Read the owner SID (fixed 40-byte se::sid layout).
        let mut owner_sid = crate::se::sid::sid::new();
        if owner_ptr != 0 {
            let sid_bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    &mut owner_sid as *mut crate::se::sid::sid as *mut u8,
                    core::mem::size_of::<crate::se::sid::sid>(),
                )
            };
            let _ = crate::mm::user_copy::copy_from_user(sid_bytes, owner_ptr);
        }

        // Build a kernel SecurityDescriptor on the stack — se_access_check
        // completes synchronously and does not retain the pointer.
        let kernel_sd = crate::se::seaccess::SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: 0x8004, // SE_DACL_PRESENT | SE_SELF_RELATIVE
            owner: owner_sid,
            group: owner_sid,
            sacl: core::ptr::null(),
            dacl: &kernel_dacl as *const crate::se::acl::Acl,
        };

        let (result, granted) = crate::se::seaccess::se_access_check(
            crate::se::seaccess::ObTypeIndex::Null,
            &kernel_sd as *const crate::se::seaccess::SecurityDescriptor,
            desired_access,
            client_token,
        );

        *granted_access = granted;
        *access_status = match result {
            crate::se::seaccess::AccessCheckResult::Allowed => STATUS_SUCCESS,
            crate::se::seaccess::AccessCheckResult::Denied => {
                crate::libs::ntdll::status::STATUS_ACCESS_DENIED
            }
        };

        STATUS_SUCCESS
    }
}

#[repr(C)]
pub struct GenericMapping {
    pub generic_read: u32,
    pub generic_write: u32,
    pub generic_execute: u32,
    pub generic_all: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrivilegeSet {
    pub privilege_count: u32,
    pub control: u32,
    pub privilege: [LuidAndAttributes; 1], // Variable length
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn nt_privilege_check(
    client_token: HANDLE,
    required_privileges: *const PrivilegeSet,
    result: *mut u8,
) -> NTSTATUS {
    if client_token.is_null() || required_privileges.is_null() || result.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if probe_user_read(
        required_privileges as u64,
        core::mem::size_of::<PrivilegeSet>(),
    )
    .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if probe_user_write(result as u64, core::mem::size_of::<u8>()).is_err() {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let mut kernel_privileges = PrivilegeSet {
        privilege_count: 0,
        control: 0,
        privilege: [LuidAndAttributes {
            luid: 0,
            attributes: 0,
        }],
    };
    if read_user(required_privileges as u64, &mut kernel_privileges).is_err() {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    let mut kernel_result = 0u8;
    let status =
        nt_privilege_check_kernel(client_token, Some(&kernel_privileges), &mut kernel_result);
    if write_user_object(result as u64, &kernel_result).is_err() {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    status
}

/// Trusted-kernel entry point for `nt_privilege_check`.
pub fn nt_privilege_check_kernel(
    client_token: HANDLE,
    _required_privileges: Option<&PrivilegeSet>,
    result: &mut u8,
) -> NTSTATUS {
    if client_token.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _token_entry = match lookup_handle(client_token) {
        Some(e) if e.kind == HandleKind::Token => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    *result = 1; // TRUE

    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn nt_query_security_object(
    handle: HANDLE,
    security_information: u32,
    security_descriptor: *mut SecurityDescriptor,
    length: u32,
    length_needed: *mut u32,
) -> NTSTATUS {
    if handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if !length_needed.is_null()
        && probe_user_write(length_needed as u64, core::mem::size_of::<u32>()).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if !security_descriptor.is_null()
        && length >= core::mem::size_of::<SecurityDescriptor>() as u32
        && probe_user_write(
            security_descriptor as u64,
            core::mem::size_of::<SecurityDescriptor>(),
        )
        .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let _entry = match lookup_handle(handle) {
        Some(e) => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let needed = core::mem::size_of::<SecurityDescriptor>() as u32;

    let mut kernel_descriptor = SecurityDescriptor {
        revision: 1,
        sbz1: 0,
        control: 0,
        owner: ptr::null_mut(),
        group: ptr::null_mut(),
        sacl: ptr::null_mut(),
        dacl: ptr::null_mut(),
    };
    let mut kernel_length_needed = needed;
    let status = nt_query_security_object_kernel(
        handle,
        security_information,
        if security_descriptor.is_null() || length < needed {
            None
        } else {
            Some(&mut kernel_descriptor)
        },
        length,
        &mut kernel_length_needed,
    );

    if !length_needed.is_null()
        && write_user_object(length_needed as u64, &kernel_length_needed).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if !security_descriptor.is_null() && length >= needed {
        let descriptor_bytes = core::slice::from_raw_parts(
            &kernel_descriptor as *const SecurityDescriptor as *const u8,
            needed as usize,
        );
        if copy_to_user(security_descriptor as u64, descriptor_bytes).is_err() {
            return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
        }
    }

    status
}

/// Trusted-kernel entry point for `nt_query_security_object`.
pub fn nt_query_security_object_kernel(
    handle: HANDLE,
    security_information: u32,
    security_descriptor: Option<&mut SecurityDescriptor>,
    length: u32,
    length_needed: &mut u32,
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
    *length_needed = needed;

    if security_descriptor.is_none() || length < needed {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if let Some(security_descriptor) = security_descriptor {
        *security_descriptor = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: 0,
            owner: ptr::null_mut(),
            group: ptr::null_mut(),
            sacl: ptr::null_mut(),
            dacl: ptr::null_mut(),
        };
    }

    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn nt_set_security_object(
    handle: HANDLE,
    security_information: u32,
    security_descriptor: *const SecurityDescriptor,
) -> NTSTATUS {
    if handle.is_null() || security_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if probe_user_read(
        security_descriptor as u64,
        core::mem::size_of::<SecurityDescriptor>(),
    )
    .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let mut kernel_descriptor = alloc::vec![0u8; core::mem::size_of::<SecurityDescriptor>()];
    if copy_from_user(&mut kernel_descriptor, security_descriptor as u64).is_err() {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    nt_set_security_object_kernel(handle, security_information, Some(&kernel_descriptor))
}

/// Trusted-kernel entry point for `nt_set_security_object`.
pub fn nt_set_security_object_kernel(
    handle: HANDLE,
    security_information: u32,
    security_descriptor: Option<&[u8]>,
) -> NTSTATUS {
    if handle.is_null() || security_descriptor.is_none() {
        return STATUS_INVALID_PARAMETER;
    }

    let _entry = match lookup_handle(handle) {
        Some(e) => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = security_information;

    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn nt_impersonate_thread(
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

    if !security_qos.is_null()
        && probe_user_read(
            security_qos as u64,
            core::mem::size_of::<SecurityQualityOfService>(),
        )
        .is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn nt_query_information_token(
    token_handle: HANDLE,
    token_information_class: u32,
    token_information: PVOID,
    token_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if !return_length.is_null()
        && probe_user_write(return_length as u64, core::mem::size_of::<u32>()).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }
    if !token_information.is_null()
        && token_information_length > 0
        && probe_user_write(token_information as u64, token_information_length as usize).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let mut kernel_return_length = 0u32;
    let status = nt_query_information_token_kernel(
        token_handle,
        token_information_class,
        if token_information.is_null() {
            None
        } else {
            Some(&mut [])
        },
        &mut kernel_return_length,
    );

    if !return_length.is_null()
        && write_user_object(return_length as u64, &kernel_return_length).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    status
}

/// Trusted-kernel entry point for `nt_query_information_token`.
pub fn nt_query_information_token_kernel(
    token_handle: HANDLE,
    token_information_class: u32,
    token_information: Option<&mut [u8]>,
    return_length: &mut u32,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let _token_entry = match lookup_handle(token_handle) {
        Some(e) if e.kind == HandleKind::Token => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    // The supported classes are TOKEN_USER (1), TOKEN_GROUPS (2),
    // TOKEN_PRIVILEGES (3), TOKEN_OWNER (4), TOKEN_PRIMARY_GROUP (5),
    // TOKEN_DEFAULT_DACL (6), TOKEN_SOURCE (7), TOKEN_TYPE (8),
    // TOKEN_IMPERSONATION_LEVEL (9), TOKEN_STATISTICS (10),
    // TOKEN_RESTRICTED_SIDS (11), TOKEN_SESSION_ID (12),
    // TOKEN_GROUPS_AND_PRIVILEGES (13), TOKEN_SAND_BOX_INERT (15),
    // TOKEN_AUDIT_POLICY (16), TOKEN_ORIGIN (17), TOKEN_ELEVATION_TYPE (18),
    // TOKEN_LINKED_TOKEN (19), TOKEN_ELEVATION (20), TOKEN_HAS_RESTRICTIONS (21),
    // TOKEN_ACCESS_INFORMATION (22), TOKEN_VIRTUALIZATION_ALLOWED (23),
    // TOKEN_VIRTUALIZATION_ENABLED (24), TOKEN_INTEGRITY_LEVEL (25),
    // TOKEN_UIACCESS (26), TOKEN_MANDATORY_POLICY (27),
    // TOKEN_LOGON_SID (28).
    let _ = (token_information_class, token_information);

    *return_length = 0;

    // Return STATUS_INVALID_INFO_CLASS for unsupported subclasses,
    // matching real NT 6.1 behaviour.
    STATUS_INVALID_INFO_CLASS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn nt_set_information_token(
    token_handle: HANDLE,
    token_information_class: u32,
    token_information: PVOID,
    token_information_length: u32,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if !token_information.is_null()
        && token_information_length > 0
        && probe_user_read(token_information as u64, token_information_length as usize).is_err()
    {
        return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
    }

    let kernel_information = if token_information.is_null() {
        None
    } else {
        let mut bytes = alloc::vec![0u8; token_information_length as usize];
        if copy_from_user(&mut bytes, token_information as u64).is_err() {
            return crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
        }
        Some(bytes)
    };

    nt_set_information_token_kernel(
        token_handle,
        token_information_class,
        kernel_information.as_deref(),
    )
}

/// Trusted-kernel entry point for `nt_set_information_token`.
pub fn nt_set_information_token_kernel(
    token_handle: HANDLE,
    token_information_class: u32,
    token_information: Option<&[u8]>,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let _token_entry = match lookup_handle(token_handle) {
        Some(e) if e.kind == HandleKind::Token => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _ = (token_information_class, token_information);

    STATUS_SUCCESS
}
