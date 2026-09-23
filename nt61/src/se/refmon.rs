//! Security Reference Monitor
//!
//! The Security Reference Monitor (SRM) is the central security enforcement
//! component in Windows. It:
//!   - Validates access to objects
//!   - Manages security tokens
//!   - Generates audit events
//!   - Enforces mandatory integrity levels
//!   - Handles privilege checks
//!
//! The SRM is called by the Object Manager and other subsystems before
//! granting access to kernel objects.
//!
//! References: Windows Internals, WRK

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, AtomicBool, AtomicPtr, Ordering};
use super::token::{Token, TokenTypeEnum, ImpersonationLevel, Luid};
use super::sid::Sid;
use super::acl::Acl;
use super::seaccess::{SecurityDescriptor, AccessCheckResult, GenericMapping};

static SRM_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_phase0() {
    unsafe {
        SRM_INITIALIZED = true;
    }
}

pub fn init_phase1() {
}

#[repr(C)]
pub struct SecuritySubjectContext {
    pub client_token: *mut Token,
    pub impersonation_level: ImpersonationLevel,
    pub primary_token: *mut Token,
    pub process_audit_id: Luid,
}

impl SecuritySubjectContext {
    pub fn new() -> Self {
        Self {
            client_token: core::ptr::null_mut(),
            impersonation_level: ImpersonationLevel::SecurityAnonymous,
            primary_token: core::ptr::null_mut(),
            process_audit_id: Luid::new(),
        }
    }

    pub fn capture() -> Self {
        let ctx = Self::new();

        // otherwise use the process token

        ctx
    }

    pub fn release(&mut self) {
        if !self.client_token.is_null() {
            self.client_token = core::ptr::null_mut();
        }
        if !self.primary_token.is_null() {
            self.primary_token = core::ptr::null_mut();
        }
    }

    pub fn effective_token(&self) -> *mut Token {
        if !self.client_token.is_null() {
            self.client_token
        } else {
            self.primary_token
        }
    }
}

pub fn se_access_check_with_context(
    security_descriptor: *const SecurityDescriptor,
    subject_context: &SecuritySubjectContext,
    desired_access: u32,
    generic_mapping: &GenericMapping,
    previous_granted_access: u32,
) -> (AccessCheckResult, u32) {
    let token = subject_context.effective_token();

    if token.is_null() {
        return (AccessCheckResult::Denied, 0);
    }

    let token_ref = unsafe { &*token };

    let mut access = desired_access | previous_granted_access;
    generic_mapping.map_generic(&mut access);

    if security_descriptor.is_null() {
        return (AccessCheckResult::Allowed, access);
    }

    let sd = unsafe { &*security_descriptor };

    let result = super::seaccess::check_access(
        access,
        token_ref,
        unsafe { &*sd.owner },
        sd.dacl,
        Some(generic_mapping),
    );

    let granted = match result {
        AccessCheckResult::Allowed => access,
        AccessCheckResult::Denied => previous_granted_access,
    };

    (result, granted)
}

pub fn se_valid_security_descriptor(
    _length: u32,
    security_descriptor: *const SecurityDescriptor,
) -> bool {
    if security_descriptor.is_null() {
        return false;
    }

    unsafe {
        (*security_descriptor).is_valid()
    }
}

pub fn se_assign_security(
    parent_descriptor: *const SecurityDescriptor,
    explicit_descriptor: *const SecurityDescriptor,
    is_directory: bool,
    token: *const Token,
) -> *mut SecurityDescriptor {
    let new_sd = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<SecurityDescriptor>(),
    ) as *mut SecurityDescriptor;

    if new_sd.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        (*new_sd).revision = 1;
        (*new_sd).sbz1 = 0;
        (*new_sd).control = 0;

        if !explicit_descriptor.is_null() && !(*explicit_descriptor).owner.is_null() {
            (*new_sd).owner = (*explicit_descriptor).owner;
        } else if !token.is_null() {
            // Owner comes from token's user SID
            let token_ref = &*token;
            let owner_ptr = crate::mm::pool::allocate(
                crate::mm::pool::PoolType::NonPaged,
                core::mem::size_of::<Sid>(),
            ) as *mut Sid;
            if !owner_ptr.is_null() {
                *owner_ptr = token_ref.user;
                (*new_sd).owner = owner_ptr;
            }
        }

        if !explicit_descriptor.is_null() && !(*explicit_descriptor).group.is_null() {
            (*new_sd).group = (*explicit_descriptor).group;
        } else if !token.is_null() {
            let token_ref = &*token;
            let group_ptr = crate::mm::pool::allocate(
                crate::mm::pool::PoolType::NonPaged,
                core::mem::size_of::<Sid>(),
            ) as *mut Sid;
            if !group_ptr.is_null() {
                *group_ptr = token_ref.primary_group;
                (*new_sd).group = group_ptr;
            }
        }

        if !explicit_descriptor.is_null() {
            (*new_sd).dacl = (*explicit_descriptor).dacl;
            (*new_sd).control |= super::descriptor::SE_DACL_PRESENT;
        } else if !parent_descriptor.is_null() && is_directory {
            (*new_sd).dacl = (*parent_descriptor).dacl;
            (*new_sd).control |= super::descriptor::SE_DACL_PRESENT;
        } else {
            (*new_sd).dacl = core::ptr::null_mut();
        }

        (*new_sd).sacl = core::ptr::null_mut();
    }

    new_sd
}

pub fn se_deassign_security(security_descriptor: *mut *mut SecurityDescriptor) {
    if security_descriptor.is_null() {
        return;
    }

    unsafe {
        let sd = *security_descriptor;
        if !sd.is_null() {
            if !(*sd).owner.is_null() {
                crate::mm::pool::free((*sd).owner as *mut u8);
            }
            if !(*sd).group.is_null() {
                crate::mm::pool::free((*sd).group as *mut u8);
            }

            crate::mm::pool::free(sd as *mut u8);
            *security_descriptor = core::ptr::null_mut();
        }
    }
}

pub fn se_query_security_descriptor_info(
    security_information: u32,
    security_descriptor: *const SecurityDescriptor,
    output_buffer: *mut u8,
    output_length: *mut u32,
) -> bool {
    if security_descriptor.is_null() || output_length.is_null() {
        return false;
    }

    const OWNER_SECURITY_INFORMATION: u32 = 0x00000001;
    const GROUP_SECURITY_INFORMATION: u32 = 0x00000002;
    const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
    const SACL_SECURITY_INFORMATION: u32 = 0x00000008;

    let mut required_length = 20u32; // Header size

    unsafe {
        let sd = &*security_descriptor;

        if (security_information & OWNER_SECURITY_INFORMATION) != 0 && !sd.owner.is_null() {
            required_length += (*sd.owner).size() as u32;
        }
        if (security_information & GROUP_SECURITY_INFORMATION) != 0 && !sd.group.is_null() {
            required_length += (*sd.group).size() as u32;
        }
        if (security_information & DACL_SECURITY_INFORMATION) != 0 && !sd.dacl.is_null() {
            required_length += (*sd.dacl).size() as u32;
        }
        if (security_information & SACL_SECURITY_INFORMATION) != 0 && !sd.sacl.is_null() {
            required_length += (*sd.sacl).size() as u32;
        }

        *output_length = required_length;

        if output_buffer.is_null() {
            return true; // Just querying required size
        }

        true
    }
}

pub fn se_set_security_descriptor_info(
    _object: *mut core::ffi::c_void,
    security_information: u32,
    modification: *const SecurityDescriptor,
    object_descriptor: *mut *mut SecurityDescriptor,
    _pool_type: u32,
    _generic_mapping: &GenericMapping,
) -> bool {
    if object_descriptor.is_null() || modification.is_null() {
        return false;
    }

    const OWNER_SECURITY_INFORMATION: u32 = 0x00000001;
    const GROUP_SECURITY_INFORMATION: u32 = 0x00000002;
    const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
    const SACL_SECURITY_INFORMATION: u32 = 0x00000008;

    unsafe {
        let current_sd = *object_descriptor;
        let mod_sd = &*modification;

        if current_sd.is_null() {
            *object_descriptor = crate::mm::pool::allocate(
                crate::mm::pool::PoolType::NonPaged,
                core::mem::size_of::<SecurityDescriptor>(),
            ) as *mut SecurityDescriptor;

            if (*object_descriptor).is_null() {
                return false;
            }

            (**object_descriptor).revision = 1;
            (**object_descriptor).sbz1 = 0;
            (**object_descriptor).control = 0;
        }

        let sd = &mut **object_descriptor;

        if (security_information & OWNER_SECURITY_INFORMATION) != 0 {
            sd.owner = mod_sd.owner;
        }

        if (security_information & GROUP_SECURITY_INFORMATION) != 0 {
            sd.group = mod_sd.group;
        }

        if (security_information & DACL_SECURITY_INFORMATION) != 0 {
            sd.dacl = mod_sd.dacl;
            sd.control |= super::descriptor::SE_DACL_PRESENT;
        }

        if (security_information & SACL_SECURITY_INFORMATION) != 0 {
            sd.sacl = mod_sd.sacl;
            sd.control |= super::descriptor::SE_SACL_PRESENT;
        }
    }

    true
}

pub fn init() {
    init_phase0();
}
