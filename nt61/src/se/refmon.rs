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

use super::seaccess::{AccessCheckResult, GenericMapping, SecurityDescriptor};
use super::token::{luid, ImpersonationLevel, Token};
use core::sync::atomic::{AtomicBool, Ordering};

static SRM_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_phase0() {
    SRM_INITIALIZED.store(true, Ordering::SeqCst);
}

pub fn init_phase1() {}

#[repr(C)]
pub struct SecuritySubjectContext {
    pub client_token: *mut Token,
    pub impersonation_level: ImpersonationLevel,
    pub primary_token: *mut Token,
    pub process_audit_id: luid,
}

impl SecuritySubjectContext {
    pub fn new() -> Self {
        Self {
            client_token: core::ptr::null_mut(),
            impersonation_level: ImpersonationLevel::SecurityAnonymous,
            primary_token: core::ptr::null_mut(),
            process_audit_id: luid::new(),
        }
    }

    pub fn capture() -> Self {
        let mut ctx = Self::new();

        // Windows NT semantics for SeCaptureSecuritySubjectContext:
        //   - Client token: the thread's impersonation token
        //     (ETHREAD -> ClientSecurity -> ClientToken).
        //   - Primary token: the process's primary token
        //     (EPROCESS -> Token).
        //   - Impersonation level: from the client token's
        //     impersonation level, or SecurityAnonymous if no client token.

        // 1. Client (impersonation) token from the calling ETHREAD.
        let thread = crate::ps::thread::get_current_ethread();
        if !thread.is_null() {
            let thread_token = unsafe { (*thread).primary_token };
            if thread_token != 0 {
                let token = thread_token as *mut Token;
                ctx.client_token = token;
                ctx.impersonation_level = unsafe { (*token).impersonation_level };
            }

            // 2. Primary token from the owning EPROCESS.
            let process = unsafe { (*thread).threads_process };
            if !process.is_null() {
                let proc_token = unsafe { (*process).token.get_object() };
                if proc_token != 0 {
                    ctx.primary_token = proc_token as *mut Token;
                }
            }
        }

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

impl Default for SecuritySubjectContext {
    fn default() -> Self {
        Self::new()
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn se_access_check_with_context(
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

    // Deny-by-default when there is no security descriptor.
    // This matches ob/mod.rs policy: bootstrap objects without an SD
    // must not silently grant access in production.
    if security_descriptor.is_null() {
        return (AccessCheckResult::Denied, 0);
    }

    let sd = unsafe { &*security_descriptor };

    let result =
        super::seaccess::check_access(access, token_ref, &sd.owner, sd.dacl, Some(generic_mapping));

    let granted = match result {
        AccessCheckResult::Allowed => access,
        AccessCheckResult::Denied => previous_granted_access,
    };

    (result, granted)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn se_valid_security_descriptor(
    _length: u32,
    security_descriptor: *const SecurityDescriptor,
) -> bool {
    if security_descriptor.is_null() {
        return false;
    }

    unsafe { (*security_descriptor).is_valid() }
}

/// Deep-copy an ACL so an inherited descriptor owns its DACL instead of
/// aliasing the parent's (freeing one must not dangle the other).
fn copy_dacl(dacl: *const super::acl::Acl) -> *mut super::acl::Acl {
    if dacl.is_null() {
        return core::ptr::null_mut();
    }
    let copy = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<super::acl::Acl>(),
    ) as *mut super::acl::Acl;
    if copy.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            dacl as *const u8,
            copy as *mut u8,
            core::mem::size_of::<super::acl::Acl>(),
        );
    }
    copy
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn se_assign_security(
    parent_descriptor: *const SecurityDescriptor,
    explicit_descriptor: *const SecurityDescriptor,
    is_directory: bool,
    token: *const Token,
) -> *mut SecurityDescriptor {
    // Both files and directories inherit the parent DACL, so the flag no
    // longer selects a different branch; it is kept for API compatibility.
    let _ = is_directory;

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

        if !explicit_descriptor.is_null() {
            (*new_sd).owner = (*explicit_descriptor).owner;
        } else if !token.is_null() {
            // owner comes from token's user SID
            let token_ref = &*token;
            (*new_sd).owner = token_ref.user;
        }

        if !explicit_descriptor.is_null() {
            (*new_sd).group = (*explicit_descriptor).group;
        } else if !token.is_null() {
            let token_ref = &*token;
            (*new_sd).group = token_ref.primary_group;
        }

        if !explicit_descriptor.is_null() {
            (*new_sd).dacl = copy_dacl((*explicit_descriptor).dacl);
            (*new_sd).control |= super::descriptor::SE_DACL_PRESENT;
        } else if !parent_descriptor.is_null() {
            // Files and directories both inherit the parent DACL (Windows
            // semantics). Leaving the DACL NULL here would make every new
            // object "allow everyone".
            (*new_sd).dacl = copy_dacl((*parent_descriptor).dacl);
            (*new_sd).control |= super::descriptor::SE_DACL_PRESENT;
        } else if !token.is_null() {
            // No inherited DACL is available. Build the default DACL from
            // the creator token instead of allowing everyone.
            let token_ref = &*token;
            let token_sd = super::seaccess::SecurityDescriptor::from_token(token_ref);
            if !token_sd.is_null() {
                // Take ownership of the freshly built DACL and drop the
                // shell descriptor so it does not leak.
                (*new_sd).dacl = (*token_sd).dacl;
                (*new_sd).control |= super::descriptor::SE_DACL_PRESENT;
                crate::mm::pool::free(token_sd as *mut u8);
            }
        }

        // Attach a mandatory label SACL from the creator token's integrity
        // level so new objects carry an object-side integrity level.
        if !token.is_null() {
            let level = super::integrity::se_token_integrity_level(token);
            super::integrity::se_set_object_integrity_level(
                new_sd,
                level,
                super::integrity::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            );
        }
    }

    new_sd
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn se_deassign_security(security_descriptor: *mut *mut SecurityDescriptor) {
    if security_descriptor.is_null() {
        return;
    }

    unsafe {
        let sd = *security_descriptor;
        if !sd.is_null() {
            crate::mm::pool::free(sd as *mut u8);
            *security_descriptor = core::ptr::null_mut();
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn se_query_security_descriptor_info(
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

        if (security_information & OWNER_SECURITY_INFORMATION) != 0 {
            required_length += sd.owner.size() as u32;
        }
        if (security_information & GROUP_SECURITY_INFORMATION) != 0 {
            required_length += sd.group.size() as u32;
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn se_set_security_descriptor_info(
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Audit an object-access event. Delegates to the SE audit subsystem,
/// which writes to the event log buffer if auditing is enabled for the
/// ObjectAccess category.
pub unsafe fn audit_event(
    object_type: &str,
    object_name: Option<&str>,
    security_descriptor: *const SecurityDescriptor,
    token: *const Token,
    desired_access: u32,
    granted_access: u32,
    access_granted: bool,
) {
    unsafe {
        super::audit::se_open_object_audit_alarm(
            object_type,
            object_name,
            security_descriptor,
            token,
            desired_access,
            granted_access,
            access_granted,
        );
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Full access check with audit: captures the subject context, performs
/// the access check against a security descriptor, and generates an
/// audit event for the outcome. Returns (result, granted_access).
pub unsafe fn check_access(
    security_descriptor: *const SecurityDescriptor,
    desired_access: u32,
    generic_mapping: &GenericMapping,
    object_type: &str,
    object_name: Option<&str>,
) -> (AccessCheckResult, u32) {
    unsafe {
        let subject = SecuritySubjectContext::capture();
        let token = subject.effective_token();

        let (result, granted) = se_access_check_with_context(
            security_descriptor,
            &subject,
            desired_access,
            generic_mapping,
            0,
        );

        // Audit the outcome (no-op if auditing is disabled or token is null).
        audit_event(
            object_type,
            object_name,
            security_descriptor,
            token,
            desired_access,
            granted,
            matches!(result, AccessCheckResult::Allowed),
        );

        (result, granted)
    }
}

pub fn init() {
    init_phase0();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_returns_null_tokens_in_test_context() {
        // In the unit test environment there is no per-CPU current
        // thread installed, so capture() should return a context
        // with null tokens (rather than dangling pointers).
        let ctx = SecuritySubjectContext::capture();
        assert!(ctx.client_token.is_null());
        assert!(ctx.primary_token.is_null());
        assert!(ctx.effective_token().is_null());
    }

    #[test]
    fn capture_new_default_has_null_tokens() {
        let ctx = SecuritySubjectContext::new();
        assert!(ctx.client_token.is_null());
        assert!(ctx.primary_token.is_null());
    }

    #[test]
    fn effective_token_prefers_client_over_primary() {
        let mut ctx = SecuritySubjectContext::new();
        let dummy = 0x1000 as *mut Token;

        // Only primary set.
        ctx.primary_token = dummy;
        assert_eq!(ctx.effective_token(), dummy);

        // Client set: client takes precedence.
        let dummy2 = 0x2000 as *mut Token;
        ctx.client_token = dummy2;
        assert_eq!(ctx.effective_token(), dummy2);
    }

    #[test]
    fn release_nulls_tokens() {
        let mut ctx = SecuritySubjectContext::new();
        ctx.client_token = 0x1000 as *mut Token;
        ctx.primary_token = 0x2000 as *mut Token;

        ctx.release();

        assert!(ctx.client_token.is_null());
        assert!(ctx.primary_token.is_null());
    }
}
