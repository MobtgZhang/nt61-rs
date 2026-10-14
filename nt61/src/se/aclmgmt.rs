//! ACL Manipulation and ACE Management
//!
//! Provides functions to add, remove, and query ACEs in ACLs.
//! This is the runtime ACL editing API used by security descriptor management.
//!
//! References: Windows SDK advapi32, WRK

use super::acl::{AceFlags, AceHeader, AceType, Acl, ACL_REVISION, MAX_ACES};
use super::sid::Sid;

pub fn create_acl(acl: *mut Acl, acl_length: u32, acl_revision: u8) -> bool {
    if acl.is_null() {
        return false;
    }
    if acl_length < 8 || acl_length as usize > Acl::new().data.len() {
        return false;
    }
    if acl_revision != ACL_REVISION && acl_revision != super::acl::ACL_REVISION_DS {
        return false;
    }

    unsafe {
        (*acl).revision = acl_revision;
        (*acl).sbz1 = 0;
        (*acl).acl_size = 8;
        (*acl).ace_count = 0;
        (*acl).sbz2 = 0;
        for i in 0..(*acl).data.len() {
            (*acl).data[i] = 0;
        }
    }

    true
}

pub fn add_access_allowed_ace(
    acl: *mut Acl,
    ace_revision: u8,
    access_mask: u32,
    sid: &Sid,
) -> bool {
    if acl.is_null() {
        return false;
    }

    unsafe {
        if ace_revision != ACL_REVISION && ace_revision != super::acl::ACL_REVISION_DS {
            return false;
        }
        (*acl).add_access_allowed(sid, access_mask, AceFlags::NONE)
    }
}

pub fn add_access_allowed_ace_ex(
    acl: *mut Acl,
    ace_revision: u8,
    ace_flags: AceFlags,
    access_mask: u32,
    sid: &Sid,
) -> bool {
    if acl.is_null() {
        return false;
    }

    unsafe {
        if ace_revision != ACL_REVISION && ace_revision != super::acl::ACL_REVISION_DS {
            return false;
        }
        (*acl).add_access_allowed(sid, access_mask, ace_flags)
    }
}

pub fn add_access_denied_ace(acl: *mut Acl, ace_revision: u8, access_mask: u32, sid: &Sid) -> bool {
    if acl.is_null() {
        return false;
    }

    unsafe {
        if ace_revision != ACL_REVISION && ace_revision != super::acl::ACL_REVISION_DS {
            return false;
        }
        (*acl).add_access_denied(sid, access_mask, AceFlags::NONE)
    }
}

pub fn add_access_denied_ace_ex(
    acl: *mut Acl,
    ace_revision: u8,
    ace_flags: AceFlags,
    access_mask: u32,
    sid: &Sid,
) -> bool {
    if acl.is_null() {
        return false;
    }

    unsafe {
        if ace_revision != ACL_REVISION && ace_revision != super::acl::ACL_REVISION_DS {
            return false;
        }
        (*acl).add_access_denied(sid, access_mask, ace_flags)
    }
}

pub fn add_mandatory_ace(
    acl: *mut Acl,
    ace_revision: u8,
    ace_flags: AceFlags,
    mandatory_policy: u32,
    label_sid: &Sid,
) -> bool {
    if acl.is_null() {
        return false;
    }

    // Mandatory ACEs use SYSTEM_MANDATORY_LABEL_ACE type
    // For now, add as a regular ACE (full implementation would use special type)
    unsafe {
        if ace_revision != ACL_REVISION && ace_revision != super::acl::ACL_REVISION_DS {
            return false;
        }
        (*acl).add_ace(
            AceType::SystemMandatoryLabel,
            ace_flags,
            mandatory_policy,
            label_sid,
        )
    }
}

pub fn get_ace(acl: *const Acl, ace_index: u32) -> (*const AceHeader, bool) {
    if acl.is_null() {
        return (core::ptr::null(), false);
    }

    unsafe {
        let acl_ref = &*acl;
        if !acl_ref.is_valid() {
            return (core::ptr::null(), false);
        }
        if ace_index >= acl_ref.ace_count as u32 {
            return (core::ptr::null(), false);
        }

        let mut offset = 8usize; // Skip ACL header
        let mut current_index = 0u32;

        while offset + 4 <= acl_ref.used_size().unwrap_or(0) && current_index <= ace_index {
            let ace_size =
                (acl_ref.data[offset + 2] as usize) | ((acl_ref.data[offset + 3] as usize) << 8);
            if ace_size < 8 || offset + ace_size > acl_ref.used_size().unwrap_or(0) {
                return (core::ptr::null(), false);
            }

            if current_index == ace_index {
                let ace_ptr = acl_ref.data.as_ptr().add(offset) as *const AceHeader;
                return (ace_ptr, true);
            }

            offset += ace_size;
            current_index += 1;
        }

        (core::ptr::null(), false)
    }
}

pub fn delete_ace(acl: *mut Acl, ace_index: u32) -> bool {
    if acl.is_null() {
        return false;
    }

    unsafe {
        let acl_ref = &mut *acl;
        if !acl_ref.is_valid() {
            return false;
        }
        if ace_index >= acl_ref.ace_count as u32 {
            return false;
        }

        let mut offset = 8usize;
        let mut current_index = 0u32;

        while offset + 4 <= acl_ref.used_size().unwrap_or(0) && current_index <= ace_index {
            let ace_size =
                (acl_ref.data[offset + 2] as usize) | ((acl_ref.data[offset + 3] as usize) << 8);
            if ace_size < 8 || offset + ace_size > acl_ref.used_size().unwrap_or(0) {
                return false;
            }

            if current_index == ace_index {
                let used_size = acl_ref.used_size().unwrap_or(0);
                let remaining_size = used_size - offset - ace_size;
                if remaining_size > 0 {
                    for i in 0..remaining_size {
                        acl_ref.data[offset + i] = acl_ref.data[offset + ace_size + i];
                    }
                }
                for i in 0..ace_size {
                    let clear_offset = used_size - ace_size + i;
                    if clear_offset < acl_ref.data.len() {
                        acl_ref.data[clear_offset] = 0;
                    }
                }
                acl_ref.acl_size -= ace_size as u16;
                acl_ref.ace_count -= 1;
                return true;
            }

            offset += ace_size;
            current_index += 1;
        }

        false
    }
}

pub fn first_free_ace(acl: *const Acl) -> (*mut u8, bool) {
    if acl.is_null() {
        return (core::ptr::null_mut(), false);
    }

    unsafe {
        let acl_ref = &*acl;
        if !acl_ref.is_valid() {
            return (core::ptr::null_mut(), false);
        }
        let mut offset = 8usize;

        for _ in 0..acl_ref.ace_count {
            if offset + 4 > acl_ref.used_size().unwrap_or(0) {
                return (core::ptr::null_mut(), false);
            }
            let ace_size =
                (acl_ref.data[offset + 2] as usize) | ((acl_ref.data[offset + 3] as usize) << 8);
            if ace_size < 8 || offset + ace_size > acl_ref.used_size().unwrap_or(0) {
                return (core::ptr::null_mut(), false);
            }
            offset += ace_size;
        }

        if offset >= acl_ref.data.len() {
            return (core::ptr::null_mut(), false);
        }

        let free_ptr = acl_ref.data.as_ptr().add(offset) as *mut u8;
        (free_ptr, true)
    }
}

pub fn query_information_acl(
    acl: *const Acl,
    ace_count: *mut u32,
    acl_size: *mut u32,
    acl_bytes_free: *mut u32,
) -> bool {
    if acl.is_null() {
        return false;
    }

    unsafe {
        let acl_ref = &*acl;
        if !acl_ref.is_valid() {
            return false;
        }

        if !ace_count.is_null() {
            *ace_count = acl_ref.ace_count as u32;
        }

        if !acl_size.is_null() {
            *acl_size = acl_ref.acl_size as u32;
        }

        if !acl_bytes_free.is_null() {
            let used = acl_ref.used_size().unwrap_or(8);
            *acl_bytes_free = acl_ref.data.len().saturating_sub(used) as u32;
        }

        true
    }
}

pub fn set_information_acl(acl: *mut Acl, acl_revision: u8) -> bool {
    if acl.is_null() {
        return false;
    }

    if acl_revision != ACL_REVISION && acl_revision != super::acl::ACL_REVISION_DS {
        return false;
    }

    unsafe {
        (*acl).revision = acl_revision;
    }

    true
}

pub fn valid_acl(acl: *const Acl) -> bool {
    if acl.is_null() {
        return false;
    }

    unsafe { (*acl).is_valid() }
}

pub fn find_ace_by_sid(acl: *const Acl, sid: &Sid) -> Option<u32> {
    if acl.is_null() {
        return None;
    }

    unsafe {
        let acl_ref = &*acl;
        if !acl_ref.is_valid() || !sid.is_valid() {
            return None;
        }
        let used_size = acl_ref.used_size()?;
        let mut offset = 8usize;

        for ace_index in 0..acl_ref.ace_count {
            if offset + 8 > used_size {
                break;
            }

            let ace_size =
                (acl_ref.data[offset + 2] as usize) | ((acl_ref.data[offset + 3] as usize) << 8);

            if ace_size < 8 || offset + ace_size > used_size {
                break;
            }

            let sid_offset = offset + 8;
            if matches!(
                AceType::from_u8(acl_ref.data[offset]),
                Some(
                    AceType::AccessAllowed
                        | AceType::AccessDenied
                        | AceType::SystemAudit
                        | AceType::SystemAlarm
                        | AceType::AccessAllowedCallback
                        | AceType::AccessDeniedCallback
                        | AceType::SystemAuditCallback
                        | AceType::SystemAlarmCallback
                        | AceType::SystemMandatoryLabel
                        | AceType::SystemProcessTrustLabel
                )
            ) {
                if let Some(ace_sid) =
                    read_sid_from_acl_data(&acl_ref.data[sid_offset..offset + ace_size])
                {
                    if ace_sid.equals(sid) {
                        return Some(ace_index as u32);
                    }
                }
            }

            offset += ace_size;
        }
    }

    None
}

fn read_sid_from_acl_data(data: &[u8]) -> Option<Sid> {
    Sid::from_bytes(data)
}

pub fn build_default_dacl(owner: &Sid, is_container: bool) -> *mut Acl {
    let acl_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Acl>(),
    ) as *mut Acl;

    if acl_ptr.is_null() {
        return core::ptr::null_mut();
    }

    if !create_acl(
        acl_ptr,
        (core::mem::size_of::<Acl>() - 8) as u32,
        ACL_REVISION,
    ) {
        crate::mm::pool::free(acl_ptr as *mut u8);
        return core::ptr::null_mut();
    }

    let flags = if is_container {
        AceFlags::CONTAINER_INHERIT | AceFlags::OBJECT_INHERIT
    } else {
        AceFlags::NONE
    };

    let full_control = super::acl::ACCESS_GENERIC_ALL
        | super::acl::ACCESS_DELETE
        | super::acl::ACCESS_READ_CONTROL
        | super::acl::ACCESS_WRITE_DAC
        | super::acl::ACCESS_WRITE_OWNER;

    if !add_access_allowed_ace_ex(acl_ptr, ACL_REVISION, flags, full_control, owner) {
        crate::mm::pool::free(acl_ptr as *mut u8);
        return core::ptr::null_mut();
    }

    acl_ptr
}

pub fn init() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::se::sid::WellKnownSid;

    #[test]
    fn acl_management_uses_inline_data_for_ace_addresses() {
        let mut acl = Acl::new();
        let sid = Sid::well_known(WellKnownSid::LocalSystem);
        assert!(add_access_allowed_ace(&mut acl, ACL_REVISION, 0x10, &sid));

        let (ace, ok) = get_ace(&acl, 0);
        assert!(ok);
        assert!(!ace.is_null());
        unsafe {
            assert_eq!((*ace).ace_type, AceType::AccessAllowed as u8);
        }

        let (free, ok) = first_free_ace(&acl);
        assert!(ok);
        unsafe {
            assert_eq!(
                free,
                acl.data.as_ptr().add(8 + 4 + 4 + sid.size()) as *mut u8
            );
        }
        assert_eq!(find_ace_by_sid(&acl, &sid), Some(0));
    }

    #[test]
    fn malformed_sid_is_not_treated_as_a_match() {
        let mut acl = Acl::new();
        let sid = Sid::well_known(WellKnownSid::LocalSystem);
        assert!(add_access_allowed_ace(&mut acl, ACL_REVISION, 0x10, &sid));
        let used = acl.acl_size as usize;
        acl.data[17] = 2;
        assert!(!acl.is_valid());
        assert_eq!(find_ace_by_sid(&acl, &sid), None);
        assert_eq!(used, 28);
    }
}
