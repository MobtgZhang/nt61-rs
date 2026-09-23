//! ACL Manipulation and ACE Management
//!
//! Provides functions to add, remove, and query ACEs in ACLs.
//! This is the runtime ACL editing API used by security descriptor management.
//!
//! References: Windows SDK advapi32, WRK

use super::acl::{Acl, AceHeader, AceType, AceFlags, ACL_REVISION, MAX_ACES};
use super::sid::Sid;

pub fn create_acl(acl: *mut Acl, acl_length: u32, acl_revision: u8) -> bool {
    if acl.is_null() {
        return false;
    }
    if acl_length < 8 {
        return false;
    }
    if acl_revision != ACL_REVISION && acl_revision != super::acl::ACL_REVISION_DS {
        return false;
    }

    unsafe {
        (*acl).revision = acl_revision;
        (*acl).sbz1 = 0;
        (*acl).acl_size = acl_length as u16;
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
        (*acl).add_access_allowed(sid, access_mask, ace_flags)
    }
}

pub fn add_access_denied_ace(
    acl: *mut Acl,
    ace_revision: u8,
    access_mask: u32,
    sid: &Sid,
) -> bool {
    if acl.is_null() {
        return false;
    }

    unsafe {
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
        (*acl).add_ace(AceType::SystemMandatoryLabel, ace_flags, mandatory_policy, label_sid)
    }
}

pub fn get_ace(acl: *const Acl, ace_index: u32) -> (*const AceHeader, bool) {
    if acl.is_null() {
        return (core::ptr::null(), false);
    }

    unsafe {
        let acl_ref = &*acl;
        if ace_index >= acl_ref.ace_count as u32 {
            return (core::ptr::null(), false);
        }

        let mut offset = 8usize; // Skip ACL header
        let mut current_index = 0u32;

        while offset + 4 <= acl_ref.acl_size as usize && current_index <= ace_index {
            let ace_size = (acl_ref.data[offset + 2] as usize) | ((acl_ref.data[offset + 3] as usize) << 8);

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
        if ace_index >= acl_ref.ace_count as u32 {
            return false;
        }

        let mut offset = 8usize;
        let mut current_index = 0u32;

        while offset + 4 <= acl_ref.acl_size as usize && current_index <= ace_index {
            let ace_size = (acl_ref.data[offset + 2] as usize) | ((acl_ref.data[offset + 3] as usize) << 8);

            if current_index == ace_index {
                let remaining_size = acl_ref.acl_size as usize - offset - ace_size;
                if remaining_size > 0 {
                    for i in 0..remaining_size {
                        acl_ref.data[offset + i] = acl_ref.data[offset + ace_size + i];
                    }
                }
                for i in 0..ace_size {
                    let clear_offset = acl_ref.acl_size as usize - ace_size + i;
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
        let mut offset = 8usize;

        for _ in 0..acl_ref.ace_count {
            if offset + 4 > acl_ref.acl_size as usize {
                return (core::ptr::null_mut(), false);
            }
            let ace_size = (acl_ref.data[offset + 2] as usize) | ((acl_ref.data[offset + 3] as usize) << 8);
            offset += ace_size;
        }

        if offset >= acl_ref.acl_size as usize {
            return (core::ptr::null_mut(), false);
        }

        let free_ptr = (acl as *mut u8).add(offset);
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

        if !ace_count.is_null() {
            *ace_count = acl_ref.ace_count as u32;
        }

        if !acl_size.is_null() {
            *acl_size = acl_ref.acl_size as u32;
        }

        if !acl_bytes_free.is_null() {
            let mut used = 8usize; // ACL header
            for _ in 0..acl_ref.ace_count {
                if used + 4 > acl_ref.acl_size as usize {
                    break;
                }
                let ace_size = (acl_ref.data[used - 8 + 2] as usize) | ((acl_ref.data[used - 8 + 3] as usize) << 8);
                used += ace_size;
            }
            *acl_bytes_free = (acl_ref.acl_size as usize).saturating_sub(used) as u32;
        }

        true
    }
}

pub fn set_information_acl(
    acl: *mut Acl,
    acl_revision: u8,
) -> bool {
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

    unsafe {
        (*acl).is_valid()
    }
}

pub fn find_ace_by_sid(acl: *const Acl, sid: &Sid) -> Option<u32> {
    if acl.is_null() {
        return None;
    }

    unsafe {
        let acl_ref = &*acl;
        let mut offset = 8usize;

        for ace_index in 0..acl_ref.ace_count {
            if offset + 8 > acl_ref.acl_size as usize {
                break;
            }

            let ace_size = (acl_ref.data[offset + 2] as usize) | ((acl_ref.data[offset + 3] as usize) << 8);

            if ace_size < 8 {
                break;
            }

            let sid_offset = offset + 8;
            if sid_offset + 8 <= acl_ref.data.len() {
                let ace_sid = read_sid_from_acl_data(&acl_ref.data, sid_offset);
                if ace_sid.equals(sid) {
                    return Some(ace_index as u32);
                }
            }

            offset += ace_size;
        }
    }

    None
}

fn read_sid_from_acl_data(data: &[u8], offset: usize) -> Sid {
    if offset + 8 > data.len() {
        return Sid::new();
    }

    let revision = data[offset];
    let subauth_count = data[offset + 1];
    let mut ia = [0u8; 6];
    for i in 0..6 {
        if offset + 2 + i < data.len() {
            ia[i] = data[offset + 2 + i];
        }
    }

    let count = (subauth_count as usize).min(8);
    let mut subs = [0u32; 8];
    for i in 0..count {
        let off = offset + 8 + i * 4;
        if off + 4 <= data.len() {
            subs[i] = u32::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ]);
        }
    }

    Sid::with_authority_and_subs_arr(
        ia,
        count as u8,
        subs[0], subs[1], subs[2], subs[3],
        subs[4], subs[5], subs[6], subs[7],
    )
}

pub fn build_default_dacl(owner: &Sid, is_container: bool) -> *mut Acl {
    let acl_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Acl>(),
    ) as *mut Acl;

    if acl_ptr.is_null() {
        return core::ptr::null_mut();
    }

    if !create_acl(acl_ptr, core::mem::size_of::<Acl>() as u32, ACL_REVISION) {
        crate::mm::pool::free(acl_ptr as *mut u8);
        return core::ptr::null_mut();
    }

    let flags = if is_container {
        AceFlags::CONTAINER_INHERIT | AceFlags::OBJECT_INHERIT
    } else {
        AceFlags::NONE
    };

    let full_control = super::acl::ACCESS_GENERIC_ALL |
                       super::acl::ACCESS_DELETE |
                       super::acl::ACCESS_READ_CONTROL |
                       super::acl::ACCESS_WRITE_DAC |
                       super::acl::ACCESS_WRITE_OWNER;

    if !add_access_allowed_ace_ex(acl_ptr, ACL_REVISION, flags, full_control, owner) {
        crate::mm::pool::free(acl_ptr as *mut u8);
        return core::ptr::null_mut();
    }

    acl_ptr
}

pub fn init() {
}
