//! SID Allocation and Validation
//!
//! Provides utilities for:
//!   - Allocating and copying SIDs
//!   - Converting SIDs to/from string format
//!   - Validating SID structure
//!   - Comparing SIDs
//!   - Well-known SID helpers
//!
//! References: Windows SDK advapi32, WRK

use alloc::vec::Vec;

use super::sid::{Sid, WellKnownSid, SID_REVISION, SID_MAX_SUB_AUTHORITIES};

pub fn allocate_and_initialize_sid(
    identifier_authority: [u8; 6],
    sub_authority_count: u8,
    sub_authorities: &[u32],
) -> *mut Sid {
    if sub_authority_count as usize > SID_MAX_SUB_AUTHORITIES {
        return core::ptr::null_mut();
    }

    let sid_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Sid>(),
    ) as *mut Sid;

    if sid_ptr.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        (*sid_ptr).revision = SID_REVISION;
        (*sid_ptr).sub_authority_count = sub_authority_count;
        (*sid_ptr).identifier_authority = identifier_authority;

        for i in 0..SID_MAX_SUB_AUTHORITIES {
            if i < sub_authority_count as usize && i < sub_authorities.len() {
                (*sid_ptr).sub_authority[i] = sub_authorities[i];
            } else {
                (*sid_ptr).sub_authority[i] = 0;
            }
        }
    }

    sid_ptr
}

pub fn free_sid(sid: *mut Sid) {
    if !sid.is_null() {
        crate::mm::pool::free(sid as *mut u8);
    }
}

pub fn copy_sid(destination: *mut Sid, source: *const Sid) -> bool {
    if destination.is_null() || source.is_null() {
        return false;
    }

    unsafe {
        *destination = *source;
    }

    true
}

pub fn equal_sid(sid1: *const Sid, sid2: *const Sid) -> bool {
    if sid1.is_null() || sid2.is_null() {
        return false;
    }

    unsafe {
        (*sid1).equals(&*sid2)
    }
}

pub fn valid_sid(sid: *const Sid) -> bool {
    if sid.is_null() {
        return false;
    }

    unsafe {
        let s = &*sid;

        if s.revision != SID_REVISION {
            return false;
        }

        if s.sub_authority_count as usize > SID_MAX_SUB_AUTHORITIES {
            return false;
        }

        true
    }
}

pub fn length_sid(sid: *const Sid) -> u32 {
    if sid.is_null() {
        return 0;
    }

    unsafe {
        (*sid).size() as u32
    }
}

pub fn identifier_authority_sid(sid: *const Sid) -> u64 {
    if sid.is_null() {
        return 0;
    }

    unsafe {
        (*sid).identifier_authority()
    }
}

pub fn sub_authority_count_sid(sid: *const Sid) -> u8 {
    if sid.is_null() {
        return 0;
    }

    unsafe {
        (*sid).sub_authority_count
    }
}

pub fn sub_authority_sid(sid: *mut Sid, sub_authority_index: u32) -> *mut u32 {
    if sid.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        if sub_authority_index as usize >= (*sid).sub_authority_count as usize {
            return core::ptr::null_mut();
        }

        &mut (*sid).sub_authority[sub_authority_index as usize] as *mut u32
    }
}

pub fn convert_sid_to_unicode_string(sid: *const Sid, output: &mut [u16], max_length: usize) -> bool {
    if sid.is_null() || output.len() == 0 {
        return false;
    }

    unsafe {
        let sid_str = (*sid).to_string();
        let mut len = 0;
        for i in 0..max_length.min(output.len()) {
            if sid_str[i] == 0 {
                break;
            }
            output[i] = sid_str[i];
            len += 1;
        }
        if len < output.len() {
            output[len] = 0;
        }
        true
    }
}

pub fn allocate_well_known_sid(which: WellKnownSid) -> *mut Sid {
    let sid_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Sid>(),
    ) as *mut Sid;

    if sid_ptr.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        *sid_ptr = Sid::well_known(which);
    }

    sid_ptr
}

pub fn create_security_descriptor_for_sid(owner: *const Sid, group: *const Sid) -> *mut super::seaccess::SecurityDescriptor {
    if owner.is_null() {
        return core::ptr::null_mut();
    }

    let sd_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<super::seaccess::SecurityDescriptor>(),
    ) as *mut super::seaccess::SecurityDescriptor;

    if sd_ptr.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        (*sd_ptr).revision = 1;
        (*sd_ptr).sbz1 = 0;
        (*sd_ptr).control = 0;
        (*sd_ptr).owner = owner as *mut Sid;
        (*sd_ptr).group = if group.is_null() { owner as *mut Sid } else { group as *mut Sid };
        (*sd_ptr).sacl = core::ptr::null_mut();
        (*sd_ptr).dacl = core::ptr::null_mut();
    }

    sd_ptr
}

pub fn parse_sid_string(sid_string: &str) -> Option<Sid> {
    let parts: Vec<&str> = sid_string.split('-').collect();

    if parts.len() < 3 || parts[0] != "S" {
        return None;
    }

    let revision = parts[1].parse::<u8>().ok()?;
    if revision != SID_REVISION {
        return None;
    }

    let ia_value = parts[2].parse::<u64>().ok()?;
    let ia = [
        ((ia_value >> 40) & 0xFF) as u8,
        ((ia_value >> 32) & 0xFF) as u8,
        ((ia_value >> 24) & 0xFF) as u8,
        ((ia_value >> 16) & 0xFF) as u8,
        ((ia_value >> 8) & 0xFF) as u8,
        (ia_value & 0xFF) as u8,
    ];

    let mut sub_authorities = [0u32; SID_MAX_SUB_AUTHORITIES];
    let sub_count = (parts.len() - 3).min(SID_MAX_SUB_AUTHORITIES);

    for i in 0..sub_count {
        sub_authorities[i] = parts[3 + i].parse::<u32>().ok()?;
    }

    Some(Sid::with_authority_and_subs_arr(
        ia,
        sub_count as u8,
        sub_authorities[0], sub_authorities[1], sub_authorities[2], sub_authorities[3],
        sub_authorities[4], sub_authorities[5], sub_authorities[6], sub_authorities[7],
    ))
}

pub fn is_well_known_sid(sid: *const Sid, which: WellKnownSid) -> bool {
    if sid.is_null() {
        return false;
    }

    let well_known = Sid::well_known(which);
    unsafe {
        (*sid).equals(&well_known)
    }
}

pub fn get_sid_rid(sid: *const Sid) -> u32 {
    if sid.is_null() {
        return 0;
    }

    unsafe {
        let count = (*sid).sub_authority_count as usize;
        if count == 0 {
            return 0;
        }
        (*sid).sub_authority[count - 1]
    }
}

pub fn sid_in_domain(sid: *const Sid, domain_sid: *const Sid) -> bool {
    if sid.is_null() || domain_sid.is_null() {
        return false;
    }

    unsafe {
        let s = &*sid;
        let d = &*domain_sid;

        if s.identifier_authority() != d.identifier_authority() {
            return false;
        }

        if s.sub_authority_count < d.sub_authority_count {
            return false;
        }

        for i in 0..d.sub_authority_count as usize {
            if s.sub_authority[i] != d.sub_authority[i] {
                return false;
            }
        }

        true
    }
}

pub fn create_domain_sid(domain_sid: *const Sid, rid: u32) -> *mut Sid {
    if domain_sid.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        let domain = &*domain_sid;
        if domain.sub_authority_count as usize >= SID_MAX_SUB_AUTHORITIES {
            return core::ptr::null_mut();
        }

        let new_sid_ptr = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<Sid>(),
        ) as *mut Sid;

        if new_sid_ptr.is_null() {
            return core::ptr::null_mut();
        }

        *new_sid_ptr = *domain;
        let new_count = domain.sub_authority_count + 1;
        (*new_sid_ptr).sub_authority_count = new_count;
        (*new_sid_ptr).sub_authority[new_count as usize - 1] = rid;

        new_sid_ptr
    }
}

pub fn create_integrity_sid(level: u32) -> *mut Sid {

    let ia = [0, 0, 0, 0, 0, 16]; // Authority 16 = Mandatory Label
    let sub_authorities = [level];

    allocate_and_initialize_sid(ia, 1, &sub_authorities)
}

pub fn init() {
}
