//! Mandatory Integrity Control (MIC)
//!
//! Implements Windows Vista+ integrity levels that enforce the "no write-up"
//! policy: a process at a lower integrity level cannot write to objects at
//! a higher integrity level.
//!
//! Integrity levels:
//!   - Untrusted (0x0000): Sandbox, highly restricted
//!   - Low (0x1000): Protected Mode IE, sandboxed apps
//!   - Medium (0x2000): Standard user processes (default)
//!   - High (0x3000): Elevated administrator processes
//!   - System (0x4000): System services and kernel
//!   - Protected (0x5000): Protected processes (DRM, anti-malware)
//!
//! References: Windows SDK, Windows Internals

use super::sid::Sid;
use super::token::{Token, TokenGroup, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_ENABLED};
use super::acl::Acl;

pub const SECURITY_MANDATORY_UNTRUSTED_RID: u32 = 0x0000;
pub const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;
pub const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;
pub const SECURITY_MANDATORY_MEDIUM_PLUS_RID: u32 = 0x2100;
pub const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;
pub const SECURITY_MANDATORY_SYSTEM_RID: u32 = 0x4000;
pub const SECURITY_MANDATORY_PROTECTED_PROCESS_RID: u32 = 0x5000;

pub const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x1;
pub const SYSTEM_MANDATORY_LABEL_NO_READ_UP: u32 = 0x2;
pub const SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP: u32 = 0x4;

pub fn create_integrity_level_sid(level_rid: u32) -> Sid {
    let ia = [0, 0, 0, 0, 0, 16];
    Sid::with_authority_and_subs_arr(
        ia,
        1,
        level_rid, 0, 0, 0, 0, 0, 0, 0,
    )
}

pub fn se_token_integrity_level(token: *const Token) -> u32 {
    if token.is_null() {
        return SECURITY_MANDATORY_MEDIUM_RID;
    }
    unsafe {
        (*token).integrity_level_rid
    }
}

pub fn se_set_token_integrity_level(token: *mut Token, level_rid: u32) -> bool {
    if token.is_null() {
        return false;
    }

    unsafe {
        (*token).integrity_level_rid = level_rid;

        let integrity_sid = create_integrity_level_sid(level_rid);

        let mut found = false;
        for i in 0..(*token).group_count {
            let sid = &(*token).groups[i].sid;
            if sid.identifier_authority() == 16 {
                (*token).groups[i].sid = integrity_sid;
                (*token).groups[i].attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED | SE_GROUP_ENABLED;
                found = true;
                break;
            }
        }

        if !found {
            (*token).add_group(TokenGroup {
                sid: integrity_sid,
                attributes: SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED | SE_GROUP_ENABLED,
            });
        }
    }

    true
}

pub fn se_check_mandatory_integrity(
    subject_token: *const Token,
    object_integrity: u32,
    desired_access: u32,
) -> bool {
    if subject_token.is_null() {
        return false;
    }

    let subject_level = se_token_integrity_level(subject_token);

    const WRITE_ACCESS_MASK: u32 =
        super::seaccess::ACCESS_GENERIC_WRITE |
        super::seaccess::ACCESS_WRITE_DAC |
        super::seaccess::ACCESS_WRITE_OWNER |
        0x40000000; // GENERIC_WRITE

    if (desired_access & WRITE_ACCESS_MASK) != 0 {
        if subject_level < object_integrity {
            return false;
        }
    }

    true
}

pub fn se_get_object_integrity_level(
    security_descriptor: *const super::seaccess::SecurityDescriptor,
) -> u32 {
    if security_descriptor.is_null() {
        return SECURITY_MANDATORY_MEDIUM_RID;
    }

    unsafe {
        let sd = &*security_descriptor;

        if !sd.sacl.is_null() {
            let sacl = &*sd.sacl;

            let mut offset = 8usize;
            for _ in 0..sacl.ace_count {
                if offset + 4 > sacl.acl_size as usize {
                    break;
                }

                let ace_type = sacl.data[offset];
                let ace_size = (sacl.data[offset + 2] as usize) | ((sacl.data[offset + 3] as usize) << 8);

                if ace_type == 0x11 && ace_size >= 8 {
                    let sid_offset = offset + 8;
                    if sid_offset + 8 <= sacl.data.len() {
                        let sid = read_sid_from_acl_data(&sacl.data, sid_offset);
                        if sid.identifier_authority() == 16 && sid.sub_authority_count >= 1 {
                            return sid.sub_authority[0];
                        }
                    }
                }

                offset += ace_size;
            }
        }
    }

    SECURITY_MANDATORY_MEDIUM_RID
}

fn read_sid_from_acl_data(data: &[u8], offset: usize) -> Sid {
    if offset + 8 > data.len() {
        return Sid::new();
    }

    let _revision = data[offset];
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

pub fn se_set_object_integrity_level(
    security_descriptor: *mut super::seaccess::SecurityDescriptor,
    level_rid: u32,
    policy: u32,
) -> bool {
    if security_descriptor.is_null() {
        return false;
    }


    unsafe {
        (*security_descriptor).control |= super::descriptor::SE_SACL_PRESENT;
    }

    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityComparison {
    Lower,
    Equal,
    Higher,
}

pub fn compare_integrity_levels(level1: u32, level2: u32) -> IntegrityComparison {
    if level1 < level2 {
        IntegrityComparison::Lower
    } else if level1 > level2 {
        IntegrityComparison::Higher
    } else {
        IntegrityComparison::Equal
    }
}

pub fn integrity_level_name(level_rid: u32) -> &'static str {
    match level_rid {
        SECURITY_MANDATORY_UNTRUSTED_RID => "Untrusted",
        SECURITY_MANDATORY_LOW_RID => "Low",
        SECURITY_MANDATORY_MEDIUM_RID => "Medium",
        SECURITY_MANDATORY_MEDIUM_PLUS_RID => "Medium Plus",
        SECURITY_MANDATORY_HIGH_RID => "High",
        SECURITY_MANDATORY_SYSTEM_RID => "System",
        SECURITY_MANDATORY_PROTECTED_PROCESS_RID => "Protected Process",
        _ => "Unknown",
    }
}

pub fn se_token_is_low_integrity(token: *const Token) -> bool {
    se_token_integrity_level(token) <= SECURITY_MANDATORY_LOW_RID
}

pub fn se_token_is_elevated(token: *const Token) -> bool {
    se_token_integrity_level(token) >= SECURITY_MANDATORY_HIGH_RID
}

pub fn se_lower_token_integrity(token: *mut Token, new_level: u32) -> bool {
    let current_level = se_token_integrity_level(token);

    if new_level >= current_level {
        return false;
    }

    se_set_token_integrity_level(token, new_level)
}

pub fn se_create_low_integrity_token(existing_token: *const Token) -> *mut Token {
    if existing_token.is_null() {
        return core::ptr::null_mut();
    }

    let new_token = super::tokenmgmt::se_duplicate_token(
        existing_token,
        unsafe { (*existing_token).impersonation_level },
        unsafe { (*existing_token).token_type },
    );

    if new_token.is_null() {
        return core::ptr::null_mut();
    }

    se_set_token_integrity_level(new_token, SECURITY_MANDATORY_LOW_RID);

    new_token
}

pub fn se_integrity_access_check(
    subject_token: *const Token,
    object_sd: *const super::seaccess::SecurityDescriptor,
    desired_access: u32,
) -> bool {
    let object_integrity = se_get_object_integrity_level(object_sd);
    se_check_mandatory_integrity(subject_token, object_integrity, desired_access)
}

pub fn init() {
}
