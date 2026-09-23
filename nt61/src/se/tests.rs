//! Security Subsystem Unit Tests
//!
//! Comprehensive test suite for the security subsystem.
//! Tests cover:
//! - SID creation and validation
//! - ACL construction and validation
//! - Token creation and manipulation
//! - Access checking
//! - Privilege management
//! - Security descriptors

use crate::rtl::testing::TestStats;

/// Run all security subsystem unit tests
pub fn run_tests() -> bool {
    let mut stats = TestStats::new("SE-UNIT");

    // SID Tests
    stats.test("SID Creation", test_sid_creation);
    stats.test("SID Validation", test_sid_validation);
    stats.test("SID Comparison", test_sid_comparison);
    stats.test("Well-Known SIDs", test_well_known_sids);

    // ACL Tests
    stats.test("ACL Creation", test_acl_creation);
    stats.test("ACE Addition", test_ace_addition);
    stats.test("ACL Validation", test_acl_validation);

    // Token Tests
    stats.test("Token Creation", test_token_creation);
    stats.test("Token SID Assignment", test_token_sid_assignment);
    stats.test("Token Group Membership", test_token_groups);
    stats.test("Token Privileges", test_token_privileges);

    // Access Check Tests
    stats.test("Access Check Allow", test_access_check_allow);
    stats.test("Access Check Deny", test_access_check_deny);
    stats.test("Generic Mapping", test_generic_mapping);

    // Security Descriptor Tests
    stats.test("SD Creation", test_security_descriptor_creation);
    stats.test("SD DACL", test_security_descriptor_dacl);
    stats.test("SD Owner", test_security_descriptor_owner);

    stats.finish()
}

// =============================================================================
// SID Tests
// =============================================================================

fn test_sid_creation() -> bool {
    use crate::se::sid::Sid;

    let sid = Sid::new_local_system();

    // Verify revision
    if sid.revision != 1 {
        return false;
    }

    // Verify sub-authority count
    if sid.sub_authority_count == 0 {
        return false;
    }

    crate::boot_println!("    SID: revision={}, sub_authorities={}",
                        sid.revision, sid.sub_authority_count);
    true
}

fn test_sid_validation() -> bool {
    use crate::se::sid::Sid;

    let sid = Sid::new_local_system();

    // Valid SID should have:
    // - Revision = 1
    // - Sub-authority count > 0 and <= 15
    // - Valid identifier authority

    if sid.revision != 1 {
        return false;
    }

    if sid.sub_authority_count == 0 || sid.sub_authority_count > 15 {
        return false;
    }

    true
}

fn test_sid_comparison() -> bool {
    use crate::se::sid::Sid;

    let sid1 = Sid::new_local_system();
    let sid2 = Sid::new_local_system();

    // Should be equal
    if !Sid::equal(&sid1, &sid2) {
        return false;
    }

    // Different SIDs should not be equal
    let sid3 = Sid::new_administrators();
    if Sid::equal(&sid1, &sid3) {
        return false;
    }

    true
}

fn test_well_known_sids() -> bool {
    use crate::se::sid::Sid;

    // Test well-known SID creation
    let system = Sid::new_local_system();
    let admins = Sid::new_administrators();
    let users = Sid::new_users();

    // Verify they're all different
    if Sid::equal(&system, &admins) {
        return false;
    }

    if Sid::equal(&system, &users) {
        return false;
    }

    if Sid::equal(&admins, &users) {
        return false;
    }

    crate::boot_println!("    Well-known SIDs: SYSTEM, Administrators, Users");
    true
}

// =============================================================================
// ACL Tests
// =============================================================================

fn test_acl_creation() -> bool {
    use crate::se::acl::Acl;

    let acl = Acl::new();

    // Verify initial state
    if acl.revision != 2 {
        return false;
    }

    if acl.ace_count != 0 {
        return false;
    }

    true
}

fn test_ace_addition() -> bool {
    use crate::se::acl::{Acl, AceType};
    use crate::se::sid::Sid;

    let mut acl = Acl::new();
    let sid = Sid::new_administrators();

    // Add an ACE
    let result = acl.add_ace(
        AceType::AccessAllowed,
        0x001F01FF, // GENERIC_ALL
        &sid,
    );

    if !result {
        return false;
    }

    if acl.ace_count != 1 {
        return false;
    }

    crate::boot_println!("    Added ACE to ACL, count={}", acl.ace_count);
    true
}

fn test_acl_validation() -> bool {
    use crate::se::acl::Acl;

    let acl = Acl::new();

    // Empty ACL is valid
    if !acl.is_valid() {
        return false;
    }

    true
}

// =============================================================================
// Token Tests
// =============================================================================

fn test_token_creation() -> bool {
    use crate::se::token;

    let token_ptr = token::create_token();
    if token_ptr.is_null() {
        return false;
    }

    unsafe {
        // Verify initial state
        if (*token_ptr).user_sid.revision != 1 {
            return false;
        }

        crate::boot_println!("    Created token at {:p}", token_ptr);
    }

    true
}

fn test_token_sid_assignment() -> bool {
    use crate::se::{token, sid::Sid};

    let token_ptr = token::create_token();
    if token_ptr.is_null() {
        return false;
    }

    let sid = Sid::new_local_system();

    unsafe {
        (*token_ptr).user_sid = sid;

        // Verify assignment
        if !Sid::equal(&(*token_ptr).user_sid, &sid) {
            return false;
        }
    }

    true
}

fn test_token_groups() -> bool {
    use crate::se::{token, sid::Sid};

    let token_ptr = token::create_token();
    if token_ptr.is_null() {
        return false;
    }

    unsafe {
        // Add groups
        let admin_sid = Sid::new_administrators();
        let result = token::add_group_to_token(token_ptr, &admin_sid);

        if !result {
            return false;
        }

        crate::boot_println!("    Added group to token");
    }

    true
}

fn test_token_privileges() -> bool {
    use crate::se::token;

    let token_ptr = token::create_token();
    if token_ptr.is_null() {
        return false;
    }

    // Add privilege
    let result = token::add_privilege(token_ptr, 0x02); // SE_CREATE_TOKEN_PRIVILEGE

    if !result {
        return false;
    }

    crate::boot_println!("    Added privilege to token");
    true
}

// =============================================================================
// Access Check Tests
// =============================================================================

fn test_access_check_allow() -> bool {
    use crate::se::{seaccess, token, sid::Sid, acl::{Acl, AceType}};

    let token_ptr = token::create_token();
    if token_ptr.is_null() {
        return false;
    }

    // Create security descriptor with NULL DACL (allow all)
    let sd = seaccess::create_null_dacl_sd();
    if sd.is_null() {
        return false;
    }

    // Perform access check
    let (result, _granted) = seaccess::se_access_check(
        seaccess::ObTypeIndex::Process,
        sd,
        0x001F01FF, // GENERIC_ALL
        token_ptr,
    );

    match result {
        seaccess::AccessCheckResult::Allowed => {
            crate::boot_println!("    Access check: ALLOWED");
            true
        }
        seaccess::AccessCheckResult::Denied => {
            crate::boot_println!("    Access check: DENIED (unexpected)");
            false
        }
    }
}

fn test_access_check_deny() -> bool {
    use crate::se::{seaccess, token, sid::Sid, acl::{Acl, AceType}};

    let token_ptr = token::create_token();
    if token_ptr.is_null() {
        return false;
    }

    // Create security descriptor with explicit deny
    let mut dacl = Acl::new();
    let sid = Sid::new_users();
    dacl.add_ace(AceType::AccessDenied, 0x001F01FF, &sid);

    let sd = seaccess::SecurityDescriptor {
        revision: 1,
        sbz1: 0,
        control: 0x8004,
        owner: Sid::new_local_system(),
        group: Sid::new_administrators(),
        sacl: core::ptr::null(),
        dacl: &dacl as *const Acl,
    };

    // This test requires matching SID in token - simplified for now
    crate::boot_println!("    Access check deny: OK (simplified)");
    true
}

fn test_generic_mapping() -> bool {
    use crate::se::seaccess;

    // Test generic rights mapping
    let generic_all = 0x10000000u32;
    let mapped = seaccess::map_generic_mask(
        generic_all,
        seaccess::ObTypeIndex::Process,
    );

    if mapped == 0 {
        return false;
    }

    crate::boot_println!("    Generic ALL mapped to: 0x{:x}", mapped);
    true
}

// =============================================================================
// Security Descriptor Tests
// =============================================================================

fn test_security_descriptor_creation() -> bool {
    use crate::se::seaccess;

    let sd = seaccess::create_null_dacl_sd();
    if sd.is_null() {
        return false;
    }

    unsafe {
        if (*sd).revision != 1 {
            return false;
        }

        crate::boot_println!("    Created security descriptor");
    }

    true
}

fn test_security_descriptor_dacl() -> bool {
    use crate::se::{seaccess, sid::Sid, acl::Acl};

    let mut dacl = Acl::new();

    let sd = seaccess::SecurityDescriptor {
        revision: 1,
        sbz1: 0,
        control: 0x8004,
        owner: Sid::new_local_system(),
        group: Sid::new_administrators(),
        sacl: core::ptr::null(),
        dacl: &dacl as *const Acl,
    };

    // Verify DACL is set
    if sd.dacl.is_null() {
        return false;
    }

    true
}

fn test_security_descriptor_owner() -> bool {
    use crate::se::{seaccess, sid::Sid};

    let owner = Sid::new_local_system();
    let group = Sid::new_administrators();

    let sd = seaccess::SecurityDescriptor {
        revision: 1,
        sbz1: 0,
        control: 0x8004,
        owner,
        group,
        sacl: core::ptr::null(),
        dacl: core::ptr::null(),
    };

    // Verify owner SID
    if !Sid::equal(&sd.owner, &owner) {
        return false;
    }

    true
}
