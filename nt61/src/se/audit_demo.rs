//! Security Audit System Demo
//!
//! Demonstrates the complete security audit functionality including:
//! - Audit policy management
//! - Audit event generation
//! - Audit log querying
//! - Integration with SeAccessCheck


use crate::se::audit_policy::{self, AuditCategory, presets};
use crate::se::audit_log::{self, get_statistics};
use crate::se::audit::{self, AuditEventOutcome, AuditCategoryId};
use crate::se::sid::{Sid, WellKnownSid};
use crate::se::token::Token;
use crate::se::seaccess::{self, ObTypeIndex, SecurityDescriptor};

/// Run the audit system demonstration

use crate::kprintln;
pub fn run_audit_demo() {
    crate::kprintln!("\n=== Security Audit System Demo ===\n");

    // 1. Initialize audit system
    crate::kprintln!("1. Initializing audit system...");
    audit::init();
    crate::kprintln!("   Audit system initialized");

    // 2. Configure audit policies
    crate::kprintln!("\n2. Configuring audit policies...");
    presets::apply_baseline();
    crate::kprintln!("   Applied baseline audit policy");

    // Display current policies
    let policies = audit_policy::get_all_policies();
    for (category, policy) in &policies {
        if policy.is_any_enabled() {
            kprintln!("   {} - Success: {}, Failure: {}", category.name(), policy.success_enabled, policy.failure_enabled);
        }
    }

    // 3. Generate sample audit events
    crate::kprintln!("\n3. Generating sample audit events...");

    // Logon event
    let user_sid = Sid::well_known(WellKnownSid::World);
    audit::se_audit_logon(
        AuditEventOutcome::Success,
        &user_sid,
        2, // Interactive logon
        0x1234567890ABCDEF,
    );
    crate::kprintln!("   Generated logon event (4624)");

    // Object access event
    let token = Token::create_system_token();
    audit::se_audit_object_access(
        AuditEventOutcome::Success,
        &token,
        "File",
        "C:\\Windows\\System32\\config\\SAM",
        0x001F01FF, // GENERIC_ALL
    );
    crate::kprintln!("   Generated object access event (4663)");

    // Privilege use event
    let privilege = crate::se::token::Luid {
        low_part: seaccess::privileges::SE_DEBUG as u32,
        high_part: 0,
    };
    audit::se_audit_privilege_use(
        AuditEventOutcome::Success,
        &token,
        &privilege,
    );
    crate::kprintln!("   Generated privilege use event (4673)");

    // Policy change event
    audit::se_audit_policy_change(&token, "Audit policy modified");
    crate::kprintln!("   Generated policy change event (4719)");

    // Process creation event
    audit::se_audit_process_creation(
        &token,
        1234,
        "C:\\Windows\\System32\\notepad.exe",
        4,
    );
    crate::kprintln!("   Generated process creation event (4688)");

    // 4. Query audit logs
    crate::kprintln!("\n4. Querying audit logs...");

    let all_events = audit_log::query_records(None, None, None, None, 100);
    crate::kprintln!("   Total events: {}", all_events.len());

    let logon_events = audit_log::query_records(
        Some(AuditCategory::Logon),
        None,
        None,
        None,
        100,
    );
    crate::kprintln!("   Logon events: {}", logon_events.len());

    let object_events = audit_log::query_records(
        Some(AuditCategory::ObjectAccess),
        None,
        None,
        None,
        100,
    );
    crate::kprintln!("   Object access events: {}", object_events.len());

    // 5. Display statistics
    crate::kprintln!("\n5. Audit log statistics:");
    let stats = get_statistics();
    crate::kprintln!("   Current records: {}", stats.current_count);
    crate::kprintln!("   Total written: {}", stats.total_written);
    crate::kprintln!("   Rotations: {}", stats.rotation_count);
    crate::kprintln!("   Next record ID: {}", stats.next_record_id);

    // 6. Display recent events
    crate::kprintln!("\n6. Recent audit events:");
    let recent = audit_log::get_recent_records(5);
    for (i, event) in recent.iter().enumerate() {
        kprintln!("   [{}] Event ID: {}, Category: {}, Success: {}", i + 1, event.event_id, event.category.name(), event.success);
        if !event.object_name.is_empty() {
            crate::kprintln!("       Object: {}", event.object_name);
        }
        if !event.details.is_empty() {
            crate::kprintln!("       Details: {}", event.details);
        }
    }

    // 7. Test audit integration with SeAccessCheck
    crate::kprintln!("\n7. Testing SeAccessCheck audit integration...");

    // Enable object access auditing
    audit::se_set_audit_policy(AuditCategoryId::ObjectAccess, true, true);

    // Clear log to see only new events
    let before_count = audit_log::get_record_count();

    // Perform an access check (will generate audit event)
    let sd_ptr = SecurityDescriptor::new_null_dacl();
    let token_ptr = &token as *const Token;
    let (result, granted) = seaccess::se_access_check(
        ObTypeIndex::File,
        sd_ptr,
        0x001F01FF, // GENERIC_ALL
        token_ptr,
    );

    crate::kprintln!("   Access check result: {:?}", result);
    crate::kprintln!("   Granted access: 0x{:08X}", granted);

    let after_count = audit_log::get_record_count();
    if after_count > before_count {
        crate::kprintln!("   Audit event generated by SeAccessCheck!");
    }

    crate::kprintln!("\n=== Demo Complete ===\n");
}

/// Test audit policy changes
pub fn test_audit_policy_changes() {
    crate::kprintln!("\n=== Audit Policy Change Test ===\n");

    audit_log::clear_log();

    // Test different policy configurations
    crate::kprintln!("1. Testing minimal policy...");
    presets::apply_minimal();

    let token = Token::create_system_token();

    // This should be logged (Logon enabled)
    let sid = Sid::well_known(WellKnownSid::World);
    audit::se_audit_logon(AuditEventOutcome::Success, &sid, 2, 0x1234);

    // This should NOT be logged (ObjectAccess disabled)
    audit::se_audit_object_access(
        AuditEventOutcome::Success,
        &token,
        "File",
        "test.txt",
        0x001F01FF,
    );

    let count_minimal = audit_log::get_record_count();
    crate::kprintln!("   Events with minimal policy: {}", count_minimal);

    crate::kprintln!("\n2. Testing comprehensive policy...");
    presets::apply_comprehensive();

    // Both should be logged now
    audit::se_audit_logon(AuditEventOutcome::Success, &sid, 2, 0x5678);
    audit::se_audit_object_access(
        AuditEventOutcome::Success,
        &token,
        "File",
        "test2.txt",
        0x001F01FF,
    );

    let count_comprehensive = audit_log::get_record_count();
    crate::kprintln!("   Events with comprehensive policy: {}", count_comprehensive);

    crate::kprintln!("\n=== Test Complete ===\n");
}

/// Stress test the audit system
pub fn stress_test_audit_system() {
    crate::kprintln!("\n=== Audit System Stress Test ===\n");

    audit_log::clear_log();
    presets::apply_comprehensive();

    let token = Token::create_system_token();
    let sid = Sid::well_known(WellKnownSid::World);

    crate::kprintln!("Generating 1000 audit events...");

    for i in 0..1000 {
        match i % 5 {
            0 => {
                audit::se_audit_logon(
                    AuditEventOutcome::Success,
                    &sid,
                    2,
                    i as u64,
                );
            }
            1 => {
                audit::se_audit_object_access(
                    AuditEventOutcome::Success,
                    &token,
                    "File",
                    "test.txt",
                    0x001F01FF,
                );
            }
            2 => {
                let priv_luid = crate::se::token::Luid {
                    low_part: seaccess::privileges::SE_DEBUG as u32,
                    high_part: 0,
                };
                audit::se_audit_privilege_use(
                    AuditEventOutcome::Success,
                    &token,
                    &priv_luid,
                );
            }
            3 => {
                audit::se_audit_process_creation(
                    &token,
                    i as u64,
                    "test.exe",
                    0,
                );
            }
            _ => {
                audit::se_audit_system_event(
                    5038,
                    "System event",
                );
            }
        }
    }

    let stats = get_statistics();
    crate::kprintln!("\nResults:");
    crate::kprintln!("  Total written: {}", stats.total_written);
    crate::kprintln!("  Current count: {}", stats.current_count);
    crate::kprintln!("  Rotations: {}", stats.rotation_count);

    if stats.rotation_count > 0 {
        crate::kprintln!("\n  Log rotation triggered successfully!");
    }

    crate::kprintln!("\n=== Stress Test Complete ===\n");
}
