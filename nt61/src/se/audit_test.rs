//! Security Audit System Tests
//!
//! Comprehensive tests for the audit policy, audit log, and audit event generation.

#[cfg(test)]
mod tests {
    use crate::se::audit_policy::{self, AuditCategory, CategoryPolicy};
    use crate::se::audit_log::{self, AuditRecord};
    use crate::se::audit::{self, AuditEventOutcome, AuditCategoryId};
    use crate::se::sid::{Sid, WellKnownSid};
    use crate::se::token::{Token, Luid};
    use alloc::string::String;

    #[test]
    fn test_audit_policy_initialization() {
        audit_policy::init();

        // Check default policies (Logon and AccountLogon should be enabled)
        let logon_policy = audit_policy::get_category_policy(AuditCategory::Logon);
        assert!(logon_policy.success_enabled);
        assert!(logon_policy.failure_enabled);

        let account_logon_policy = audit_policy::get_category_policy(AuditCategory::AccountLogon);
        assert!(account_logon_policy.success_enabled);
        assert!(account_logon_policy.failure_enabled);
    }

    #[test]
    fn test_audit_policy_set_get() {
        audit_policy::init();

        // Set a custom policy
        let category = AuditCategory::ObjectAccess;
        let policy = CategoryPolicy::new(true, false);
        audit_policy::set_category_policy(category, policy);

        // Verify it was set correctly
        let retrieved = audit_policy::get_category_policy(category);
        assert!(retrieved.success_enabled);
        assert!(!retrieved.failure_enabled);
    }

    #[test]
    fn test_audit_policy_enable_disable() {
        audit_policy::init();

        // Enable a category
        audit_policy::enable_category(AuditCategory::PrivilegeUse);
        assert!(audit_policy::is_enabled(AuditCategory::PrivilegeUse, true));
        assert!(audit_policy::is_enabled(AuditCategory::PrivilegeUse, false));

        // Disable it
        audit_policy::disable_category(AuditCategory::PrivilegeUse);
        assert!(!audit_policy::is_enabled(AuditCategory::PrivilegeUse, true));
        assert!(!audit_policy::is_enabled(AuditCategory::PrivilegeUse, false));
    }

    #[test]
    fn test_audit_policy_presets() {
        // Test minimal preset
        audit_policy::presets::apply_minimal();
        assert!(audit_policy::is_enabled(AuditCategory::Logon, true));
        assert!(!audit_policy::is_enabled(AuditCategory::ObjectAccess, true));

        // Test comprehensive preset
        audit_policy::presets::apply_comprehensive();
        assert!(audit_policy::is_enabled(AuditCategory::ObjectAccess, true));
        assert!(audit_policy::is_enabled(AuditCategory::PrivilegeUse, true));
        assert!(audit_policy::is_enabled(AuditCategory::System, true));
    }

    #[test]
    fn test_audit_log_write() {
        audit_log::init();
        audit_log::clear_log();

        let sid = Sid::well_known(WellKnownSid::World);
        let mut record = AuditRecord::new(
            4624,
            AuditCategory::Logon,
            true,
            sid,
        );
        record.set_details(String::from("Test logon event"));

        audit_log::write_audit_record(record);

        let count = audit_log::get_record_count();
        assert!(count > 0);
    }

    #[test]
    fn test_audit_log_query_by_category() {
        audit_log::init();
        audit_log::clear_log();

        let sid = Sid::well_known(WellKnownSid::World);

        // Write different event types
        for i in 0..5 {
            let category = if i % 2 == 0 {
                AuditCategory::Logon
            } else {
                AuditCategory::ObjectAccess
            };

            let record = AuditRecord::new(4624, category, true, sid.clone());
            audit_log::write_audit_record(record);
        }

        // Query by category
        let logon_events = audit_log::query_records(
            Some(AuditCategory::Logon),
            None,
            None,
            None,
            100,
        );
        assert_eq!(logon_events.len(), 3);

        let object_events = audit_log::query_records(
            Some(AuditCategory::ObjectAccess),
            None,
            None,
            None,
            100,
        );
        assert_eq!(object_events.len(), 2);
    }

    #[test]
    fn test_audit_log_query_by_success() {
        audit_log::init();
        audit_log::clear_log();

        let sid = Sid::well_known(WellKnownSid::World);

        // Write mixed success/failure events
        for i in 0..10 {
            let record = AuditRecord::new(
                4624,
                AuditCategory::Logon,
                i % 2 == 0,
                sid.clone(),
            );
            audit_log::write_audit_record(record);
        }

        // Query success only
        let success_events = audit_log::query_records(
            None,
            None,
            None,
            Some(true),
            100,
        );
        assert_eq!(success_events.len(), 5);

        // Query failure only
        let failure_events = audit_log::query_records(
            None,
            None,
            None,
            Some(false),
            100,
        );
        assert_eq!(failure_events.len(), 5);
    }

    #[test]
    fn test_audit_log_rotation() {
        audit_log::init();
        audit_log::clear_log();

        let sid = Sid::well_known(WellKnownSid::World);

        // Write more than MAX_AUDIT_RECORDS to trigger rotation
        for i in 0..audit_log::MAX_AUDIT_RECORDS + 100 {
            let record = AuditRecord::new(
                4624,
                AuditCategory::Logon,
                true,
                sid.clone(),
            );
            audit_log::write_audit_record(record);
        }

        let stats = audit_log::get_statistics();
        assert!(stats.rotation_count > 0);
        assert_eq!(stats.current_count, audit_log::MAX_AUDIT_RECORDS);
        assert_eq!(stats.total_written, audit_log::MAX_AUDIT_RECORDS as u64 + 100);
    }

    #[test]
    fn test_audit_logon_event() {
        audit::init();
        audit_log::clear_log();

        // Enable logon auditing
        audit::se_set_audit_policy(AuditCategoryId::Logon, true, true);

        let sid = Sid::well_known(WellKnownSid::World);

        // Generate a successful logon event
        audit::se_audit_logon(
            AuditEventOutcome::Success,
            &sid,
            2, // Interactive logon
            0x1234567890ABCDEF,
        );

        // Verify event was logged
        let events = audit_log::query_records(
            Some(AuditCategory::Logon),
            None,
            None,
            Some(true),
            10,
        );
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 4624);
    }

    #[test]
    fn test_audit_logoff_event() {
        audit::init();
        audit_log::clear_log();

        audit::se_set_audit_policy(AuditCategoryId::Logon, true, true);

        let sid = Sid::well_known(WellKnownSid::World);

        audit::se_audit_logoff(&sid, 0x1234567890ABCDEF);

        let events = audit_log::query_records(
            Some(AuditCategory::Logon),
            None,
            None,
            None,
            10,
        );
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 4634);
    }

    #[test]
    fn test_audit_object_access_event() {
        audit::init();
        audit_log::clear_log();

        audit::se_set_audit_policy(AuditCategoryId::ObjectAccess, true, true);

        let token = Token::create_system_token();

        audit::se_audit_object_access(
            AuditEventOutcome::Success,
            &token,
            "File",
            "C:\\Windows\\System32\\test.txt",
            0x001F01FF, // GENERIC_ALL
        );

        let events = audit_log::query_records(
            Some(AuditCategory::ObjectAccess),
            None,
            None,
            Some(true),
            10,
        );
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 4663);
        assert!(events[0].object_name.contains("test.txt"));
    }

    #[test]
    fn test_audit_privilege_use_event() {
        audit::init();
        audit_log::clear_log();

        audit::se_set_audit_policy(AuditCategoryId::PrivilegeUse, true, true);

        let token = Token::create_system_token();
        let privilege = Luid {
            low_part: crate::se::seaccess::privileges::SE_DEBUG as u32,
            high_part: 0,
        };

        audit::se_audit_privilege_use(
            AuditEventOutcome::Success,
            &token,
            &privilege,
        );

        let events = audit_log::query_records(
            Some(AuditCategory::PrivilegeUse),
            None,
            None,
            Some(true),
            10,
        );
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 4673);
    }

    #[test]
    fn test_audit_policy_change_event() {
        audit::init();
        audit_log::clear_log();

        audit::se_set_audit_policy(AuditCategoryId::PolicyChange, true, true);

        let token = Token::create_system_token();

        audit::se_audit_policy_change(&token, "Audit Policy Modified");

        let events = audit_log::query_records(
            Some(AuditCategory::PolicyChange),
            None,
            None,
            None,
            10,
        );
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 4719);
    }

    #[test]
    fn test_audit_process_creation() {
        audit::init();
        audit_log::clear_log();

        audit::se_set_audit_policy(AuditCategoryId::DetailTracking, true, true);

        let token = Token::create_system_token();

        audit::se_audit_process_creation(
            &token,
            1234,
            "C:\\Windows\\System32\\notepad.exe",
            4,
        );

        let events = audit_log::query_records(
            Some(AuditCategory::DetailedTracking),
            None,
            None,
            None,
            10,
        );
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 4688);
        assert_eq!(events[0].process_id, 1234);
    }

    #[test]
    fn test_audit_system_event() {
        audit::init();
        audit_log::clear_log();

        audit::se_set_audit_policy(AuditCategoryId::System, true, true);

        audit::se_audit_system_event(5038, "System integrity check failed");

        let events = audit_log::query_records(
            Some(AuditCategory::System),
            None,
            None,
            None,
            10,
        );
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 5038);
    }

    #[test]
    fn test_audit_filtering_respects_policy() {
        audit::init();
        audit_log::clear_log();

        // Disable object access auditing
        audit::se_set_audit_policy(AuditCategoryId::ObjectAccess, false, false);

        let token = Token::create_system_token();

        // Try to generate an object access event
        audit::se_audit_object_access(
            AuditEventOutcome::Success,
            &token,
            "File",
            "test.txt",
            0x001F01FF,
        );

        // Should not be logged
        let events = audit_log::query_records(
            Some(AuditCategory::ObjectAccess),
            None,
            None,
            None,
            10,
        );
        assert_eq!(events.len(), 0);

        // Enable it
        audit::se_set_audit_policy(AuditCategoryId::ObjectAccess, true, true);

        // Try again
        audit::se_audit_object_access(
            AuditEventOutcome::Success,
            &token,
            "File",
            "test.txt",
            0x001F01FF,
        );

        // Should be logged now
        let events = audit_log::query_records(
            Some(AuditCategory::ObjectAccess),
            None,
            None,
            None,
            10,
        );
        assert!(events.len() > 0);
    }

    #[test]
    fn test_audit_log_query_by_user() {
        audit_log::init();
        audit_log::clear_log();

        let sid1 = Sid::well_known(WellKnownSid::World);
        let sid2 = Sid::well_known(WellKnownSid::LocalSystem);

        // Write events for different users
        for i in 0..5 {
            let sid = if i % 2 == 0 { sid1.clone() } else { sid2.clone() };
            let record = AuditRecord::new(4624, AuditCategory::Logon, true, sid);
            audit_log::write_audit_record(record);
        }

        // Query by user
        let user1_events = audit_log::query_by_user(&sid1, 100);
        assert_eq!(user1_events.len(), 3);

        let user2_events = audit_log::query_by_user(&sid2, 100);
        assert_eq!(user2_events.len(), 2);
    }

    #[test]
    fn test_audit_log_statistics() {
        audit_log::init();
        audit_log::clear_log();

        let sid = Sid::well_known(WellKnownSid::World);

        // Write some events
        for i in 0..10 {
            let record = AuditRecord::new(4624, AuditCategory::Logon, true, sid.clone());
            audit_log::write_audit_record(record);
        }

        let stats = audit_log::get_statistics();
        assert_eq!(stats.current_count, 10);
        assert_eq!(stats.total_written, 10);
        assert!(stats.next_record_id > 10);
    }
}
