//! Audit and Event Generation
//!
//! Implements the Windows auditing subsystem that generates security audit events.
//! These events are written to the Security event log and track:
//!   - Logon/logoff events
//!   - Object access
//!   - Privilege use
//!   - Account management
//!   - Policy changes
//!   - System events
//!
//! References: Windows SDK, WRK security audit

use super::audit_log::{
    clear_log as audit_clear_log, get_recent_records, get_record_count, get_statistics,
    query_records, write_audit_record, AuditRecord,
};
use super::audit_policy::{is_enabled as policy_is_enabled, presets, AuditCategory};
use super::sid::sid;
use super::token::{create_system_token, Token};
use alloc::string::ToString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditCategoryId {
    System = 0,
    Logon = 1,
    ObjectAccess = 2,
    PrivilegeUse = 3,
    DetailTracking = 4,
    PolicyChange = 5,
    AccountManagement = 6,
    DirectoryServiceAccess = 7,
    AccountLogon = 8,
}

impl AuditCategoryId {
    pub fn to_audit_category(self) -> AuditCategory {
        match self {
            AuditCategoryId::System => AuditCategory::System,
            AuditCategoryId::Logon => AuditCategory::Logon,
            AuditCategoryId::ObjectAccess => AuditCategory::ObjectAccess,
            AuditCategoryId::PrivilegeUse => AuditCategory::PrivilegeUse,
            AuditCategoryId::DetailTracking => AuditCategory::DetailedTracking,
            AuditCategoryId::PolicyChange => AuditCategory::PolicyChange,
            AuditCategoryId::AccountManagement => AuditCategory::AccountManagement,
            AuditCategoryId::DirectoryServiceAccess => AuditCategory::DirectoryServiceAccess,
            AuditCategoryId::AccountLogon => AuditCategory::AccountLogon,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditEventType {
    AuditEventObjectAccess = 0,
    AuditEventDirectoryServiceAccess = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventOutcome {
    Success,
    Failure,
}

/// Check if auditing is enabled for any category
pub fn se_auditing_state() -> bool {
    super::audit_policy::is_any_enabled()
}

/// Check if auditing is enabled for a specific category and outcome
pub fn se_auditing_state_for_category(
    category: AuditCategoryId,
    outcome: AuditEventOutcome,
) -> bool {
    let audit_cat = category.to_audit_category();
    let success = matches!(outcome, AuditEventOutcome::Success);
    policy_is_enabled(audit_cat, success)
}

/// Set audit policy for a category
pub fn se_set_audit_policy(
    category: AuditCategoryId,
    success_enabled: bool,
    failure_enabled: bool,
) {
    use super::audit_policy::{set_category_policy, CategoryPolicy};
    let audit_cat = category.to_audit_category();
    set_category_policy(
        audit_cat,
        CategoryPolicy::new(success_enabled, failure_enabled),
    );
}

/// Audit a logon event
pub fn se_audit_logon(outcome: AuditEventOutcome, user_sid: &sid, logon_type: u32, logon_id: u64) {
    if !se_auditing_state_for_category(AuditCategoryId::Logon, outcome) {
        return;
    }

    let event_id = match outcome {
        AuditEventOutcome::Success => 4624, // Successful logon
        AuditEventOutcome::Failure => 4625, // Failed logon
    };

    let success = matches!(outcome, AuditEventOutcome::Success);
    let mut record = AuditRecord::new(event_id, AuditCategory::Logon, success, user_sid.clone());

    let details = alloc::format!(
        "Logon Type: {}, Logon ID: 0x{:016X}",
        logon_type_name(logon_type),
        logon_id
    );
    record.set_details(details);

    write_audit_record(record);
}

/// Audit a logoff event
pub fn se_audit_logoff(user_sid: &sid, logon_id: u64) {
    if !se_auditing_state_for_category(AuditCategoryId::Logon, AuditEventOutcome::Success) {
        return;
    }

    let mut record = AuditRecord::new(
        4634, // Logoff event
        AuditCategory::Logon,
        true,
        user_sid.clone(),
    );

    let details = alloc::format!("Logon ID: 0x{:016X}", logon_id);
    record.set_details(details);

    write_audit_record(record);
}

/// Audit object access
pub fn se_audit_object_access(
    outcome: AuditEventOutcome,
    token: &Token,
    object_type: &str,
    object_name: &str,
    access_mask: u32,
) {
    if !se_auditing_state_for_category(AuditCategoryId::ObjectAccess, outcome) {
        return;
    }

    let event_id = match outcome {
        AuditEventOutcome::Success => 4663, // Object access attempt
        AuditEventOutcome::Failure => 4656, // Object handle requested (may be denied)
    };

    let success = matches!(outcome, AuditEventOutcome::Success);
    let mut record = AuditRecord::new(
        event_id,
        AuditCategory::ObjectAccess,
        success,
        token.user.clone(),
    );

    record.set_object_info(object_name.to_string(), access_mask);

    let details = alloc::format!(
        "Object Type: {}, Access: 0x{:08X}",
        object_type,
        access_mask
    );
    record.set_details(details);

    write_audit_record(record);
}

/// Audit privilege use
pub fn se_audit_privilege_use(
    outcome: AuditEventOutcome,
    token: &Token,
    privilege_luid: &super::token::luid,
) {
    if !se_auditing_state_for_category(AuditCategoryId::PrivilegeUse, outcome) {
        return;
    }

    let success = matches!(outcome, AuditEventOutcome::Success);
    let mut record = AuditRecord::new(
        4673, // Privilege use
        AuditCategory::PrivilegeUse,
        success,
        token.user.clone(),
    );

    let privilege_name = privilege_luid_to_name(privilege_luid);
    let details = alloc::format!(
        "Privilege: {} (0x{:08X})",
        privilege_name,
        privilege_luid.low_part
    );
    record.set_details(details);

    write_audit_record(record);
}

/// Audit policy change
pub fn se_audit_policy_change(token: &Token, change_type: &str) {
    if !se_auditing_state_for_category(AuditCategoryId::PolicyChange, AuditEventOutcome::Success) {
        return;
    }

    let mut record = AuditRecord::new(
        4719, // Policy change
        AuditCategory::PolicyChange,
        true,
        token.user.clone(),
    );

    let details = alloc::format!("Policy Change: {}", change_type);
    record.set_details(details);

    write_audit_record(record);
}

/// Audit account management
pub fn se_audit_account_management(
    outcome: AuditEventOutcome,
    token: &Token,
    target_sid: &sid,
    operation: &str,
) {
    if !se_auditing_state_for_category(AuditCategoryId::AccountManagement, outcome) {
        return;
    }

    let success = matches!(outcome, AuditEventOutcome::Success);
    let mut record = AuditRecord::new(
        4720, // Account management
        AuditCategory::AccountManagement,
        success,
        token.user.clone(),
    );

    let details = alloc::format!(
        "Operation: {}, Target SID: S-1-5-{}",
        operation,
        target_sid.sub_authority[0]
    );
    record.set_details(details);

    write_audit_record(record);
}

/// Audit process creation
pub fn se_audit_process_creation(
    token: &Token,
    process_id: u64,
    process_name: &str,
    parent_pid: u64,
) {
    if !se_auditing_state_for_category(AuditCategoryId::DetailTracking, AuditEventOutcome::Success)
    {
        return;
    }

    let mut record = AuditRecord::new(
        4688, // Process created
        AuditCategory::DetailedTracking,
        true,
        token.user.clone(),
    );

    record.set_process_info(process_id, 0);

    let details = alloc::format!("Process Name: {}, Parent PID: {}", process_name, parent_pid);
    record.set_details(details);

    write_audit_record(record);
}

/// Audit process termination
pub fn se_audit_process_termination(token: &Token, process_id: u64, exit_code: i32) {
    if !se_auditing_state_for_category(AuditCategoryId::DetailTracking, AuditEventOutcome::Success)
    {
        return;
    }

    let mut record = AuditRecord::new(
        4689, // Process terminated
        AuditCategory::DetailedTracking,
        true,
        token.user.clone(),
    );

    record.set_process_info(process_id, 0);

    let details = alloc::format!("Exit Code: 0x{:08X}", exit_code);
    record.set_details(details);

    write_audit_record(record);
}

/// Audit system event
pub fn se_audit_system_event(event_id: u16, description: &str) {
    if !se_auditing_state_for_category(AuditCategoryId::System, AuditEventOutcome::Success) {
        return;
    }

    let system_sid = sid::well_known(super::sid::WellKnownSid::LocalSystem);
    let mut record = AuditRecord::new(event_id, AuditCategory::System, true, system_sid);

    record.set_details(description.to_string());

    write_audit_record(record);
}

/// Open object audit alarm (compatibility wrapper)
pub fn se_open_object_audit_alarm(
    object_type_name: &str,
    object_name: Option<&str>,
    _security_descriptor: *const super::seaccess::SecurityDescriptor,
    token: *const Token,
    desired_access: u32,
    granted_access: u32,
    access_granted: bool,
) {
    if token.is_null() {
        return;
    }

    let token_ref = unsafe { &*token };
    let outcome = if access_granted {
        AuditEventOutcome::Success
    } else {
        AuditEventOutcome::Failure
    };

    se_audit_object_access(
        outcome,
        token_ref,
        object_type_name,
        object_name.unwrap_or(""),
        if access_granted {
            granted_access
        } else {
            desired_access
        },
    );
}

/// Check privilege and audit
pub fn se_privilege_check_and_audit(
    token: &Token,
    required_privilege: &super::token::luid,
) -> bool {
    let has_privilege = token.has_privilege(required_privilege);

    let outcome = if has_privilege {
        AuditEventOutcome::Success
    } else {
        AuditEventOutcome::Failure
    };

    se_audit_privilege_use(outcome, token, required_privilege);

    has_privilege
}

/// Helper: Convert logon type to name
fn logon_type_name(logon_type: u32) -> &'static str {
    match logon_type {
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        _ => "Unknown",
    }
}

/// Helper: Convert privilege LUID to name
fn privilege_luid_to_name(luid: &super::token::luid) -> &'static str {
    match luid.low_part as i64 {
        super::seaccess::privileges::SE_DEBUG => "SeDebugPrivilege",
        super::seaccess::privileges::SE_BACKUP => "SeBackupPrivilege",
        super::seaccess::privileges::SE_RESTORE => "SeRestorePrivilege",
        super::seaccess::privileges::SE_SECURITY => "SeSecurityPrivilege",
        super::seaccess::privileges::SE_TAKE_OWNERSHIP => "SeTakeOwnershipPrivilege",
        super::seaccess::privileges::SE_SYSTEM_PROFILE => "SeSystemProfilePrivilege",
        super::seaccess::privileges::SE_CREATE_PAGEFILE => "SeCreatePagefilePrivilege",
        super::seaccess::privileges::SE_ASSIGN_PRIMARY_TOKEN => "SeAssignPrimaryTokenPrivilege",
        _ => "UnknownPrivilege",
    }
}

/// Initialize audit subsystem
pub fn init() {
    // Initialize sub-modules
    super::audit_policy::init();
    super::audit_log::init();

    // Set default policies
    se_set_audit_policy(AuditCategoryId::Logon, true, true);
    se_set_audit_policy(AuditCategoryId::AccountLogon, true, true);
}

// ============================================================================
// Demo Functions (for testing and demonstration)
// ============================================================================

pub fn run_audit_demo() {
    crate::kprintln!("\n=== Security Audit System Demo ===\n");

    // 1. Initialize audit system
    crate::kprintln!("1. Initializing audit system...");
    init();
    crate::kprintln!("   Audit system initialized");

    // 2. Configure audit policies
    crate::kprintln!("\n2. Configuring audit policies...");
    presets::apply_baseline();
    crate::kprintln!("   Applied baseline audit policy");

    // Display current policies
    let policies = super::audit_policy::get_all_policies();
    for (category, policy) in &policies {
        if policy.is_any_enabled() {
            crate::kprintln!(
                "   {} - Success: {}, Failure: {}",
                category.name(),
                policy.success_enabled,
                policy.failure_enabled
            );
        }
    }

    // 3. Generate sample audit events
    crate::kprintln!("\n3. Generating sample audit events...");

    // Logon event
    let user_sid = sid::well_known(super::sid::WellKnownSid::World);
    se_audit_logon(
        AuditEventOutcome::Success,
        &user_sid,
        2, // Interactive logon
        0x1234567890ABCDEF,
    );
    crate::kprintln!("   Generated logon event (4624)");

    // Object access event
    let token_ptr = create_system_token();
    if token_ptr.is_null() {
        return;
    }
    let token = unsafe { &*token_ptr };
    se_audit_object_access(
        AuditEventOutcome::Success,
        token,
        "File",
        "C:\\Windows\\System32\\config\\SAM",
        0x001F01FF, // GENERIC_ALL
    );
    crate::kprintln!("   Generated object access event (4663)");

    // Privilege use event
    let privilege = super::token::luid {
        low_part: super::seaccess::privileges::SE_DEBUG as u32,
        high_part: 0,
    };
    se_audit_privilege_use(AuditEventOutcome::Success, token, &privilege);
    crate::kprintln!("   Generated privilege use event (4673)");

    // Policy change event
    se_audit_policy_change(token, "Audit policy modified");
    crate::kprintln!("   Generated policy change event (4719)");

    // Process creation event
    se_audit_process_creation(token, 1234, "C:\\Windows\\System32\\notepad.exe", 4);
    crate::kprintln!("   Generated process creation event (4688)");

    // 4. Query audit logs
    crate::kprintln!("\n4. Querying audit logs...");

    let all_events = query_records(None, None, None, None, 100);
    crate::kprintln!("   Total events: {}", all_events.len());

    let logon_events = query_records(Some(AuditCategory::Logon), None, None, None, 100);
    crate::kprintln!("   Logon events: {}", logon_events.len());

    let object_events = query_records(Some(AuditCategory::ObjectAccess), None, None, None, 100);
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
    let recent = get_recent_records(5);
    for (i, event) in recent.iter().enumerate() {
        crate::kprintln!(
            "   [{}] Event ID: {}, Category: {}, Success: {}",
            i + 1,
            event.event_id,
            event.category.name(),
            event.success
        );
        if !event.object_name.is_empty() {
            crate::kprintln!("       Object: {}", event.object_name);
        }
        if !event.details.is_empty() {
            crate::kprintln!("       Details: {}", event.details);
        }
    }

    crate::kprintln!("\n=== Demo Complete ===\n");
}

/// Test audit policy changes
pub fn test_audit_policy_changes() {
    crate::kprintln!("\n=== Audit Policy Change Test ===\n");

    audit_clear_log();

    // Test different policy configurations
    crate::kprintln!("1. Testing minimal policy...");
    presets::apply_minimal();

    let token_ptr = create_system_token();
    if token_ptr.is_null() {
        return;
    }
    let token = unsafe { &*token_ptr };

    // This should be logged (Logon enabled)
    let sid = sid::well_known(super::sid::WellKnownSid::World);
    se_audit_logon(AuditEventOutcome::Success, &sid, 2, 0x1234);

    // This should NOT be logged (ObjectAccess disabled)
    se_audit_object_access(
        AuditEventOutcome::Success,
        token,
        "File",
        "test.txt",
        0x001F01FF,
    );

    let count_minimal = get_record_count();
    crate::kprintln!("   Events with minimal policy: {}", count_minimal);

    crate::kprintln!("\n2. Testing comprehensive policy...");
    presets::apply_comprehensive();

    // Both should be logged now
    se_audit_logon(AuditEventOutcome::Success, &sid, 2, 0x5678);
    se_audit_object_access(
        AuditEventOutcome::Success,
        &token,
        "File",
        "test2.txt",
        0x001F01FF,
    );

    let count_comprehensive = get_record_count();
    crate::kprintln!(
        "   Events with comprehensive policy: {}",
        count_comprehensive
    );

    crate::kprintln!("\n=== Test Complete ===\n");
}

// ============================================================================
// Verification Functions (compile-time API verification)
// ============================================================================

fn verify_audit_policy_api() {
    // Policy management
    super::audit_policy::init();
    let _ = super::audit_policy::get_category_policy(AuditCategory::Logon);
    super::audit_policy::enable_category(AuditCategory::ObjectAccess);
    super::audit_policy::disable_category(AuditCategory::System);
    let _ = super::audit_policy::is_enabled(AuditCategory::Logon, true);

    // Presets
    presets::apply_minimal();
    presets::apply_baseline();
    presets::apply_comprehensive();
}

fn verify_audit_log_api() {
    // Log management
    super::audit_log::init();
    let _ = get_record_count();
    let _ = get_statistics();
    let _ = get_recent_records(10);

    // Querying
    let _ = query_records(None, None, None, None, 100);
    let sid = sid::well_known(super::sid::WellKnownSid::World);
    let _ = super::audit_log::query_by_user(&sid, 100);
    let _ = super::audit_log::query_by_object("test", 100);
}

fn verify_audit_event_api() {
    // Event generation
    init();

    let sid = sid::well_known(super::sid::WellKnownSid::World);
    let token_ptr = create_system_token();
    if token_ptr.is_null() {
        return;
    }
    let token = unsafe { &*token_ptr };
    let privilege = super::token::luid {
        low_part: 0,
        high_part: 0,
    };

    se_audit_logon(AuditEventOutcome::Success, &sid, 2, 0);
    se_audit_logoff(&sid, 0);
    se_audit_object_access(AuditEventOutcome::Success, token, "File", "test.txt", 0);
    se_audit_privilege_use(AuditEventOutcome::Success, token, &privilege);
    se_audit_policy_change(token, "test");
    se_audit_account_management(AuditEventOutcome::Success, token, &sid, "test");
    se_audit_process_creation(token, 0, "test", 0);
    se_audit_process_termination(token, 0, 0);
    se_audit_system_event(0, "test");
}

pub fn verify_all() {
    verify_audit_policy_api();
    verify_audit_log_api();
    verify_audit_event_api();
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn test_audit_policy_initialization() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        crate::se::audit_policy::init();

        // Check default policies (Logon and AccountLogon should be enabled)
        let logon_policy = crate::se::audit_policy::get_category_policy(AuditCategory::Logon);
        assert!(logon_policy.success_enabled);
        assert!(logon_policy.failure_enabled);

        let account_logon_policy =
            crate::se::audit_policy::get_category_policy(AuditCategory::AccountLogon);
        assert!(account_logon_policy.success_enabled);
        assert!(account_logon_policy.failure_enabled);
    }

    #[test]
    fn test_audit_policy_set_get() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        crate::se::audit_policy::init();

        // Set a custom policy
        let category = AuditCategory::ObjectAccess;
        let policy = crate::se::audit_policy::CategoryPolicy::new(true, false);
        crate::se::audit_policy::set_category_policy(category, policy);

        // Verify it was set correctly
        let retrieved = crate::se::audit_policy::get_category_policy(category);
        assert!(retrieved.success_enabled);
        assert!(!retrieved.failure_enabled);
    }

    #[test]
    fn test_audit_policy_enable_disable() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        crate::se::audit_policy::init();

        // Enable a category
        crate::se::audit_policy::enable_category(AuditCategory::PrivilegeUse);
        assert!(crate::se::audit_policy::is_enabled(
            AuditCategory::PrivilegeUse,
            true
        ));
        assert!(crate::se::audit_policy::is_enabled(
            AuditCategory::PrivilegeUse,
            false
        ));

        // Disable it
        crate::se::audit_policy::disable_category(AuditCategory::PrivilegeUse);
        assert!(!crate::se::audit_policy::is_enabled(
            AuditCategory::PrivilegeUse,
            true
        ));
        assert!(!crate::se::audit_policy::is_enabled(
            AuditCategory::PrivilegeUse,
            false
        ));
    }

    #[test]
    fn test_audit_policy_presets() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        // Test minimal preset
        presets::apply_minimal();
        assert!(crate::se::audit_policy::is_enabled(
            AuditCategory::Logon,
            true
        ));
        assert!(!crate::se::audit_policy::is_enabled(
            AuditCategory::ObjectAccess,
            true
        ));

        // Test comprehensive preset
        presets::apply_comprehensive();
        assert!(crate::se::audit_policy::is_enabled(
            AuditCategory::ObjectAccess,
            true
        ));
        assert!(crate::se::audit_policy::is_enabled(
            AuditCategory::PrivilegeUse,
            true
        ));
        assert!(crate::se::audit_policy::is_enabled(
            AuditCategory::System,
            true
        ));
    }

    #[test]
    fn test_audit_log_write() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        crate::se::audit_log::init();
        audit_clear_log();

        let sid = sid::well_known(crate::se::sid::WellKnownSid::World);
        let mut record = AuditRecord::new(4624, AuditCategory::Logon, true, sid);
        record.set_details(String::from("Test logon event"));

        write_audit_record(record);

        let count = get_record_count();
        assert!(count > 0);
    }

    #[test]
    fn test_audit_log_query_by_category() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        crate::se::audit_log::init();
        audit_clear_log();

        let sid = sid::well_known(crate::se::sid::WellKnownSid::World);

        // write different event types
        for i in 0..5 {
            let category = if i % 2 == 0 {
                AuditCategory::Logon
            } else {
                AuditCategory::ObjectAccess
            };

            let record = AuditRecord::new(4624, category, true, sid.clone());
            write_audit_record(record);
        }

        // Query by category
        let logon_events = query_records(Some(AuditCategory::Logon), None, None, None, 100);
        assert_eq!(logon_events.len(), 3);

        let object_events = query_records(Some(AuditCategory::ObjectAccess), None, None, None, 100);
        assert_eq!(object_events.len(), 2);
    }

    #[test]
    fn test_audit_log_query_by_success() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        crate::se::audit_log::init();
        audit_clear_log();

        let sid = sid::well_known(crate::se::sid::WellKnownSid::World);

        // write mixed success/failure events
        for i in 0..10 {
            let record = AuditRecord::new(4624, AuditCategory::Logon, i % 2 == 0, sid.clone());
            write_audit_record(record);
        }

        // Query success only
        let success_events = query_records(None, None, None, Some(true), 100);
        assert_eq!(success_events.len(), 5);

        // Query failure only
        let failure_events = query_records(None, None, None, Some(false), 100);
        assert_eq!(failure_events.len(), 5);
    }

    #[test]
    fn test_audit_log_rotation() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        crate::se::audit_log::init();
        audit_clear_log();

        let sid = sid::well_known(crate::se::sid::WellKnownSid::World);

        // write more than MAX_AUDIT_RECORDS to trigger rotation
        for _i in 0..crate::se::audit_log::MAX_AUDIT_RECORDS + 100 {
            let record = AuditRecord::new(4624, AuditCategory::Logon, true, sid.clone());
            write_audit_record(record);
        }

        let stats = get_statistics();
        assert!(stats.rotation_count > 0);
        assert_eq!(stats.current_count, crate::se::audit_log::MAX_AUDIT_RECORDS);
        assert_eq!(
            stats.total_written,
            crate::se::audit_log::MAX_AUDIT_RECORDS as u64 + 100
        );
    }

    #[test]
    fn test_audit_logon_event() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        init();
        audit_clear_log();

        // Enable logon auditing
        se_set_audit_policy(AuditCategoryId::Logon, true, true);

        let sid = sid::well_known(crate::se::sid::WellKnownSid::World);

        // Generate a successful logon event
        se_audit_logon(AuditEventOutcome::Success, &sid, 2, 0x1234567890ABCDEF);

        // Verify event was logged
        let events = query_records(Some(AuditCategory::Logon), None, None, Some(true), 10);
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 4624);
    }

    #[test]
    fn test_audit_logoff_event() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        init();
        audit_clear_log();

        se_set_audit_policy(AuditCategoryId::Logon, true, true);

        let sid = sid::well_known(crate::se::sid::WellKnownSid::World);

        se_audit_logoff(&sid, 0x1234567890ABCDEF);

        let events = query_records(Some(AuditCategory::Logon), None, None, None, 10);
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 4634);
    }

    #[test]
    fn test_audit_object_access_event() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        init();
        audit_clear_log();

        se_set_audit_policy(AuditCategoryId::ObjectAccess, true, true);

        let token = Token::new_primary(sid::well_known(crate::se::sid::WellKnownSid::LocalSystem));

        se_audit_object_access(
            AuditEventOutcome::Success,
            &token,
            "File",
            "C:\\Windows\\System32\\test.txt",
            0x001F01FF, // GENERIC_ALL
        );

        let events = query_records(
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
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        init();
        audit_clear_log();

        se_set_audit_policy(AuditCategoryId::PrivilegeUse, true, true);

        let token = Token::new_primary(sid::well_known(crate::se::sid::WellKnownSid::LocalSystem));
        let privilege = crate::se::token::luid {
            low_part: crate::se::seaccess::privileges::SE_DEBUG as u32,
            high_part: 0,
        };

        se_audit_privilege_use(AuditEventOutcome::Success, &token, &privilege);

        let events = query_records(
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
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        init();
        audit_clear_log();

        se_set_audit_policy(AuditCategoryId::PolicyChange, true, true);

        let token = Token::new_primary(sid::well_known(crate::se::sid::WellKnownSid::LocalSystem));

        se_audit_policy_change(&token, "Audit Policy Modified");

        let events = query_records(Some(AuditCategory::PolicyChange), None, None, None, 10);
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 4719);
    }

    #[test]
    fn test_audit_process_creation() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        init();
        audit_clear_log();

        se_set_audit_policy(AuditCategoryId::DetailTracking, true, true);

        let token = Token::new_primary(sid::well_known(crate::se::sid::WellKnownSid::LocalSystem));

        se_audit_process_creation(&token, 1234, "C:\\Windows\\System32\\notepad.exe", 4);

        let events = query_records(Some(AuditCategory::DetailedTracking), None, None, None, 10);
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 4688);
        assert_eq!(events[0].process_id, 1234);
    }

    #[test]
    fn test_audit_system_event() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        init();
        audit_clear_log();

        se_set_audit_policy(AuditCategoryId::System, true, true);

        se_audit_system_event(5038, "System integrity check failed");

        let events = query_records(Some(AuditCategory::System), None, None, None, 10);
        assert!(events.len() > 0);
        assert_eq!(events[0].event_id, 5038);
    }

    #[test]
    fn test_audit_filtering_respects_policy() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        init();
        audit_clear_log();

        // Disable object access auditing
        se_set_audit_policy(AuditCategoryId::ObjectAccess, false, false);

        let token = Token::new_primary(sid::well_known(crate::se::sid::WellKnownSid::LocalSystem));

        // Try to generate an object access event
        se_audit_object_access(
            AuditEventOutcome::Success,
            &token,
            "File",
            "test.txt",
            0x001F01FF,
        );

        // Should not be logged
        let events = query_records(Some(AuditCategory::ObjectAccess), None, None, None, 10);
        assert_eq!(events.len(), 0);

        // Enable it
        se_set_audit_policy(AuditCategoryId::ObjectAccess, true, true);

        // Try again
        se_audit_object_access(
            AuditEventOutcome::Success,
            &token,
            "File",
            "test.txt",
            0x001F01FF,
        );

        // Should be logged now
        let events = query_records(Some(AuditCategory::ObjectAccess), None, None, None, 10);
        assert!(events.len() > 0);
    }

    #[test]
    fn test_audit_log_query_by_user() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        crate::se::audit_log::init();
        audit_clear_log();

        let sid1 = sid::well_known(crate::se::sid::WellKnownSid::World);
        let sid2 = sid::well_known(crate::se::sid::WellKnownSid::LocalSystem);

        // write events for different users
        for i in 0..5 {
            let sid = if i % 2 == 0 {
                sid1.clone()
            } else {
                sid2.clone()
            };
            let record = AuditRecord::new(4624, AuditCategory::Logon, true, sid);
            write_audit_record(record);
        }

        // Query by user
        let user1_events = crate::se::audit_log::query_by_user(&sid1, 100);
        assert_eq!(user1_events.len(), 3);

        let user2_events = crate::se::audit_log::query_by_user(&sid2, 100);
        assert_eq!(user2_events.len(), 2);
    }

    #[test]
    fn test_audit_log_statistics() {
        let _guard = crate::se::audit_log::test_support::TestGuard::new();
        crate::se::audit_log::init();
        audit_clear_log();

        let sid = sid::well_known(crate::se::sid::WellKnownSid::World);

        // write some events
        for _i in 0..10 {
            let record = AuditRecord::new(4624, AuditCategory::Logon, true, sid.clone());
            write_audit_record(record);
        }

        let stats = get_statistics();
        assert_eq!(stats.current_count, 10);
        assert_eq!(stats.total_written, 10);
        assert!(stats.next_record_id > 10);
    }
}
