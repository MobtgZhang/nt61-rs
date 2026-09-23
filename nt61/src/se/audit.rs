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

use super::token::Token;
use super::sid::Sid;
use super::audit_policy::{AuditCategory, is_enabled as policy_is_enabled};
use super::audit_log::{AuditRecord, write_audit_record};
use alloc::string::{String, ToString};

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
pub fn se_auditing_state_for_category(category: AuditCategoryId, outcome: AuditEventOutcome) -> bool {
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
    set_category_policy(audit_cat, CategoryPolicy::new(success_enabled, failure_enabled));
}

/// Audit a logon event
pub fn se_audit_logon(
    outcome: AuditEventOutcome,
    user_sid: &Sid,
    logon_type: u32,
    logon_id: u64,
) {
    if !se_auditing_state_for_category(AuditCategoryId::Logon, outcome) {
        return;
    }

    let event_id = match outcome {
        AuditEventOutcome::Success => 4624, // Successful logon
        AuditEventOutcome::Failure => 4625, // Failed logon
    };

    let success = matches!(outcome, AuditEventOutcome::Success);
    let mut record = AuditRecord::new(
        event_id,
        AuditCategory::Logon,
        success,
        user_sid.clone(),
    );

    let details = alloc::format!(
        "Logon Type: {}, Logon ID: 0x{:016X}",
        logon_type_name(logon_type),
        logon_id
    );
    record.set_details(details);

    write_audit_record(record);
}

/// Audit a logoff event
pub fn se_audit_logoff(user_sid: &Sid, logon_id: u64) {
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
    privilege_luid: &super::token::Luid,
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
pub fn se_audit_policy_change(
    token: &Token,
    change_type: &str,
) {
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
    target_sid: &Sid,
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
    if !se_auditing_state_for_category(AuditCategoryId::DetailTracking, AuditEventOutcome::Success) {
        return;
    }

    let mut record = AuditRecord::new(
        4688, // Process created
        AuditCategory::DetailedTracking,
        true,
        token.user.clone(),
    );

    record.set_process_info(process_id, 0);

    let details = alloc::format!(
        "Process Name: {}, Parent PID: {}",
        process_name,
        parent_pid
    );
    record.set_details(details);

    write_audit_record(record);
}

/// Audit process termination
pub fn se_audit_process_termination(
    token: &Token,
    process_id: u64,
    exit_code: i32,
) {
    if !se_auditing_state_for_category(AuditCategoryId::DetailTracking, AuditEventOutcome::Success) {
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
pub fn se_audit_system_event(
    event_id: u16,
    description: &str,
) {
    if !se_auditing_state_for_category(AuditCategoryId::System, AuditEventOutcome::Success) {
        return;
    }

    let system_sid = Sid::well_known(super::sid::WellKnownSid::LocalSystem);
    let mut record = AuditRecord::new(
        event_id,
        AuditCategory::System,
        true,
        system_sid,
    );

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
        if access_granted { granted_access } else { desired_access },
    );
}

/// Check privilege and audit
pub fn se_privilege_check_and_audit(
    token: &Token,
    required_privilege: &super::token::Luid,
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
fn privilege_luid_to_name(luid: &super::token::Luid) -> &'static str {
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
