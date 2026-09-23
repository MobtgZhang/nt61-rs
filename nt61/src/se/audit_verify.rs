//! Quick verification that audit modules compile correctly
//! This file can be checked independently to verify audit system implementation

// Import all audit modules
use crate::se::audit_policy;
use crate::se::audit_log;
use crate::se::audit;

#[allow(dead_code)]
fn verify_audit_policy_api() {
    // Policy management
    audit_policy::init();
    let _ = audit_policy::get_category_policy(audit_policy::AuditCategory::Logon);
    audit_policy::enable_category(audit_policy::AuditCategory::ObjectAccess);
    audit_policy::disable_category(audit_policy::AuditCategory::System);
    let _ = audit_policy::is_enabled(audit_policy::AuditCategory::Logon, true);

    // Presets
    audit_policy::presets::apply_minimal();
    audit_policy::presets::apply_baseline();
    audit_policy::presets::apply_comprehensive();
}

#[allow(dead_code)]
fn verify_audit_log_api() {
    // Log management
    audit_log::init();
    let _ = audit_log::get_record_count();
    let _ = audit_log::get_statistics();
    let _ = audit_log::get_recent_records(10);

    // Querying
    let _ = audit_log::query_records(None, None, None, None, 100);
    let sid = crate::se::sid::Sid::well_known(crate::se::sid::WellKnownSid::World);
    let _ = audit_log::query_by_user(&sid, 100);
    let _ = audit_log::query_by_object("test", 100);
}

#[allow(dead_code)]
fn verify_audit_event_api() {
    // Event generation
    audit::init();

    let sid = crate::se::sid::Sid::well_known(crate::se::sid::WellKnownSid::World);
    let token = crate::se::token::Token::create_system_token();
    let privilege = crate::se::token::Luid { low_part: 0, high_part: 0 };

    audit::se_audit_logon(
        audit::AuditEventOutcome::Success,
        &sid,
        2,
        0,
    );

    audit::se_audit_logoff(&sid, 0);

    audit::se_audit_object_access(
        audit::AuditEventOutcome::Success,
        &token,
        "File",
        "test.txt",
        0,
    );

    audit::se_audit_privilege_use(
        audit::AuditEventOutcome::Success,
        &token,
        &privilege,
    );

    audit::se_audit_policy_change(&token, "test");

    audit::se_audit_account_management(
        audit::AuditEventOutcome::Success,
        &token,
        &sid,
        "test",
    );

    audit::se_audit_process_creation(&token, 0, "test", 0);
    audit::se_audit_process_termination(&token, 0, 0);
    audit::se_audit_system_event(0, "test");
}

pub fn verify_all() {
    verify_audit_policy_api();
    verify_audit_log_api();
    verify_audit_event_api();
}
