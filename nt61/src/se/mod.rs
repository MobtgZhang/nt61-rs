//! Security Reference Monitor
//
//! Implements the Windows security model:
//!   * SID (Security Identifier) — uniquely identifies a principal
//!   * ACL (Access control List) — list of ACEs granting/denying access
//!   * TOKEN — per-process security context with user, groups, privileges
//!   * SeAccessCheck — the core access validation function
//!   * SePrivilegeCheck — checks if a token has required privileges
//
//! References:
//!   * Windows SDK: winnt.h (SID, ACL, ACE structures)
//!   * Windows Research Kernel (WRK)
//!   * ReactOS security subystem

// Security subsystem uses NT-driver naming (SeAccessCheck,
// SeSinglePrivilegeCheck, SE_* access masks, SID_*, ...).

pub mod acl;
pub mod logon;
pub mod seaccess;
pub mod sid;
pub mod token;
pub mod users;

/// Initialize the Security Reference Monitor.
pub fn init() {
    sid::init();
    acl::init();
    token::init();
    seaccess::init();
    users::init();
    logon::init();
    // crate::kprintln!("    Security Reference Monitor: initialized");
}

pub mod aclmgmt;
pub mod appcontainer;
pub mod audit;
pub mod audit_log;
pub mod audit_policy;
pub mod descriptor;
pub mod integrity;
pub mod logonsession;
pub mod refmon;
pub mod sidmgmt;
pub mod smoke;
pub mod tests;
pub mod tokenmgmt;
