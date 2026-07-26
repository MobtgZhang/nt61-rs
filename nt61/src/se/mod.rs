//! Security Reference Monitor
//
//! Implements the Windows security model:
//!   * SID (Security Identifier) — uniquely identifies a principal
//!   * ACL (Access Control List) — list of ACEs granting/denying access
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
#![allow(unused_imports)]

pub mod sid;
pub mod acl;
pub mod token;
pub mod seaccess;
pub mod users;
pub mod logon;

use crate::kprintln;

/// Initialize the Security Reference Monitor.
pub fn init() {
    sid::init();
    acl::init();
    token::init();
    seaccess::init();
    users::init();
    logon::init();
    // crate::kprintln!("    Security Reference Monitor: initialized")  // kprintln disabled (memcpy crash workaround);
}
