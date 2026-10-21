//! sechost.exe — Service Host Process
//
//! Implements the Service Host process that hosts COM servers and
//! services. This is a stub that provides the basic sechost
//! functionality.
//
//! Clean-room implementation. Spec source: Windows Services documentation,
//! "Windows Internals 6th ed." ch. 10.

/// Initialize the sechost stub.
pub fn init() {
    // crate::kprintln!("    SECHOST: init");
    // crate::kprintln!("      COM:  ready (CoInitializeEx)");
    // crate::kprintln!("      RPC:  ready (SvcMgr entry points)");
}

pub mod acl;
pub mod event;
pub mod security;
pub mod service;
pub mod token;
pub mod types;
