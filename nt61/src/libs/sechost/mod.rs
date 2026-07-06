//! sechost.exe — Service Host Process
//
//! Implements the Service Host process that hosts COM servers and
//! services. This is a stub that provides the basic sechost
//! functionality.
//
//! Clean-room implementation. Spec source: Windows Services documentation,
//! "Windows Internals 6th ed." ch. 10.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use crate::kprintln;

/// Initialize the sechost stub.
pub fn init() {
    // crate::kprintln!("    SECHOST: init")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      COM:  ready (CoInitializeEx)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      RPC:  ready (SvcMgr entry points)")  // kprintln disabled (memcpy crash workaround);
}
