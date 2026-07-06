//! advapi32.dll — Advanced Local API
//
//! Provides access to advanced Windows features: security (registry
//! keys, access control, privileges), event log, service control,
//! and the registry API.
//
//! This is a stub implementation that provides the entry points
//! needed for ntdll integration and basic functionality.

// advapi32 uses Win32 naming (RegOpenKeyExW, LSA_*, ...).
#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use crate::kprintln;

/// Initialize the advapi32 stub.
pub fn init() {
    // crate::kprintln!("    ADVAPI32: init")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      registry: ready (RegOpenKeyEx etc.)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      security: ready (OpenProcessToken etc.)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      services: ready (OpenSCManager etc.)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      crypto:   ready (CryptAcquireContext etc.)")  // kprintln disabled (memcpy crash workaround);
}
