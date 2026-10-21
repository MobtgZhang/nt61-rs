//! advapi32.dll — Advanced Local API
//
//! Provides access to advanced Windows features: security (registry
//! keys, access control, privileges), event log, service control,
//! and the registry API.
//
//! This is a stub implementation that provides the entry points
//! needed for ntdll integration and basic functionality.

// advapi32 uses Win32 naming (RegOpenKeyExW, LSA_*, ...).

/// Initialize the advapi32 stub.
pub fn init() {
    // crate::kprintln!("    ADVAPI32: init");
    // crate::kprintln!("      registry: ready (RegOpenKeyEx etc.)");
    // crate::kprintln!("      security: ready (OpenProcessToken etc.)");
    // crate::kprintln!("      services: ready (OpenSCManager etc.)");
    // crate::kprintln!("      crypto:   ready (CryptAcquireContext etc.)");
}

pub mod cred;
pub mod event;
pub mod registry;
pub mod security;
pub mod service;
pub mod types;
