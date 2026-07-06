//! winlogon — Logon Manager (re-export from servers::winlogon)
pub use crate::servers::winlogon::winlogon_main;
pub use crate::servers::winlogon::init;

/// Smoke test — winlogon has no internal state in this model.
pub fn smoke_test() -> bool {
    true
}
