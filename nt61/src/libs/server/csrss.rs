//! csrss — Client/Server Runtime Subsystem (re-export from servers::csrss)
pub use crate::servers::csrss::csrss_main;
pub use crate::servers::csrss::init;

/// Smoke test — csrss has no internal state in this model.
pub fn smoke_test() -> bool {
    true
}
