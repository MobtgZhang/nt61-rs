//! winlogon.exe — Logon Manager (user-mode side)
//!
//! Re-exports from `crate::libs::server::winlogon`, which in turn
//! re-exports the real implementation from `crate::servers::winlogon`.

pub use crate::libs::server::winlogon::init;
pub use crate::libs::server::winlogon::winlogon_main;
