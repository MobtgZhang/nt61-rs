//! csrss.exe — Client/Server Runtime Subsystem (user-mode side)
//!
//! Re-exports from `crate::libs::server::csrss`, which in turn
//! re-exports the real implementation from `crate::servers::csrss`.

pub use crate::libs::server::csrss::csrss_main;
pub use crate::libs::server::csrss::init;
