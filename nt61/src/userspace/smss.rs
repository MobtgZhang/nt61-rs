//! smss.exe — Session Manager (user-mode side)
//!
//! Re-exports from `crate::libs::server::smss`, which in turn
//! re-exports the real implementation from `crate::servers::smss`.
//!
//! Architecture:
//! - `crate::servers::smss` — full SMSS boot logic (session creation,
//!   CSRSS launch, wininit/winlogon startup)
//! - `crate::libs::server::smss` — re-export of `servers::smss`
//! - `crate::userspace::smss` — user-mode shim that re-exports from
//!   `libs::server::smss`

pub use crate::libs::server::smss::smss_main;
pub use crate::libs::server::smss::init;
pub use crate::libs::server::smss::create_session_0;
pub use crate::libs::server::smss::create_session_1;
