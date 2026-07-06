//! lsass.exe — Local Security Authority Subsystem (user-mode side)
//!
//! Re-exports the real implementation from `crate::servers::lsass`
//! (via `crate::libs::server::lsass`).

pub use crate::libs::server::lsass::init;
pub use crate::libs::server::lsass::main;
