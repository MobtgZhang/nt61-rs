//! cmd.exe — Command interpreter (user-mode side)
//!
//! Re-exports from `crate::libs::server::cmd`, which in turn
//! re-exports the real shell implementation from `crate::servers::cmd`.

#[cfg(target_arch = "x86_64")]
pub use crate::libs::server::cmd::ShellMode;
#[cfg(target_arch = "x86_64")]
pub use crate::libs::server::cmd::run_shell;
#[cfg(target_arch = "x86_64")]
pub use crate::libs::server::cmd::run_batch_file;
