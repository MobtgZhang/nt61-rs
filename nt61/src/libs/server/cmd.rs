//! cmd — Command interpreter (re-export from servers::cmd)
//!
pub use crate::servers::cmd::{run_batch_file, run_shell, ShellMode};

/// Smoke test — the real shell lives in `servers::cmd`.
pub fn smoke_test() -> bool {
    true
}
