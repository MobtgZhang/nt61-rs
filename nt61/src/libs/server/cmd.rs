//! cmd — Command interpreter (re-export from servers::cmd)
//!
//! The shell itself lives in `servers::cmd` which is gated to
//! x86_64 by `#![cfg(target_arch = "x86_64")]`. The re-exports
//! below are therefore also x86_64-only; callers should fall back
//! to the stub `smoke_test()` (always `true`) on other archs.
#[cfg(target_arch = "x86_64")]
pub use crate::servers::cmd::{run_batch_file, run_shell, ShellMode};

/// Smoke test — the real shell lives in `servers::cmd`.
pub fn smoke_test() -> bool {
    true
}
