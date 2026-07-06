//! wininit — Boot-time init helper (re-export from servers::wininit)
pub use crate::servers::wininit::wininit_main;
pub use crate::servers::wininit::init;

/// Smoke test — wininit has no internal state in this model.
pub fn smoke_test() -> bool {
    true
}
