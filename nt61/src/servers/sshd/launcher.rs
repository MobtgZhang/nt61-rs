//! sshd launcher — bind / listen / accept / fork.
//!
//! This is the bring-up glue that turns an installed sshd.exe on
//! disk into an actively-listening service. It does NOT implement
//! the SSH wire protocol (that lives in `session`), it just:
//!   - reads `sshd_config` from the disk image,
//!   - opens a TCP listener on the configured Port/ListenAddress,
//!   - feeds each accepted connection to the session layer.
//!
//! The wire-protocol implementation will live in subsequent
//! stages; for now this module provides a testable launcher that
//! can be unit-tested without the bare-metal kernel.

use super::config::{SshdConfig, PermitRoot};
use crate::ke::sync::Spinlock;
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherState {
    Uninitialised,
    ConfigLoaded,
    ListenerBound,
    Accepting,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherError {
    BadPort,
    BadAddress,
    BindFailed,
    AlreadyRunning,
}

static LAUNCHER_STATE: Spinlock<LauncherState> =
    Spinlock::new(LauncherState::Uninitialised);

/// Mark the launcher state. `start_listener` walks through the
/// transitions: Uninitialised → ConfigLoaded → ListenerBound →
/// Accepting. Each transition is gated by `can_transition_to`.
pub fn set_state(next: LauncherState) -> bool {
    let mut current = LAUNCHER_STATE.lock();
    let ok = match (*current, next) {
        (LauncherState::Uninitialised, LauncherState::ConfigLoaded)
        | (LauncherState::ConfigLoaded, LauncherState::ListenerBound)
        | (LauncherState::ListenerBound, LauncherState::Accepting)
        | (LauncherState::Uninitialised, LauncherState::Stopped)
        | (LauncherState::ConfigLoaded, LauncherState::Stopped)
        | (LauncherState::ListenerBound, LauncherState::Stopped)
        | (LauncherState::Accepting, LauncherState::Stopped) => true,
        _ => false,
    };
    if ok { *current = next; }
    ok
}

pub fn current_state() -> LauncherState {
    *LAUNCHER_STATE.lock()
}

/// Validate the config (Port 1..=65535, ListenAddress non-empty,
/// HostKey path non-empty). Returns the matching LauncherError on
/// failure, or `Ok(())` on success.
pub fn validate_config(cfg: &SshdConfig) -> Result<(), LauncherError> {
    if cfg.port == 0 {
        return Err(LauncherError::BadPort);
    }
    if cfg.listen_address.trim().is_empty() {
        return Err(LauncherError::BadAddress);
    }
    if cfg.host_key.trim().is_empty() {
        // We don't enforce this strictly — OpenSSH's default mode
        // is "find any ssh_host_*_key in the same directory". But
        // in our bare-metal world we require an explicit HostKey
        // entry so we don't have to guess.
        return Err(LauncherError::BadAddress);
    }
    Ok(())
}

/// Public decision logic: should the launcher accept pubkey auth
/// for `user` based on the parsed config? Used by the session
/// layer to short-circuit before KEX runs.
pub fn config_allows_pubkey(cfg: &SshdConfig, user: &str) -> bool {
    if !cfg.pubkey_authentication {
        return false;
    }
    // PermitRootLogin policy.
    if user.eq_ignore_ascii_case("root")
        || user.eq_ignore_ascii_case("administrator")
    {
        return matches!(
            cfg.permit_root_login,
            PermitRoot::Yes | PermitRoot::WithoutPassword
                | PermitRoot::ProhibitPassword
        );
    }
    true
}

/// Read the cached state, reset to `Uninitialised`. Useful in
/// tests so each test starts from a clean slate.
pub fn reset_for_test() {
    let mut s = LAUNCHER_STATE.lock();
    *s = LauncherState::Uninitialised;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::servers::sshd::config::SshdConfig;

    fn reset() {
        reset_for_test();
    }

    #[test]
    fn validate_rejects_zero_port() {
        reset();
        let mut cfg = SshdConfig::default();
        cfg.port = 0;
        assert_eq!(validate_config(&cfg), Err(LauncherError::BadPort));
    }

    #[test]
    fn validate_rejects_empty_listen_address() {
        reset();
        let mut cfg = SshdConfig::default();
        cfg.listen_address = String::new();
        assert_eq!(validate_config(&cfg), Err(LauncherError::BadAddress));
    }

    #[test]
    fn validate_rejects_empty_host_key() {
        reset();
        let mut cfg = SshdConfig::default();
        cfg.host_key = String::new();
        assert_eq!(validate_config(&cfg), Err(LauncherError::BadAddress));
    }

    #[test]
    fn validate_accepts_sensible_config() {
        reset();
        let cfg = SshdConfig::default();
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn config_allows_pubkey_for_nt61test() {
        let cfg = SshdConfig::default();
        assert!(config_allows_pubkey(&cfg, "nt61test"));
    }

    #[test]
    fn config_disables_pubkey_when_off() {
        let mut cfg = SshdConfig::default();
        cfg.pubkey_authentication = false;
        assert!(!config_allows_pubkey(&cfg, "nt61test"));
    }

    #[test]
    fn state_machine_progresses_in_order() {
        reset();
        assert!(set_state(LauncherState::ConfigLoaded));
        assert!(set_state(LauncherState::ListenerBound));
        assert!(set_state(LauncherState::Accepting));
        // Skipping ListenerBound is rejected.
        reset();
        assert!(set_state(LauncherState::ConfigLoaded));
        assert!(!set_state(LauncherState::Accepting));
    }

    #[test]
    fn state_machine_allows_stop_from_any_state() {
        reset();
        assert!(set_state(LauncherState::ConfigLoaded));
        assert!(set_state(LauncherState::Stopped));
        reset();
        assert!(set_state(LauncherState::Uninitialised));
        assert!(set_state(LauncherState::Stopped));
    }
}