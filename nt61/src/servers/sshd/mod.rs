//! Win32-OpenSSH sshd launcher and bring-up scaffolding.
//!
//! This module ties together the bring-up pieces: read the
//! `sshd_config`, bind/listen on the configured port/address,
//! and dispatch each accepted connection to the auth + child
//! path. The actual KEX/auth/child orchestration lives in
//! `servers::sshd::session` (added in later stages).

pub mod config;
pub mod session;
pub mod child;
pub mod launcher;

use crate::ke::sync::Spinlock;
use alloc::string::String;
use config::{SshdConfig, PermitRoot};

/// Live sshd state, used by debug prints and by the session layer.
pub struct SshdState {
    pub config: SshdConfig,
    pub running: bool,
    pub listening_socket_id: Option<u32>,
    pub accepted_connections: u64,
    pub auth_failures: u64,
    pub child_processes_spawned: u64,
    pub last_error: Option<String>,
}

impl SshdState {
    pub const fn empty() -> Self {
        Self {
            config: SshdConfig {
                port: 22,
                listen_address: String::new(),
                host_key: String::new(),
                pid_file: None,
                permit_root_login: PermitRoot::ProhibitPassword,
                pubkey_authentication: false,
                password_authentication: false,
                challenge_response_authentication: false,
                authorized_keys_file: String::new(),
                subsystem: alloc::vec::Vec::new(),
                use_dns: false,
                login_grace_time: 0,
                max_auth_tries: 0,
                client_alive_interval: 0,
            },
            running: false,
            listening_socket_id: None,
            accepted_connections: 0,
            auth_failures: 0,
            child_processes_spawned: 0,
            last_error: None,
        }
    }
}

static SSHD_STATE: Spinlock<SshdState> = Spinlock::new(SshdState::empty());

/// Return the current sshd state (cloned) so callers don't have to
/// hold the spinlock across long-running operations.
pub fn state_snapshot() -> SshdState {
    let s = SSHD_STATE.lock();
    SshdState {
        config: s.config.clone(),
        running: s.running,
        listening_socket_id: s.listening_socket_id,
        accepted_connections: s.accepted_connections,
        auth_failures: s.auth_failures,
        child_processes_spawned: s.child_processes_spawned,
        last_error: s.last_error.clone(),
    }
}

/// Install the parsed `sshd_config` into the live state. This must
/// be done before `start_listener` is called.
pub fn install_config(cfg: SshdConfig) {
    let mut s = SSHD_STATE.lock();
    s.config = cfg;
}

/// Look up the configured `Port`. Returns the default (22) when no
/// config has been installed.
pub fn configured_port() -> u16 {
    SSHD_STATE.lock().config.port
}

/// Look up the configured listen address (default 0.0.0.0).
pub fn configured_listen_address() -> String {
    SSHD_STATE.lock().config.listen_address.clone()
}

/// Mark sshd as started and remember the listening socket id. The
/// session layer uses the id to enqueue accepted connections.
pub fn mark_started(listen_id: u32) {
    let mut s = SSHD_STATE.lock();
    s.running = true;
    s.listening_socket_id = Some(listen_id);
    s.last_error = None;
}

/// Mark sshd as stopped and clear the listener id. Used during
/// shutdown / SCM Stop control.
pub fn mark_stopped() {
    let mut s = SSHD_STATE.lock();
    s.running = false;
    s.listening_socket_id = None;
}

/// Bump the accepted-connections counter. Called once per
/// `accept()` in the listener loop.
pub fn note_accepted() {
    let mut s = SSHD_STATE.lock();
    s.accepted_connections = s.accepted_connections.wrapping_add(1);
}

/// Record an authentication failure. Used by the session layer
/// to feed `MaxAuthTries` enforcement.
pub fn note_auth_failure() {
    let mut s = SSHD_STATE.lock();
    s.auth_failures = s.auth_failures.wrapping_add(1);
}

/// Record that a child process (e.g. `cmd.exe`, `sftp-server.exe`)
/// was spawned in response to a session.
pub fn note_child_spawned() {
    let mut s = SSHD_STATE.lock();
    s.child_processes_spawned = s.child_processes_spawned.wrapping_add(1);
}

/// Capture the most recent sshd error string. Surfaces in the
/// serial log via `last_error()`.
pub fn record_error(msg: String) {
    let mut s = SSHD_STATE.lock();
    s.last_error = Some(msg);
}

/// Read the last error (for diagnostics).
pub fn last_error() -> Option<String> {
    SSHD_STATE.lock().last_error.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_is_22() {
        assert_eq!(configured_port(), 22);
    }

    #[test]
    fn install_config_changes_port() {
        let mut cfg = SshdConfig::default();
        cfg.port = 2222;
        install_config(cfg);
        assert_eq!(configured_port(), 2222);
    }

    #[test]
    fn counters_increment() {
        note_accepted();
        note_accepted();
        note_auth_failure();
        note_child_spawned();
        let snap = state_snapshot();
        assert!(snap.accepted_connections >= 2);
        assert!(snap.auth_failures >= 1);
        assert!(snap.child_processes_spawned >= 1);
    }

    #[test]
    fn mark_started_and_stopped() {
        mark_started(42);
        assert!(state_snapshot().running);
        mark_stopped();
        assert!(!state_snapshot().running);
    }
}