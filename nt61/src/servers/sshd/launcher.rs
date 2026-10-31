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

use super::child;
use super::config::{PermitRoot, SshdConfig};
use super::session;
use crate::ke::sync::Spinlock;
use crate::netstack::socket::{self, SockAddr, SocketError, SocketType};

/// Listen backlog for the sshd TCP listener (RFC 4253 does not
/// mandate a size; 8 matches the socket layer's default).
pub const LISTEN_BACKLOG: u32 = 8;

/// Set once the dedicated service thread has been spawned, so a
/// re-run of start_from_disk cannot accumulate duplicate threads.
static SERVICE_THREAD_STARTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Canonical Windows OpenSSH installation path for `sshd_config`.
pub const SSHD_CONFIG_PATH: &str = "C:\\Program Files\\OpenSSH\\sshd_config";

/// Load `sshd_config` from the system partition and start the listener.
/// Returns `Ok(false)` when no OpenSSH configuration is installed, which
/// is the normal state for a non-SSH test image.
pub fn start_from_disk() -> Result<bool, LauncherError> {
    crate::hal::serial::write_string_always("[SSHD] boot check\r\n");
    let Some(config_bytes) = crate::fs::read_file_from_disk(SSHD_CONFIG_PATH) else {
        crate::hal::serial::write_string_always("[SSHD] config missing\r\n");
        return Ok(false);
    };
    crate::hal::serial::write_string_always("[SSHD] config loaded\r\n");
    let Ok(config_text) = alloc::string::String::from_utf8(config_bytes) else {
        crate::hal::serial::write_string_always("[SSHD] config invalid UTF-8\r\n");
        return Err(LauncherError::BadAddress);
    };
    let config = SshdConfig::parse(&config_text);
    super::install_config(config);
    // Load public keys from the configured authorized_keys file so
    // public-key authentication works on real images. Fail closed:
    // when no keys can be loaded, publickey auth stays unavailable;
    // no default account or empty password is ever created.
    install_authorized_keys_from_disk();
    // SECURITY: Fail closed. Authentication credentials are installed
    // explicitly by platform policy; never create a default account.
    start_listener()?;
    set_state(LauncherState::Accepting);
    // Spawn the dedicated service thread once the listener is live.
    // Guarded so a re-run of start_from_disk never accumulates
    // duplicate service threads.
    if SERVICE_THREAD_STARTED
        .compare_exchange(
            false,
            true,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
    {
        let _ =
            crate::ps::thread::ps_create_system_thread(service_thread_entry as *const () as u64, 0);
    }
    crate::hal::serial::write_string_always("[SSHD] listener started\r\n");
    Ok(true)
}

/// Load ssh-rsa public keys from the configured authorized_keys file
/// and install them for the primary OS account. Lines that fail to
/// parse are skipped; a missing or unreadable file leaves public-key
/// authentication unavailable (fail closed).
fn install_authorized_keys_from_disk() {
    let config = super::state_snapshot().config;
    let path = config.authorized_keys_file.clone();
    let Some(bytes) = crate::fs::read_file_from_disk(&path) else {
        crate::hal::serial::write_string_always("[SSHD] authorized_keys missing\r\n");
        return;
    };
    let Ok(text) = alloc::string::String::from_utf8(bytes) else {
        crate::hal::serial::write_string_always("[SSHD] authorized_keys invalid UTF-8\r\n");
        return;
    };
    let mut installed = 0usize;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(algorithm) = fields.next() else {
            continue;
        };
        if algorithm != "ssh-rsa" {
            continue;
        }
        let Some(blob_b64) = fields.next() else {
            continue;
        };
        let Some(blob) = base64_decode(blob_b64) else {
            continue;
        };
        if let Some(key) = super::kex::parse_rsa_public_key_blob(&blob) {
            super::auth::install_authorized_key("user", key);
            installed += 1;
        }
    }
    if installed == 0 {
        crate::hal::serial::write_string_always("[SSHD] no valid authorized keys\r\n");
    }
}

/// Decode standard base64 (RFC 4648, with padding). Returns None on
/// any character outside the alphabet or on a length that cannot
/// decode to whole bytes.
fn base64_decode(input: &str) -> Option<alloc::vec::Vec<u8>> {
    fn value_of(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let filtered: alloc::vec::Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace())
        .collect();
    let body: &[u8] = match filtered.iter().position(|&b| b == b'=') {
        Some(pad) => &filtered[..pad],
        None => &filtered[..],
    };
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = alloc::vec::Vec::with_capacity(body.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in body {
        let v = value_of(c)?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Drive listener accepts and active SSH sessions from the timer
/// tick. Compatibility wrapper; the dedicated service thread
/// handles this work via service_thread_entry.
pub fn service_tick() {
    poll_once();
}

/// True when the listener has a pending connection or any live SSH
/// session has receive data ready, so the service thread can skip
/// a park and make progress immediately.
fn has_pending_work() -> bool {
    let listen_id = super::state_snapshot().listening_socket_id;
    let accept_pending = match listen_id {
        Some(id) => socket::is_read_ready(id),
        None => false,
    };
    accept_pending || session::has_ready_session()
}

/// Bounded park for the sshd service thread, in milliseconds. Long
/// enough to amortize wakeups, short enough to cover the interval
/// before a TCP arrival races the readiness clear.
const SSHD_SERVICE_WAIT_MS: u32 = 200;

/// Dedicated sshd service thread. Drives listener accepts and session
/// I/O by parking on the socket readiness event between rounds of
/// work, instead of relying on the scheduler tick to poll. Mirrors
/// the csrss server-thread entry model.
pub extern "C" fn service_thread_entry(_context: u64) {
    loop {
        poll_once();
        socket::clear_readiness();
        if !has_pending_work() {
            socket::wait_readiness(SSHD_SERVICE_WAIT_MS);
        }
    }
}

/// AF_INET value used by the socket layer.
const AF_INET: u16 = 2;

/// Bind a TCP listener on the configured Port/ListenAddress and hand
/// it to the session layer. The command executor used by SSH shell
/// channels is wired to the kernel cmd dispatcher here.
pub fn start_listener() -> Result<u32, LauncherError> {
    child::install_command_executor(|line| {
        crate::servers::cmd::begin_output_capture();
        let exit_code = if crate::servers::cmd::execute_command_line(line) {
            0
        } else {
            1
        };
        child::CommandExecution::new(
            exit_code,
            crate::servers::cmd::take_output_capture().unwrap_or_default(),
        )
    });

    let cfg = super::state_snapshot().config;
    if validate_config(&cfg).is_err() {
        return Err(LauncherError::BadAddress);
    }

    let socket_id = socket::socket_auto(SocketType::Stream).ok_or(LauncherError::BindFailed)?;
    let addr = SockAddr::new(AF_INET, cfg.port, 0);
    match socket::bind(socket_id, &addr) {
        Ok(()) => {}
        Err(SocketError::AddressInUse) => return Err(LauncherError::BindFailed),
        Err(_) => return Err(LauncherError::BindFailed),
    }
    match socket::listen(socket_id, LISTEN_BACKLOG) {
        Ok(()) => {}
        Err(_) => return Err(LauncherError::BindFailed),
    }

    super::mark_started(socket_id);
    Ok(socket_id)
}

/// Accept one pending connection and step all active sessions.
/// Returns the number of live SSH sessions.
pub fn poll_once() -> usize {
    let listen_id = match super::state_snapshot().listening_socket_id {
        Some(id) => id,
        None => return 0,
    };
    match socket::accept(listen_id) {
        Ok(peer_socket_id) => {
            super::note_accepted();
            session::accept_connection(peer_socket_id);
        }
        Err(SocketError::WouldBlock) => {}
        Err(_) => {}
    }
    session::poll_sessions()
}

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

static LAUNCHER_STATE: Spinlock<LauncherState> = Spinlock::new(LauncherState::Uninitialised);

/// Mark the launcher state. `start_listener` walks through the
/// transitions: Uninitialised → ConfigLoaded → ListenerBound →
/// Accepting. Each transition is gated by `can_transition_to`.
pub fn set_state(next: LauncherState) -> bool {
    let mut current = LAUNCHER_STATE.lock();
    let ok = matches!(
        (*current, next),
        (LauncherState::Uninitialised, LauncherState::ConfigLoaded)
            | (LauncherState::ConfigLoaded, LauncherState::ListenerBound)
            | (LauncherState::ListenerBound, LauncherState::Accepting)
            | (LauncherState::Uninitialised, LauncherState::Stopped)
            | (LauncherState::ConfigLoaded, LauncherState::Stopped)
            | (LauncherState::ListenerBound, LauncherState::Stopped)
            | (LauncherState::Accepting, LauncherState::Stopped)
    );
    if ok {
        *current = next;
    }
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
    if user.eq_ignore_ascii_case("root") || user.eq_ignore_ascii_case("administrator") {
        return matches!(
            cfg.permit_root_login,
            PermitRoot::Yes | PermitRoot::WithoutPassword | PermitRoot::ProhibitPassword
        );
    }
    true
}

/// read the cached state, reset to `Uninitialised`. Useful in
/// tests so each test starts from a clean slate.
pub fn reset_for_test() {
    let mut s = LAUNCHER_STATE.lock();
    *s = LauncherState::Uninitialised;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::servers::sshd::config::SshdConfig;
    use alloc::string::String;

    fn reset() {
        reset_for_test();
    }

    // The two state-machine tests share the process-global
    // LAUNCHER_STATE. Running them in parallel lets one test observe the
    // other's transitions (a reset() from one thread between another
    // thread's reset() and set_state() leaves the machine in an
    // unexpected state), so they are serialized on this test-local lock.
    static STATE_MACHINE_TEST_LOCK: Spinlock<()> = Spinlock::new(());

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
        let _guard = STATE_MACHINE_TEST_LOCK.lock();
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
        let _guard = STATE_MACHINE_TEST_LOCK.lock();
        reset();
        assert!(set_state(LauncherState::ConfigLoaded));
        assert!(set_state(LauncherState::Stopped));
        reset();
        // After reset(), the state is back to Uninitialised,
        // so going straight to Stopped must work.
        assert!(set_state(LauncherState::Stopped));
    }
}
