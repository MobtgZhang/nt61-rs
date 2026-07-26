//! Host-side port of the sshd launcher state-machine and config
//! validation. Mirrors `servers::sshd::launcher`.

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

pub fn validate_port(port: u16) -> Result<(), LauncherError> {
    if port == 0 { Err(LauncherError::BadPort) } else { Ok(()) }
}

pub fn validate_listen_address(addr: &str) -> Result<(), LauncherError> {
    if addr.trim().is_empty() { Err(LauncherError::BadAddress) } else { Ok(()) }
}

pub fn validate_host_key(path: &str) -> Result<(), LauncherError> {
    if path.trim().is_empty() { Err(LauncherError::BadAddress) } else { Ok(()) }
}

/// Run the state-machine transition under the given (current, next)
/// pair. Used by tests; the real kernel uses a spinlock-guarded
/// static.
pub fn can_transition(from: LauncherState, to: LauncherState) -> bool {
    matches!(
        (from, to),
        (LauncherState::Uninitialised, LauncherState::ConfigLoaded)
        | (LauncherState::ConfigLoaded, LauncherState::ListenerBound)
        | (LauncherState::ListenerBound, LauncherState::Accepting)
        | (LauncherState::Uninitialised, LauncherState::Stopped)
        | (LauncherState::ConfigLoaded, LauncherState::Stopped)
        | (LauncherState::ListenerBound, LauncherState::Stopped)
        | (LauncherState::Accepting, LauncherState::Stopped)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_progression() {
        let path = [
            LauncherState::Uninitialised,
            LauncherState::ConfigLoaded,
            LauncherState::ListenerBound,
            LauncherState::Accepting,
        ];
        for w in path.windows(2) {
            assert!(can_transition(w[0], w[1]),
                "transition {:?} -> {:?} must be allowed", w[0], w[1]);
        }
    }

    #[test]
    fn cannot_skip_steps() {
        assert!(!can_transition(LauncherState::Uninitialised,
            LauncherState::Accepting));
        assert!(!can_transition(LauncherState::ConfigLoaded,
            LauncherState::Accepting));
    }

    #[test]
    fn can_stop_from_any_state() {
        for s in [
            LauncherState::Uninitialised,
            LauncherState::ConfigLoaded,
            LauncherState::ListenerBound,
            LauncherState::Accepting,
        ] {
            assert!(can_transition(s, LauncherState::Stopped),
                "{:?} -> Stopped must be allowed", s);
        }
    }

    #[test]
    fn cannot_go_backwards() {
        assert!(!can_transition(LauncherState::Accepting,
            LauncherState::ListenerBound));
        assert!(!can_transition(LauncherState::Stopped,
            LauncherState::Uninitialised));
    }

    #[test]
    fn port_validation() {
        assert!(validate_port(0).is_err());
        assert!(validate_port(22).is_ok());
        assert!(validate_port(65535).is_ok());
    }

    #[test]
    fn listen_address_validation() {
        assert!(validate_listen_address("").is_err());
        assert!(validate_listen_address("   ").is_err());
        assert!(validate_listen_address("0.0.0.0").is_ok());
        assert!(validate_listen_address("127.0.0.1").is_ok());
    }

    #[test]
    fn host_key_validation() {
        assert!(validate_host_key("").is_err());
        assert!(validate_host_key("C:\\key").is_ok());
        assert!(validate_host_key("/sshd/key").is_ok());
    }
}