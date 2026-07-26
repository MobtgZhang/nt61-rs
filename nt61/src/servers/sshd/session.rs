//! Session lifecycle scaffolding (KEX/auth/child).
//!
//! Real OpenSSH walks: TCP accept → protocol version exchange
//! → KEX → service request (ssh-userauth) → pubkey auth → service
//! request (ssh-connection) → channel open → shell/exec/subsystem
//! request → child spawn.
//!
//! We don't implement the binary protocol yet, but we expose the
//! state-machine skeleton so future stages can fill it in without
//! rewriting the listener glue. Each state is reachable from
//! `SessionState::transition()`, which enforces valid
//! forward-only transitions and rejects loops.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    /// No state — fresh session.
    New = 0,
    /// TCP accepted but no bytes exchanged yet.
    TcpAccepted = 1,
    /// Both sides have sent their SSH protocol banner.
    BannerExchanged = 2,
    /// Algorithm negotiation in progress (KEXINIT sent/received).
    KexInit = 3,
    /// Key exchange completed; session is encrypted.
    Encrypted = 4,
    /// ssh-userauth service requested.
    UserauthRequested = 5,
    /// Authentication succeeded.
    Authenticated = 6,
    /// ssh-connection service requested.
    ConnectionRequested = 7,
    /// Channel opened.
    ChannelOpen = 8,
    /// Shell/exec/subsystem request issued.
    ExecRequest = 9,
    /// Child process spawned.
    ChildSpawned = 10,
    /// Session torn down.
    Closed = 11,
}

impl SessionState {
    pub fn can_transition_to(self, next: SessionState) -> bool {
        // Closed is reachable from any non-terminal state (for
        // disconnect, timeout, fatal error). Otherwise we only
        // allow strictly forward single-step transitions to
        // prevent skipping required protocol exchanges.
        if next == SessionState::Closed {
            return self != SessionState::Closed;
        }
        (next as u8) == (self as u8) + 1
    }

    pub fn transition(self, next: SessionState) -> Option<SessionState> {
        if self.can_transition_to(next) { Some(next) } else { None }
    }

    pub fn is_terminal(self) -> bool {
        self == SessionState::Closed
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SessionStats {
    pub state: SessionState,
    pub kex_attempts: u32,
    pub auth_attempts: u32,
    pub bytes_from_client: u64,
    pub bytes_to_client: u64,
}

impl SessionStats {
    pub const fn new() -> Self {
        Self {
            state: SessionState::New,
            kex_attempts: 0,
            auth_attempts: 0,
            bytes_from_client: 0,
            bytes_to_client: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_transitions_allowed() {
        assert!(SessionState::New.can_transition_to(SessionState::TcpAccepted));
        assert!(SessionState::TcpAccepted.can_transition_to(SessionState::BannerExchanged));
        assert!(SessionState::Encrypted.can_transition_to(SessionState::UserauthRequested));
    }

    #[test]
    fn backward_transitions_rejected() {
        assert!(!SessionState::BannerExchanged.can_transition_to(SessionState::TcpAccepted));
        assert!(!SessionState::ExecRequest.can_transition_to(SessionState::Encrypted));
    }

    #[test]
    fn closed_is_reachable_from_any_state() {
        for s in [
            SessionState::New,
            SessionState::TcpAccepted,
            SessionState::Encrypted,
            SessionState::ExecRequest,
            SessionState::ChildSpawned,
        ] {
            assert!(s.can_transition_to(SessionState::Closed));
        }
    }

    #[test]
    fn closed_is_terminal() {
        assert!(SessionState::Closed.is_terminal());
        assert!(!SessionState::New.is_terminal());
        assert!(SessionState::ChildSpawned.can_transition_to(SessionState::Closed));
        // Once closed, no further transitions.
        assert!(!SessionState::Closed.can_transition_to(SessionState::New));
    }

    #[test]
    fn transition_returns_some_for_valid() {
        let n = SessionState::New.transition(SessionState::TcpAccepted);
        assert_eq!(n, Some(SessionState::TcpAccepted));
    }

    #[test]
    fn transition_returns_none_for_invalid() {
        let n = SessionState::TcpAccepted.transition(SessionState::New);
        assert_eq!(n, None);
    }
}