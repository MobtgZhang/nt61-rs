//! SessionState forward-progression logic, ported to the host
//! for unit testing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    New = 0,
    TcpAccepted = 1,
    BannerExchanged = 2,
    KexInit = 3,
    Encrypted = 4,
    UserauthRequested = 5,
    Authenticated = 6,
    ConnectionRequested = 7,
    ChannelOpen = 8,
    ExecRequest = 9,
    ChildSpawned = 10,
    Closed = 11,
}

impl SessionState {
    pub fn can_transition_to(self, next: SessionState) -> bool {
        if next == SessionState::Closed {
            return self != SessionState::Closed;
        }
        // Strict forward-only: next must be exactly current + 1.
        (next as u8) == (self as u8) + 1
    }

    pub fn transition(self, next: SessionState) -> Option<SessionState> {
        if self.can_transition_to(next) { Some(next) } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_happy_path() {
        let path = [
            SessionState::New,
            SessionState::TcpAccepted,
            SessionState::BannerExchanged,
            SessionState::KexInit,
            SessionState::Encrypted,
            SessionState::UserauthRequested,
            SessionState::Authenticated,
            SessionState::ConnectionRequested,
            SessionState::ChannelOpen,
            SessionState::ExecRequest,
            SessionState::ChildSpawned,
            SessionState::Closed,
        ];
        for w in path.windows(2) {
            assert!(w[0].can_transition_to(w[1]),
                "happy-path transition {:?} -> {:?} blocked", w[0], w[1]);
        }
    }

    #[test]
    fn no_skipping_states() {
        // New cannot jump straight to Encrypted.
        assert!(!SessionState::New.can_transition_to(SessionState::Encrypted));
        // Authenticated cannot jump to ChannelOpen without going
        // through ConnectionRequested first.
        assert!(!SessionState::Authenticated.can_transition_to(SessionState::ChannelOpen));
    }

    #[test]
    fn backward_blocked() {
        for w in [
            SessionState::Encrypted,
            SessionState::KexInit,
            SessionState::BannerExchanged,
        ] {
            assert!(!w.can_transition_to(SessionState::TcpAccepted),
                "backward {:?} -> TcpAccepted should be blocked", w);
        }
    }

    #[test]
    fn closed_reachable_from_anywhere() {
        for s in [
            SessionState::New,
            SessionState::TcpAccepted,
            SessionState::Encrypted,
            SessionState::ChildSpawned,
        ] {
            assert!(s.can_transition_to(SessionState::Closed),
                "{:?} -> Closed must be allowed", s);
        }
    }

    #[test]
    fn closed_is_terminal() {
        for s in [
            SessionState::New,
            SessionState::Encrypted,
            SessionState::Authenticated,
            SessionState::ChildSpawned,
        ] {
            assert!(!SessionState::Closed.can_transition_to(s),
                "from Closed, must not transition to {:?}", s);
        }
    }

    #[test]
    fn transition_returns_some_on_valid() {
        assert_eq!(SessionState::New.transition(SessionState::TcpAccepted),
            Some(SessionState::TcpAccepted));
    }

    #[test]
    fn transition_returns_none_on_invalid() {
        assert_eq!(SessionState::TcpAccepted.transition(SessionState::New), None);
        assert_eq!(SessionState::Encrypted.transition(SessionState::New), None);
    }
}