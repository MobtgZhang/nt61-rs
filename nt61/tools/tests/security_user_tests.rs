//! Re-implementation of the SID-based account lookup table to
//! validate the semantics in a host environment. The kernel
//! version lives in `se::users`; here we mirror the logic so
//! the test harness can exercise it without a full kernel.

#[cfg(test)]
mod tests {
    /// Hard-coded well-known SIDs (mirrors `se::sid::WellKnownSid`).
    const LOCAL_SYSTEM_IA: [u8; 6] = [0, 0, 0, 0, 0, 5];
    const WORLD_IA: [u8; 6] = [0, 0, 0, 0, 0, 1];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AccountKind {
        System,
        Administrators,
        User,
        Guest,
    }

    #[derive(Clone, Copy)]
    struct Sid {
        sub_authority_count: u8,
        identifier_authority: [u8; 6],
        sub_authority: [u32; 8],
    }

    impl Sid {
        fn equals(&self, other: &Sid) -> bool {
            if self.sub_authority_count != other.sub_authority_count {
                return false;
            }
            if self.identifier_authority != other.identifier_authority {
                return false;
            }
            for i in 0..self.sub_authority_count as usize {
                if self.sub_authority[i] != other.sub_authority[i] {
                    return false;
                }
            }
            true
        }
    }

    #[derive(Clone, Copy)]
    struct AccountEntry {
        rid: u32,
        sid: Sid,
        kind: AccountKind,
        enabled: bool,
    }

    const SYSTEM: AccountEntry = AccountEntry {
        rid: 18,
        sid: Sid {
            sub_authority_count: 1,
            identifier_authority: LOCAL_SYSTEM_IA,
            sub_authority: [18, 0, 0, 0, 0, 0, 0, 0],
        },
        kind: AccountKind::System,
        enabled: true,
    };

    const ADMINS: AccountEntry = AccountEntry {
        rid: 544,
        sid: Sid {
            sub_authority_count: 2,
            identifier_authority: LOCAL_SYSTEM_IA,
            sub_authority: [32, 544, 0, 0, 0, 0, 0, 0],
        },
        kind: AccountKind::Administrators,
        enabled: true,
    };

    const NT61TEST: AccountEntry = AccountEntry {
        rid: 1001,
        sid: Sid {
            sub_authority_count: 2,
            identifier_authority: LOCAL_SYSTEM_IA,
            sub_authority: [21, 1001, 0, 0, 0, 0, 0, 0],
        },
        kind: AccountKind::User,
        enabled: true,
    };

    const GUESTS: AccountEntry = AccountEntry {
        rid: 546,
        sid: Sid {
            sub_authority_count: 2,
            identifier_authority: LOCAL_SYSTEM_IA,
            sub_authority: [32, 546, 0, 0, 0, 0, 0, 0],
        },
        kind: AccountKind::Guest,
        enabled: false,
    };

    const BUILTIN: &[AccountEntry] = &[SYSTEM, ADMINS, GUESTS, NT61TEST];

    fn lookup_by_name(name: &str) -> Option<AccountEntry> {
        let normalized = name.trim().trim_end_matches('\0');
        for a in BUILTIN {
            let n = match a.kind {
                AccountKind::System => "SYSTEM",
                AccountKind::Administrators => "Administrators",
                AccountKind::User => "nt61test",
                AccountKind::Guest => "Guest",
            };
            if normalized.eq_ignore_ascii_case(n) {
                return Some(*a);
            }
        }
        None
    }

    fn lookup_by_sid(sid: &Sid) -> Option<AccountEntry> {
        for a in BUILTIN {
            if a.sid.equals(sid) {
                return Some(*a);
            }
        }
        None
    }

    #[test]
    fn lookup_system_by_name_exact() {
        let a = lookup_by_name("SYSTEM").unwrap();
        assert_eq!(a.kind, AccountKind::System);
    }

    #[test]
    fn lookup_system_by_name_lowercase() {
        let a = lookup_by_name("system").unwrap();
        assert_eq!(a.kind, AccountKind::System);
    }

    #[test]
    fn lookup_system_by_name_trailing_null() {
        let a = lookup_by_name("SYSTEM\0").unwrap();
        assert_eq!(a.kind, AccountKind::System);
    }

    #[test]
    fn lookup_admin_by_name() {
        let a = lookup_by_name("Administrators").unwrap();
        assert_eq!(a.rid, 544);
    }

    #[test]
    fn lookup_nt61test_by_name() {
        let a = lookup_by_name("nt61test").unwrap();
        assert_eq!(a.rid, 1001);
        assert!(a.enabled);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup_by_name("nobody_such_user").is_none());
    }

    #[test]
    fn lookup_by_sid_returns_account() {
        let sys_sid = Sid {
            sub_authority_count: 1,
            identifier_authority: LOCAL_SYSTEM_IA,
            sub_authority: [18, 0, 0, 0, 0, 0, 0, 0],
        };
        let a = lookup_by_sid(&sys_sid).unwrap();
        assert_eq!(a.kind, AccountKind::System);
    }

    #[test]
    fn lookup_by_sid_no_match() {
        let bogus_sid = Sid {
            sub_authority_count: 1,
            identifier_authority: WORLD_IA,
            sub_authority: [99, 0, 0, 0, 0, 0, 0, 0],
        };
        assert!(lookup_by_sid(&bogus_sid).is_none());
    }

    #[test]
    fn guests_are_disabled_by_default() {
        let a = lookup_by_name("Guest").unwrap();
        assert!(!a.enabled, "Guest account must be disabled by default");
    }
}