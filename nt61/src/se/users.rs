//! Built-in user database (SAM).
//!
//! A minimal Security Account Manager (SAM) stub. The real NT SAM
//! stores hashed credentials in the registry hive `SAM\Domains\Account
//! \Users\<RID>`. We don't persist any hashes yet — OpenSSH only
//! uses pubkey authentication at first, so we just need a stable
//! mapping from account name → SID → well-known privileges for the
//! few accounts we ship:
//!
//!   SYSTEM              — S-1-5-18
//!   Administrators      — S-1-5-32-544
//!   nt61test            — S-1-5-21-0-0-0-1001 (placeholder RID)
//!
//! Lookup is linear in the table (≤ a handful of entries), which is
//! fine for kernel boot-time decisions.
//!
//! Authorization decisions (token creation, privilege set, etc.)
//! continue to live in `se::token`. This module is purely the
//! "who exists" lookup.

use super::sid::{Sid, WellKnownSid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    System,
    Administrators,
    User,
    Guest,
}

#[derive(Debug, Clone, Copy)]
pub struct AccountEntry {
    /// Stable relative identifier (RID). Built-in accounts use
    /// the well-known RIDs; `User` accounts use the placeholder
    /// `0x3E8 + slot`.
    pub rid: u32,
    pub sid: Sid,
    pub kind: AccountKind,
    /// Whether the account is currently enabled. OpenSSH skips
    /// disabled accounts at logon.
    pub enabled: bool,
}

const SYSTEM: AccountEntry = AccountEntry {
    rid: 18,
    sid: Sid::well_known(WellKnownSid::LocalSystem),
    kind: AccountKind::System,
    enabled: true,
};

const ADMINS: AccountEntry = AccountEntry {
    rid: 544,
    sid: Sid::well_known(WellKnownSid::Administrators),
    kind: AccountKind::Administrators,
    enabled: true,
};

const GUESTS: AccountEntry = AccountEntry {
    rid: 546,
    sid: Sid::well_known(WellKnownSid::Guests),
    kind: AccountKind::Guest,
    enabled: false,
};

const NT61TEST: AccountEntry = AccountEntry {
    rid: 1001,
    sid: Sid::with_2subs([0, 0, 0, 0, 0, 5], 21, 1001),
    kind: AccountKind::User,
    enabled: true,
};

const BUILTIN: &[AccountEntry] = &[SYSTEM, ADMINS, GUESTS, NT61TEST];

/// Look up an account by SID.
pub fn lookup_by_sid(sid: &Sid) -> Option<AccountEntry> {
    for a in BUILTIN {
        if a.sid.equals(sid) {
            return Some(*a);
        }
    }
    None
}

/// Look up an account by case-insensitive name. Names use the
/// Windows convention: `SYSTEM`, `Administrators`, `Guest`,
/// `nt61test`. The match is byte-wise for ASCII; Unicode
/// matches are not yet supported because we only have ASCII
/// account names.
pub fn lookup_by_name(name: &str) -> Option<AccountEntry> {
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

/// Return an iterator over the account table. Used by
/// `NetUserEnum` and similar enumeration APIs.
pub fn all_accounts() -> &'static [AccountEntry] {
    BUILTIN
}

pub fn init() {
    // crate::kprintln!("    SE/USERS: initialized (built-in accounts: SYSTEM, Administrators, nt61test)")  // kprintln disabled (memcpy crash workaround);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::se::sid::WellKnownSid;

    #[test]
    fn lookup_system_by_name() {
        let sys = lookup_by_name("SYSTEM").unwrap();
        assert_eq!(sys.kind, AccountKind::System);
    }

    #[test]
    fn lookup_system_by_name_lowercase() {
        let sys = lookup_by_name("system").unwrap();
        assert_eq!(sys.kind, AccountKind::System);
    }

    #[test]
    fn lookup_system_by_sid() {
        let sid = Sid::well_known(WellKnownSid::LocalSystem);
        let sys = lookup_by_sid(&sid).unwrap();
        assert_eq!(sys.rid, 18);
    }

    #[test]
    fn lookup_nt61test() {
        let u = lookup_by_name("nt61test").unwrap();
        assert_eq!(u.kind, AccountKind::User);
        assert_eq!(u.rid, 1001);
        assert!(u.enabled);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup_by_name("nobody").is_none());
    }
}