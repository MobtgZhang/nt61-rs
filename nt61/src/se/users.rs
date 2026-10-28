//! Built-in user database (SAM).
//!
//! A minimal Security Account Manager (SAM). Built-in accounts are an
//! immutable boot baseline. Runtime accounts are kept under a spinlock and
//! store salted password hashes. The production persistence backend is the
//! `SAM\Domains\Account\Users\<RID>` registry hive; this module provides the
//! allocation and verification semantics used by that backend.
//!
//!   SYSTEM              — S-1-5-18
//!   Administrators      — S-1-5-32-544
//!   nt61test            — S-1-5-21-0-0-0-1001
//!
//! Lookup is linear in the table (≤ a handful of entries), which is
//! fine for kernel boot-time decisions.
//!
//! Authorization decisions (token creation, privilege set, etc.)
//! continue to live in `se::token`. This module is purely the
//! "who exists" lookup.

use super::sid::{sid, WellKnownSid};
use crate::crypto::csprng;
use crate::crypto::hash::sha256;
use crate::ke::sync::Spinlock;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

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
    pub sid: sid,
    pub kind: AccountKind,
    /// Whether the account is currently enabled. OpenSSH skips
    /// disabled accounts at logon.
    pub enabled: bool,
}

/// Runtime-only credentials for a dynamically created account.
struct UserRecord {
    name: String,
    entry: AccountEntry,
    salt: [u8; 16],
    password_hash: [u8; 32],
}

const SYSTEM: AccountEntry = AccountEntry {
    rid: 18,
    sid: sid::well_known(WellKnownSid::LocalSystem),
    kind: AccountKind::System,
    enabled: true,
};

const ADMINS: AccountEntry = AccountEntry {
    rid: 544,
    sid: sid::well_known(WellKnownSid::Administrators),
    kind: AccountKind::Administrators,
    enabled: true,
};

const GUESTS: AccountEntry = AccountEntry {
    rid: 546,
    sid: sid::well_known(WellKnownSid::Guests),
    kind: AccountKind::Guest,
    enabled: false,
};

const NT61TEST: AccountEntry = AccountEntry {
    rid: 1001,
    sid: sid::with_2subs([0, 0, 0, 0, 0, 5], 21, 1001),
    kind: AccountKind::User,
    enabled: true,
};

const BUILTIN: &[AccountEntry] = &[SYSTEM, ADMINS, GUESTS, NT61TEST];

/// Runtime-created accounts. `Vec` is intentionally small and bounded by the
/// caller; a real registry-backed SAM can replace this storage later.
static RUNTIME_ACCOUNTS: Spinlock<Vec<UserRecord>> = Spinlock::new(Vec::new());
static NEXT_DYNAMIC_RID: AtomicU32 = AtomicU32::new(0x1002);

const MAX_NAME_LENGTH: usize = 64;

/// Errors returned when creating a runtime account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateUserError {
    NameTooLong,
    EmptyName,
    DuplicateName,
    RidExhausted,
    OutOfMemory,
}

fn password_hash(password: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut salted = alloc::vec::Vec::with_capacity(salt.len() + password.len());
    salted.extend_from_slice(salt);
    salted.extend_from_slice(password);
    sha256(&salted)
}

/// Look up an account by SID.
pub fn lookup_by_sid(sid: &sid) -> Option<AccountEntry> {
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
        let n = builtin_name(a);
        if normalized.eq_ignore_ascii_case(n) {
            return Some(*a);
        }
    }
    let normalized = normalized.to_ascii_lowercase();
    RUNTIME_ACCOUNTS
        .lock()
        .iter()
        .find(|record| record.name.as_str().eq_ignore_ascii_case(&normalized))
        .map(|record| record.entry)
}

fn builtin_name(entry: &AccountEntry) -> &'static str {
    match entry.kind {
        AccountKind::System => "SYSTEM",
        AccountKind::Administrators => "Administrators",
        AccountKind::User => "nt61test",
        AccountKind::Guest => "Guest",
    }
}

/// Return an iterator over the account table. Used by
/// `NetUserEnum` and similar enumeration APIs.
pub fn all_accounts() -> &'static [AccountEntry] {
    BUILTIN
}

pub fn init() {
    RUNTIME_ACCOUNTS.lock().clear();
}

/// Create a runtime account with a salted password hash and a fresh RID.
pub fn create_user(
    name: &str,
    password: &[u8],
    enabled: bool,
) -> Result<AccountEntry, CreateUserError> {
    let name = name.trim().trim_end_matches('\0');
    if name.is_empty() {
        return Err(CreateUserError::EmptyName);
    }
    if name.len() > MAX_NAME_LENGTH {
        return Err(CreateUserError::NameTooLong);
    }

    let mut accounts = RUNTIME_ACCOUNTS.lock();
    if accounts
        .iter()
        .any(|record| record.name.as_str().eq_ignore_ascii_case(name))
        || BUILTIN
            .iter()
            .any(|entry| builtin_name(entry).eq_ignore_ascii_case(name))
    {
        return Err(CreateUserError::DuplicateName);
    }

    let rid = loop {
        let current = NEXT_DYNAMIC_RID.load(Ordering::SeqCst);
        let next = current.checked_add(1).ok_or(CreateUserError::RidExhausted)?;
        if NEXT_DYNAMIC_RID
            .compare_exchange_weak(current, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            break current;
        }
    };

    let mut salt = [0u8; 16];
    if !csprng::fill(&mut salt) {
        return Err(CreateUserError::OutOfMemory);
    }
    let entry = AccountEntry {
        rid,
        sid: sid::with_2subs([0, 0, 0, 0, 0, 5], 21, rid),
        kind: AccountKind::User,
        enabled,
    };
    accounts.push(UserRecord {
        name: String::from(name),
        entry,
        salt,
        password_hash: password_hash(password, &salt),
    });
    Ok(entry)
}

/// Verify a runtime account password. Unknown accounts always fail.
pub fn verify_runtime_password(name: &str, password: &[u8]) -> bool {
    let normalized = name.trim().trim_end_matches('\0').to_ascii_lowercase();
    let accounts = RUNTIME_ACCOUNTS.lock();
    accounts
        .iter()
        .find(|record| record.name.as_str().eq_ignore_ascii_case(&normalized))
        .map(|record| {
            constant_time_eq(
                &record.password_hash,
                &password_hash(password, &record.salt),
            )
        })
        .unwrap_or(false)
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
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
        let sid = sid::well_known(WellKnownSid::LocalSystem);
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

    #[test]
    fn creates_and_verifies_runtime_user() {
        init();
        let account = create_user("runtime-user", b"secret", true).unwrap();
        assert_eq!(account.rid, 0x1002);
        assert_eq!(account.kind, AccountKind::User);
        assert!(lookup_by_name("RUNTIME-USER").is_some());
        assert!(verify_runtime_password("runtime-user", b"secret"));
        assert!(!verify_runtime_password("runtime-user", b"wrong"));
        assert!(create_user("Runtime-User", b"secret", true)
            .is_err());
    }
}
