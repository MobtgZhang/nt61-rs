//! Logon primitives for OpenSSH.
//!
//! Real NT logon is `LsaLogonUser` → MSV1_0 / Kerberos / NTLM
//! authentication package → primary token creation. For OpenSSH
//! pubkey auth we only need:
//!
//!   - `logon_user(name)` → primary token (with appropriate groups
//!     and privileges, default DACL set to user-only).
//!   - `create_impersonation_token(primary, level)` → for
//!     `ImpersonateLoggedOnUser` semantics.
//!
//! All tokens returned here are kernel-pool allocated; the
//! caller is responsible for `release()`-ing them.

use super::sid::Sid;
use super::token::{Token, TokenGroup, TokenPrivilege, TokenTypeEnum, ImpersonationLevel,
                   SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT,
                   SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED,
                   TOKEN_HAS_IMPERSONATE_PRIVILEGE,
                   privileges as priv_luids};
use super::users;

/// Look up an account and create a primary token for it.
///
/// Returns `None` if the account doesn't exist or is disabled.
pub fn logon_user(name: &str) -> Option<*mut Token> {
    let account = users::lookup_by_name(name)?;
    if !account.enabled {
        return None;
    }
    let mut token = Token::new_primary(account.sid);
    // Add the standard user groups (Everyone, Users).
    token.add_group(TokenGroup {
        sid: super::sid::SID_EVERYONE,
        attributes: SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT,
    });
    token.add_group(TokenGroup {
        sid: super::sid::SID_USERS,
        attributes: SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT,
    });
    // Administrators group if this is an admin account.
    if account.kind == users::AccountKind::Administrators {
        token.add_group(TokenGroup {
            sid: super::sid::SID_ADMINISTRATORS,
            attributes: SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT,
        });
    }
    // Bare-minimum privilege set: backup/restore are useful for
    // sshd key generation; change-notify is needed for the SCM
    // registration and file watcher machinery.
    token.add_privilege(TokenPrivilege {
        luid: priv_luids::SE_CHANGE_NOTIFY_PRIVILEGE,
        attributes: SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED,
    });
    if account.kind == users::AccountKind::Administrators
        || account.kind == users::AccountKind::System
    {
        token.add_privilege(TokenPrivilege {
            luid: priv_luids::SE_BACKUP_PRIVILEGE,
            attributes: SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED,
        });
        token.add_privilege(TokenPrivilege {
            luid: priv_luids::SE_RESTORE_PRIVILEGE,
            attributes: SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED,
        });
        token.add_privilege(TokenPrivilege {
            luid: priv_luids::SE_IMPERSONATE_PRIVILEGE,
            attributes: SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED,
        });
        token.flags |= TOKEN_HAS_IMPERSONATE_PRIVILEGE;
    }
    Some(crate::se::token::persist_token(&token))
}

/// Build an impersonation token from a primary token. Used by
/// `ImpersonateLoggedOnUser` / `SetThreadToken` paths.
pub fn create_impersonation(
    primary_user_sid: Sid,
    level: ImpersonationLevel,
) -> Token {
    let mut t = Token::new_impersonation(primary_user_sid, level);
    t.add_group(TokenGroup {
        sid: super::sid::SID_EVERYONE,
        attributes: SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT,
    });
    t
}

/// Convert a SID back to the user name (inverse of logon_user).
/// Returns `None` for SIDs we don't know.
pub fn name_for_sid(sid: &Sid) -> Option<&'static str> {
    let account = users::lookup_by_sid(sid)?;
    Some(match account.kind {
        users::AccountKind::System => "SYSTEM",
        users::AccountKind::Administrators => "Administrators",
        users::AccountKind::User => "nt61test",
        users::AccountKind::Guest => "Guest",
    })
}

/// Token type as exposed to user-mode callers (e.g. via
/// `NtQueryInformationToken(TokenType)`).
pub fn token_kind(t: &Token) -> TokenTypeEnum {
    t.token_type
}

pub fn init() {
    // crate::kprintln!("    SE/LOGON: initialized (logon_user / impersonation / name_for_sid)")  // kprintln disabled (memcpy crash workaround);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::se::sid::WellKnownSid;

    #[test]
    fn logon_system_succeeds() {
        let token = logon_user("SYSTEM");
        assert!(token.is_some());
    }

    #[test]
    fn logon_nt61test_succeeds() {
        let token = logon_user("nt61test");
        assert!(token.is_some());
    }

    #[test]
    fn logon_unknown_fails() {
        let token = logon_user("definitely_no_such_user");
        assert!(token.is_none());
    }

    #[test]
    fn name_for_sid_round_trip() {
        let sid = Sid::well_known(WellKnownSid::LocalSystem);
        assert_eq!(name_for_sid(&sid), Some("SYSTEM"));
    }

    #[test]
    fn impersonation_token_has_correct_level() {
        let sid = Sid::well_known(WellKnownSid::LocalSystem);
        let t = create_impersonation(sid, ImpersonationLevel::SecurityDelegation);
        assert_eq!(t.token_type, TokenTypeEnum::TokenImpersonation);
        assert_eq!(t.impersonation_level, ImpersonationLevel::SecurityDelegation);
    }
}