//! Security Token
//
//! A TOKEN is attached to every process and thread. It carries
//! the security identity of the subject: the user SID, group SIDs,
//! privileges, and default DACL.
//
//! Token types:
//!   TokenPrimary    — attached to a process, used for all actions
//!   TokenImpersonation — attached to a thread, used to impersonate
//
//! Token groups contain:
//!   SID
//!   Attributes (SE_GROUP_ENABLED, SE_GROUP_LOGON_ID, ...)
//
//! Token privileges contain:
//!   LUID (Locally Unique ID)
//!   Attributes (SE_PRIVILEGE_ENABLED, ...)
//
//! References: Windows SDK winnt.h, WRK secobj.c

// Security subsystem uses NT naming (`TokenUser`, `SID_*`,
// `SE_GROUP_ENABLED`, etc.). These names ARE the kernel
// security ABI and cannot be renamed.
#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use super::sid::{Sid, WellKnownSid, SID_USERS, SID_INTERACTIVE};

/// Token information class values.
pub const TokenUser: u32 = 1;
pub const TokenGroups: u32 = 2;
pub const TokenPrivileges: u32 = 3;
pub const TokenOwner: u32 = 4;
pub const TokenPrimaryGroup: u32 = 5;
pub const TokenDefaultDacl: u32 = 6;
pub const TokenSource: u32 = 7;
pub const TokenType: u32 = 8;
pub const TokenImpersonationLevel: u32 = 9;
pub const TokenStatistics: u32 = 10;
pub const TokenRestrictedSids: u32 = 11;
pub const TokenSessionId: u32 = 12;
pub const TokenGroupsAndPrivileges: u32 = 13;
pub const TokenSessionReference: u32 = 14;
pub const TokenSandBoxInert: u32 = 15;
pub const TokenAuditPolicy: u32 = 16;
pub const TokenOrigin: u32 = 17;
pub const TokenElevationType: u32 = 18;
pub const TokenLinkedToken: u32 = 19;
pub const TokenElevation: u32 = 20;
pub const TokenHasRestrictions: u32 = 21;
pub const TokenAccessInformation: u32 = 22;
pub const TokenVirtualizationAllowed: u32 = 23;
pub const TokenVirtualizationEnabled: u32 = 24;
pub const TokenIntegrityLevel: u32 = 25;
pub const TokenUIAccess: u32 = 26;
pub const TokenMandatoryPolicy: u32 = 27;
pub const TokenLogonSid: u32 = 28;
pub const TOKEN_IS_APP_CONTAINER: u32 = 29;

/// Token types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenTypeEnum {
    TokenPrimary = 1,
    TokenImpersonation = 2,
}

impl Default for TokenTypeEnum {
    fn default() -> Self {
        Self::TokenPrimary
    }
}

/// Token group attributes.
pub const SE_GROUP_MANDATORY: u32 = 0x00000001;
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x00000002;
pub const SE_GROUP_ENABLED: u32 = 0x00000004;
pub const SE_GROUP_OWNER: u32 = 0x00000008;
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x00000010;
pub const SE_GROUP_INTEGRITY: u32 = 0x00000020;
pub const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x00000040;
pub const SE_GROUP_LOGON_ID: u32 = 0xC0000000;

/// Privilege attributes.
pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x00000001;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;
pub const SE_PRIVILEGE_REMOVED: u32 = 0x00000004;
pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x80000000;

/// LUID (Locally Unique ID) — a 64-bit identifier.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Luid {
    pub low_part: u32,
    pub high_part: i32,
}

impl Default for Luid {
    fn default() -> Self {
        Self { low_part: 0, high_part: 0 }
    }
}

impl Luid {
    pub const fn new() -> Self {
        Self { low_part: 0, high_part: 0 }
    }

    pub const fn from_u64(v: u64) -> Self {
        Self {
            low_part: (v & 0xFFFFFFFF) as u32,
            high_part: (v >> 32) as i32,
        }
    }

    pub fn to_u64(&self) -> u64 {
        ((self.high_part as u64) << 32) | (self.low_part as u64)
    }

    pub fn equals(&self, other: &Luid) -> bool {
        self.low_part == other.low_part && self.high_part == other.high_part
    }
}

impl core::fmt::Debug for Luid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Luid(0x{:08x}:{:08x})", self.high_part, self.low_part)
    }
}

/// Token group entry.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TokenGroup {
    pub sid: Sid,
    pub attributes: u32,
}

impl TokenGroup {
    pub fn new(sid: Sid, attributes: u32) -> Self {
        Self { sid, attributes }
    }

    pub fn is_enabled(&self) -> bool {
        (self.attributes & SE_GROUP_ENABLED) != 0
    }

    pub fn is_mandatory(&self) -> bool {
        (self.attributes & SE_GROUP_MANDATORY) != 0
    }

    pub fn is_logon_id(&self) -> bool {
        (self.attributes & SE_GROUP_LOGON_ID) != 0
    }
}

/// Token privilege entry.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TokenPrivilege {
    pub luid: Luid,
    pub attributes: u32,
}

impl TokenPrivilege {
    pub fn new(luid: Luid, attributes: u32) -> Self {
        Self { luid, attributes }
    }

    pub fn is_enabled(&self) -> bool {
        (self.attributes & SE_PRIVILEGE_ENABLED) != 0
    }

    pub fn enable(&mut self) {
        self.attributes |= SE_PRIVILEGE_ENABLED;
    }
}

/// Maximum groups per token.
pub const TOKEN_MAX_GROUPS: usize = 16;
/// Maximum privileges per token.
pub const TOKEN_MAX_PRIVILEGES: usize = 16;

/// Token flags.
pub const TOKEN_HAS_TRAVERSE_PRIVILEGE: u32 = 0x0001;
pub const TOKEN_HAS_BACKUP_PRIVILEGE: u32 = 0x0002;
pub const TOKEN_HAS_RESTORE_PRIVILEGE: u32 = 0x0004;
pub const TOKEN_WRITE_RESTRICTED: u32 = 0x0008;
pub const TOKEN_HAS_IMPERSONATE_PRIVILEGE: u32 = 0x0010;

/// Integrity level values.
pub const SECURITY_MANDATORY_UNTRUSTED_RID: u32 = 0x0000;
pub const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;
pub const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;
pub const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;
pub const SECURITY_MANDATORY_SYSTEM_RID: u32 = 0x4000;
pub const SECURITY_MANDATORY_PROTECTED_PROCESS_RID: u32 = 0x5000;

/// TOKEN_INFORMATION_CLASS: TokenIntegrityLevel
#[repr(C)]
pub struct TokenIntegrityLevel {
    pub label: Sid,
    pub sub_auth_count: u32,
}

/// SECURITY_MANDATORY_LABEL_RID (in sub_auth[0] of a SID).
pub const SECURITY_MANDATORY_UNTRUSTED: u32 = 0x0000;
pub const SECURITY_MANDATORY_LOW: u32 = 0x1000;
pub const SECURITY_MANDATORY_MEDIUM: u32 = 0x2000;
pub const SECURITY_MANDATORY_HIGH: u32 = 0x3000;
pub const SECURITY_MANDATORY_SYSTEM: u32 = 0x4000;

/// TOKEN_SOURCE — identifies who created the token.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TokenSource {
    pub source_name: [u8; 8],
    pub source_identifier: Luid,
}

impl TokenSource {
    pub const fn from_name(name: &[u8; 8]) -> Self {
        Self {
            source_name: *name,
            source_identifier: Luid::new(),
        }
    }
}

/// SECURITY_IMPERSONATION_LEVEL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ImpersonationLevel {
    SecurityAnonymous = 0,
    SecurityIdentification = 1,
    SecurityImpersonation = 2,
    SecurityDelegation = 3,
}

impl Default for ImpersonationLevel {
    fn default() -> Self {
        Self::SecurityIdentification
    }
}

/// TOKEN_CONTROL — unique identifier for a token.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TokenId {
    pub token_id: Luid,
    pub authentication_id: Luid,
    pub token_type: TokenTypeEnum,
    pub impersonation_level: ImpersonationLevel,
    pub modified_id: Luid,
}

/// A security token. This is the core security object attached
/// to processes and threads.
#[repr(C)]
pub struct Token {
    /// Token ID
    pub token_id: Luid,
    /// Authentication ID (logon session)
    pub authentication_id: Luid,
    /// User SID
    pub user: Sid,
    /// Primary group SID
    pub primary_group: Sid,
    /// Default DACL
    pub default_dacl: *mut super::acl::Acl,
    /// Session ID
    pub session_id: u32,
    /// Token flags
    pub flags: u32,
    /// Integrity level RID
    pub integrity_level_rid: u32,
    /// Token type
    pub token_type: TokenTypeEnum,
    /// Impersonation level (for impersonation tokens)
    pub impersonation_level: ImpersonationLevel,
    /// Groups
    pub groups: [TokenGroup; TOKEN_MAX_GROUPS],
    /// Number of groups
    pub group_count: usize,
    /// Privileges
    pub privileges: [TokenPrivilege; TOKEN_MAX_PRIVILEGES],
    /// Number of privileges
    pub privilege_count: usize,
    /// Token reference count (for reference counting)
    pub refcount: u32,
    _padding: [u8; 4],
}

impl Token {
    /// Create a new primary token for a user.
    pub fn new_primary(user_sid: Sid) -> Self {
        let mut t = Self::new();
        t.token_id = Luid::new();
        t.authentication_id = Luid::new();
        t.user = user_sid;
        t.primary_group = SID_USERS;
        t.token_type = TokenTypeEnum::TokenPrimary;
        t.default_dacl = core::ptr::null_mut();
        t.session_id = 0;
        t.flags = 0;
        t.integrity_level_rid = SECURITY_MANDATORY_MEDIUM;
        t.impersonation_level = ImpersonationLevel::SecurityImpersonation;
        t.refcount = 1;
        t
    }

    /// Create a new impersonation token.
    pub fn new_impersonation(user_sid: Sid, level: ImpersonationLevel) -> Self {
        let mut t = Self::new();
        t.token_id = Luid::new();
        t.authentication_id = Luid::new();
        t.user = user_sid;
        t.primary_group = SID_USERS;
        t.token_type = TokenTypeEnum::TokenImpersonation;
        t.impersonation_level = level;
        t.default_dacl = core::ptr::null_mut();
        t.refcount = 1;
        t
    }

    pub fn new() -> Self {
        Self {
            token_id: Luid::new(),
            authentication_id: Luid::new(),
            user: Sid::well_known(WellKnownSid::Null),
            primary_group: Sid::well_known(WellKnownSid::Null),
            default_dacl: core::ptr::null_mut(),
            session_id: 0,
            flags: 0,
            integrity_level_rid: SECURITY_MANDATORY_MEDIUM,
            token_type: TokenTypeEnum::TokenPrimary,
            impersonation_level: ImpersonationLevel::SecurityImpersonation,
            groups: [TokenGroup {
                sid: Sid {
                    revision: 1,
                    sub_authority_count: 0,
                    identifier_authority: [0; 6],
                    sub_authority: [0; 8],
                },
                attributes: 0,
            }; TOKEN_MAX_GROUPS],
            group_count: 0,
            privileges: [TokenPrivilege { luid: Luid::new(), attributes: 0 }; TOKEN_MAX_PRIVILEGES],
            privilege_count: 0,
            refcount: 0,
            _padding: [0; 4],
        }
    }

    /// Add a group to the token.
    pub fn add_group(&mut self, group: TokenGroup) {
        if self.group_count < TOKEN_MAX_GROUPS {
            self.groups[self.group_count] = group;
            self.group_count += 1;
        }
    }

    /// Add a privilege to the token.
    pub fn add_privilege(&mut self, privilege: TokenPrivilege) {
        if self.privilege_count < TOKEN_MAX_PRIVILEGES {
            self.privileges[self.privilege_count] = privilege;
            self.privilege_count += 1;
        }
    }

    /// Check if the token has a specific privilege enabled.
    pub fn has_privilege(&self, luid: &Luid) -> bool {
        for i in 0..self.privilege_count {
            if self.privileges[i].luid.equals(luid) && self.privileges[i].is_enabled() {
                return true;
            }
        }
        false
    }

    /// Check if the token belongs to the administrators group.
    pub fn is_admin(&self) -> bool {
        self.user.equals(&Sid::well_known(WellKnownSid::LocalSystem))
            || self.user.equals(&Sid::well_known(WellKnownSid::Administrators))
    }

    /// Check if the token belongs to the LocalSystem account.
    pub fn is_local_system(&self) -> bool {
        self.user.equals(&Sid::well_known(WellKnownSid::LocalSystem))
    }

    /// Reference counting.
    pub fn add_ref(&mut self) {
        self.refcount += 1;
    }

    pub fn release(&mut self) -> u32 {
        if self.refcount > 0 {
            self.refcount -= 1;
        }
        self.refcount
    }
}

/// Well-known privilege LUIDs.
pub mod privileges {
    use super::Luid;

    /// SeCreateTokenPrivilege
    pub const SE_CREATE_TOKEN_PRIVILEGE: Luid = Luid { low_part: 0x00000002, high_part: 0 };
    /// SeAssignPrimaryTokenPrivilege
    pub const SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE: Luid = Luid { low_part: 0x00000003, high_part: 0 };
    /// SeLockMemoryPrivilege
    pub const SE_LOCK_MEMORY_PRIVILEGE: Luid = Luid { low_part: 0x00000004, high_part: 0 };
    /// SeIncreaseQuotaPrivilege
    pub const SE_INCREASE_QUOTA_PRIVILEGE: Luid = Luid { low_part: 0x00000005, high_part: 0 };
    /// SeMachineAccountPrivilege
    pub const SE_MACHINE_ACCOUNT_PRIVILEGE: Luid = Luid { low_part: 0x00000006, high_part: 0 };
    /// SeTcbPrivilege
    pub const SE_TCB_PRIVILEGE: Luid = Luid { low_part: 0x00000007, high_part: 0 };
    /// SeSecurityPrivilege
    pub const SE_SECURITY_PRIVILEGE: Luid = Luid { low_part: 0x00000008, high_part: 0 };
    /// SeTakeOwnershipPrivilege
    pub const SE_TAKE_OWNERSHIP_PRIVILEGE: Luid = Luid { low_part: 0x00000009, high_part: 0 };
    /// SeLoadDriverPrivilege
    pub const SE_LOAD_DRIVER_PRIVILEGE: Luid = Luid { low_part: 0x0000000A, high_part: 0 };
    /// SeSystemProfilePrivilege
    pub const SE_SYSTEM_PROFILE_PRIVILEGE: Luid = Luid { low_part: 0x0000000B, high_part: 0 };
    /// SeSystemtimePrivilege
    pub const SE_SYSTEMTIME_PRIVILEGE: Luid = Luid { low_part: 0x0000000C, high_part: 0 };
    /// SeProfileSingleProcessPrivilege
    pub const SE_PROFILE_SINGLE_PROCESS_PRIVILEGE: Luid = Luid { low_part: 0x0000000D, high_part: 0 };
    /// SeIncreaseBasePriorityPrivilege
    pub const SE_INCREASE_BASE_PRIORITY_PRIVILEGE: Luid = Luid { low_part: 0x0000000E, high_part: 0 };
    /// SeCreatePagefilePrivilege
    pub const SE_CREATE_PAGEFILE_PRIVILEGE: Luid = Luid { low_part: 0x0000000F, high_part: 0 };
    /// SeCreatePermanentPrivilege
    pub const SE_CREATE_PERMANENT_PRIVILEGE: Luid = Luid { low_part: 0x00000010, high_part: 0 };
    /// SeBackupPrivilege
    pub const SE_BACKUP_PRIVILEGE: Luid = Luid { low_part: 0x00000011, high_part: 0 };
    /// SeRestorePrivilege
    pub const SE_RESTORE_PRIVILEGE: Luid = Luid { low_part: 0x00000012, high_part: 0 };
    /// SeShutdownPrivilege
    pub const SE_SHUTDOWN_PRIVILEGE: Luid = Luid { low_part: 0x00000013, high_part: 0 };
    /// SeDebugPrivilege
    pub const SE_DEBUG_PRIVILEGE: Luid = Luid { low_part: 0x00000014, high_part: 0 };
    /// SeAuditPrivilege
    pub const SE_AUDIT_PRIVILEGE: Luid = Luid { low_part: 0x00000015, high_part: 0 };
    /// SeSystemEnvironmentPrivilege
    pub const SE_SYSTEM_ENVIRONMENT_PRIVILEGE: Luid = Luid { low_part: 0x00000016, high_part: 0 };
    /// SeChangeNotifyPrivilege
    pub const SE_CHANGE_NOTIFY_PRIVILEGE: Luid = Luid { low_part: 0x00000017, high_part: 0 };
    /// SeRemoteShutdownPrivilege
    pub const SE_REMOTE_SHUTDOWN_PRIVILEGE: Luid = Luid { low_part: 0x00000018, high_part: 0 };
    /// SeUndockPrivilege
    pub const SE_UNDOCK_PRIVILEGE: Luid = Luid { low_part: 0x00000019, high_part: 0 };
    /// SeSyncAgentPrivilege
    pub const SE_SYNC_AGENT_PRIVILEGE: Luid = Luid { low_part: 0x0000001A, high_part: 0 };
    /// SeEnableDelegationPrivilege
    pub const SE_ENABLE_DELEGATION_PRIVILEGE: Luid = Luid { low_part: 0x0000001B, high_part: 0 };
    /// SeManageVolumePrivilege
    pub const SE_MANAGE_VOLUME_PRIVILEGE: Luid = Luid { low_part: 0x0000001C, high_part: 0 };
    /// SeImpersonatePrivilege
    pub const SE_IMPERSONATE_PRIVILEGE: Luid = Luid { low_part: 0x0000001D, high_part: 0 };
    /// SeCreateGlobalPrivilege
    pub const SE_CREATE_GLOBAL_PRIVILEGE: Luid = Luid { low_part: 0x0000001E, high_part: 0 };
    /// SeTrustedCredManAccessPrivilege
    pub const SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE: Luid = Luid { low_part: 0x0000001F, high_part: 0 };
    /// SeRelabelPrivilege
    pub const SE_RELABEL_PRIVILEGE: Luid = Luid { low_part: 0x00000020, high_part: 0 };
    /// SeTimeZonePrivilege
    pub const SE_TIME_ZONE_PRIVILEGE: Luid = Luid { low_part: 0x00000021, high_part: 0 };
    /// SeCreateSymbolicLinkPrivilege
    pub const SE_CREATE_SYMBOLIC_LINK_PRIVILEGE: Luid = Luid { low_part: 0x00000022, high_part: 0 };
}

pub fn init() {
    // crate::kprintln!("    SE/TOKEN: initialized (Token, Group, Privilege, LUID, well-known SIDs)")  // kprintln disabled (memcpy crash workaround);
}

/// Create a system token for kernel processes.
/// Returns a pointer to the allocated token.
pub fn create_system_token() -> *mut Token {
    use super::sid::Sid;
    use super::sid::WellKnownSid;

    let token = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Token>(),
    ) as *mut Token;

    if !token.is_null() {
        unsafe {
            core::ptr::write_bytes(token as *mut u8, 0, core::mem::size_of::<Token>());
            // System tokens have LocalSystem SID
            let system_sid = Sid::well_known(WellKnownSid::LocalSystem);
            (*token) = Token::new_primary(system_sid);
        }
        // crate::kprintln!("[SEC] Created system token at 0x{:016x}", token as u64)  // kprintln disabled (memcpy crash workaround);
    }
    token
}

/// Create a user token for user-mode processes.
/// Returns a pointer to the allocated token.
pub fn create_user_token(user_sid: Sid) -> *mut Token {
    let token = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Token>(),
    ) as *mut Token;

    if !token.is_null() {
        unsafe {
            core::ptr::write_bytes(token as *mut u8, 0, core::mem::size_of::<Token>());
            (*token) = Token::new_primary(user_sid);
        }
        // crate::kprintln!("[SEC] Created user token at 0x{:016x}", token as u64)  // kprintln disabled (memcpy crash workaround);
    }
    token
}
