//! SeAccessCheck — core access validation
//
//! The SeAccessCheck function determines whether a subject
//! (identified by a token) should be granted access to a securable
//! object (identified by a security descriptor).
//
//! Algorithm:
//!   1. If the token is LocalSystem or has SeTakeOwnershipPrivilege,
//!      grant WRITE_OWNER access (needed to change security on an object).
//!   2. Walk the DACL in order:
//!      a. ACCESS_DENIED_ACE matching subject -> DENY immediately
//!      b. ACCESS_ALLOWED_ACE matching subject -> grant those bits
//!   3. If any requested access bits are still denied -> ACCESS_DENIED
//!   4. If token has SeSecurityPrivilege and requested SECURITY,
//!      grant it.
//!   5. Mandatory access: check integrity level (no write-up rule).
//
//! References: Windows SDK, WRK secobj.c, ReactOS

use super::sid::Sid;
use super::acl::{Acl, AceFlags, AceType};
use super::token::{Token, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY};

/// Maximum number of SIDs in an access check.
pub const MAX_SIDS: usize = 16;

/// Well-known privilege LUIDs for SeAccessCheck overrides
pub mod privileges {
    /// SeTakeOwnershipPrivilege - allows taking ownership of objects
    pub const SE_TAKE_OWNERSHIP: i64 = 0x00000017;
    /// SeSecurityPrivilege - allows reading/writing security (AUDIT/ACCESS)
    pub const SE_SECURITY: i64 = 0x00000013;
    /// SeBackupPrivilege - allows reading files for backup
    pub const SE_BACKUP: i64 = 0x00000011;
    /// SeRestorePrivilege - allows writing files for restore
    pub const SE_RESTORE: i64 = 0x00000012;
    /// SeDebugPrivilege - allows debugging processes
    pub const SE_DEBUG: i64 = 0x00000014;
    /// SeCreatePagefilePrivilege - allows creating page files
    pub const SE_CREATE_PAGEFILE: i64 = 0x0000000E;
    /// SeSystemProfilePrivilege - allows profiling
    pub const SE_SYSTEM_PROFILE: i64 = 0x0000000C;
    /// SeAssignPrimaryTokenPrivilege - allows assigning primary tokens
    pub const SE_ASSIGN_PRIMARY_TOKEN: i64 = 0x0000000F;
}

/// Generic mapping for object types.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GenericMapping {
    pub generic_read: u32,
    pub generic_write: u32,
    pub generic_execute: u32,
    pub generic_all: u32,
}

impl GenericMapping {
    pub const fn new(read: u32, write: u32, execute: u32, all: u32) -> Self {
        Self {
            generic_read: read,
            generic_write: write,
            generic_execute: execute,
            generic_all: all,
        }
    }

    /// Map generic rights to object-specific rights.
    pub fn map_generic(&self, access: &mut u32) {
        if (*access & ACCESS_GENERIC_READ) != 0 {
            *access = (*access & !ACCESS_GENERIC_READ) | self.generic_read;
        }
        if (*access & ACCESS_GENERIC_WRITE) != 0 {
            *access = (*access & !ACCESS_GENERIC_WRITE) | self.generic_write;
        }
        if (*access & ACCESS_GENERIC_EXECUTE) != 0 {
            *access = (*access & !ACCESS_GENERIC_EXECUTE) | self.generic_execute;
        }
        if (*access & ACCESS_GENERIC_ALL) != 0 {
            *access = (*access & !ACCESS_GENERIC_ALL) | self.generic_all;
        }
    }
}

/// Generic access rights (common across object types).
pub const ACCESS_GENERIC_READ: u32 = 0x80000000;
pub const ACCESS_GENERIC_WRITE: u32 = 0x40000000;
pub const ACCESS_GENERIC_EXECUTE: u32 = 0x20000000;
pub const ACCESS_GENERIC_ALL: u32 = 0x10000000;
pub const ACCESS_MAXIMUM_ALLOWED: u32 = 0x02000000;
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x01000000;
pub const ACCESS_DELETE: u32 = 0x00010000;
pub const ACCESS_READ_CONTROL: u32 = 0x00020000;
pub const ACCESS_WRITE_DAC: u32 = 0x00040000;
pub const ACCESS_WRITE_OWNER: u32 = 0x00080000;
pub const ACCESS_SYNCHRONIZE: u32 = 0x00100000;
pub const ACCESS_STANDARD_RIGHTS_READ: u32 = ACCESS_READ_CONTROL;
pub const ACCESS_STANDARD_RIGHTS_WRITE: u32 = ACCESS_READ_CONTROL;
pub const ACCESS_STANDARD_RIGHTS_EXECUTE: u32 = ACCESS_READ_CONTROL;
pub const ACCESS_STANDARD_RIGHTS_ALL: u32 = ACCESS_DELETE | ACCESS_READ_CONTROL
    | ACCESS_WRITE_DAC | ACCESS_WRITE_OWNER | ACCESS_SYNCHRONIZE;

/// Process access rights.
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0010;
pub const PROCESS_VM_OPERATION: u32 = 0x0020;
pub const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;

/// Thread access rights.
pub const THREAD_QUERY_INFORMATION: u32 = 0x0400;
pub const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
pub const THREAD_GET_CONTEXT: u32 = 0x0008;
pub const THREAD_SET_CONTEXT: u32 = 0x0010;
pub const THREAD_SET_INFORMATION: u32 = 0x0020;
pub const THREAD_ALL_ACCESS: u32 = 0x1F03FF;

/// Directory access rights.
pub const DIRECTORY_QUERY: u32 = 0x0001;
pub const DIRECTORY_TRAVERSE: u32 = 0x0002;
pub const DIRECTORY_CREATE_SUBDIRECTORY: u32 = 0x0004;
pub const DIRECTORY_ADD_FILE: u32 = 0x0001;
pub const DIRECTORY_ALL_ACCESS: u32 = 0x000F;

/// Event access rights.
pub const EVENT_QUERY_STATE: u32 = 0x0001;
pub const EVENT_MODIFY_STATE: u32 = 0x0002;
pub const EVENT_ALL_ACCESS: u32 = 0x001F;

/// Semaphore access rights.
pub const SEMAPHORE_QUERY_STATE: u32 = 0x0001;
pub const SEMAPHORE_MODIFY_STATE: u32 = 0x0002;
pub const SEMAPHORE_ALL_ACCESS: u32 = 0x001F;

/// Mutant (mutex) access rights.
pub const MUTANT_QUERY_STATE: u32 = 0x0001;
pub const MUTANT_ALL_ACCESS: u32 = 0x001F;

/// Section access rights.
pub const SECTION_MAP_READ: u32 = 0x0004;
pub const SECTION_MAP_WRITE: u32 = 0x0002;
pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
pub const SECTION_QUERY: u32 = 0x0001;
pub const SECTION_ALL_ACCESS: u32 = 0x000F;

/// Token access rights.
pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
pub const TOKEN_ALL_ACCESS: u32 = 0x00F07FF;

/// NTSTATUS codes for access check.
pub const STATUS_ACCESS_DENIED: u32 = 0xC0000022;
pub const STATUS_ACCESS_ALLOWED: u32 = 0x00000000;
pub const STATUS_MUST_BE_DISABLED: u32 = 0xC0000350;

/// Result of SeAccessCheck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCheckResult {
    Allowed,
    Denied,
}

/// Check if a SID matches a subject (token).
/// A SID matches if it equals any of the token's group SIDs
/// or the token's user SID.
fn sid_matches_token(sid: &Sid, token: &Token) -> bool {
    // Check user
    if sid.equals(&token.user) {
        return true;
    }
    // Check groups
    for i in 0..token.group_count {
        let g = &token.groups[i];
        // Skip groups that are "deny only"
        if (g.attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0 {
            continue;
        }
        if sid.equals(&g.sid) {
            return true;
        }
    }
    false
}

/// Check if a SID is present in the token (used for access check).
fn sid_in_token(sid: &Sid, token: &Token) -> bool {
    // Check user
    if sid.equals(&token.user) {
        return true;
    }
    // Check all groups (including deny-only)
    for i in 0..token.group_count {
        if sid.equals(&token.groups[i].sid) {
            return true;
        }
    }
    false
}

/// Perform an access check: does the subject (token) have the requested
/// access rights to the object (described by a security descriptor)?
///
/// Arguments:
///   desired_access — requested access rights (bitmask)
///   token — the subject's security token
///   owner — the object's owner SID
///   dacl — the object's DACL (can be null for NULL DACL = allow all)
///   generic_mapping — maps generic rights to object-specific rights
///   privilege_used — out parameter: set to true if a privilege was used
///
/// Returns: AccessCheckResult::Allowed or AccessCheckResult::Denied
pub fn check_access(
    mut desired_access: u32,
    token: &Token,
    _owner: &Sid,
    dacl: *const Acl,
    generic_mapping: Option<&GenericMapping>,
) -> AccessCheckResult {
    // Map generic rights
    if let Some(gm) = generic_mapping {
        gm.map_generic(&mut desired_access);
    }

    // NULL DACL means full access
    if dacl.is_null() {
        return AccessCheckResult::Allowed;
    }

    // ============================================================
    // PRIVILEGE OVERRIDES (before DACL check)
    // ============================================================

    // SeTakeOwnershipPrivilege override: grant WRITE_OWNER if privilege is enabled
    if (desired_access & ACCESS_WRITE_OWNER) != 0 {
        let take_ownership_luid = super::token::Luid {
            low_part: privileges::SE_TAKE_OWNERSHIP as u32,
            high_part: 0,
        };
        if token.has_privilege(&take_ownership_luid) {
            // crate::kprintln!("[SE] SeAccessCheck: SeTakeOwnershipPrivilege override granted")  // kprintln disabled (memcpy crash workaround);
            return AccessCheckResult::Allowed;
        }
    }

    // SeSecurityPrivilege override: grant ACCESS_SYSTEM_SECURITY if privilege is enabled
    if (desired_access & ACCESS_SYSTEM_SECURITY) != 0 {
        let security_luid = super::token::Luid {
            low_part: privileges::SE_SECURITY as u32,
            high_part: 0,
        };
        if token.has_privilege(&security_luid) {
            // crate::kprintln!("[SE] SeAccessCheck: SeSecurityPrivilege override granted")  // kprintln disabled (memcpy crash workaround);
            return AccessCheckResult::Allowed;
        }
    }

    // SeBackupPrivilege override: grant READ_CONTROL | FILE_READ_DATA if enabled
    if (desired_access & ACCESS_READ_CONTROL) != 0 {
        let backup_luid = super::token::Luid {
            low_part: privileges::SE_BACKUP as u32,
            high_part: 0,
        };
        if token.has_privilege(&backup_luid) {
            // crate::kprintln!("[SE] SeAccessCheck: SeBackupPrivilege override granted")  // kprintln disabled (memcpy crash workaround);
            return AccessCheckResult::Allowed;
        }
    }

    // SeRestorePrivilege override: grant WRITE_DAC | FILE_WRITE_DATA if enabled
    if (desired_access & ACCESS_WRITE_DAC) != 0 {
        let restore_luid = super::token::Luid {
            low_part: privileges::SE_RESTORE as u32,
            high_part: 0,
        };
        if token.has_privilege(&restore_luid) {
            // crate::kprintln!("[SE] SeAccessCheck: SeRestorePrivilege override granted")  // kprintln disabled (memcpy crash workaround);
            return AccessCheckResult::Allowed;
        }
    }

    // SeDebugPrivilege override: grant specific access for debugging
    // Windows behavior: SeDebugPrivilege only allows specific debug-related access rights,
    // not all access. Additionally, it should only work for administrators.
    //
    // The allowed access includes:
    // - PROCESS_ALL_ACCESS (0x1F0FFF)
    // - PROCESS_QUERY_INFORMATION (0x0400)
    // - PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
    // - PROCESS_VM_READ (0x0010)
    // - PROCESS_VM_WRITE (0x0010)
    // - PROCESS_VM_OPERATION (0x0020)
    // - PROCESS_DUP_HANDLE (0x0040)
    // - PROCESS_CREATE_THREAD (0x0002)
    const SE_DEBUG_ALLOWED_ACCESS: u32 =
        PROCESS_ALL_ACCESS |
        PROCESS_QUERY_INFORMATION |
        PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_DUP_HANDLE |
        PROCESS_CREATE_THREAD;

    if (desired_access & SE_DEBUG_ALLOWED_ACCESS) != 0 {
        let debug_luid = super::token::Luid {
            low_part: privileges::SE_DEBUG as u32,
            high_part: 0,
        };
        // Only grant if privilege is enabled AND token is admin or LocalSystem
        if token.has_privilege(&debug_luid) && token.is_admin() {
            // crate::kprintln!("[SE] SeAccessCheck: SeDebugPrivilege override granted (admin)")  // kprintln disabled (memcpy crash workaround);
            return AccessCheckResult::Allowed;
        }
    }

    // ============================================================
    // DACL WALK
    // ============================================================

    let acl = unsafe { &*dacl };

    // Walk the DACL ACE by ACE
    let mut granted_access: u32 = 0;
    let mut denied_access: u32 = 0;

    let mut offset = 8usize; // Skip ACL header
    while offset + 4 <= acl.acl_size as usize {
        let ace_type = acl.data[offset];
        let _ace_flags = acl.data[offset + 1];
        let ace_size = acl.data[offset + 2] as usize
            | ((acl.data[offset + 3] as usize) << 8);

        if ace_size < 8 {
            break;
        }

        let ace_mask = u32::from_le_bytes([acl.data[offset + 4], acl.data[offset + 5], acl.data[offset + 6], acl.data[offset + 7]]);

        // Extract the SID from the ACE
        // ACE header (4) + mask (4) = 8, then SID
        let sid_offset = offset + 8;
        let sid_size = ace_size - 8;
        if sid_size >= 8 {
            // Read SID from the ACL data
            let sid = read_sid_from_acl(&acl.data, sid_offset);

            let ace_type = AceType::from_u8(ace_type);

            match ace_type {
                AceType::AccessDenied => {
                    // ACCESS_DENIED_ACE — denied bits apply regardless
                    // of enabled/disabled group status
                    if sid_in_token(&sid, token) {
                        denied_access |= ace_mask;
                    }
                }
                AceType::AccessAllowed => {
                    // ACCESS_ALLOWED_ACE — only grant if the SID
                    // matches an enabled group or the user
                    if sid_matches_token(&sid, token) {
                        granted_access |= ace_mask;
                    }
                }
                _ => {}
            }
        }

        offset += ace_size;
    }

    // Any requested access that was explicitly denied -> DENY
    if (desired_access & denied_access) != 0 {
        return AccessCheckResult::Denied;
    }

    // Granted access from ALLOWED ACEs
    let remaining = desired_access & !granted_access;

    // If anything remains ungranted, check MAXIMUM_ALLOWED
    if remaining == 0 {
        return AccessCheckResult::Allowed;
    }

    // For MAXIMUM_ALLOWED, check if we have any enabled group matching
    if (desired_access & ACCESS_MAXIMUM_ALLOWED) != 0 {
        return AccessCheckResult::Allowed;
    }

    // Check if the remaining access is just SYNCHRONIZE (often ignored)
    if remaining == ACCESS_SYNCHRONIZE || remaining == ACCESS_STANDARD_RIGHTS_READ {
        return AccessCheckResult::Allowed;
    }

    // Default: access denied
    AccessCheckResult::Denied
}

/// Read a SID from ACL data at the given offset.
fn read_sid_from_acl(data: &[u8; 512], offset: usize) -> Sid {
    // SID layout: revision(1) + subauth_count(1) + ia(6) + subauths(variable)
    if offset + 8 > data.len() {
        return Sid::well_known(super::sid::WellKnownSid::Null);
    }
    let _revision = data[offset];
    let subauth_count = data[offset + 1];
    let mut ia = [0u8; 6];
    ia[0] = data[offset + 2];
    ia[1] = data[offset + 3];
    ia[2] = data[offset + 4];
    ia[3] = data[offset + 5];
    ia[4] = data[offset + 6];
    ia[5] = data[offset + 7];

    let count = subauth_count as usize;
    let mut subs = [0u32; 8];
    for i in 0..count.min(8) {
        let off = offset + 8 + i * 4;
        if off + 4 <= data.len() {
            subs[i] = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        }
    }

    Sid::with_authority_and_subs_arr(ia, count as u8,
        subs[0], subs[1], subs[2], subs[3],
        subs[4], subs[5], subs[6], subs[7])
}

/// SePrivilegeCheck — check if a token has required privileges.
pub fn check_privilege(token: &Token, required_privilege: &super::token::Luid) -> bool {
    token.has_privilege(required_privilege)
}

/// SeSinglePrivilegeCheck — check a single privilege by LUID.
pub fn check_single_privilege(token: &Token, luid: &super::token::Luid) -> bool {
    token.has_privilege(luid)
}

/// Check write-up for mandatory integrity levels.
/// A lower-integrity process should not be able to write to a
/// higher-integrity object.
pub fn check_mandatory_write_up(
    subject_level: u32,
    object_level: u32,
    _desired_access: u32,
) -> bool {
    // The no-write-up policy: subject integrity must be >= object integrity
    subject_level >= object_level
}

/// Generic file mapping.
pub static FILE_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    ACCESS_STANDARD_RIGHTS_READ | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010, // FILE_READ_DATA etc.
    ACCESS_STANDARD_RIGHTS_WRITE | 0x0010 | 0x0020 | ACCESS_DELETE,
    ACCESS_STANDARD_RIGHTS_EXECUTE | 0x0020,
    ACCESS_DELETE | ACCESS_READ_CONTROL | ACCESS_WRITE_DAC | ACCESS_WRITE_OWNER | 0x01FF,
);

/// Generic registry mapping.
pub static REGISTRY_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x00020000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010, // KEY_READ etc.
    0x00020000 | 0x0002 | 0x0004 | 0x0010 | 0x0020,           // KEY_WRITE etc.
    0x00020000 | 0x0004 | 0x0008,                              // KEY_EXECUTE
    0xF003F,                                                    // KEY_ALL_ACCESS
);

/// Generic process mapping.
pub static PROCESS_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,     // Generic read
    PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE, // Generic write
    PROCESS_QUERY_LIMITED_INFORMATION,               // Generic execute
    PROCESS_ALL_ACCESS,                               // Generic all
);

/// Generic thread mapping.
pub static THREAD_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT,   // Generic read
    THREAD_SET_INFORMATION | THREAD_SET_CONTEXT,    // Generic write
    THREAD_QUERY_LIMITED_INFORMATION,                // Generic execute
    THREAD_ALL_ACCESS,                               // Generic all
);

/// Generic directory mapping.
pub static DIRECTORY_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    DIRECTORY_QUERY | DIRECTORY_TRAVERSE,            // Generic read
    DIRECTORY_CREATE_SUBDIRECTORY | DIRECTORY_ADD_FILE, // Generic write
    DIRECTORY_QUERY | DIRECTORY_TRAVERSE,            // Generic execute
    DIRECTORY_ALL_ACCESS,                            // Generic all
);

/// Generic event mapping.
pub static EVENT_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    EVENT_QUERY_STATE,                               // Generic read
    EVENT_MODIFY_STATE,                             // Generic write
    EVENT_QUERY_STATE,                               // Generic execute
    EVENT_ALL_ACCESS,                               // Generic all
);

/// Generic semaphore mapping.
pub static SEMAPHORE_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    SEMAPHORE_QUERY_STATE,                          // Generic read
    SEMAPHORE_MODIFY_STATE,                         // Generic write
    SEMAPHORE_QUERY_STATE,                          // Generic execute
    SEMAPHORE_ALL_ACCESS,                           // Generic all
);

/// Generic mutant (mutex) mapping.
pub static MUTANT_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    MUTANT_QUERY_STATE,                             // Generic read
    MUTANT_QUERY_STATE,                             // Generic write (not typically granted)
    MUTANT_QUERY_STATE,                             // Generic execute
    MUTANT_ALL_ACCESS,                              // Generic all
);

/// Generic section (shared memory) mapping.
pub static SECTION_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    SECTION_MAP_READ | SECTION_QUERY,                // Generic read
    SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,         // Generic write
    SECTION_MAP_EXECUTE,                            // Generic execute
    SECTION_ALL_ACCESS,                             // Generic all
);

/// Generic token mapping.
pub static TOKEN_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    TOKEN_QUERY,                                    // Generic read
    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS, // Generic write
    TOKEN_QUERY,                                    // Generic execute
    TOKEN_ALL_ACCESS,                               // Generic all
);

/// Object type identifiers for access checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObTypeIndex {
    Null = 0,
    Process = 1,
    Thread = 2,
    Directory = 3,
    SymbolicLink = 4,
    Token = 5,
    ProcessToken = 6,
    ThreadToken = 7,
    Event = 8,
    EventPair = 9,
    Mutant = 10,
    Callback = 11,
    Section = 12,
    Alias = 13,
    WindowStation = 14,
    Desktop = 15,
    Type = 16,
    ObjectDirectory = 17,
    Key = 18,
    File = 19,
    Semaphore = 20,
    // ... more types
}

/// Get the GenericMapping for an object type.
pub fn get_generic_mapping_for_type(object_type: ObTypeIndex) -> &'static GenericMapping {
    match object_type {
        ObTypeIndex::Process => &PROCESS_GENERIC_MAPPING,
        ObTypeIndex::Thread => &THREAD_GENERIC_MAPPING,
        ObTypeIndex::File => &FILE_GENERIC_MAPPING,
        ObTypeIndex::Key => &REGISTRY_GENERIC_MAPPING,
        ObTypeIndex::Directory | ObTypeIndex::ObjectDirectory => &DIRECTORY_GENERIC_MAPPING,
        ObTypeIndex::Event => &EVENT_GENERIC_MAPPING,
        ObTypeIndex::Semaphore => &SEMAPHORE_GENERIC_MAPPING,
        ObTypeIndex::Mutant => &MUTANT_GENERIC_MAPPING,
        ObTypeIndex::Section => &SECTION_GENERIC_MAPPING,
        ObTypeIndex::Token => &TOKEN_GENERIC_MAPPING,
        _ => {
            // Default mapping for unknown types
            static DEFAULT_MAPPING: GenericMapping = GenericMapping::new(
                ACCESS_READ_CONTROL,
                ACCESS_WRITE_DAC,
                ACCESS_READ_CONTROL,
                ACCESS_READ_CONTROL | ACCESS_WRITE_DAC | ACCESS_WRITE_OWNER | ACCESS_DELETE,
            );
            &DEFAULT_MAPPING
        }
    }
}

/// SeAccessCheck — the main Windows security access check API.
///
/// This is the primary entry point for access validation in the NT security model.
///
/// # Arguments
/// * `object_type` - The type of object being accessed
/// * `sd_ptr` - Pointer to a security descriptor (can be null for NULL DACL = allow all)
/// * `desired_access` - The access rights being requested
/// * `token_ptr` - Pointer to the subject's security token
///
/// # Returns
/// * `(AccessCheckResult, granted_access)` - Whether access is allowed and what was granted
pub fn se_access_check(
    object_type: ObTypeIndex,
    sd_ptr: *const SecurityDescriptor,
    desired_access: u32,
    token_ptr: *const Token,
) -> (AccessCheckResult, u32) {
    // Get generic mapping for this object type
    let generic_mapping = get_generic_mapping_for_type(object_type);

    // Validate inputs
    if token_ptr.is_null() {
        // crate::kprintln!("[SE] SeAccessCheck: NULL token, denying access")  // kprintln disabled (memcpy crash workaround);
        return (AccessCheckResult::Denied, 0);
    }

    let token = unsafe { &*token_ptr };

    // NULL security descriptor means full access
    if sd_ptr.is_null() {
        // crate::kprintln!("[SE] SeAccessCheck: NULL SD, allowing full access")  // kprintln disabled (memcpy crash workaround);
        return (AccessCheckResult::Allowed, desired_access);
    }

    let sd = unsafe { &*sd_ptr };

    // NULL DACL means full access
    if sd.dacl.is_null() {
        // crate::kprintln!("[SE] SeAccessCheck: NULL DACL, allowing full access")  // kprintln disabled (memcpy crash workaround);
        return (AccessCheckResult::Allowed, desired_access);
    }

    // Perform the access check
    let result = check_access(
        desired_access,
        token,
        &sd.owner,
        sd.dacl,
        Some(generic_mapping),
    );

    // Calculate granted access
    let granted = match result {
        AccessCheckResult::Allowed => desired_access,
        AccessCheckResult::Denied => 0,
    };

    (result, granted)
}

/// SeAccessCheckByType — access check with object-type specific logic.
///
/// Extended version of SeAccessCheck that handles object-type specific checks
/// like directory traversal and file append.
pub fn se_access_check_by_type(
    object_type: ObTypeIndex,
    _object_type_ptr: *const (),
    sd_ptr: *const SecurityDescriptor,
    desired_access: u32,
    token_ptr: *const Token,
) -> (AccessCheckResult, u32) {
    // _object_type_ptr is intentionally unused - reserved for future type-specific checks
    // For now, delegate to the basic version
    // In a full implementation, this would handle type-specific logic
    se_access_check(object_type, sd_ptr, desired_access, token_ptr)
}

/// Security descriptor structure (simplified for kernel use).
#[repr(C)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub sbz1: u8,
    pub control: u16,
    pub owner: Sid,
    pub group: Sid,
    pub sacl: *const Acl,    // System ACL
    pub dacl: *const Acl,    // Discretionary ACL
}

impl SecurityDescriptor {
    /// Create a default security descriptor with NULL DACL (allows all).
    ///
    /// Returns a pointer to a statically allocated NULL DACL security descriptor.
    /// NULL DACL means full access is granted to everyone.
    pub fn new_null_dacl() -> *const Self {
        // Return a null pointer to indicate NULL DACL (allow all)
        // Callers should check for null and treat it as "allow all"
        core::ptr::null()
    }

    /// Build a proper security descriptor from a token.
    ///
    /// Creates a DACL that grants access based on token's user and groups.
    /// This is used for process and thread security descriptors.
    ///
    /// Returns a pointer to an allocated SecurityDescriptor, or null on failure.
    pub fn from_token(token: &super::token::Token) -> *const Self {
        // Allocate SecurityDescriptor
        let sd_ptr = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<SecurityDescriptor>(),
        ) as *mut SecurityDescriptor;

        if sd_ptr.is_null() {
            // crate::kprintln!("[SE] SecurityDescriptor::from_token: allocation failed")  // kprintln disabled (memcpy crash workaround);
            return core::ptr::null();
        }

        unsafe {
            (*sd_ptr).revision = 1;
            (*sd_ptr).sbz1 = 0;
            (*sd_ptr).control = 0x8004; // SE_DACL_PRESENT | SE_SELF_RELATIVE

            // Copy owner and group from token
            (*sd_ptr).owner = token.user.clone();
            (*sd_ptr).group = token.primary_group.clone();
            (*sd_ptr).sacl = core::ptr::null();

            // Build DACL based on token's user and enabled groups
            let dacl = build_dacl_from_token(token);
            (*sd_ptr).dacl = dacl;

            // crate::kprintln!("[SE] SecurityDescriptor::from_token: created SD for user")  // kprintln disabled (memcpy crash workaround);
        }

        sd_ptr as *const Self
    }
}

/// Build a DACL based on a token's user and enabled groups.
///
/// The DACL grants:
/// - Full access to the token's owner (user)
/// - Read access to the token's primary group
/// - Standard rights to enabled groups
fn build_dacl_from_token(token: &super::token::Token) -> *const Acl {
    // Calculate ACE count: owner + primary_group + enabled groups
    let mut ace_count = 2u16; // owner + primary_group

    // Count enabled groups
    for i in 0..token.group_count {
        if token.groups[i].is_enabled() {
            ace_count += 1;
        }
    }

    // Calculate total DACL size
    // ACL header: 8 bytes
    // Each ACE: 8 bytes header + SID size
    let sid_size = 8 + (token.user.sub_authority_count as usize) * 4;
    let ace_size = (8 + sid_size) as u16;
    let _total_acl_size = (8 + ace_count as usize * ace_size as usize) as u16;
    // _total_acl_size is reserved for future use in ACL validation

    // Try to allocate ACL inline in the SD or separately
    // For simplicity, we'll embed a small DACL directly
    // ACL structure uses inline data storage, so we build it in-place

    // For this implementation, create a simple ACL with:
    // 1. ACCESS_ALLOWED_ACE for the user with GENERIC_ALL
    // 2. ACCESS_ALLOWED_ACE for SYSTEM with GENERIC_ALL (common in Windows)
    // 3. ACCESS_ALLOWED_ACE for each enabled group with GENERIC_READ

    // Use a fixed-size inline ACL for simplicity
    let acl_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Acl>(),
    ) as *mut Acl;

    if acl_ptr.is_null() {
        // crate::kprintln!("[SE] build_dacl_from_token: ACL allocation failed")  // kprintln disabled (memcpy crash workaround);
        return core::ptr::null();
    }

    unsafe {
        // Initialize ACL header
        (*acl_ptr).revision = 2; // ACL_REVISION2
        (*acl_ptr).sbz1 = 0;
        (*acl_ptr).acl_size = core::mem::size_of::<Acl>() as u16;
        (*acl_ptr).ace_count = ace_count;
        (*acl_ptr).sbz2 = 0;

        // Build ACEs starting at offset 8 (after ACL header)
        let mut offset = 8usize;
        let max_size = core::mem::size_of::<Acl>();

        // ACE 1: Grant GENERIC_ALL to the user (owner)
        if offset + 8 + sid_size <= max_size {
            // ACE Header
            (*acl_ptr).data[offset] = 0x00; // ACCESS_ALLOWED_ACE_TYPE
            (*acl_ptr).data[offset + 1] = 0x00; // flags
            (*acl_ptr).data[offset + 2] = (ace_size & 0xFF) as u8;
            (*acl_ptr).data[offset + 3] = ((ace_size >> 8) & 0xFF) as u8;

            // Access mask: GENERIC_ALL | standard rights
            let access_mask: u32 = ACCESS_GENERIC_ALL | ACCESS_DELETE | ACCESS_READ_CONTROL |
                                   ACCESS_WRITE_DAC | ACCESS_WRITE_OWNER | ACCESS_SYNCHRONIZE;
            (*acl_ptr).data[offset + 4] = (access_mask & 0xFF) as u8;
            (*acl_ptr).data[offset + 5] = ((access_mask >> 8) & 0xFF) as u8;
            (*acl_ptr).data[offset + 6] = ((access_mask >> 16) & 0xFF) as u8;
            (*acl_ptr).data[offset + 7] = ((access_mask >> 24) & 0xFF) as u8;

            // Copy user SID
            let sid_offset = offset + 8;
            copy_sid(&token.user, &mut (*acl_ptr).data, sid_offset);
            offset += ace_size as usize;
        }

        // ACE 2: Grant GENERIC_ALL to SYSTEM (primary group, treated as well-known)
        // Build a well-known SID for LocalSystem: S-1-5-18
        if offset + 8 + sid_size <= max_size {
            (*acl_ptr).data[offset] = 0x00; // ACCESS_ALLOWED_ACE_TYPE
            (*acl_ptr).data[offset + 1] = 0x00;
            (*acl_ptr).data[offset + 2] = (ace_size & 0xFF) as u8;
            (*acl_ptr).data[offset + 3] = ((ace_size >> 8) & 0xFF) as u8;

            let access_mask: u32 = ACCESS_GENERIC_ALL;
            (*acl_ptr).data[offset + 4] = (access_mask & 0xFF) as u8;
            (*acl_ptr).data[offset + 5] = ((access_mask >> 8) & 0xFF) as u8;
            (*acl_ptr).data[offset + 6] = ((access_mask >> 16) & 0xFF) as u8;
            (*acl_ptr).data[offset + 7] = ((access_mask >> 24) & 0xFF) as u8;

            // SID: S-1-5-18 (LocalSystem)
            let sid_offset = offset + 8;
            (*acl_ptr).data[sid_offset] = 1; // revision
            (*acl_ptr).data[sid_offset + 1] = 1; // sub_authority_count
            (*acl_ptr).data[sid_offset + 2] = 0; // identifier_authority[0]
            (*acl_ptr).data[sid_offset + 3] = 0; // identifier_authority[1]
            (*acl_ptr).data[sid_offset + 4] = 0; // identifier_authority[2]
            (*acl_ptr).data[sid_offset + 5] = 0; // identifier_authority[3]
            (*acl_ptr).data[sid_offset + 6] = 5; // identifier_authority[4] (NT AUTHORITY)
            (*acl_ptr).data[sid_offset + 7] = 18; // identifier_authority[5] (18 = LocalSystem)
            // sub_authority[0] = 18
            (*acl_ptr).data[sid_offset + 8] = 18;
            (*acl_ptr).data[sid_offset + 9] = 0;
            (*acl_ptr).data[sid_offset + 10] = 0;
            (*acl_ptr).data[sid_offset + 11] = 0;
            offset += ace_size as usize;
        }

        // ACE 3+: Grant GENERIC_READ to enabled groups
        for i in 0..token.group_count {
            if token.groups[i].is_enabled() && offset + 8 + sid_size <= max_size {
                (*acl_ptr).data[offset] = 0x00; // ACCESS_ALLOWED_ACE_TYPE
                (*acl_ptr).data[offset + 1] = 0x02; // CONTAINER_INHERIT
                (*acl_ptr).data[offset + 2] = (ace_size & 0xFF) as u8;
                (*acl_ptr).data[offset + 3] = ((ace_size >> 8) & 0xFF) as u8;

                // Access mask: GENERIC_READ | SYNCHRONIZE
                let access_mask: u32 = ACCESS_GENERIC_READ | ACCESS_SYNCHRONIZE;
                (*acl_ptr).data[offset + 4] = (access_mask & 0xFF) as u8;
                (*acl_ptr).data[offset + 5] = ((access_mask >> 8) & 0xFF) as u8;
                (*acl_ptr).data[offset + 6] = ((access_mask >> 16) & 0xFF) as u8;
                (*acl_ptr).data[offset + 7] = ((access_mask >> 24) & 0xFF) as u8;

                // Copy group SID
                let sid_offset = offset + 8;
                copy_sid(&token.groups[i].sid, &mut (*acl_ptr).data, sid_offset);
                offset += ace_size as usize;
            }
        }
    }

    acl_ptr as *const Acl
}

/// Copy a SID to a byte array at the specified offset.
fn copy_sid(sid: &Sid, dest: &mut [u8], offset: usize) {
    dest[offset] = sid.revision;
    dest[offset + 1] = sid.sub_authority_count;
    // Copy identifier_authority (6 bytes)
    for i in 0..6 {
        dest[offset + 2 + i] = sid.identifier_authority[i];
    }
    // Copy sub_authority (up to 8 * 4 = 32 bytes)
    let sub_count = sid.sub_authority_count as usize;
    for i in 0..sub_count.min(8) {
        let val = sid.sub_authority[i];
        dest[offset + 8 + i * 4] = (val & 0xFF) as u8;
        dest[offset + 8 + i * 4 + 1] = ((val >> 8) & 0xFF) as u8;
        dest[offset + 8 + i * 4 + 2] = ((val >> 16) & 0xFF) as u8;
        dest[offset + 8 + i * 4 + 3] = ((val >> 24) & 0xFF) as u8;
    }
}

/// Build a security descriptor for a process.
/// This is called from ps/process.rs to create proper process security descriptors.
pub fn build_process_security_descriptor(process: *mut crate::ps::process::Eprocess) -> *const SecurityDescriptor {
    if process.is_null() {
        return core::ptr::null();
    }

    unsafe {
        let token_ptr = (*process).get_token();
        if token_ptr.is_null() {
            // System process has no token, use NULL DACL
            // crate::kprintln!("[SE] build_process_security_descriptor: null token, using NULL DACL")  // kprintln disabled (memcpy crash workaround);
            return SecurityDescriptor::new_null_dacl();
        }

        let token = &*token_ptr;
        // crate::kprintln!("[SE] build_process_security_descriptor: building SD from token")  // kprintln disabled (memcpy crash workaround);
        SecurityDescriptor::from_token(token)
    }
}

/// Create a NULL DACL security descriptor that allows all access.
///
/// This is used for bootstrap when no security checks are needed.
pub fn create_null_dacl_sd() -> *const SecurityDescriptor {
    // Allocate from kernel pool
    let sd_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<SecurityDescriptor>(),
    ) as *mut SecurityDescriptor;

    if sd_ptr.is_null() {
        return core::ptr::null();
    }

    unsafe {
        (*sd_ptr).revision = 1;
        (*sd_ptr).sbz1 = 0;
        (*sd_ptr).control = 0x8004; // SE_DACL_PRESENT | SE_SELF_RELATIVE
        (*sd_ptr).owner = Sid {
            revision: 1,
            sub_authority_count: 0,
            identifier_authority: [0, 0, 0, 0, 0, 0],
            sub_authority: [0; 8],
        };
        (*sd_ptr).group = Sid {
            revision: 1,
            sub_authority_count: 0,
            identifier_authority: [0, 0, 0, 0, 0, 0],
            sub_authority: [0; 8],
        };
        (*sd_ptr).sacl = core::ptr::null();
        (*sd_ptr).dacl = core::ptr::null(); // NULL DACL = allow all
    }

    sd_ptr as *const SecurityDescriptor
}

pub fn init() {
    // crate::kprintln!("    SE/ACCESS: initialized (SeAccessCheck, SePrivilegeCheck, GenericMapping)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      Generic mappings: PROCESS, THREAD, FILE, KEY, DIRECTORY, EVENT, etc.")  // kprintln disabled (memcpy crash workaround);
}
