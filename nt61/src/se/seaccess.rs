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

use super::acl::{AceFlags, AceType, Acl};
use super::sid::sid;
use super::token::{Token, SE_GROUP_USE_FOR_DENY_ONLY};

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
pub const ACCESS_STANDARD_RIGHTS_ALL: u32 = ACCESS_DELETE
    | ACCESS_READ_CONTROL
    | ACCESS_WRITE_DAC
    | ACCESS_WRITE_OWNER
    | ACCESS_SYNCHRONIZE;

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

/// mutant (mutex) access rights.
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
fn sid_matches_token(sid: &sid, token: &Token) -> bool {
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
fn sid_in_token(sid: &sid, token: &Token) -> bool {
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
    desired_access: u32,
    token: &Token,
    owner: &sid,
    dacl: *const Acl,
    generic_mapping: Option<&GenericMapping>,
) -> AccessCheckResult {
    check_access_with_granted(desired_access, token, owner, dacl, generic_mapping).0
}

fn check_access_with_granted(
    mut desired_access: u32,
    token: &Token,
    _owner: &sid,
    dacl: *const Acl,
    generic_mapping: Option<&GenericMapping>,
) -> (AccessCheckResult, u32) {
    let maximum_allowed = (desired_access & ACCESS_MAXIMUM_ALLOWED) != 0;
    desired_access &= !ACCESS_MAXIMUM_ALLOWED;

    if let Some(gm) = generic_mapping {
        gm.map_generic(&mut desired_access);
    }

    let maximum_access = generic_mapping
        .map(|gm| gm.generic_all)
        .unwrap_or(u32::MAX & !ACCESS_MAXIMUM_ALLOWED);

    if dacl.is_null() {
        let granted = if maximum_allowed {
            maximum_access
        } else {
            desired_access
        };
        return (AccessCheckResult::Allowed, granted);
    }

    if (desired_access & ACCESS_WRITE_OWNER) != 0 {
        let luid = super::token::luid {
            low_part: privileges::SE_TAKE_OWNERSHIP as u32,
            high_part: 0,
        };
        if token.has_privilege(&luid) {
            return (AccessCheckResult::Allowed, desired_access);
        }
    }

    if (desired_access & ACCESS_SYSTEM_SECURITY) != 0 {
        let luid = super::token::luid {
            low_part: privileges::SE_SECURITY as u32,
            high_part: 0,
        };
        if token.has_privilege(&luid) {
            return (AccessCheckResult::Allowed, desired_access);
        }
    }

    if (desired_access & ACCESS_READ_CONTROL) != 0 {
        let luid = super::token::luid {
            low_part: privileges::SE_BACKUP as u32,
            high_part: 0,
        };
        if token.has_privilege(&luid) {
            return (AccessCheckResult::Allowed, desired_access);
        }
    }

    if (desired_access & ACCESS_WRITE_DAC) != 0 {
        let luid = super::token::luid {
            low_part: privileges::SE_RESTORE as u32,
            high_part: 0,
        };
        if token.has_privilege(&luid) {
            return (AccessCheckResult::Allowed, desired_access);
        }
    }

    const SE_DEBUG_ALLOWED_ACCESS: u32 = PROCESS_ALL_ACCESS
        | PROCESS_QUERY_INFORMATION
        | PROCESS_QUERY_LIMITED_INFORMATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_VM_OPERATION
        | PROCESS_DUP_HANDLE
        | PROCESS_CREATE_THREAD;
    if (desired_access & SE_DEBUG_ALLOWED_ACCESS) != 0 {
        let luid = super::token::luid {
            low_part: privileges::SE_DEBUG as u32,
            high_part: 0,
        };
        if token.has_privilege(&luid) && token.is_admin() {
            return (AccessCheckResult::Allowed, desired_access);
        }
    }

    let acl = unsafe { &*dacl };
    if !acl.is_valid() {
        return (AccessCheckResult::Denied, 0);
    }
    let walk_limit = acl.acl_size as usize;
    let mut granted_access = 0u32;
    let mut denied_access = 0u32;
    let mut offset = 8usize;

    while offset + 4 <= walk_limit {
        let ace_type = acl.data[offset];
        let ace_size = acl.data[offset + 2] as usize | ((acl.data[offset + 3] as usize) << 8);
        if ace_size < 8 || offset + ace_size > walk_limit {
            break;
        }

        let ace_mask = u32::from_le_bytes([
            acl.data[offset + 4],
            acl.data[offset + 5],
            acl.data[offset + 6],
            acl.data[offset + 7],
        ]);
        let sid_offset = offset + 8;
        if ace_size < 16 {
            return (AccessCheckResult::Denied, 0);
        }
        let Some(sid) = read_sid_from_acl(&acl.data[sid_offset..offset + ace_size]) else {
            return (AccessCheckResult::Denied, 0);
        };
        let Some(ace_type) = AceType::from_u8(ace_type) else {
            return (AccessCheckResult::Denied, 0);
        };

        match ace_type {
            AceType::AccessDenied if sid_in_token(&sid, token) => denied_access |= ace_mask,
            AceType::AccessAllowed if sid_matches_token(&sid, token) => granted_access |= ace_mask,
            _ => {}
        }
        offset += ace_size;
    }

    granted_access &= !denied_access;
    if (desired_access & denied_access) != 0 {
        return (AccessCheckResult::Denied, 0);
    }

    let remaining = desired_access & !granted_access;
    if remaining != 0 {
        return (AccessCheckResult::Denied, 0);
    }

    let granted = if maximum_allowed {
        granted_access & maximum_access
    } else {
        granted_access & desired_access
    };
    if maximum_allowed && granted == 0 {
        return (AccessCheckResult::Denied, 0);
    }
    (AccessCheckResult::Allowed, granted)
}

/// read a SID from ACL data at the given offset.
fn read_sid_from_acl(data: &[u8]) -> Option<sid> {
    sid::from_bytes(data)
}

/// SePrivilegeCheck — check if a token has required privileges.
pub fn check_privilege(token: &Token, required_privilege: &super::token::luid) -> bool {
    token.has_privilege(required_privilege)
}

/// SeSinglePrivilegeCheck — check a single privilege by LUID.
pub fn check_single_privilege(token: &Token, luid: &super::token::luid) -> bool {
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
    0x00020000 | 0x0002 | 0x0004 | 0x0010 | 0x0020,          // KEY_WRITE etc.
    0x00020000 | 0x0004 | 0x0008,                            // KEY_EXECUTE
    0xF003F,                                                 // KEY_ALL_ACCESS
);

/// Generic process mapping.
pub static PROCESS_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, // Generic read
    PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE, // Generic write
    PROCESS_QUERY_LIMITED_INFORMATION,           // Generic execute
    PROCESS_ALL_ACCESS,                          // Generic all
);

/// Generic thread mapping.
pub static THREAD_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, // Generic read
    THREAD_SET_INFORMATION | THREAD_SET_CONTEXT,   // Generic write
    THREAD_QUERY_LIMITED_INFORMATION,              // Generic execute
    THREAD_ALL_ACCESS,                             // Generic all
);

/// Generic directory mapping.
pub static DIRECTORY_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    DIRECTORY_QUERY | DIRECTORY_TRAVERSE, // Generic read
    DIRECTORY_CREATE_SUBDIRECTORY | DIRECTORY_ADD_FILE, // Generic write
    DIRECTORY_QUERY | DIRECTORY_TRAVERSE, // Generic execute
    DIRECTORY_ALL_ACCESS,                 // Generic all
);

/// Generic event mapping.
pub static EVENT_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    EVENT_QUERY_STATE,  // Generic read
    EVENT_MODIFY_STATE, // Generic write
    EVENT_QUERY_STATE,  // Generic execute
    EVENT_ALL_ACCESS,   // Generic all
);

/// Generic semaphore mapping.
pub static SEMAPHORE_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    SEMAPHORE_QUERY_STATE,  // Generic read
    SEMAPHORE_MODIFY_STATE, // Generic write
    SEMAPHORE_QUERY_STATE,  // Generic execute
    SEMAPHORE_ALL_ACCESS,   // Generic all
);

/// Generic mutant (mutex) mapping.
pub static MUTANT_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    MUTANT_QUERY_STATE, // Generic read
    MUTANT_QUERY_STATE, // Generic write (not typically granted)
    MUTANT_QUERY_STATE, // Generic execute
    MUTANT_ALL_ACCESS,  // Generic all
);

/// Generic section (shared memory) mapping.
pub static SECTION_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    SECTION_MAP_READ | SECTION_QUERY,        // Generic read
    SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, // Generic write
    SECTION_MAP_EXECUTE,                     // Generic execute
    SECTION_ALL_ACCESS,                      // Generic all
);

/// Generic token mapping.
pub static TOKEN_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    TOKEN_QUERY,                                   // Generic read
    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS, // Generic write
    TOKEN_QUERY,                                   // Generic execute
    TOKEN_ALL_ACCESS,                              // Generic all
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
    r#Type = 16,
    ObjectDirectory = 17,
    Key = 18,
    File = 19,
    Semaphore = 20,
    // ... more types
}

impl ObTypeIndex {
    /// Map the 1-byte `ObjectHeader.type_index` (Windows 7+ ObTypeIndex)
    /// to this enum. Unknown indices map to `Null` so the caller falls
    /// back to the default generic mapping instead of guessing.
    pub const fn from_u8(value: u8) -> ObTypeIndex {
        match value {
            0 => ObTypeIndex::Null,
            1 => ObTypeIndex::Process,
            2 => ObTypeIndex::Thread,
            3 => ObTypeIndex::Directory,
            4 => ObTypeIndex::SymbolicLink,
            5 => ObTypeIndex::Token,
            6 => ObTypeIndex::ProcessToken,
            7 => ObTypeIndex::ThreadToken,
            8 => ObTypeIndex::Event,
            9 => ObTypeIndex::EventPair,
            10 => ObTypeIndex::Mutant,
            11 => ObTypeIndex::Callback,
            12 => ObTypeIndex::Section,
            13 => ObTypeIndex::Alias,
            14 => ObTypeIndex::WindowStation,
            15 => ObTypeIndex::Desktop,
            16 => ObTypeIndex::Type,
            17 => ObTypeIndex::ObjectDirectory,
            18 => ObTypeIndex::Key,
            19 => ObTypeIndex::File,
            20 => ObTypeIndex::Semaphore,
            _ => ObTypeIndex::Null,
        }
    }
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
        // crate::kprintln!("[SE] SeAccessCheck: NULL token, denying access");
        return (AccessCheckResult::Denied, 0);
    }

    let token = unsafe { &*token_ptr };

    // A null security descriptor has the same effective access semantics as a
    // null DACL for this simplified kernel interface.
    let (owner, dacl) = if sd_ptr.is_null() {
        (&token.user, core::ptr::null())
    } else {
        let sd = unsafe { &*sd_ptr };
        (&sd.owner, sd.dacl)
    };

    check_access_with_granted(desired_access, token, owner, dacl, Some(generic_mapping))
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
    pub owner: sid,
    pub group: sid,
    pub sacl: *const Acl, // System ACL
    pub dacl: *const Acl, // Discretionary ACL
}

impl SecurityDescriptor {
    /// Validate the descriptor against the documented SECURITY_DESCRIPTOR
    /// layout (SE_REVISION = 1). Present ACLs must themselves be valid.
    pub fn is_valid(&self) -> bool {
        if self.revision != 1 {
            return false;
        }

        unsafe {
            if (self.control & super::descriptor::SE_DACL_PRESENT) != 0 && !self.dacl.is_null() {
                if !(*self.dacl).is_valid() {
                    return false;
                }
            }
            if (self.control & super::descriptor::SE_SACL_PRESENT) != 0 && !self.sacl.is_null() {
                if !(*self.sacl).is_valid() {
                    return false;
                }
            }
        }

        true
    }

    /// create a default security descriptor with NULL DACL (allows all).
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
            // crate::kprintln!("[SE] SecurityDescriptor::from_token: allocation failed");
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

            // crate::kprintln!("[SE] SecurityDescriptor::from_token: created SD for user");
        }

        sd_ptr as *const Self
    }
}

/// Build a DACL based on a token's user and enabled groups.
///
/// The DACL grants:
/// - Full access to the token's owner (user)
/// - read access to the token's primary group
/// - Standard rights to enabled groups
fn build_dacl_from_token(token: &super::token::Token) -> *const Acl {
    let acl_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Acl>(),
    ) as *mut Acl;

    if acl_ptr.is_null() {
        return core::ptr::null();
    }

    unsafe {
        core::ptr::write(acl_ptr, Acl::new());
        let acl = &mut *acl_ptr;

        let owner_mask = ACCESS_GENERIC_ALL
            | ACCESS_DELETE
            | ACCESS_READ_CONTROL
            | ACCESS_WRITE_DAC
            | ACCESS_WRITE_OWNER
            | ACCESS_SYNCHRONIZE;
        if !acl.add_access_allowed(&token.user, owner_mask, AceFlags::NONE) {
            crate::mm::pool::free(acl_ptr as *mut u8);
            return core::ptr::null();
        }

        let system_sid = super::sid::sid::well_known(super::sid::WellKnownSid::LocalSystem);
        if !acl.add_access_allowed(&system_sid, ACCESS_GENERIC_ALL, AceFlags::NONE) {
            crate::mm::pool::free(acl_ptr as *mut u8);
            return core::ptr::null();
        }

        for group in token.groups.iter().take(token.group_count) {
            if group.is_enabled()
                && !acl.add_access_allowed(
                    &group.sid,
                    ACCESS_GENERIC_READ | ACCESS_SYNCHRONIZE,
                    AceFlags::CONTAINER_INHERIT,
                )
            {
                break;
            }
        }
    }

    acl_ptr as *const Acl
}

/// Build a security descriptor for a process.
/// This is called from ps/process.rs to create proper process security descriptors.
pub fn build_process_security_descriptor(
    process: *mut crate::ps::process::Eprocess,
) -> *const SecurityDescriptor {
    if process.is_null() {
        return core::ptr::null();
    }

    unsafe {
        let token_ptr = (*process).get_token();
        if token_ptr.is_null() {
            // System process has no token, use NULL DACL
            // crate::kprintln!("[SE] build_process_security_descriptor: null token, using NULL DACL");
            return SecurityDescriptor::new_null_dacl();
        }

        let token = &*token_ptr;
        // crate::kprintln!("[SE] build_process_security_descriptor: building SD from token");
        SecurityDescriptor::from_token(token)
    }
}

/// create a NULL DACL security descriptor that allows all access.
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
        (*sd_ptr).owner = sid {
            revision: 1,
            sub_authority_count: 0,
            identifier_authority: [0, 0, 0, 0, 0, 0],
            sub_authority: [0; 8],
        };
        (*sd_ptr).group = sid {
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
    // crate::kprintln!("    SE/ACCESS: initialized (SeAccessCheck, SePrivilegeCheck, GenericMapping)");
    // crate::kprintln!("      Generic mappings: PROCESS, THREAD, FILE, KEY, DIRECTORY, EVENT, etc.");
}

#[cfg(test)]
mod tests {
    use super::{
        check_access, se_access_check, AccessCheckResult, ObTypeIndex, SecurityDescriptor,
        ACCESS_MAXIMUM_ALLOWED, ACCESS_READ_CONTROL, ACCESS_SYNCHRONIZE,
    };
    use crate::se::{
        acl::Acl,
        sid::{sid, WellKnownSid},
        token::Token,
    };

    #[test]
    fn empty_dacl_does_not_grant_standard_or_synchronize_access() {
        let token = Token::new_primary(sid::well_known(WellKnownSid::Users));
        let acl = Acl::new();

        assert_eq!(
            check_access(ACCESS_READ_CONTROL, &token, &token.user, &acl, None,),
            AccessCheckResult::Denied
        );
        assert_eq!(
            check_access(ACCESS_SYNCHRONIZE, &token, &token.user, &acl, None,),
            AccessCheckResult::Denied
        );
    }

    #[test]
    fn maximum_allowed_is_not_treated_as_a_literal_right() {
        let token = Token::new_primary(sid::well_known(WellKnownSid::Users));
        let acl = Acl::new();
        let sd = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: 0,
            owner: token.user,
            group: token.user,
            sacl: core::ptr::null(),
            dacl: &acl,
        };

        let (result, granted) =
            se_access_check(ObTypeIndex::File, &sd, ACCESS_MAXIMUM_ALLOWED, &token);
        assert_eq!(result, AccessCheckResult::Denied);
        assert_eq!(granted, 0);
    }

    #[test]
    fn maximum_allowed_on_null_dacl_returns_mapped_access_without_request_bit() {
        let token = Token::new_primary(sid::well_known(WellKnownSid::Users));
        let (result, granted) = se_access_check(
            ObTypeIndex::File,
            core::ptr::null(),
            ACCESS_MAXIMUM_ALLOWED,
            &token,
        );
        assert_eq!(result, AccessCheckResult::Allowed);
        assert_eq!(granted & ACCESS_MAXIMUM_ALLOWED, 0);
        assert_ne!(granted, 0);
    }
}
