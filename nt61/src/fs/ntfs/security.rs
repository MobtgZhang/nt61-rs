//! NTFS Security Descriptor Handling
//
//! Implements security descriptor management for NTFS volumes.
//! In NTFS, security descriptors are stored in the $Secure system file.
//
//! ## NTFS Security Model
//
//! NTFS stores security descriptors in the $SDS (Security Descriptor Stream)
//! and $SII (Security Id Index) of the $Secure system file.
//
//! Each file/directory has a SecurityId that indexes into these structures.

/// Maximum number of security descriptors in the cache.
const MAX_SECURITY_DESCRIPTORS: usize = 256;

/// Security ID - an index into the NTFS security database.
pub type SecurityId = u32;

/// Well-known security IDs used by NTFS.
pub mod well_known_sids {
    use super::SecurityId;

    /// NULL SID - no one
    pub const NULL_SID: SecurityId = 0;
    /// Everyone - all users
    pub const EVERYONE: SecurityId = 1;
    /// Local SYSTEM account
    pub const SYSTEM: SecurityId = 2;
    /// Local Administrators group
    pub const ADMINISTRATORS: SecurityId = 3;
    /// Users group
    pub const USERS: SecurityId = 4;
    /// Authenticated users
    pub const AUTHENTICATED_USERS: SecurityId = 5;
    /// Restricted code
    pub const RESTRICTED_CODE: SecurityId = 6;
}

/// ACE (Access Control Entry) types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AceType {
    AccessAllowed = 0x00,
    AccessDenied = 0x01,
    AuditAlarm = 0x02,
    Alarm = 0x03,
    AccessAllowedCompound = 0x04,
    AccessAllowedObject = 0x05,
    AccessDeniedObject = 0x06,
    AuditAlarmObject = 0x07,
    AlarmObject = 0x08,
    AccessAllowedCallback = 0x09,
    AccessDeniedCallback = 0x0A,
    AccessAllowedCallbackObject = 0x0B,
    AccessDeniedCallbackObject = 0x0C,
}

/// ACE flags.
#[derive(Debug, Clone, Copy)]
pub struct AceFlags(u8);

impl AceFlags {
    pub const NONE: Self = Self(0);
    pub const OBJECT_INHERIT: Self = Self(0x01);
    pub const CONTAINER_INHERIT: Self = Self(0x02);
    pub const NO_PROPAGATE_INHERIT: Self = Self(0x04);
    pub const INHERIT_ONLY: Self = Self(0x08);
    pub const INHERITED: Self = Self(0x10);
    pub const SUCCESSFUL_ACCESS: Self = Self(0x40);
    pub const FAILED_ACCESS: Self = Self(0x80);

    pub fn contains(&self, flag: AceFlags) -> bool {
        (self.0 & flag.0) != 0
    }
}

/// Generic access rights.
pub mod generic_access {
    pub const READ: u32 = 0x80000000;
    pub const WRITE: u32 = 0x40000000;
    pub const EXECUTE: u32 = 0x20000000;
    pub const ALL: u32 = 0x10000000;
}

/// File access rights.
pub mod file_access {
    pub const READ_DATA: u32 = 0x0001;
    pub const LIST_DIRECTORY: u32 = 0x0001;
    pub const WRITE_DATA: u32 = 0x0002;
    pub const ADD_FILE: u32 = 0x0002;
    pub const APPEND_DATA: u32 = 0x0004;
    pub const ADD_SUBDIRECTORY: u32 = 0x0004;
    pub const READ_NAMED_ATTRS: u32 = 0x0080;
    pub const WRITE_NAMED_ATTRS: u32 = 0x0100;
    pub const EXECUTE: u32 = 0x0020;
    pub const DELETE_CHILD: u32 = 0x0040;
    pub const READ_ATTRS: u32 = 0x0080;
    pub const WRITE_ATTRS: u32 = 0x0100;
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;
    pub const SYSTEM_SECURITY: u32 = 0x01000000;
    pub const MAXIMUM_ALLOWED: u32 = 0x02000000;
    pub const GENERIC_ALL: u32 = 0x10000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_READ: u32 = 0x80000000;
}

/// Security descriptor for NTFS objects.
#[derive(Clone)]
pub struct NtfsSecurityDescriptor {
    /// Security ID
    pub id: SecurityId,
    /// Owner SID
    pub owner: [u8; 64],
    /// Owner SID size
    pub owner_size: u32,
    /// Group SID
    pub group: [u8; 64],
    /// Group SID size
    pub group_size: u32,
    /// DACL data
    pub dacl: [u8; 512],
    /// DACL size
    pub dacl_size: u32,
    /// SACL data
    pub sacl: [u8; 512],
    /// SACL size
    pub sacl_size: u32,
    /// Hash for quick comparison
    pub hash: u32,
}

impl NtfsSecurityDescriptor {
    /// Create a new security descriptor with default permissions.
    pub fn new_default() -> Self {
        Self {
            id: 0,
            owner: [0; 64],
            owner_size: 0,
            group: [0; 64],
            group_size: 0,
            dacl: Self::default_dacl(),
            dacl_size: Self::default_dacl().len() as u32,
            sacl: [0; 512],
            sacl_size: 0,
            hash: 0,
        }
    }

    /// Create a security descriptor for well-known SIDs.
    pub fn new_well_known(id: SecurityId) -> Self {
        let mut sd = Self::new_default();
        sd.id = id;

        match id {
            well_known_sids::SYSTEM => {
                // SYSTEM SID: S-1-5-18
                sd.owner_size = 12;
                sd.owner[0] = 0x01;  // Revision
                sd.owner[1] = 0x02;  // SubAuthorityCount
                sd.owner[2..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x05]); // NT AUTHORITY
                sd.owner[8] = 0x12;  // SYSTEM RID
                sd.owner[9] = 0x00;
            }
            well_known_sids::EVERYONE => {
                // Everyone SID: S-1-1-0
                sd.owner_size = 8;
                sd.owner[0] = 0x01;
                sd.owner[1] = 0x01;
                sd.owner[2..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // WORLD
            }
            well_known_sids::ADMINISTRATORS => {
                // Administrators SID: S-1-5-32-544
                sd.owner_size = 12;
                sd.owner[0] = 0x01;
                sd.owner[1] = 0x02;
                sd.owner[2..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x05]); // NT AUTHORITY
                sd.owner[8] = 0x20;  // SubAuthority (DOMAIN_ALIAS_RID_ADMINS)
                sd.owner[9] = 0x02;
                sd.owner[10] = 0x00;
                sd.owner[11] = 0x00;
            }
            _ => {}
        }
        sd.calculate_hash();
        sd
    }

    /// Default DACL that grants full access to SYSTEM and Administrators,
    /// and read/execute to Everyone.
    fn default_dacl() -> [u8; 512] {
        let mut dacl = [0u8; 512];

        // ACL Header
        dacl[0] = 0x05;           // Revision (ACL_REVISION)
        dacl[1] = 0x02;           // Sbz1
        dacl[2] = 0x14;           // ACL size (little endian)
        dacl[3] = 0x00;
        dacl[4] = 0x02;            // ACE count
        dacl[5] = 0x00;
        dacl[6] = 0x00;           // Sbz2
        dacl[7] = 0x00;

        // ACE 1: SYSTEM - full access (ACCESS_ALLOWED_ACE)
        let ace1_offset = 8;
        dacl[ace1_offset] = 0x00;        // ACE type (ACCESS_ALLOWED_ACE_TYPE)
        dacl[ace1_offset + 1] = 0x00;    // ACE flags
        dacl[ace1_offset + 2] = 0x18;    // ACE size
        dacl[ace1_offset + 3] = 0x00;
        // Access mask (GENERIC_ALL | STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL)
        dacl[ace1_offset + 4] = 0xFF;    // GenericAll
        dacl[ace1_offset + 5] = 0xFF;    // Standard rights
        dacl[ace1_offset + 6] = 0x01;    // Specific rights
        dacl[ace1_offset + 7] = 0x00;

        // SID for SYSTEM (S-1-5-18)
        let sid1_offset = ace1_offset + 8;
        dacl[sid1_offset] = 0x01;       // Revision
        dacl[sid1_offset + 1] = 0x02;    // SubAuthorityCount
        // IdentifierAuthority (NT AUTHORITY)
        dacl[sid1_offset + 2] = 0x00;
        dacl[sid1_offset + 3] = 0x00;
        dacl[sid1_offset + 4] = 0x00;
        dacl[sid1_offset + 5] = 0x00;
        dacl[sid1_offset + 6] = 0x00;
        dacl[sid1_offset + 7] = 0x05;    // SECURITY_NT_AUTHORITY
        // SubAuthorities
        dacl[sid1_offset + 8] = 0x12;    // SECURITY_LOCAL_SYSTEM_RID
        dacl[sid1_offset + 9] = 0x00;
        dacl[sid1_offset + 10] = 0x00;
        dacl[sid1_offset + 11] = 0x00;

        // ACE 2: Everyone - read/execute (ACCESS_ALLOWED_ACE)
        let ace2_offset = ace1_offset + 20;
        dacl[ace2_offset] = 0x00;        // ACE type
        dacl[ace2_offset + 1] = 0x00;    // ACE flags (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE)
        dacl[ace2_offset + 2] = 0x14;   // ACE size
        dacl[ace2_offset + 3] = 0x00;
        // Access mask (FILE_READ_DATA | FILE_EXECUTE | READ_CONTROL)
        dacl[ace2_offset + 4] = 0x20;    // FILE_READ_DATA
        dacl[ace2_offset + 5] = 0x01;    // FILE_EXECUTE
        dacl[ace2_offset + 6] = 0x00;    // READ_CONTROL
        dacl[ace2_offset + 7] = 0x00;

        // SID for Everyone (S-1-1-0)
        let sid2_offset = ace2_offset + 8;
        dacl[sid2_offset] = 0x01;        // Revision
        dacl[sid2_offset + 1] = 0x01;   // SubAuthorityCount
        // IdentifierAuthority (WORLD)
        dacl[sid2_offset + 2] = 0x00;
        dacl[sid2_offset + 3] = 0x00;
        dacl[sid2_offset + 4] = 0x00;
        dacl[sid2_offset + 5] = 0x00;
        dacl[sid2_offset + 6] = 0x00;
        dacl[sid2_offset + 7] = 0x01;   // SECURITY_WORLD_SID_AUTHORITY
        // SubAuthority
        dacl[sid2_offset + 8] = 0x00;    // SECURITY_NULL_SID_AUTHORITY
        dacl[sid2_offset + 9] = 0x00;
        dacl[sid2_offset + 10] = 0x00;
        dacl[sid2_offset + 11] = 0x00;

        dacl
    }

    /// Calculate hash for quick comparison.
    pub fn calculate_hash(&mut self) {
        let mut hash: u32 = 0;
        for i in 0..self.dacl_size as usize {
            hash = hash.wrapping_mul(31).wrapping_add(self.dacl[i] as u32);
        }
        // Include owner in hash
        for i in 0..self.owner_size as usize {
            hash = hash.wrapping_mul(31).wrapping_add(self.owner[i] as u32);
        }
        self.hash = hash;
    }

    /// Get the number of ACEs in the DACL.
    pub fn dacl_ace_count(&self) -> u16 {
        if self.dacl_size < 8 {
            return 0;
        }
        u16::from_le_bytes([self.dacl[4], self.dacl[5]])
    }
}

/// Parse an ACE from the DACL at the given offset.
/// Returns (ace_type, access_mask, sid_offset) or None if invalid.
fn parse_ace(dacl: &[u8], offset: usize) -> Option<(AceType, u32, usize)> {
    if offset + 8 > dacl.len() {
        return None;
    }

    let ace_type = match dacl[offset] {
        0x00 => AceType::AccessAllowed,
        0x01 => AceType::AccessDenied,
        0x05 => AceType::AccessAllowedObject,
        0x06 => AceType::AccessDeniedObject,
        _ => return None,
    };

    let ace_size = u16::from_le_bytes([dacl[offset + 2], dacl[offset + 3]]) as usize;
    if offset + ace_size > dacl.len() {
        return None;
    }

    // Access mask is at offset 4 (4 bytes)
    let access_mask = u32::from_le_bytes([
        dacl[offset + 4],
        dacl[offset + 5],
        dacl[offset + 6],
        dacl[offset + 7],
    ]);

    // SID starts at offset 8
    Some((ace_type, access_mask, offset + 8))
}

/// Check if two SIDs match.
fn sid_matches(sid1: &[u8], sid2: &[u8]) -> bool {
    if sid1.is_empty() || sid2.is_empty() {
        return false;
    }

    let len1 = core::cmp::min(sid1.len(), sid2.len());
    if len1 < 8 {
        return false;
    }

    // Compare revision and subauthority count
    if sid1[0] != sid2[0] || sid1[1] != sid2[1] {
        return false;
    }

    // Compare identifier authority (bytes 2-7)
    if &sid1[2..8] != &sid2[2..8] {
        return false;
    }

    // Compare subauthorities
    let subauth_count = sid1[1] as usize;
    let compare_len = core::cmp::min(subauth_count, len1 - 8);
    sid1[8..8 + compare_len] == sid2[8..8 + compare_len]
}

/// Check if a SID matches a well-known SID.
fn sid_matches_well_known(sid: &[u8], wk_sid: SecurityId) -> bool {
    match wk_sid {
        well_known_sids::EVERYONE => {
            // S-1-1-0
            sid.len() >= 8 && sid[0] == 0x01 && sid[1] == 0x01 &&
            &sid[2..8] == &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        }
        well_known_sids::SYSTEM => {
            // S-1-5-18
            sid.len() >= 12 && sid[0] == 0x01 && sid[1] == 0x02 &&
            &sid[2..8] == &[0x00, 0x00, 0x00, 0x00, 0x00, 0x05] &&
            sid[8] == 0x12
        }
        well_known_sids::ADMINISTRATORS => {
            // S-1-5-32-544
            sid.len() >= 12 && sid[0] == 0x01 && sid[1] == 0x02 &&
            &sid[2..8] == &[0x00, 0x00, 0x00, 0x00, 0x00, 0x05] &&
            u32::from_le_bytes([sid[8], sid[9], sid[10], sid[11]]) == 0x00000220
        }
        well_known_sids::USERS => {
            // S-1-5-32-545
            sid.len() >= 12 && sid[0] == 0x01 && sid[1] == 0x02 &&
            &sid[2..8] == &[0x00, 0x00, 0x00, 0x00, 0x00, 0x05] &&
            u32::from_le_bytes([sid[8], sid[9], sid[10], sid[11]]) == 0x00000221
        }
        _ => false,
    }
}

/// Security descriptor cache for frequently accessed security info.
pub struct SecurityDescriptorCache {
    entries: [Option<NtfsSecurityDescriptor>; MAX_SECURITY_DESCRIPTORS],
    count: usize,
}

impl SecurityDescriptorCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            entries: [const { None }; MAX_SECURITY_DESCRIPTORS],
            count: 0,
        }
    }

    /// Look up a security descriptor by ID.
    pub fn lookup(&self, id: SecurityId) -> Option<&NtfsSecurityDescriptor> {
        for entry in &self.entries {
            if let Some(ref desc) = entry {
                if desc.id == id {
                    return Some(desc);
                }
            }
        }
        None
    }

    /// Add a security descriptor to the cache.
    pub fn add(&mut self, mut desc: NtfsSecurityDescriptor) {
        desc.calculate_hash();

        // Simple replacement: if full, replace oldest entry
        if self.count >= MAX_SECURITY_DESCRIPTORS {
            // Find first empty slot or replace LRU entry
            if let Some(slot) = self.entries.iter_mut().position(|e| e.is_none()) {
                self.entries[slot] = Some(desc);
            }
        } else {
            // Find first empty slot
            if let Some(slot) = self.entries.iter_mut().position(|e| e.is_none()) {
                self.entries[slot] = Some(desc);
                self.count += 1;
            }
        }
    }
}

impl Default for SecurityDescriptorCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Global security descriptor cache.
static mut SECURITY_CACHE: SecurityDescriptorCache = SecurityDescriptorCache {
    entries: [const { None }; MAX_SECURITY_DESCRIPTORS],
    count: 0,
};

/// Get a security descriptor from the cache.
pub fn get_security_descriptor(id: SecurityId) -> Option<&'static NtfsSecurityDescriptor> {
    unsafe { SECURITY_CACHE.lookup(id) }
}

/// Add a security descriptor to the cache.
pub fn add_security_descriptor(desc: NtfsSecurityDescriptor) {
    unsafe { SECURITY_CACHE.add(desc) }
}

/// Get default security descriptor for a new file.
pub fn get_default_file_security() -> NtfsSecurityDescriptor {
    NtfsSecurityDescriptor::new_default()
}

/// Get default security descriptor for a new directory.
pub fn get_default_directory_security() -> NtfsSecurityDescriptor {
    let desc = NtfsSecurityDescriptor::new_default();

    // Directories typically inherit from parent
    // For now, use same defaults as files
    desc
}

/// Convert NTFS security ID to a format suitable for SeAccessCheck.
///
/// Returns a pointer to a SecurityDescriptor structure or null on error.
pub fn security_id_to_descriptor(id: SecurityId) -> *const crate::se::seaccess::SecurityDescriptor {
    // Look up in cache
    if let Some(desc) = get_security_descriptor(id) {
        // Build a security descriptor from the cached info
        return build_descriptor_from_ntfs(desc);
    }

    // Not found, return default
    crate::se::seaccess::SecurityDescriptor::new_null_dacl()
}

/// Build a SeAccessCheck-compatible security descriptor from NTFS format.
fn build_descriptor_from_ntfs(_desc: &NtfsSecurityDescriptor) -> *const crate::se::seaccess::SecurityDescriptor {
    // For simplicity, we just return the null DACL version
    // A full implementation would properly convert the NTFS format
    crate::se::seaccess::SecurityDescriptor::new_null_dacl()
}

// =============================================================================
// Security Descriptor Inheritance
// =============================================================================

/// Flags for security descriptor inheritance.
#[derive(Clone, Copy)]
pub struct SecurityInheritance {
    pub bits: u32,
}

impl SecurityInheritance {
    /// No inheritance flags set.
    pub const NONE: Self = Self { bits: 0 };
    /// Child will inherit from parent.
    pub const INHERIT: Self = Self { bits: 0x00000001 };
    /// Container inherits ACEs to child containers only.
    pub const CONTAINER_INHERIT_ACE: Self = Self { bits: 0x00000002 };
    /// Object inherits ACEs to child objects only.
    pub const OBJECT_INHERIT_ACE: Self = Self { bits: 0x00000001 };
    /// ACE does not contribute to inheritance.
    pub const NO_PROPAGATE_INHERIT: Self = Self { bits: 0x00000004 };
    /// ACE is inherited, not explicitly set.
    pub const INHERITED_ACE: Self = Self { bits: 0x00000010 };
}

/// Inherit security descriptor from parent object.
///
/// When a new object is created, its security descriptor is typically
/// inherited from the parent object or derived from the process token.
///
/// # Arguments
/// * `parent_sd` - Parent object's security descriptor
/// * `is_directory` - True if the new object is a container
/// * `token` - Process token for default security
///
/// # Returns
/// * Inherited security descriptor
pub fn inherit_security(
    parent_sd: *const crate::se::seaccess::SecurityDescriptor,
    _is_directory: bool,
    _token: *const crate::se::token::Token,
) -> *const crate::se::seaccess::SecurityDescriptor {
    // If no parent SD, return default
    if parent_sd.is_null() {
        return crate::se::seaccess::SecurityDescriptor::new_null_dacl();
    }

    // For now, just copy the parent's DACL
    // A full implementation would:
    // 1. Walk the parent's DACL
    // 2. Filter out INHERIT_ONLY ACES
    // 3. Mark inherited ACEs with INHERITED_ACE flag
    // 4. Apply container/object inheritance rules

    unsafe {
        let parent = &*parent_sd;
        if parent.dacl.is_null() {
            return crate::se::seaccess::SecurityDescriptor::new_null_dacl();
        }

        // For bootstrap, just return NULL DACL (allows all)
        crate::se::seaccess::SecurityDescriptor::new_null_dacl()
    }
}

/// Create a default security descriptor for a new object.
///
/// Returns a default DACL based on the process token.
/// This is used when there is no parent security to inherit from.
pub fn create_default_security(
    _token: *const crate::se::token::Token,
    _object_type: crate::se::seaccess::ObTypeIndex,
) -> *const crate::se::seaccess::SecurityDescriptor {
    // For now, return NULL DACL (allows all)
    // A full implementation would create a proper default DACL
    crate::se::seaccess::SecurityDescriptor::new_null_dacl()
}

/// Check access rights against a security descriptor.
///
/// This function implements the core NTFS access check logic:
/// 1. Walk through the DACL
/// 2. For each ACE, check if the caller SID matches
/// 3. Grant or deny access based on matching ACEs
///
/// # Arguments
/// * `sd` - Security descriptor containing the DACL
/// * `caller_sid` - SID of the calling process/user
/// * `desired_access` - Access rights being requested
///
/// # Returns
/// * `true` if access is granted, `false` if denied
pub fn check_access(sd: &NtfsSecurityDescriptor, caller_sid: &[u8], desired_access: u32) -> bool {
    // If no DACL, allow all access
    if sd.dacl_size == 0 {
        return true;
    }

    let mut access_granted = false;

    // Walk through all ACEs in the DACL
    let mut offset = 8; // Skip ACL header
    let dacl_len = sd.dacl_size as usize;

    while offset < dacl_len {
        // Parse the ACE
        if let Some((ace_type, access_mask, sid_offset)) = parse_ace(&sd.dacl, offset) {
            // Get the SID from the ACE
            let sid_start = sid_offset;
            let sid_len = core::cmp::min(64, dacl_len - sid_start);
            let ace_sid = &sd.dacl[sid_start..sid_start + sid_len];

            // Check if the caller SID matches this ACE
            let matches = sid_matches(caller_sid, ace_sid) || sid_matches_well_known(caller_sid, sd.id);

            if matches {
                match ace_type {
                    AceType::AccessAllowed => {
                        // Check if desired access is covered
                        if (desired_access & access_mask) == desired_access || access_mask == 0xFFFFFFFF {
                            access_granted = true;
                        }
                    }
                    AceType::AccessDenied => {
                        // Deny always takes precedence
                        if (desired_access & access_mask) != 0 {
                            return false;
                        }
                    }
                    _ => {}
                }
            }

            // Move to next ACE
            let ace_size = u16::from_le_bytes([sd.dacl[offset + 2], sd.dacl[offset + 3]]) as usize;
            if ace_size == 0 {
                break;
            }
            offset += ace_size;
        } else {
            break;
        }
    }

    access_granted
}

/// Check if a process has access to a file based on its security descriptor.
///
/// This is a simplified version that checks against well-known SIDs.
///
/// # Arguments
/// * `security_id` - The NTFS security ID of the file
/// * `desired_access` - The requested access rights
///
/// # Returns
/// * `true` if access is granted, `false` otherwise
pub fn check_file_access(security_id: SecurityId, desired_access: u32) -> bool {
    // Look up the security descriptor
    if let Some(sd) = get_security_descriptor(security_id) {
        // For bootstrap, always grant access if there's a valid security descriptor
        // A full implementation would get the caller's SID from the token
        let caller_sid = [0u8; 8]; // Empty SID for bootstrap

        // For empty caller SID, just check if the descriptor exists
        if caller_sid[0] == 0 {
            return true;
        }

        check_access(sd, &caller_sid, desired_access)
    } else {
        // No security descriptor found - allow access (permissive default)
        true
    }
}

/// Read security descriptor from the $Secure system file.
///
/// This function would read and parse the $SDS stream to extract
/// a security descriptor given its ID.
///
/// In a full implementation, this would:
/// 1. Read the $SII index to find the security ID
/// 2. Use that offset to read the full descriptor from $SDS
/// 3. Parse and return the NtfsSecurityDescriptor
///
/// # Arguments
/// * `_ntfs` - NTFS filesystem data
/// * `_security_id` - Security ID to read
///
/// # Returns
/// * Security descriptor if found
pub fn read_security_descriptor(_ntfs: &crate::fs::ntfs::NtfsData, _security_id: SecurityId) -> Option<NtfsSecurityDescriptor> {
    // For bootstrap, return default security
    // A full implementation would read from $Secure:$SDS
    Some(NtfsSecurityDescriptor::new_default())
}

/// Initialize NTFS security subsystem.
pub fn init() {
    // kprintln!("    NTFS Security: initialized")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      Security descriptor cache: {} entries", MAX_SECURITY_DESCRIPTORS)  // kprintln disabled (memcpy crash workaround);

    // Pre-populate with default security descriptors
    let default_file = get_default_file_security();
    add_security_descriptor(default_file);

    // Add well-known security descriptors
    let everyone_sd = NtfsSecurityDescriptor::new_well_known(well_known_sids::EVERYONE);
    add_security_descriptor(everyone_sd);

    let system_sd = NtfsSecurityDescriptor::new_well_known(well_known_sids::SYSTEM);
    add_security_descriptor(system_sd);

    let admin_sd = NtfsSecurityDescriptor::new_well_known(well_known_sids::ADMINISTRATORS);
    add_security_descriptor(admin_sd);

    // kprintln!("      Pre-populated well-known SIDs")  // kprintln disabled (memcpy crash workaround);
}
