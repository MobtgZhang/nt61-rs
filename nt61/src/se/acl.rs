//! Access Control Lists (ACL) and Access Control Entries (ACE)
//
//! An ACL is a list of ACEs. Each ACE grants or denies a specific
//! set of access rights to a set of SIDs.
//
//! ACE types:
//!   ACCESS_ALLOWED_ACE  (type 0x00)  — grant access
//!   ACCESS_DENIED_ACE   (type 0x01)  — deny access
//!   ACCESS_ALLOWED_CALLBACK_ACE (type 0x09)
//!   ACCESS_DENIED_CALLBACK_ACE (type 0x0A)
//!   SYSTEM_AUDIT_ACE    (type 0x02)  — audit on access
//!   SYSTEM_MANDATORY_LABEL_ACE (type 0x11) — integrity level
//
//! References: Windows SDK winnt.h, WRK

use super::sid::{Sid, SID_MAX_SUB_AUTHORITIES};

/// ACL revision levels.
pub const ACL_REVISION: u8 = 2;
pub const ACL_REVISION_DS: u8 = 4;

/// Maximum number of ACEs in a statically-allocated ACL.
pub const MAX_ACES: usize = 16;

/// ACE header size (without SID).
pub const ACE_HEADER_SIZE: usize = 4;

/// ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE structure.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AceHeader {
    pub ace_type: u8,
    pub ace_flags: u8,
    pub ace_size: u16,
}

impl AceHeader {
    pub const fn new(ace_type: AceType, flags: AceFlags, size: u16) -> Self {
        Self {
            ace_type: ace_type as u8,
            ace_flags: flags.bits(),
            ace_size: size,
        }
    }

    pub fn ace_type(&self) -> AceType {
        AceType::from_u8(self.ace_type)
    }

    pub fn ace_flags(&self) -> AceFlags {
        AceFlags::from_bits(self.ace_flags)
    }

    pub fn mask(&self) -> u32 {
        // The access mask is at offset 0 (after the header)
        // Stored as a raw u32; we need a reference
        0
    }
}

/// ACE types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AceType {
    AccessAllowed = 0x00,
    AccessDenied = 0x01,
    SystemAudit = 0x02,
    SystemAlarm = 0x03,
    AccessAllowedCompound = 0x04,
    AccessAllowedObject = 0x05,
    AccessDeniedObject = 0x06,
    SystemAuditObject = 0x07,
    SystemAlarmObject = 0x08,
    AccessAllowedCallback = 0x09,
    AccessDeniedCallback = 0x0A,
    AccessAllowedCallbackObject = 0x0B,
    AccessDeniedCallbackObject = 0x0C,
    SystemAuditCallback = 0x0D,
    SystemAlarmCallback = 0x0E,
    SystemAuditCallbackObject = 0x0F,
    SystemAlarmCallbackObject = 0x10,
    AccessAllowedMandatoryLabel = 0x11,
    SystemResourceAttribute = 0x12,
    SystemScopedPolicy = 0x13,
    SystemMandatoryLabel = 0x14,
}

impl AceType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => AceType::AccessAllowed,
            0x01 => AceType::AccessDenied,
            0x02 => AceType::SystemAudit,
            0x11 => AceType::SystemMandatoryLabel,
            _ => AceType::AccessAllowed,
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self,
            AceType::AccessAllowed |
            AceType::AccessAllowedCallback |
            AceType::AccessAllowedCallbackObject |
            AceType::AccessAllowedMandatoryLabel |
            AceType::AccessAllowedObject
        )
    }

    pub fn is_denied(&self) -> bool {
        matches!(self,
            AceType::AccessDenied |
            AceType::AccessDeniedCallback |
            AceType::AccessDeniedCallbackObject
        )
    }
}

/// ACE flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct AceFlags(u8);

impl AceFlags {
    pub const NONE: AceFlags = AceFlags(0);
    pub const OBJECT_INHERIT: AceFlags = AceFlags(0x01);
    pub const CONTAINER_INHERIT: AceFlags = AceFlags(0x02);
    pub const NO_PROPAGATE_INHERIT: AceFlags = AceFlags(0x04);
    pub const INHERIT_ONLY: AceFlags = AceFlags(0x08);
    pub const INHERITED: AceFlags = AceFlags(0x10);
    pub const VALID_INHERIT_FLAGS: AceFlags = AceFlags(0x1F);
    pub const SUCCESSFUL_ACCESS: AceFlags = AceFlags(0x40);
    pub const FAILED_ACCESS: AceFlags = AceFlags(0x80);

    pub const fn bits(&self) -> u8 { self.0 }
    pub const fn from_bits(b: u8) -> Self { Self(b) }
}

/// ACE access mask — which rights are being granted/denied.
pub const ACCESS_READ: u32 = 0x80000000;
pub const ACCESS_WRITE: u32 = 0x40000000;
pub const ACCESS_EXECUTE: u32 = 0x20000000;
pub const ACCESS_DELETE: u32 = 0x00010000;
pub const ACCESS_READ_CONTROL: u32 = 0x00020000;
pub const ACCESS_WRITE_DAC: u32 = 0x00040000;
pub const ACCESS_WRITE_OWNER: u32 = 0x00080000;
pub const ACCESS_SYNCHRONIZE: u32 = 0x00100000;
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x01000000;
pub const ACCESS_MAXIMUM_ALLOWED: u32 = 0x02000000;
pub const ACCESS_GENERIC_ALL: u32 = 0x10000000;
pub const ACCESS_GENERIC_READ: u32 = 0x80000000;
pub const ACCESS_GENERIC_WRITE: u32 = 0x40000000;
pub const ACCESS_GENERIC_EXECUTE: u32 = 0x20000000;

/// Generic mapping for files.
pub const FILE_GENERIC_READ: u32 = ACCESS_READ_CONTROL | ACCESS_SYNCHRONIZE | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010;
pub const FILE_GENERIC_WRITE: u32 = ACCESS_READ_CONTROL | ACCESS_WRITE_DAC | ACCESS_WRITE_OWNER | ACCESS_SYNCHRONIZE | 0x0010 | 0x0020;
pub const FILE_ALL_ACCESS: u32 = ACCESS_DELETE | ACCESS_READ_CONTROL | ACCESS_WRITE_DAC | ACCESS_WRITE_OWNER | 0x01FF;

/// A statically-allocated ACL.
#[repr(C)]
pub struct Acl {
    pub revision: u8,
    pub sbz1: u8,
    pub acl_size: u16,
    pub ace_count: u16,
    pub sbz2: u16,
    /// Inline ACE storage (variable).
    pub(crate) data: [u8; MAX_ACES * 32],
}

impl Acl {
    /// Create an empty ACL.
    pub const fn new() -> Self {
        Self {
            revision: ACL_REVISION,
            sbz1: 0,
            acl_size: 8, // header only
            ace_count: 0,
            sbz2: 0,
            data: [0; MAX_ACES * 32],
        }
    }

    /// Get the total byte size of this ACL.
    pub fn size(&self) -> usize {
        self.acl_size as usize
    }

    /// Get the ACE count.
    pub fn ace_count(&self) -> usize {
        self.ace_count as usize
    }

    /// Add an ACCESS_ALLOWED_ACE to this ACL.
    pub fn add_access_allowed(&mut self, sid: &Sid, mask: u32, flags: AceFlags) -> bool {
        self.add_ace(AceType::AccessAllowed, flags, mask, sid)
    }

    /// Add an ACCESS_DENIED_ACE to this ACL.
    pub fn add_access_denied(&mut self, sid: &Sid, mask: u32, flags: AceFlags) -> bool {
        self.add_ace(AceType::AccessDenied, flags, mask, sid)
    }

    fn add_ace(&mut self, ace_type: AceType, flags: AceFlags, mask: u32, sid: &Sid) -> bool {
        if self.ace_count as usize >= MAX_ACES {
            return false;
        }

        let sid_bytes = sid.size();
        let ace_size = (ACE_HEADER_SIZE + 4 + sid_bytes) as u16;

        if (self.acl_size as usize + ace_size as usize) > core::mem::size_of::<Self>() {
            return false;
        }

        let offset = self.acl_size as usize;
        let data = &mut self.data;

        // Write header
        data[offset] = ace_type as u8;
        data[offset + 1] = flags.bits();
        data[offset + 2] = (ace_size & 0xFF) as u8;
        data[offset + 3] = (ace_size >> 8) as u8;

        // Write mask
        data[offset + 4] = (mask & 0xFF) as u8;
        data[offset + 5] = ((mask >> 8) & 0xFF) as u8;
        data[offset + 6] = ((mask >> 16) & 0xFF) as u8;
        data[offset + 7] = ((mask >> 24) & 0xFF) as u8;

        // Copy SID bytes
        let sid_offset = offset + ACE_HEADER_SIZE + 4;
        for i in 0..sid_bytes {
            data[sid_offset + i] = 0; // Will be filled from Sid struct
        }

        self.ace_count += 1;
        self.acl_size += ace_size;
        true
    }

    /// Validate that this ACL is well-formed.
    pub fn is_valid(&self) -> bool {
        if self.acl_size < 8 {
            return false;
        }
        if self.revision > ACL_REVISION_DS {
            return false;
        }

        let mut offset = 8usize;
        let mut count = 0usize;
        while offset + ACE_HEADER_SIZE <= self.acl_size as usize {
            let ace_size = (self.data[offset + 2] as usize) | ((self.data[offset + 3] as usize) << 8);
            if ace_size < ACE_HEADER_SIZE + 4 {
                return false;
            }
            offset += ace_size;
            count += 1;
            if count > self.ace_count as usize {
                return false;
            }
        }
        offset == self.acl_size as usize && count == self.ace_count as usize
    }
}

/// Well-known DACLs for common objects.
pub static ACL_EVERYONE_FULL: Acl = Acl::new();

/// Well-known NULL DACL (no protection).
pub static ACL_NULL: Acl = Acl::new();

/// Create a default DACL that grants Everyone read/execute access.
pub fn create_default_dacl() -> Acl {
    // Note: in real implementation, we'd use SID_EVERYONE
    // For now, just create an empty ACL.
    Acl::new()
}

/// Check if a DACL is NULL (allows all access).
pub fn is_null_dacl(acl: *const Acl) -> bool {
    if acl.is_null() {
        return true;
    }
    let a = unsafe { &*acl };
    a.acl_size == 0 && a.ace_count == 0
}

pub fn init() {
    // crate::kprintln!("    SE/ACL: initialized (ACL validation, ACE types, access masks)")  // kprintln disabled (memcpy crash workaround);
}
