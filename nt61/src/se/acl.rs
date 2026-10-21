//! Access control Lists (ACL) and Access control Entries (ACE)
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

use super::sid::sid;

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

    pub fn ace_type(&self) -> Option<AceType> {
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
    SystemMandatoryLabel = 0x11,
    SystemResourceAttribute = 0x12,
    SystemScopedPolicy = 0x13,
    SystemProcessTrustLabel = 0x14,
}

impl AceType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(AceType::AccessAllowed),
            0x01 => Some(AceType::AccessDenied),
            0x02 => Some(AceType::SystemAudit),
            0x03 => Some(AceType::SystemAlarm),
            0x04 => Some(AceType::AccessAllowedCompound),
            0x05 => Some(AceType::AccessAllowedObject),
            0x06 => Some(AceType::AccessDeniedObject),
            0x07 => Some(AceType::SystemAuditObject),
            0x08 => Some(AceType::SystemAlarmObject),
            0x09 => Some(AceType::AccessAllowedCallback),
            0x0A => Some(AceType::AccessDeniedCallback),
            0x0B => Some(AceType::AccessAllowedCallbackObject),
            0x0C => Some(AceType::AccessDeniedCallbackObject),
            0x0D => Some(AceType::SystemAuditCallback),
            0x0E => Some(AceType::SystemAlarmCallback),
            0x0F => Some(AceType::SystemAuditCallbackObject),
            0x10 => Some(AceType::SystemAlarmCallbackObject),
            0x11 => Some(AceType::SystemMandatoryLabel),
            0x12 => Some(AceType::SystemResourceAttribute),
            0x13 => Some(AceType::SystemScopedPolicy),
            0x14 => Some(AceType::SystemProcessTrustLabel),
            _ => None,
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            AceType::AccessAllowed
                | AceType::AccessAllowedCallback
                | AceType::AccessAllowedCallbackObject
                | AceType::AccessAllowedObject
        )
    }

    pub fn is_denied(&self) -> bool {
        matches!(
            self,
            AceType::AccessDenied
                | AceType::AccessDeniedCallback
                | AceType::AccessDeniedCallbackObject
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

    pub const fn bits(&self) -> u8 {
        self.0
    }
    pub const fn from_bits(b: u8) -> Self {
        Self(b)
    }
}

impl core::ops::BitOr for AceFlags {
    type Output = AceFlags;

    fn bitor(self, rhs: AceFlags) -> AceFlags {
        AceFlags(self.0 | rhs.0)
    }
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
pub const FILE_GENERIC_READ: u32 =
    ACCESS_READ_CONTROL | ACCESS_SYNCHRONIZE | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010;
pub const FILE_GENERIC_WRITE: u32 = ACCESS_READ_CONTROL
    | ACCESS_WRITE_DAC
    | ACCESS_WRITE_OWNER
    | ACCESS_SYNCHRONIZE
    | 0x0010
    | 0x0020;
pub const FILE_ALL_ACCESS: u32 =
    ACCESS_DELETE | ACCESS_READ_CONTROL | ACCESS_WRITE_DAC | ACCESS_WRITE_OWNER | 0x01FF;

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
    /// create an empty ACL.
    pub const fn new() -> Self {
        Self {
            revision: ACL_REVISION,
            sbz1: 0,
            // `acl_size` is the currently used logical ACL length. The fixed
            // backing array supplies the remaining capacity.
            acl_size: 8,
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

    /// Return the byte offset immediately after the last encoded ACE.
    pub fn used_size(&self) -> Option<usize> {
        if self.acl_size < 8
            || self.acl_size as usize > self.data.len()
            || (self.revision != ACL_REVISION && self.revision != ACL_REVISION_DS)
            || self.ace_count as usize > MAX_ACES
        {
            return None;
        }

        let limit = self.acl_size as usize;
        let mut offset = 8usize;
        for _ in 0..self.ace_count as usize {
            let header_end = offset.checked_add(ACE_HEADER_SIZE)?;
            if header_end > limit {
                return None;
            }

            let ace_size =
                u16::from_le_bytes([self.data[offset + 2], self.data[offset + 3]]) as usize;
            if ace_size < ACE_HEADER_SIZE + 4 {
                return None;
            }
            let ace_end = offset.checked_add(ace_size)?;
            if ace_end > limit {
                return None;
            }

            if AceType::from_u8(self.data[offset]).is_none() {
                return None;
            }

            if matches!(
                self.data[offset],
                0x00 | 0x01 | 0x02 | 0x09 | 0x0A | 0x0D | 0x0E | 0x11 | 0x14
            ) && (ace_size < 16 || sid::from_bytes(&self.data[offset + 8..ace_end]).is_none())
            {
                return None;
            }

            offset = ace_end;
        }

        (offset == limit).then_some(offset)
    }

    /// Add an ACCESS_ALLOWED_ACE to this ACL.
    pub fn add_access_allowed(&mut self, sid: &sid, mask: u32, flags: AceFlags) -> bool {
        self.add_ace(AceType::AccessAllowed, flags, mask, sid)
    }

    /// Add an ACCESS_DENIED_ACE to this ACL.
    pub fn add_access_denied(&mut self, sid: &sid, mask: u32, flags: AceFlags) -> bool {
        self.add_ace(AceType::AccessDenied, flags, mask, sid)
    }

    pub fn add_ace(&mut self, ace_type: AceType, flags: AceFlags, mask: u32, sid: &sid) -> bool {
        if !sid.is_valid() || self.ace_count as usize >= MAX_ACES {
            return false;
        }

        let sid_bytes = sid.size();
        let ace_size = (ACE_HEADER_SIZE + 4 + sid_bytes) as u16;
        let Some(offset) = self.used_size() else {
            return false;
        };
        if offset.checked_add(ace_size as usize).is_none()
            || offset + ace_size as usize > self.data.len()
        {
            return false;
        }

        let data = &mut self.data;

        // write header
        data[offset] = ace_type as u8;
        data[offset + 1] = flags.bits();
        data[offset + 2] = (ace_size & 0xFF) as u8;
        data[offset + 3] = (ace_size >> 8) as u8;

        // write mask
        data[offset + 4] = (mask & 0xFF) as u8;
        data[offset + 5] = ((mask >> 8) & 0xFF) as u8;
        data[offset + 6] = ((mask >> 16) & 0xFF) as u8;
        data[offset + 7] = ((mask >> 24) & 0xFF) as u8;

        // Copy the SID bytes. Leaving this area zeroed would make every ACE
        // target the null SID while still reporting a successful insertion.
        let sid_offset = offset + ACE_HEADER_SIZE + 4;
        data[sid_offset] = sid.revision;
        data[sid_offset + 1] = sid.sub_authority_count;
        data[sid_offset + 2..sid_offset + 8].copy_from_slice(&sid.identifier_authority);
        for index in 0..sid.subauthority_count() {
            let sub_offset = sid_offset + 8 + index * 4;
            data[sub_offset..sub_offset + 4]
                .copy_from_slice(&sid.sub_authority[index].to_le_bytes());
        }

        self.ace_count += 1;
        self.acl_size = (offset + ace_size as usize) as u16;
        true
    }

    /// Validate that this ACL is well-formed.
    pub fn is_valid(&self) -> bool {
        self.used_size().is_some()
    }
}

/// Well-known DACLs for common objects.
pub static ACL_EVERYONE_FULL: Acl = Acl::new();

/// Well-known NULL DACL (no protection).
pub static ACL_NULL: Acl = Acl::new();

/// create a default DACL that grants Everyone read/execute access.
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
    // crate::kprintln!("    SE/ACL: initialized (ACL validation, ACE types, access masks)");
}

#[cfg(test)]
mod tests {
    use super::{AceType, Acl, ACL_REVISION};
    use crate::se::sid::sid;

    #[test]
    fn malformed_sid_count_is_bounded() {
        let sid = sid {
            revision: 1,
            sub_authority_count: u8::MAX,
            identifier_authority: [0; 6],
            sub_authority: [0; 8],
        };

        assert!(!sid.is_valid());
        assert_eq!(sid.size(), 8 + 8 * 4);
        let _ = sid.to_string();
        assert!(!sid.equals(&sid::new()));
    }

    #[test]
    fn acl_rejects_truncated_and_oversized_aces() {
        let mut acl = Acl::new();
        acl.revision = ACL_REVISION;
        acl.acl_size = 24;
        acl.ace_count = 1;
        acl.data[8] = 0;
        acl.data[10] = 16;
        acl.data[11] = 0;
        assert!(!acl.is_valid());

        acl.data[10] = 0xff;
        acl.data[11] = 0xff;
        assert!(!acl.is_valid());
    }

    #[test]
    fn acl_copies_and_validates_sid_in_added_ace() {
        let mut acl = Acl::new();
        let sid = sid::well_known(crate::se::sid::WellKnownSid::LocalSystem);

        assert!(acl.add_access_allowed(&sid, 0x1234, super::AceFlags::NONE));
        assert!(acl.is_valid());
        assert_eq!(acl.acl_size as usize, 8 + 4 + 4 + sid.size());
        assert_eq!(acl.data[16], 1);
        assert_eq!(acl.data[17], 1);
        assert_eq!(&acl.data[18..24], &sid.identifier_authority);
        assert_eq!(u32::from_le_bytes(acl.data[24..28].try_into().unwrap()), 18);
    }

    #[test]
    fn acl_rejects_unknown_ace_type() {
        let mut acl = Acl::new();
        acl.acl_size = 24;
        acl.ace_count = 1;
        acl.data[8] = 0xff;
        acl.data[10..12].copy_from_slice(&16u16.to_le_bytes());
        assert!(!acl.is_valid());
    }

    #[test]
    fn mandatory_label_is_not_an_access_allow_ace() {
        assert!(!AceType::SystemMandatoryLabel.is_allowed());
        assert!(!AceType::SystemMandatoryLabel.is_denied());
    }
}
