//! Registry Security Descriptor Support
//!
//! Implements security descriptors (SDs) for registry keys, following the
//! Windows Security Descriptor format with DACL/SACL support.

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use core::fmt;

use super::hive::HiveError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityControl {
    pub owner_defaulted: bool,
    pub group_defaulted: bool,
    pub dacl_present: bool,
    pub dacl_defaulted: bool,
    pub sacl_present: bool,
    pub sacl_defaulted: bool,
    pub dacl_auto_inherit_req: bool,
    pub sacl_auto_inherit_req: bool,
    pub dacl_auto_inherited: bool,
    pub sacl_auto_inherited: bool,
    pub dacl_protected: bool,
    pub sacl_protected: bool,
    pub rm_control_valid: bool,
    pub self_relative: bool,
}

impl SecurityControl {
    pub const OWNER_DEFAULTED: u16 = 0x0001;
    pub const GROUP_DEFAULTED: u16 = 0x0002;
    pub const DACL_PRESENT: u16 = 0x0004;
    pub const DACL_DEFAULTED: u16 = 0x0008;
    pub const SACL_PRESENT: u16 = 0x0010;
    pub const SACL_DEFAULTED: u16 = 0x0020;
    pub const DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
    pub const SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
    pub const DACL_AUTO_INHERITED: u16 = 0x0400;
    pub const SACL_AUTO_INHERITED: u16 = 0x0800;
    pub const DACL_PROTECTED: u16 = 0x1000;
    pub const SACL_PROTECTED: u16 = 0x2000;
    pub const RM_CONTROL_VALID: u16 = 0x4000;
    pub const SELF_RELATIVE: u16 = 0x8000;

    pub fn from_flags(flags: u16) -> Self {
        Self {
            owner_defaulted: (flags & Self::OWNER_DEFAULTED) != 0,
            group_defaulted: (flags & Self::GROUP_DEFAULTED) != 0,
            dacl_present: (flags & Self::DACL_PRESENT) != 0,
            dacl_defaulted: (flags & Self::DACL_DEFAULTED) != 0,
            sacl_present: (flags & Self::SACL_PRESENT) != 0,
            sacl_defaulted: (flags & Self::SACL_DEFAULTED) != 0,
            dacl_auto_inherit_req: (flags & Self::DACL_AUTO_INHERIT_REQ) != 0,
            sacl_auto_inherit_req: (flags & Self::SACL_AUTO_INHERIT_REQ) != 0,
            dacl_auto_inherited: (flags & Self::DACL_AUTO_INHERITED) != 0,
            sacl_auto_inherited: (flags & Self::SACL_AUTO_INHERITED) != 0,
            dacl_protected: (flags & Self::DACL_PROTECTED) != 0,
            sacl_protected: (flags & Self::SACL_PROTECTED) != 0,
            rm_control_valid: (flags & Self::RM_CONTROL_VALID) != 0,
            self_relative: (flags & Self::SELF_RELATIVE) != 0,
        }
    }

    pub fn to_flags(&self) -> u16 {
        let mut flags = 0;
        if self.owner_defaulted { flags |= Self::OWNER_DEFAULTED; }
        if self.group_defaulted { flags |= Self::GROUP_DEFAULTED; }
        if self.dacl_present { flags |= Self::DACL_PRESENT; }
        if self.dacl_defaulted { flags |= Self::DACL_DEFAULTED; }
        if self.sacl_present { flags |= Self::SACL_PRESENT; }
        if self.sacl_defaulted { flags |= Self::SACL_DEFAULTED; }
        if self.dacl_auto_inherit_req { flags |= Self::DACL_AUTO_INHERIT_REQ; }
        if self.sacl_auto_inherit_req { flags |= Self::SACL_AUTO_INHERIT_REQ; }
        if self.dacl_auto_inherited { flags |= Self::DACL_AUTO_INHERITED; }
        if self.sacl_auto_inherited { flags |= Self::SACL_AUTO_INHERITED; }
        if self.dacl_protected { flags |= Self::DACL_PROTECTED; }
        if self.sacl_protected { flags |= Self::SACL_PROTECTED; }
        if self.rm_control_valid { flags |= Self::RM_CONTROL_VALID; }
        if self.self_relative { flags |= Self::SELF_RELATIVE; }
        flags
    }
}

impl Default for SecurityControl {
    fn default() -> Self {
        Self::from_flags(Self::DACL_PRESENT | Self::SELF_RELATIVE)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAccessRights {
    pub query_value: bool,
    pub set_value: bool,
    pub create_sub_key: bool,
    pub enumerate_sub_keys: bool,
    pub notify: bool,
    pub create_link: bool,
    pub wow64_64key: bool,
    pub wow64_32key: bool,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl KeyAccessRights {
    pub const QUERY_VALUE: u32 = 0x0001;
    pub const SET_VALUE: u32 = 0x0002;
    pub const CREATE_SUB_KEY: u32 = 0x0004;
    pub const ENUMERATE_SUB_KEYS: u32 = 0x0008;
    pub const NOTIFY: u32 = 0x0010;
    pub const CREATE_LINK: u32 = 0x0020;
    pub const WOW64_64KEY: u32 = 0x0100;
    pub const WOW64_32KEY: u32 = 0x0200;
    pub const READ: u32 = 0x20019;
    pub const WRITE: u32 = 0x20006;
    pub const EXECUTE: u32 = 0x20019;
    pub const ALL_ACCESS: u32 = 0xF003F;

    pub fn from_mask(mask: u32) -> Self {
        Self {
            query_value: (mask & Self::QUERY_VALUE) != 0,
            set_value: (mask & Self::SET_VALUE) != 0,
            create_sub_key: (mask & Self::CREATE_SUB_KEY) != 0,
            enumerate_sub_keys: (mask & Self::ENUMERATE_SUB_KEYS) != 0,
            notify: (mask & Self::NOTIFY) != 0,
            create_link: (mask & Self::CREATE_LINK) != 0,
            wow64_64key: (mask & Self::WOW64_64KEY) != 0,
            wow64_32key: (mask & Self::WOW64_32KEY) != 0,
            read: (mask & Self::READ) != 0,
            write: (mask & Self::WRITE) != 0,
            execute: (mask & Self::EXECUTE) != 0,
        }
    }

    pub fn to_mask(&self) -> u32 {
        let mut mask = 0;
        if self.query_value { mask |= Self::QUERY_VALUE; }
        if self.set_value { mask |= Self::SET_VALUE; }
        if self.create_sub_key { mask |= Self::CREATE_SUB_KEY; }
        if self.enumerate_sub_keys { mask |= Self::ENUMERATE_SUB_KEYS; }
        if self.notify { mask |= Self::NOTIFY; }
        if self.create_link { mask |= Self::CREATE_LINK; }
        if self.wow64_64key { mask |= Self::WOW64_64KEY; }
        if self.wow64_32key { mask |= Self::WOW64_32KEY; }
        mask
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    pub revision: u8,
    pub authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    pub fn new(authority: [u8; 6], sub_authorities: Vec<u32>) -> Self {
        Self {
            revision: 1,
            authority,
            sub_authorities,
        }
    }

    pub fn everyone() -> Self {
        Self::new([0, 0, 0, 0, 0, 1], vec![0])
    }

    pub fn local_system() -> Self {
        Self::new([0, 0, 0, 0, 0, 5], vec![18])
    }

    pub fn administrators() -> Self {
        Self::new([0, 0, 0, 0, 0, 5], vec![32, 544])
    }

    pub fn users() -> Self {
        Self::new([0, 0, 0, 0, 0, 5], vec![32, 545])
    }

    pub fn parse(data: &[u8]) -> Result<Self, HiveError> {
        if data.len() < 8 {
            return Err(HiveError::Truncated);
        }

        let revision = data[0];
        let sub_auth_count = data[1] as usize;
        let mut authority = [0u8; 6];
        authority.copy_from_slice(&data[2..8]);

        if data.len() < 8 + sub_auth_count * 4 {
            return Err(HiveError::Truncated);
        }

        let mut sub_authorities = Vec::with_capacity(sub_auth_count);
        for i in 0..sub_auth_count {
            let offset = 8 + i * 4;
            let sub_auth = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            sub_authorities.push(sub_auth);
        }

        Ok(Self {
            revision,
            authority,
            sub_authorities,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.sub_authorities.len() * 4);
        bytes.push(self.revision);
        bytes.push(self.sub_authorities.len() as u8);
        bytes.extend_from_slice(&self.authority);
        for sub_auth in &self.sub_authorities {
            bytes.extend_from_slice(&sub_auth.to_le_bytes());
        }
        bytes
    }

    pub fn len(&self) -> usize {
        8 + self.sub_authorities.len() * 4
    }

    pub fn is_empty(&self) -> bool {
        self.sub_authorities.is_empty()
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-{}-", self.revision)?;

        let authority_value = u64::from_be_bytes([
            0, 0,
            self.authority[0], self.authority[1],
            self.authority[2], self.authority[3],
            self.authority[4], self.authority[5],
        ]);
        write!(f, "{}", authority_value)?;

        for sub_auth in &self.sub_authorities {
            write!(f, "-{}", sub_auth)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceType {
    AccessAllowed = 0x00,
    AccessDenied = 0x01,
    SystemAudit = 0x02,
    SystemAlarm = 0x03,
}

impl AceType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::AccessAllowed),
            0x01 => Some(Self::AccessDenied),
            0x02 => Some(Self::SystemAudit),
            0x03 => Some(Self::SystemAlarm),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub ace_type: AceType,
    pub ace_flags: u8,
    pub access_mask: u32,
    pub sid: Sid,
}

impl Ace {
    pub fn new(ace_type: AceType, ace_flags: u8, access_mask: u32, sid: Sid) -> Self {
        Self {
            ace_type,
            ace_flags,
            access_mask,
            sid,
        }
    }

    pub fn parse(data: &[u8]) -> Result<Self, HiveError> {
        if data.len() < 8 {
            return Err(HiveError::Truncated);
        }

        let ace_type = AceType::from_u8(data[0]).ok_or(HiveError::BadCellKind(data[0]))?;
        let ace_flags = data[1];
        let _size = u16::from_le_bytes([data[2], data[3]]);
        let access_mask = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let sid = Sid::parse(&data[8..])?;

        Ok(Self {
            ace_type,
            ace_flags,
            access_mask,
            sid,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let sid_bytes = self.sid.to_bytes();
        let size = (8 + sid_bytes.len()) as u16;

        let mut bytes = Vec::with_capacity(size as usize);
        bytes.push(self.ace_type as u8);
        bytes.push(self.ace_flags);
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&self.access_mask.to_le_bytes());
        bytes.extend_from_slice(&sid_bytes);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    pub revision: u8,
    pub aces: Vec<Ace>,
}

impl Acl {
    pub fn new() -> Self {
        Self {
            revision: 2, // ACL_REVISION
            aces: Vec::new(),
        }
    }

    pub fn add_ace(&mut self, ace: Ace) {
        self.aces.push(ace);
    }

    pub fn parse(data: &[u8]) -> Result<Self, HiveError> {
        if data.len() < 8 {
            return Err(HiveError::Truncated);
        }

        let revision = data[0];
        let ace_count = u16::from_le_bytes([data[4], data[5]]) as usize;

        let mut aces = Vec::with_capacity(ace_count);
        let mut offset = 8;

        for _ in 0..ace_count {
            if offset >= data.len() {
                return Err(HiveError::Truncated);
            }

            let ace = Ace::parse(&data[offset..])?;
            let ace_size = ace.to_bytes().len();
            aces.push(ace);
            offset += ace_size;
        }

        Ok(Self { revision, aces })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ace_bytes = Vec::new();
        for ace in &self.aces {
            ace_bytes.extend_from_slice(&ace.to_bytes());
        }

        let size = (8 + ace_bytes.len()) as u16;

        let mut bytes = Vec::with_capacity(size as usize);
        bytes.push(self.revision);
        bytes.push(0); // Sbz1
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&(self.aces.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0, 0]); // Sbz2
        bytes.extend_from_slice(&ace_bytes);
        bytes
    }
}

impl Default for Acl {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptor {
    pub control: SecurityControl,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub dacl: Option<Acl>,
    pub sacl: Option<Acl>,
}

impl SecurityDescriptor {
    pub fn new() -> Self {
        Self {
            control: SecurityControl::default(),
            owner: None,
            group: None,
            dacl: None,
            sacl: None,
        }
    }

    pub fn default_key_sd() -> Self {
        let mut sd = Self::new();
        sd.owner = Some(Sid::administrators());
        sd.group = Some(Sid::administrators());

        let mut dacl = Acl::new();

        dacl.add_ace(Ace::new(
            AceType::AccessAllowed,
            0,
            KeyAccessRights::ALL_ACCESS,
            Sid::administrators(),
        ));

        dacl.add_ace(Ace::new(
            AceType::AccessAllowed,
            0,
            KeyAccessRights::ALL_ACCESS,
            Sid::local_system(),
        ));

        dacl.add_ace(Ace::new(
            AceType::AccessAllowed,
            0,
            KeyAccessRights::READ,
            Sid::users(),
        ));

        sd.dacl = Some(dacl);
        sd
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 20]; // Header size
        bytes[0] = 1; // Revision
        bytes[1] = 0; // Sbz1

        let control = self.control.to_flags() | SecurityControl::SELF_RELATIVE;
        bytes[2..4].copy_from_slice(&control.to_le_bytes());

        let mut offset = 20u32;

        if let Some(ref owner) = self.owner {
            let owner_bytes = owner.to_bytes();
            bytes[4..8].copy_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(&owner_bytes);
            offset += owner_bytes.len() as u32;
        } else {
            bytes[4..8].copy_from_slice(&0u32.to_le_bytes());
        }

        if let Some(ref group) = self.group {
            let group_bytes = group.to_bytes();
            bytes[8..12].copy_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(&group_bytes);
            offset += group_bytes.len() as u32;
        } else {
            bytes[8..12].copy_from_slice(&0u32.to_le_bytes());
        }

        if let Some(ref sacl) = self.sacl {
            let sacl_bytes = sacl.to_bytes();
            bytes[12..16].copy_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(&sacl_bytes);
            offset += sacl_bytes.len() as u32;
        } else {
            bytes[12..16].copy_from_slice(&0u32.to_le_bytes());
        }

        if let Some(ref dacl) = self.dacl {
            let dacl_bytes = dacl.to_bytes();
            bytes[16..20].copy_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(&dacl_bytes);
        } else {
            bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
        }

        bytes
    }
}

impl Default for SecurityDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

pub fn check_access(
    sd: &SecurityDescriptor,
    sid: &Sid,
    requested_access: u32,
) -> bool {
    let dacl = match &sd.dacl {
        Some(dacl) => dacl,
        None => return true,
    };

    let mut granted_access = 0u32;
    let mut denied_access = 0u32;

    for ace in &dacl.aces {
        if ace.sid != *sid {
            continue;
        }

        match ace.ace_type {
            AceType::AccessAllowed => {
                granted_access |= ace.access_mask;
            }
            AceType::AccessDenied => {
                denied_access |= ace.access_mask;
            }
            _ => {}
        }
    }

    if (denied_access & requested_access) != 0 {
        return false;
    }

    (granted_access & requested_access) == requested_access
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sid_parsing() {
        let everyone = Sid::everyone();
        let bytes = everyone.to_bytes();
        let parsed = Sid::parse(&bytes).unwrap();
        assert_eq!(everyone, parsed);
        assert_eq!(format!("{}", everyone), "S-1-1-0");
    }

    #[test]
    fn test_access_check() {
        let sd = SecurityDescriptor::default_key_sd();
        let admin_sid = Sid::administrators();

        assert!(check_access(&sd, &admin_sid, KeyAccessRights::ALL_ACCESS));
        assert!(check_access(&sd, &admin_sid, KeyAccessRights::READ));
    }

    #[test]
    fn test_security_descriptor_serialization() {
        let sd = SecurityDescriptor::default_key_sd();
        let bytes = sd.to_bytes();

        assert_eq!(bytes[0], 1); // Revision
        assert_eq!(bytes.len() > 20, true);
    }
}
