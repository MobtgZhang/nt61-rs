//! NTFS Reparse Points and Junction Points
//!
//! Implements NTFS reparse points for symbolic links, junction points,
//! and mount points.
//!
//! ## Reparse Point Types
//!
//! - Symbolic links (symlinks)
//! - Junction points (directory symlinks)
//! - Mount points (volume mount points)
//! - HSM (Hierarchical Storage Management) stubs
//! - SIS (Single Instance Storage) links

use alloc::vec::Vec;
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ReparseTag {
    MountPoint = 0xA0000003,
    Hsm = 0xC0000004,
    Sis = 0x80000007,
    Dfsr = 0x80000012,
    Symlink = 0xA000000C,
}

impl ReparseTag {
    pub fn is_microsoft(&self) -> bool {
        (*self as u32) & 0x80000000 != 0
    }

    pub fn is_name_surrogate(&self) -> bool {
        (*self as u32) & 0x20000000 != 0
    }
}

#[repr(C)]
pub struct ReparseDataBuffer {
    pub reparse_tag: u32,
    pub reparse_data_length: u16,
    pub reserved: u16,
}

#[repr(C, packed)]
pub struct SymbolicLinkReparseData {
    pub substitute_name_offset: u16,
    pub substitute_name_length: u16,
    pub print_name_offset: u16,
    pub print_name_length: u16,
    pub flags: u32,
}

#[repr(C, packed)]
pub struct MountPointReparseData {
    pub substitute_name_offset: u16,
    pub substitute_name_length: u16,
    pub print_name_offset: u16,
    pub print_name_length: u16,
}

pub const SYMLINK_FLAG_RELATIVE: u32 = 0x00000001;

pub fn parse_reparse_point(data: &[u8]) -> Result<ReparsePoint, ()> {
    if data.len() < 8 {
        return Err(());
    }

    let reparse_tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let data_length = u16::from_le_bytes([data[4], data[5]]) as usize;

    if data.len() < 8 + data_length {
        return Err(());
    }

    let reparse_data = &data[8..8 + data_length];

    match reparse_tag {
        0xA000000C => {
            parse_symlink(reparse_data)
        }
        0xA0000003 => {
            parse_mount_point(reparse_data)
        }
        _ => {
            Ok(ReparsePoint::Unknown {
                tag: reparse_tag,
                data: reparse_data.to_vec(),
            })
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReparsePoint {
    Symlink {
        target: Vec<u16>,
        print_name: Vec<u16>,
        relative: bool,
    },
    MountPoint {
        target: Vec<u16>,
        print_name: Vec<u16>,
    },
    Unknown {
        tag: u32,
        data: Vec<u8>,
    },
}

impl ReparsePoint {
    pub fn target_path(&self) -> Option<Vec<u16>> {
        match self {
            ReparsePoint::Symlink { target, .. } => Some(target.clone()),
            ReparsePoint::MountPoint { target, .. } => Some(target.clone()),
            ReparsePoint::Unknown { .. } => None,
        }
    }

    pub fn is_relative(&self) -> bool {
        matches!(self, ReparsePoint::Symlink { relative: true, .. })
    }
}

fn parse_symlink(data: &[u8]) -> Result<ReparsePoint, ()> {
    if data.len() < 12 {
        return Err(());
    }

    let substitute_name_offset = u16::from_le_bytes([data[0], data[1]]) as usize;
    let substitute_name_length = u16::from_le_bytes([data[2], data[3]]) as usize;
    let print_name_offset = u16::from_le_bytes([data[4], data[5]]) as usize;
    let print_name_length = u16::from_le_bytes([data[6], data[7]]) as usize;
    let flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    let path_buffer = &data[12..];

    let substitute_start = substitute_name_offset;
    let substitute_end = substitute_start + substitute_name_length;
    if substitute_end > path_buffer.len() {
        return Err(());
    }
    let target = parse_utf16_string(&path_buffer[substitute_start..substitute_end]);

    let print_start = print_name_offset;
    let print_end = print_start + print_name_length;
    if print_end > path_buffer.len() {
        return Err(());
    }
    let print_name = parse_utf16_string(&path_buffer[print_start..print_end]);

    Ok(ReparsePoint::Symlink {
        target,
        print_name,
        relative: (flags & SYMLINK_FLAG_RELATIVE) != 0,
    })
}

fn parse_mount_point(data: &[u8]) -> Result<ReparsePoint, ()> {
    if data.len() < 8 {
        return Err(());
    }

    let substitute_name_offset = u16::from_le_bytes([data[0], data[1]]) as usize;
    let substitute_name_length = u16::from_le_bytes([data[2], data[3]]) as usize;
    let print_name_offset = u16::from_le_bytes([data[4], data[5]]) as usize;
    let print_name_length = u16::from_le_bytes([data[6], data[7]]) as usize;

    let path_buffer = &data[8..];

    let substitute_start = substitute_name_offset;
    let substitute_end = substitute_start + substitute_name_length;
    if substitute_end > path_buffer.len() {
        return Err(());
    }
    let target = parse_utf16_string(&path_buffer[substitute_start..substitute_end]);

    let print_start = print_name_offset;
    let print_end = print_start + print_name_length;
    if print_end > path_buffer.len() {
        return Err(());
    }
    let print_name = parse_utf16_string(&path_buffer[print_start..print_end]);

    Ok(ReparsePoint::MountPoint {
        target,
        print_name,
    })
}

fn parse_utf16_string(data: &[u8]) -> Vec<u16> {
    let mut result = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);
        if ch == 0 {
            break;
        }
        result.push(ch);
        i += 2;
    }
    result
}

pub fn create_symlink_reparse_data(
    target: &[u16],
    relative: bool,
) -> Vec<u8> {
    let mut data = Vec::new();

    data.extend_from_slice(&(ReparseTag::Symlink as u32).to_le_bytes());

    let data_length_pos = data.len();
    data.extend_from_slice(&0u16.to_le_bytes());

    data.extend_from_slice(&0u16.to_le_bytes());

    let substitute_name_offset = 0u16;
    let substitute_name_length = (target.len() * 2) as u16;
    let print_name_offset = substitute_name_length;
    let print_name_length = substitute_name_length;

    data.extend_from_slice(&substitute_name_offset.to_le_bytes());
    data.extend_from_slice(&substitute_name_length.to_le_bytes());
    data.extend_from_slice(&print_name_offset.to_le_bytes());
    data.extend_from_slice(&print_name_length.to_le_bytes());

    let flags = if relative { SYMLINK_FLAG_RELATIVE } else { 0 };
    data.extend_from_slice(&flags.to_le_bytes());

    for &ch in target {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    for &ch in target {
        data.extend_from_slice(&ch.to_le_bytes());
    }

    let actual_length = (data.len() - 8) as u16;
    data[data_length_pos..data_length_pos + 2].copy_from_slice(&actual_length.to_le_bytes());

    data
}

pub fn create_mount_point_reparse_data(target: &[u16]) -> Vec<u8> {
    let mut data = Vec::new();

    data.extend_from_slice(&(ReparseTag::MountPoint as u32).to_le_bytes());

    let data_length_pos = data.len();
    data.extend_from_slice(&0u16.to_le_bytes());

    data.extend_from_slice(&0u16.to_le_bytes());

    let substitute_name_offset = 0u16;
    let substitute_name_length = (target.len() * 2) as u16;
    let print_name_offset = substitute_name_length;
    let print_name_length = substitute_name_length;

    data.extend_from_slice(&substitute_name_offset.to_le_bytes());
    data.extend_from_slice(&substitute_name_length.to_le_bytes());
    data.extend_from_slice(&print_name_offset.to_le_bytes());
    data.extend_from_slice(&print_name_length.to_le_bytes());

    for &ch in target {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    for &ch in target {
        data.extend_from_slice(&ch.to_le_bytes());
    }

    let actual_length = (data.len() - 8) as u16;
    data[data_length_pos..data_length_pos + 2].copy_from_slice(&actual_length.to_le_bytes());

    data
}

pub fn has_reparse_point(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}
