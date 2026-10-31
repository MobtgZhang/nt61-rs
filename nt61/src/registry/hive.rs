//! Windows regf registry hive parser.
//!
//! Implements the real Windows on-disk registry format (major version 1),
//! as used by NTOSKRNL's Configuration Manager. This parser reads
//! standard regf hives — the same format produced by reg save,
//! regedit export, and the Windows kernel's CmpHive routines —
//! replacing the previous custom format that could not mount
//! real Windows hive files.
//!
//! Every offset stored inside a cell is hbin-relative: add
//! HBIN_BASE (0x1000) to obtain the absolute file offset.
//! Each cell begins with a 4-byte signed segment length;
//! negative = allocated, positive = free, 8-byte aligned.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// REGF header magic (lowercase ASCII).
pub const REGF_MAGIC: &[u8; 4] = b"regf";
/// HBIN block magic (lowercase ASCII).
pub const HBIN_MAGIC: &[u8; 4] = b"hbin";
/// REGF header size (must be exactly one HBIN = 4096 bytes).
pub const REGF_HEADER_SIZE: usize = 0x1000;
/// First HBIN starts immediately after the header.
pub const HBIN_BASE: usize = 0x1000;
/// HBIN page size (4096 bytes).
pub const HBIN_SIZE: usize = 0x1000;
/// HBIN header size (magic + offset_first + page_size + 20 bytes reserved).
pub const HBIN_HEADER_SIZE: usize = 32;
/// Required major version.
pub const REGF_MAJOR_VERSION: u32 = 1;
/// Offset of the major version field in the REGF header.
const MAJOR_VERSION_FIELD: usize = 0x14;
/// Offset of the root key offset field in the REGF header.
const ROOT_OFFSET_FIELD: usize = 0x24;
/// Offset of the checksum field in the REGF header.
const CHECKSUM_OFFSET: usize = 0x1FC;

const ID_NK: &[u8; 2] = b"nk";
const ID_VK: &[u8; 2] = b"vk";
const ID_LF: &[u8; 2] = b"lf";
const ID_LH: &[u8; 2] = b"lh";
const ID_LI: &[u8; 2] = b"li";
const ID_RI: &[u8; 2] = b"ri";

const NK_FLAGS: usize = 0x06;
const NK_NR_SUBKEYS: usize = 0x18;
const NK_SUBKEY_LF: usize = 0x20;
const NK_NR_VALUES: usize = 0x28;
const NK_VALLIST: usize = 0x2C;
const NK_NAME_LEN: usize = 0x4C;
const NK_NAME: usize = 0x50;
const NK_FLAG_ASCII_NAME: u16 = 0x0020;

const VK_NAME_LEN: usize = 0x06;
const VK_DATA_SIZE: usize = 0x08;
const VK_DATA_OFFSET: usize = 0x0C;
const VK_DATA_TYPE: usize = 0x10;
const VK_FLAGS: usize = 0x14;
const VK_NAME: usize = 0x18;
const VK_FLAG_ASCII_NAME: u32 = 0x0000_0001;
const VK_DATA_INLINE_FLAG: u32 = 0x8000_0000;
const VK_INLINE_MAX: usize = 4;
const NO_OFFSET: u32 = 0xFFFF_FFFF;

#[derive(Debug)]
pub enum HiveError {
    TooSmall,
    BadMagic,
    UnsupportedVersion(u32),
    BadChecksum,
    Truncated,
    BadCellKind(u8),
    BadUtf16,
    OutOfBounds,
    InvalidPointer,
}

impl fmt::Display for HiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HiveError::TooSmall => write!(f, "hive too small"),
            HiveError::BadMagic => write!(f, "bad magic"),
            HiveError::UnsupportedVersion(v) => write!(f, "unsupported version {}", v),
            HiveError::BadChecksum => write!(f, "checksum mismatch"),
            HiveError::Truncated => write!(f, "truncated cell"),
            HiveError::BadCellKind(k) => write!(f, "unknown cell kind 0x{:02X}", k),
            HiveError::BadUtf16 => write!(f, "invalid UTF-16"),
            HiveError::OutOfBounds => write!(f, "offset out of bounds"),
            HiveError::InvalidPointer => write!(f, "invalid pointer"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ValueType {
    None = 0,
    String = 1,
    ExpandString = 2,
    Binary = 3,
    DWord = 4,
    DWordBigEndian = 5,
    Link = 6,
    MultiString = 7,
    ResourceList = 8,
    FullResourceDescriptor = 9,
    ResourceRequirementsList = 10,
    QWord = 11,
}

impl ValueType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => ValueType::None,
            1 => ValueType::String,
            2 => ValueType::ExpandString,
            3 => ValueType::Binary,
            4 => ValueType::DWord,
            5 => ValueType::DWordBigEndian,
            6 => ValueType::Link,
            7 => ValueType::MultiString,
            8 => ValueType::ResourceList,
            9 => ValueType::FullResourceDescriptor,
            10 => ValueType::ResourceRequirementsList,
            11 => ValueType::QWord,
            _ => ValueType::None,
        }
    }

    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone)]
pub struct Value {
    pub name: String,
    pub value_type: ValueType,
    pub data: Vec<u8>,
}

impl Value {
    pub fn as_utf16_string(&self) -> Option<String> {
        if self.data.len() < 2 || !self.data.len().is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = self
            .data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16(&units).ok()
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() < 4 {
            return None;
        }
        Some(u32::from_le_bytes([
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
        ]))
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.data.len() < 8 {
            return None;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data[..8]);
        Some(u64::from_le_bytes(b))
    }
}

#[derive(Debug, Clone)]
pub struct KeyNode {
    pub offset: u32,
    pub name: String,
    pub flags: u16,
}

pub struct Hive<'a> {
    data: &'a [u8],
    root_offset: usize,
    cell_count: u32,
}

impl<'a> Hive<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, HiveError> {
        if bytes.len() < REGF_HEADER_SIZE {
            return Err(HiveError::TooSmall);
        }

        if &bytes[0..4] != REGF_MAGIC {
            return Err(HiveError::BadMagic);
        }

        let major = read_u32(bytes, MAJOR_VERSION_FIELD).ok_or(HiveError::TooSmall)?;
        if major != REGF_MAJOR_VERSION {
            return Err(HiveError::UnsupportedVersion(major));
        }

        let stored = read_u32(bytes, CHECKSUM_OFFSET).ok_or(HiveError::TooSmall)?;
        let computed = compute_header_checksum(bytes);
        if stored != computed {
            return Err(HiveError::BadChecksum);
        }

        let root_rel = read_u32(bytes, ROOT_OFFSET_FIELD).ok_or(HiveError::TooSmall)?;
        let root_abs = HBIN_BASE + root_rel as usize;
        if root_abs >= bytes.len() {
            return Err(HiveError::OutOfBounds);
        }

        let cell_count = Self::count_cells(bytes)?;

        Ok(Hive {
            data: bytes,
            root_offset: root_abs,
            cell_count,
        })
    }

    fn count_cells(data: &[u8]) -> Result<u32, HiveError> {
        if data.len() < HBIN_BASE + HBIN_HEADER_SIZE {
            return Err(HiveError::TooSmall);
        }
        if &data[HBIN_BASE..HBIN_BASE + 4] != HBIN_MAGIC {
            return Err(HiveError::BadMagic);
        }

        let mut hbin_off = HBIN_BASE;
        let mut count = 0u32;

        while hbin_off + HBIN_HEADER_SIZE <= data.len() {
            if &data[hbin_off..hbin_off + 4] != HBIN_MAGIC {
                break;
            }
            let hbin_size = read_u32(data, hbin_off + 8).ok_or(HiveError::Truncated)? as usize;
            if hbin_size == 0 || hbin_size < HBIN_HEADER_SIZE {
                break;
            }

            let mut cell_off = hbin_off + HBIN_HEADER_SIZE;
            let hbin_end = hbin_off + hbin_size;
            while cell_off + 4 <= hbin_end && cell_off + 4 <= data.len() {
                let seg_len = read_i32(data, cell_off).ok_or(HiveError::Truncated)?;
                if seg_len == 0 {
                    break;
                }
                let abs_len = seg_len.unsigned_abs() as usize;
                if abs_len == 0 {
                    break;
                }
                if seg_len < 0 {
                    count += 1;
                }
                cell_off += abs_len;
            }

            hbin_off += hbin_size;
        }

        Ok(count)
    }

    pub fn cell_count(&self) -> u32 {
        self.cell_count
    }

    pub fn root(&self) -> Result<KeyNode, HiveError> {
        self.read_nk(self.root_offset)
    }

    fn read_nk(&self, offset: usize) -> Result<KeyNode, HiveError> {
        if offset + NK_NAME > self.data.len() {
            return Err(HiveError::Truncated);
        }

        let seg_len = read_i32(self.data, offset).ok_or(HiveError::Truncated)?;
        if seg_len >= 0 {
            return Err(HiveError::Truncated);
        }

        if &self.data[offset + 4..offset + 6] != ID_NK {
            return Err(HiveError::BadCellKind(b'k'));
        }

        let flags = read_u16(self.data, offset + NK_FLAGS).ok_or(HiveError::Truncated)?;
        let name_len =
            read_u16(self.data, offset + NK_NAME_LEN).ok_or(HiveError::Truncated)? as usize;

        let name_start = offset + NK_NAME;
        if name_start + name_len > self.data.len() {
            return Err(HiveError::Truncated);
        }

        let name = if flags & NK_FLAG_ASCII_NAME != 0 {
            String::from_utf8_lossy(&self.data[name_start..name_start + name_len]).into_owned()
        } else {
            decode_hive_name(&self.data[name_start..name_start + name_len])
        };

        Ok(KeyNode {
            offset: offset as u32,
            name,
            flags,
        })
    }

    pub fn subkeys(&self, node: &KeyNode) -> Result<Vec<KeyNode>, HiveError> {
        if offset_field(self.data, node.offset, NK_NR_SUBKEYS)? == 0 {
            return Ok(Vec::new());
        }
        let subkey_rel =
            read_u32(self.data, node.offset as usize + NK_SUBKEY_LF).ok_or(HiveError::Truncated)?;
        if subkey_rel == NO_OFFSET || subkey_rel == 0 {
            return Ok(Vec::new());
        }

        let subkey_abs = HBIN_BASE + subkey_rel as usize;
        if subkey_abs + 6 > self.data.len() {
            return Err(HiveError::OutOfBounds);
        }

        let id = &self.data[subkey_abs + 4..subkey_abs + 6];
        let nk_offsets = if id == ID_LF || id == ID_LH {
            self.read_lf_lh(subkey_abs)?
        } else if id == ID_LI {
            self.read_li(subkey_abs)?
        } else if id == ID_RI {
            self.read_ri(subkey_abs)?
        } else {
            return Err(HiveError::BadCellKind(self.data[subkey_abs + 4]));
        };

        let mut result = Vec::with_capacity(nk_offsets.len());
        for nk_off in nk_offsets {
            if let Ok(k) = self.read_nk(nk_off) {
                result.push(k);
            }
        }
        Ok(result)
    }

    fn read_lf_lh(&self, offset: usize) -> Result<Vec<usize>, HiveError> {
        let nr = read_u16(self.data, offset + 6).ok_or(HiveError::Truncated)? as usize;
        let mut offsets = Vec::with_capacity(nr);
        for i in 0..nr {
            let entry = offset + 8 + i * 8;
            if entry + 4 > self.data.len() {
                break;
            }
            let rel = read_u32(self.data, entry).ok_or(HiveError::Truncated)?;
            offsets.push(HBIN_BASE + rel as usize);
        }
        Ok(offsets)
    }

    fn read_li(&self, offset: usize) -> Result<Vec<usize>, HiveError> {
        let nr = read_u16(self.data, offset + 6).ok_or(HiveError::Truncated)? as usize;
        let mut offsets = Vec::with_capacity(nr);
        for i in 0..nr {
            let entry = offset + 8 + i * 4;
            if entry + 4 > self.data.len() {
                break;
            }
            let rel = read_u32(self.data, entry).ok_or(HiveError::Truncated)?;
            offsets.push(HBIN_BASE + rel as usize);
        }
        Ok(offsets)
    }

    fn read_ri(&self, offset: usize) -> Result<Vec<usize>, HiveError> {
        let nr = read_u16(self.data, offset + 6).ok_or(HiveError::Truncated)? as usize;
        let mut offsets = Vec::new();
        for i in 0..nr {
            let entry = offset + 8 + i * 4;
            if entry + 4 > self.data.len() {
                break;
            }
            let rel = read_u32(self.data, entry).ok_or(HiveError::Truncated)?;
            let sub_abs = HBIN_BASE + rel as usize;
            if sub_abs + 6 > self.data.len() {
                continue;
            }
            let sub_id = &self.data[sub_abs + 4..sub_abs + 6];
            let sub_offsets = if sub_id == ID_LF || sub_id == ID_LH {
                self.read_lf_lh(sub_abs)?
            } else if sub_id == ID_LI {
                self.read_li(sub_abs)?
            } else if sub_id == ID_RI {
                self.read_ri(sub_abs)?
            } else {
                continue;
            };
            offsets.extend(sub_offsets);
        }
        Ok(offsets)
    }

    pub fn values(&self, node: &KeyNode) -> Result<Vec<Value>, HiveError> {
        let nr_values =
            read_u32(self.data, node.offset as usize + NK_NR_VALUES).ok_or(HiveError::Truncated)?;
        let vallist_rel =
            read_u32(self.data, node.offset as usize + NK_VALLIST).ok_or(HiveError::Truncated)?;
        if nr_values == 0 || vallist_rel == NO_OFFSET || vallist_rel == 0 {
            return Ok(Vec::new());
        }

        let vallist_abs = HBIN_BASE + vallist_rel as usize;
        let list_start = vallist_abs + 4;
        if list_start + (nr_values as usize) * 4 > self.data.len() {
            return Err(HiveError::Truncated);
        }

        let mut result = Vec::with_capacity(nr_values as usize);
        for i in 0..nr_values as usize {
            let entry = list_start + i * 4;
            let vk_rel = read_u32(self.data, entry).ok_or(HiveError::Truncated)?;
            let vk_abs = HBIN_BASE + vk_rel as usize;
            if let Ok(v) = self.read_vk(vk_abs) {
                result.push(v);
            }
        }
        Ok(result)
    }

    fn read_vk(&self, offset: usize) -> Result<Value, HiveError> {
        if offset + VK_NAME > self.data.len() {
            return Err(HiveError::Truncated);
        }

        let seg_len = read_i32(self.data, offset).ok_or(HiveError::Truncated)?;
        if seg_len >= 0 {
            return Err(HiveError::Truncated);
        }

        if &self.data[offset + 4..offset + 6] != ID_VK {
            return Err(HiveError::BadCellKind(b'v'));
        }

        let name_len =
            read_u16(self.data, offset + VK_NAME_LEN).ok_or(HiveError::Truncated)? as usize;
        let data_size_raw =
            read_u32(self.data, offset + VK_DATA_SIZE).ok_or(HiveError::Truncated)?;
        let data_offset_raw =
            read_u32(self.data, offset + VK_DATA_OFFSET).ok_or(HiveError::Truncated)?;
        let data_type_raw =
            read_u32(self.data, offset + VK_DATA_TYPE).ok_or(HiveError::Truncated)?;
        let flags = read_u32(self.data, offset + VK_FLAGS).ok_or(HiveError::Truncated)?;

        let name_start = offset + VK_NAME;
        if name_start + name_len > self.data.len() {
            return Err(HiveError::Truncated);
        }

        let name = if flags & VK_FLAG_ASCII_NAME != 0 {
            String::from_utf8_lossy(&self.data[name_start..name_start + name_len]).into_owned()
        } else {
            decode_hive_name(&self.data[name_start..name_start + name_len])
        };

        let inline = (data_size_raw & VK_DATA_INLINE_FLAG) != 0;
        let data_len = (data_size_raw & !VK_DATA_INLINE_FLAG) as usize;

        let data = if inline {
            let le = data_offset_raw.to_le_bytes();
            le[..data_len.min(VK_INLINE_MAX)].to_vec()
        } else {
            let data_abs = HBIN_BASE + data_offset_raw as usize;
            if data_abs + data_len > self.data.len() {
                return Err(HiveError::Truncated);
            }
            self.data[data_abs..data_abs + data_len].to_vec()
        };

        Ok(Value {
            name,
            value_type: ValueType::from_u32(data_type_raw),
            data,
        })
    }

    pub fn find_subkey(&self, node: &KeyNode, name: &str) -> Result<Option<KeyNode>, HiveError> {
        for k in self.subkeys(node)? {
            if k.name == name {
                return Ok(Some(k));
            }
        }
        Ok(None)
    }

    pub fn find_value(&self, node: &KeyNode, name: &str) -> Result<Option<Value>, HiveError> {
        for v in self.values(node)? {
            if v.name == name {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    pub fn open_path(&self, path: &[&str]) -> Result<Option<KeyNode>, HiveError> {
        let mut current = self.root()?;
        for component in path {
            match self.find_subkey(&current, component)? {
                Some(next) => current = next,
                None => return Ok(None),
            }
        }
        Ok(Some(current))
    }
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

fn read_i32(data: &[u8], off: usize) -> Option<i32> {
    if off + 4 > data.len() {
        return None;
    }
    Some(i32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn offset_field(data: &[u8], cell_offset: u32, field_offset: usize) -> Result<u32, HiveError> {
    read_u32(data, cell_offset as usize + field_offset).ok_or(HiveError::Truncated)
}

fn compute_header_checksum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut off = 0usize;
    while off + 4 <= CHECKSUM_OFFSET {
        if let Some(v) = read_u32(data, off) {
            sum ^= v;
        }
        off += 4;
    }
    sum
}

fn decode_hive_name(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    if !data.len().is_multiple_of(2) {
        return String::from_utf8_lossy(data).into_owned();
    }

    // Callers only reach this path when the name flag says the name is
    // NOT ASCII, so even-length data is UTF-16LE per the hive format.
    // The old first-byte heuristic (data[0] < 0x7F && data[1] == 0)
    // misdecoded every name whose first character is non-ASCII, such as
    // CJK key names whose UTF-16LE bytes look like text in neither
    // encoding. Decode the units and fall back to lossy ASCII only when
    // they are not valid UTF-16.
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    match String::from_utf16(&units) {
        Ok(s) => s,
        Err(_) => String::from_utf8_lossy(data).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn build_test_hive() -> Vec<u8> {
        let total_size = REGF_HEADER_SIZE + HBIN_SIZE;
        let mut buf = vec![0u8; total_size];

        buf[0..4].copy_from_slice(REGF_MAGIC);
        buf[MAJOR_VERSION_FIELD..MAJOR_VERSION_FIELD + 4].copy_from_slice(&1u32.to_le_bytes());

        let base = HBIN_BASE;
        let root_nk = base + HBIN_HEADER_SIZE;

        // We need to know offsets of all cells up-front to write them.
        // Root nk: 0x50 + 4 name bytes, aligned to 8 → 0x58
        let root_nk_size = 0x58usize;
        let lf_cell = root_nk + root_nk_size;
        // lf cell: seg_len(4) + "lf"(2) + nr(2) + entry(8) = 16
        let lf_cell_size = 16usize;
        let child_nk = lf_cell + lf_cell_size;
        // child nk: 0x50 + 6 name bytes, aligned to 8 → 0x58
        let child_nk_size = 0x58usize;
        let vallist_cell = child_nk + child_nk_size;
        // vallist: seg_len(4) + 1 x u32 = 8
        let vallist_size = 8usize;
        let vk_cell = vallist_cell + vallist_size;
        // vk: 0x18 + 9 name bytes, aligned to 8 → 0x28
        let vk_cell_size = 0x28usize;

        // --- REGF header ---
        let root_rel = (root_nk - HBIN_BASE) as u32;
        buf[ROOT_OFFSET_FIELD..ROOT_OFFSET_FIELD + 4].copy_from_slice(&root_rel.to_le_bytes());

        // --- HBIN header ---
        buf[HBIN_BASE..HBIN_BASE + 4].copy_from_slice(HBIN_MAGIC);
        buf[HBIN_BASE + 8..HBIN_BASE + 12].copy_from_slice(&(HBIN_SIZE as u32).to_le_bytes());

        // --- Root nk "ROOT" ---
        buf[root_nk..root_nk + 4].copy_from_slice(&(-(root_nk_size as i32)).to_le_bytes());
        buf[root_nk + 4..root_nk + 6].copy_from_slice(ID_NK);
        let root_flags: u16 = 0x0004 | NK_FLAG_ASCII_NAME;
        buf[root_nk + NK_FLAGS..root_nk + NK_FLAGS + 2].copy_from_slice(&root_flags.to_le_bytes());
        buf[root_nk + NK_NR_SUBKEYS..root_nk + NK_NR_SUBKEYS + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        let lf_rel = (lf_cell - HBIN_BASE) as u32;
        buf[root_nk + NK_SUBKEY_LF..root_nk + NK_SUBKEY_LF + 4]
            .copy_from_slice(&lf_rel.to_le_bytes());
        buf[root_nk + NK_NAME_LEN..root_nk + NK_NAME_LEN + 2].copy_from_slice(&4u16.to_le_bytes());
        buf[root_nk + NK_NAME..root_nk + NK_NAME + 4].copy_from_slice(b"ROOT");

        // --- lf index ---
        buf[lf_cell..lf_cell + 4].copy_from_slice(&(-(lf_cell_size as i32)).to_le_bytes());
        buf[lf_cell + 4..lf_cell + 6].copy_from_slice(ID_LF);
        buf[lf_cell + 6..lf_cell + 8].copy_from_slice(&1u16.to_le_bytes());
        let child_rel = (child_nk - HBIN_BASE) as u32;
        buf[lf_cell + 8..lf_cell + 12].copy_from_slice(&child_rel.to_le_bytes());

        // --- Child nk "SUBKEY" ---
        buf[child_nk..child_nk + 4].copy_from_slice(&(-(child_nk_size as i32)).to_le_bytes());
        buf[child_nk + 4..child_nk + 6].copy_from_slice(ID_NK);
        let child_flags: u16 = NK_FLAG_ASCII_NAME;
        buf[child_nk + NK_FLAGS..child_nk + NK_FLAGS + 2]
            .copy_from_slice(&child_flags.to_le_bytes());
        buf[child_nk + NK_NR_VALUES..child_nk + NK_NR_VALUES + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        let vallist_rel = (vallist_cell - HBIN_BASE) as u32;
        buf[child_nk + NK_VALLIST..child_nk + NK_VALLIST + 4]
            .copy_from_slice(&vallist_rel.to_le_bytes());
        buf[child_nk + NK_NAME_LEN..child_nk + NK_NAME_LEN + 2]
            .copy_from_slice(&6u16.to_le_bytes());
        buf[child_nk + NK_NAME..child_nk + NK_NAME + 6].copy_from_slice(b"SUBKEY");

        // --- vallist ---
        buf[vallist_cell..vallist_cell + 4]
            .copy_from_slice(&(-(vallist_size as i32)).to_le_bytes());
        let vk_rel = (vk_cell - HBIN_BASE) as u32;
        buf[vallist_cell + 4..vallist_cell + 8].copy_from_slice(&vk_rel.to_le_bytes());

        // --- vk "TestValue" REG_DWORD inline ---
        buf[vk_cell..vk_cell + 4].copy_from_slice(&(-(vk_cell_size as i32)).to_le_bytes());
        buf[vk_cell + 4..vk_cell + 6].copy_from_slice(ID_VK);
        buf[vk_cell + VK_NAME_LEN..vk_cell + VK_NAME_LEN + 2].copy_from_slice(&9u16.to_le_bytes());
        let data_size = VK_DATA_INLINE_FLAG | 4;
        buf[vk_cell + VK_DATA_SIZE..vk_cell + VK_DATA_SIZE + 4]
            .copy_from_slice(&data_size.to_le_bytes());
        buf[vk_cell + VK_DATA_OFFSET..vk_cell + VK_DATA_OFFSET + 4]
            .copy_from_slice(&0x42u32.to_le_bytes());
        buf[vk_cell + VK_DATA_TYPE..vk_cell + VK_DATA_TYPE + 4]
            .copy_from_slice(&4u32.to_le_bytes());
        buf[vk_cell + VK_FLAGS..vk_cell + VK_FLAGS + 4]
            .copy_from_slice(&VK_FLAG_ASCII_NAME.to_le_bytes());
        buf[vk_cell + VK_NAME..vk_cell + VK_NAME + 9].copy_from_slice(b"TestValue");

        // --- Compute and write checksum ---
        let checksum = compute_header_checksum(&buf);
        buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4]
            .copy_from_slice(checksum.to_le_bytes().as_slice());

        buf
    }

    #[test]
    fn parse_validates_magic() {
        let data = build_test_hive();
        let hive = Hive::parse(&data).unwrap();
        assert!(hive.cell_count() >= 4);
    }

    #[test]
    fn parse_rejects_wrong_magic() {
        let mut data = build_test_hive();
        data[0..4].copy_from_slice(b"REGI");
        assert!(matches!(Hive::parse(&data), Err(HiveError::BadMagic)));
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        let mut data = build_test_hive();
        data[0x20] ^= 0xFF;
        assert!(matches!(Hive::parse(&data), Err(HiveError::BadChecksum)));
    }

    #[test]
    fn parse_rejects_too_small() {
        let data = [0u8; 16];
        assert!(matches!(Hive::parse(&data), Err(HiveError::TooSmall)));
    }

    #[test]
    fn root_returns_root_key() {
        let data = build_test_hive();
        let hive = Hive::parse(&data).unwrap();
        let root = hive.root().unwrap();
        assert_eq!(root.name, "ROOT");
    }

    #[test]
    fn subkeys_finds_child() {
        let data = build_test_hive();
        let hive = Hive::parse(&data).unwrap();
        let root = hive.root().unwrap();
        let subs = hive.subkeys(&root).unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].name, "SUBKEY");
    }

    #[test]
    fn open_path_walks_tree() {
        let data = build_test_hive();
        let hive = Hive::parse(&data).unwrap();
        let node = hive.open_path(&["SUBKEY"]).unwrap();
        assert!(node.is_some());
        assert_eq!(node.unwrap().name, "SUBKEY");
    }

    #[test]
    fn find_value_returns_inline_dword() {
        let data = build_test_hive();
        let hive = Hive::parse(&data).unwrap();
        let node = hive.open_path(&["SUBKEY"]).unwrap().unwrap();
        let v = hive.find_value(&node, "TestValue").unwrap().unwrap();
        assert_eq!(v.value_type, ValueType::DWord);
        assert_eq!(v.as_u32(), Some(0x42));
    }

    #[test]
    fn find_value_missing_returns_none() {
        let data = build_test_hive();
        let hive = Hive::parse(&data).unwrap();
        let node = hive.open_path(&["SUBKEY"]).unwrap().unwrap();
        let v = hive.find_value(&node, "Nonexistent").unwrap();
        assert!(v.is_none());
    }
}
