//! Custom NT6.1.7601 registry hive binary format — parser.
//
//! This is a simplified regf-like format used by our own
//! Configuration Manager. It is **not** compatible with the real
//! Windows `regf` format — it is purpose-built for our kernel and
//! the hive files we generate with `tools::hive_gen`.
//
//! See `tools::hive_gen` for the on-disk specification in full.
//! (A short summary is included at the bottom of this file.)
//
//! The parser is allocation-light at runtime: it borrows the
//! underlying byte slice and returns `String` only for cell
//! names and string values, which are short (UTF-16, ≤ a few
//! hundred bytes in our generated hives).
#![allow(dead_code)]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

pub const REGF_MAGIC: &[u8; 4] = b"REGF";
pub const HBIN_MAGIC: &[u8; 4] = b"HBIN";
pub const REGF_HEADER_SIZE: usize = 4096;
pub const HBIN_SIZE: usize = 4096;
pub const REGF_VERSION: u32 = 1;
pub const CELL_MAGIC_NK: u8 = b'n';
pub const CELL_MAGIC_VK: u8 = b'v';
pub const CELL_MAGIC_LK: u8 = b'l';
pub const CELL_MAGIC_RI: u8 = b'r';

pub const CELL_HEADER: usize = 8; // size(4) + kind(1) + pad(3)

/// Errors returned by the hive parser.
#[derive(Debug, Clone, PartialEq, Eq)]
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
            HiveError::TooSmall => write!(f, "hive file too small"),
            HiveError::BadMagic => write!(f, "bad REGF magic"),
            HiveError::UnsupportedVersion(v) => write!(f, "unsupported hive version {}", v),
            HiveError::BadChecksum => write!(f, "bad REGF checksum"),
            HiveError::Truncated => write!(f, "cell truncated"),
            HiveError::BadCellKind(k) => write!(f, "unknown cell kind '{}'", *k as char),
            HiveError::BadUtf16 => write!(f, "bad utf-16 in name"),
            HiveError::OutOfBounds => write!(f, "offset out of bounds"),
            HiveError::InvalidPointer => write!(f, "invalid cell pointer"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// A parsed value read out of a `vk` cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub name: String,        // empty string = default value
    pub value_type: ValueType,
    pub data: Vec<u8>,
}

impl Value {
    /// Decode a UTF-16LE string. Returns an empty string if the
    /// value is not a string type, or an error if it is malformed.
    pub fn as_utf16_string(&self) -> Option<String> {
        if !matches!(self.value_type, ValueType::String | ValueType::ExpandString) {
            return None;
        }
        let bytes = &self.data;
        if bytes.len() % 2 != 0 {
            return None;
        }
        let mut out = String::new();
        for i in (0..bytes.len()).step_by(2) {
            let cu = u16::from_le_bytes([bytes[i], bytes[i+1]]);
            if cu == 0 { break; }
            match char::from_u32(cu as u32) {
                Some(c) => out.push(c),
                None => return None,
            }
        }
        Some(out)
    }

    /// Decode a little-endian u32 (REG_DWORD).
    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() < 4 { return None; }
        Some(u32::from_le_bytes([
            self.data[0], self.data[1], self.data[2], self.data[3],
        ]))
    }

    /// Decode a little-endian u64 (REG_QWORD).
    pub fn as_u64(&self) -> Option<u64> {
        if self.data.len() < 8 { return None; }
        Some(u64::from_le_bytes([
            self.data[0], self.data[1], self.data[2], self.data[3],
            self.data[4], self.data[5], self.data[6], self.data[7],
        ]))
    }
}

/// A parsed node key (`nk` cell).
#[derive(Debug, Clone)]
pub struct KeyNode {
    pub offset: u32,         // file offset of the cell
    pub name: String,
    pub flags: u16,
}

#[inline]
fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    if off + 4 > b.len() { return None; }
    Some(u32::from_le_bytes([b[off], b[off+1], b[off+2], b[off+3]]))
}

#[inline]
fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    if off + 2 > b.len() { return None; }
    Some(u16::from_le_bytes([b[off], b[off+1]]))
}

#[inline]
fn read_i32(b: &[u8], off: usize) -> Option<i32> {
    if off + 4 > b.len() { return None; }
    Some(i32::from_le_bytes([b[off], b[off+1], b[off+2], b[off+3]]))
}

#[inline]
fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    if off + 8 > b.len() { return None; }
    Some(u64::from_le_bytes([
        b[off], b[off+1], b[off+2], b[off+3],
        b[off+4], b[off+5], b[off+6], b[off+7],
    ]))
}

fn decode_utf16le(b: &[u8]) -> Result<String, HiveError> {
    if b.len() % 2 != 0 {
        return Err(HiveError::BadUtf16);
    }
    let mut out = String::new();
    for i in (0..b.len()).step_by(2) {
        let cu = u16::from_le_bytes([b[i], b[i+1]]);
        match char::from_u32(cu as u32) {
            Some(c) => out.push(c),
            None => return Err(HiveError::BadUtf16),
        }
    }
    Ok(out)
}

/// A parsed hive.
pub struct Hive<'a> {
    bytes: &'a [u8],
    root_cell: u32,
    cell_count: u32,
}

impl<'a> Hive<'a> {
    /// Parse and validate a hive file's on-disk image. The returned
    /// `Hive` borrows the byte slice; the caller must keep it alive.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, HiveError> {
        if bytes.len() < REGF_HEADER_SIZE {
            return Err(HiveError::TooSmall);
        }
        if &bytes[0..4] != REGF_MAGIC {
            return Err(HiveError::BadMagic);
        }
        let version = read_u32(bytes, 4).ok_or(HiveError::TooSmall)?;
        if version != REGF_VERSION {
            return Err(HiveError::UnsupportedVersion(version));
        }
        let _flags = read_u32(bytes, 8).ok_or(HiveError::TooSmall)?;
        let root_cell = read_u32(bytes, 12).ok_or(HiveError::TooSmall)?;
        let cell_count = read_u32(bytes, 16).ok_or(HiveError::TooSmall)?;
        let _ts = read_u64(bytes, 20).ok_or(HiveError::TooSmall)?;
        let checksum = read_u32(bytes, 28).ok_or(HiveError::TooSmall)?;

        // Verify checksum (xor of the first 28 header bytes).
        let mut cs: u32 = 0;
        for off in (0..28).step_by(4) {
            cs ^= read_u32(bytes, off).unwrap_or(0);
        }
        if cs != checksum {
            return Err(HiveError::BadChecksum);
        }

        if root_cell as usize >= bytes.len() {
            return Err(HiveError::OutOfBounds);
        }

        Ok(Hive { bytes, root_cell, cell_count })
    }

    /// The cell count recorded in the header.
    pub fn cell_count(&self) -> u32 { self.cell_count }

    /// Root node-key cell.
    pub fn root(&self) -> Result<KeyNode, HiveError> {
        self.read_nk(self.root_cell)
    }

    fn read_cell_header(&self, off: usize, expected_kind: u8) -> Result<usize, HiveError> {
        if off + CELL_HEADER > self.bytes.len() {
            return Err(HiveError::Truncated);
        }
        let size = read_i32(self.bytes, off).ok_or(HiveError::Truncated)? as i64;
        let kind = self.bytes[off + 4];
        if size <= 0 {
            return Err(HiveError::Truncated);
        }
        if kind != expected_kind {
            return Err(HiveError::BadCellKind(kind));
        }
        let size = size as usize;
        if off + size > self.bytes.len() {
            return Err(HiveError::Truncated);
        }
        Ok(size)
    }

    fn read_nk(&self, off: u32) -> Result<KeyNode, HiveError> {
        let sz = self.read_cell_header(off as usize, CELL_MAGIC_NK)?;
        let p = off as usize + CELL_HEADER;
        let flags   = read_u16(self.bytes, p).ok_or(HiveError::Truncated)?;
        let _nsubs  = read_u32(self.bytes, p + 2).ok_or(HiveError::Truncated)?;
        let _subk_o = read_u32(self.bytes, p + 6).ok_or(HiveError::Truncated)?;
        let _nv     = read_u32(self.bytes, p + 10).ok_or(HiveError::Truncated)?;
        let _vo     = read_u32(self.bytes, p + 14).ok_or(HiveError::Truncated)?;
        let name_len = read_u16(self.bytes, p + 18).ok_or(HiveError::Truncated)? as usize;
        if p + 20 + name_len * 2 > off as usize + sz {
            return Err(HiveError::Truncated);
        }
        let name = decode_utf16le(&self.bytes[p + 20 .. p + 20 + name_len * 2])?;
        Ok(KeyNode { offset: off, name, flags })
    }

    /// Enumerate immediate subkeys of a node.
    pub fn subkeys(&self, node: &KeyNode) -> Result<Vec<KeyNode>, HiveError> {
        let off = node.offset as usize;
        let _sz = self.read_cell_header(off, CELL_MAGIC_NK)?;
        let p = off + CELL_HEADER;
        let nsubs = read_u32(self.bytes, p + 2).ok_or(HiveError::Truncated)?;
        let subk_off = read_u32(self.bytes, p + 6).ok_or(HiveError::Truncated)?;
        if nsubs == 0 || subk_off == 0 {
            return Ok(Vec::new());
        }
        // lk cell: count(u32) + [u32; count]
        let lk_p = subk_off as usize;
        let _lk_sz = self.read_cell_header(lk_p, CELL_MAGIC_LK)?;
        let lk_data = lk_p + CELL_HEADER;
        let count = read_u32(self.bytes, lk_data).ok_or(HiveError::Truncated)? as usize;
        if lk_data + 4 + count * 4 > self.bytes.len() {
            return Err(HiveError::Truncated);
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let child_off = read_u32(self.bytes, lk_data + 4 + i * 4)
                .ok_or(HiveError::Truncated)?;
            out.push(self.read_nk(child_off)?);
        }
        Ok(out)
    }

    /// Find an immediate subkey by name (case-insensitive ASCII).
    pub fn find_subkey(&self, node: &KeyNode, name: &str) -> Result<Option<KeyNode>, HiveError> {
        for k in self.subkeys(node)? {
            if eq_ignore_ascii_case(&k.name, name) {
                return Ok(Some(k));
            }
        }
        Ok(None)
    }

    /// Enumerate the values of a node.
    pub fn values(&self, node: &KeyNode) -> Result<Vec<Value>, HiveError> {
        let off = node.offset as usize;
        let _sz = self.read_cell_header(off, CELL_MAGIC_NK)?;
        let p = off + CELL_HEADER;
        let nv = read_u32(self.bytes, p + 10).ok_or(HiveError::Truncated)?;
        let vo = read_u32(self.bytes, p + 14).ok_or(HiveError::Truncated)?;
        if nv == 0 || vo == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(nv as usize);
        let mut cur = vo;
        for _ in 0..nv {
            let cur_off = cur as usize;
            let sz = self.read_cell_header(cur_off, CELL_MAGIC_VK)?;
            let cp = cur_off + CELL_HEADER;
            let name_len = read_u16(self.bytes, cp).ok_or(HiveError::Truncated)? as usize;
            if cp + 2 + name_len * 2 > cur_off + sz {
                return Err(HiveError::Truncated);
            }
            let name = if name_len == 0 {
                String::new()
            } else {
                decode_utf16le(&self.bytes[cp + 2 .. cp + 2 + name_len * 2])?
            };
            let after_name = cp + 2 + name_len * 2;
            let data_type = read_u32(self.bytes, after_name).ok_or(HiveError::Truncated)?;
            let data_len = read_u32(self.bytes, after_name + 4).ok_or(HiveError::Truncated)? as usize;
            if after_name + 8 + data_len > cur_off + sz {
                return Err(HiveError::Truncated);
            }
            let data = self.bytes[after_name + 8 .. after_name + 8 + data_len].to_vec();
            out.push(Value {
                name,
                value_type: ValueType::from_u32(data_type),
                data,
            });
            cur = (cur_off + sz) as u32;
        }
        Ok(out)
    }

    /// Find a single value by name on a node. The empty string
    /// matches the default value.
    pub fn find_value(&self, node: &KeyNode, name: &str) -> Result<Option<Value>, HiveError> {
        for v in self.values(node)? {
            if v.name == name {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    /// Walk a path of subkey names from the root.
    pub fn open_path(&self, path: &[&str]) -> Result<Option<KeyNode>, HiveError> {
        let mut cur = self.root()?;
        for name in path {
            match self.find_subkey(&cur, name)? {
                Some(n) => cur = n,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }
}

fn eq_ignore_ascii_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

// =====================================================================
// On-disk format reference (mirrors what `tools::hive_gen` emits)
// =====================================================================
//
// [REGF v1 header, 4 KiB]
//   magic         b"REGF"               (4 bytes)
//   version       u32                   (=1)
//   flags         u32
//   root_cell     u32                   (offset from file start, in bytes)
//   cell_count    u32
//   timestamp     u64
//   checksum      u32                   (xor of preceding 28 bytes)
//   _reserved     [u8; 4064]
//
// [HBIN blocks, each 4 KiB, 1 or more]
//   each HBIN:
//     sig           b"HBIN"             (4 bytes)
//     offset_next   u32                 (file offset of next HBIN, 0 if last)
//     _pad          [u8; 24]
//     [cells, each cell_size aligned to 8 bytes]
//       each cell:
//         size      i32                 (cell_size incl. header; > 0 allocated)
//         kind      u8                  ('n'=nk, 'v'=vk, 'l'=lk, 'r'=ri)
//         _pad      [u8; 3]
//         payload
//
// nk (node key):
//   flags           u16
//   num_subkeys     u32
//   subkeys_off     u32     (offset to `lk` cell, 0 if none)
//   num_values      u32
//   values_off      u32     (offset to first `vk` cell, 0 if none)
//   name_len        u16     (in chars)
//   name_utf16      [u16; name_len]
//
// vk (value key):
//   name_len        u16     (in chars, 0 = default value)
//   name_utf16      [u16; name_len]
//   data_type       u32
//   data_len        u32
//   data            [u8; data_len]
//
// lk (subkey list, leaf):
//   count           u32
//   offsets         [u32; count]         (cell offsets to child `nk` cells)
//
// ri (root index):
//   count           u32
//   offsets         [u32; count]         (cell offsets to `lk` cells)
