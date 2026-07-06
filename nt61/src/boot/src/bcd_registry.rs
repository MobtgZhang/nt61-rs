//! BCD Registry Hive Parser (REGF v1 format) - Windows 7 Compatible
//
//! Parses the Windows Boot Configuration Data (BCD) registry hive file.
//! This implements the same on-disk REGF format that hivex and Windows
//! use for registry hives.
//
//! ## REGF v1 Header (offset 0x0000, 4096 bytes)
//
//! ```text
//! 0x000: magic[4]          = "regf" (ASCII)
//! 0x004: sequence1 (u32)   = primary sequence number
//! 0x008: sequence2 (u32)   = secondary sequence number
//! 0x00C: last_modified (i64) = Windows FILETIME
//! 0x014: major_ver (u32)  = must be 1
//! 0x018: minor_ver (u32)  = 1 or 3
//! 0x01C: unknown5 (u32)
//! 0x020: unknown6 (u32)    = 1
//! 0x024: offset (u32)       = root key offset (HBIN-relative)
//! 0x028: blocks (u32)      = offset of end of last hbin + 0x1000
//! 0x02C: unknown7 (u32)    = 1
//! 0x030: name[64]          = original hive filename (UTF-16LE)
//! 0x1FC: csum (u32)        = xor of dwords 0x00..0x1F8
//! 0x1000: (first hbin page)
//
//! ## HBIN Page (starts at 0x1000)
//
//! 0x00: magic[4]         = "hbin" (ASCII)
//! 0x04: offset_first (u32) = offset from first hbin (i.e. 0 for first)
//! 0x08: page_size (u32)  = size of this page (multiple of 4KB)
//! 0x10: [blocks follow]
//
//! ## Block Header (8 bytes)
//
//! 0x00: seg_len (i32)    = negative for used block, positive for free
//! 0x04: id[2]            = "nk", "vk", "lf", "lh", "ri", "sk"
//! 0x06: pad[2]
//
//! ## nk (node key) block (offset 0x50 + name_len, aligned to 8 bytes)
//
//! 0x00: seg_len (i32, negative)
//! 0x04: id[2] = "nk"
//! 0x06: pad[2]
//! 0x08: flags (u16)       bit1=HiveExit, bit2=HiveEntry(root)
//! 0x0A: timestamp (i64)
//! 0x12: unknown1 (u32)
//! 0x16: parent (u32)        offset (HBIN-relative)
//! 0x1A: nr_subkeys (u32)
//! 0x1E: subkey_lf (u32)    offset to lf/lh block (HBIN-relative)
//! 0x22: nr_subkeys_volatile (u32)
//! 0x26: subkey_lf_volatile (u32)
//! 0x2A: nr_values (u32)
//! 0x2E: vallist (u32)      offset to value-list block (HBIN-relative)
//! 0x32: sk (u32)            offset to sk block
//! 0x36: classname (u32)     offset to classname data
//! 0x3A: max_subkey_name_len (u16)
//! 0x3C: unknown2 (u16)
//! 0x3E: unknown3 (u32)
//! 0x42: max_vk_name_len (u16)
//! 0x44: max_vk_data_len (u32)
//! 0x48: unknown6 (u32)
//! 0x4C: name_len (u16)       in bytes (for short names: ASCII encoded)
//! 0x4E: classname_len (u16)
//! 0x50: name[?]             ASCII for short names (<=64 bytes) or UTF-16LE for long names
//
//! ## vk (value key) block
//
//! 0x00: seg_len (i32, negative)
//! 0x04: id[2] = "vk"
//! 0x06: pad[2]
//! 0x08: name_len (u16)      0 = default value
//! after name:
//! 0x??: data_len (u32)       top bit set = inline (<=4 bytes)
//! 0x??: data_offset (u32)    if not inline: offset (HBIN-relative)
//! 0x??: data_type (u32)      1=string, 2=expand, 4=dword, 7=multi_sz, 11=qword
//! 0x??: flags (u16)
//! 0x??: unknown2 (u16)
//! inline data: lower 4 bytes of data_offset
//
//! ## lf (leaf) block
//
//! 0x00: seg_len (i32)
//! 0x04: id[2] = "lf" or "lh"
//! 0x06: pad[2]
//! 0x08: nr_keys (u16)
//! 0x0A: [for each key: offset(4) + hash(4)]
//
//! ## ri (root index) block
//
//! 0x00: seg_len (i32)
//! 0x04: id[2] = "ri"
//! 0x06: pad[2]
//! 0x08: nr_offsets (u16)
//! 0x0A: [for each: offset(4) to lh/lf block]

#![allow(dead_code)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// REGF header size (4096 bytes)
const REGF_HEADER_SIZE: usize = 0x1000;
/// HBIN base address (first HBIN starts at 0x1000)
const HBIN_BASE: usize = 0x1000;

const REGF_MAGIC: &[u8; 4] = b"regf";
const HBIN_MAGIC: &[u8; 4] = b"hbin";
const NK_MAGIC: &[u8; 2] = b"nk";
const VK_MAGIC: &[u8; 2] = b"vk";
const LF_MAGIC: &[u8; 2] = b"lf";
const LH_MAGIC: &[u8; 2] = b"lh";
const RI_MAGIC: &[u8; 2] = b"ri";

/// Registry data types
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

#[derive(Debug)]
pub enum HiveError {
    TooSmall,
    BadMagic,
    BadChecksum,
    BadVersion,
    BadCellKind,
    UnsupportedVersion,
    BadUtf16,
    OutOfBounds,
    Truncated,
    Other(String),
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() { return None; }
    Some(u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]))
}

fn read_i32(data: &[u8], off: usize) -> Option<i32> {
    if off + 4 > data.len() { return None; }
    Some(i32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]))
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() { return None; }
    Some(u16::from_le_bytes([data[off], data[off+1]]))
}

/// Compute header checksum: xor of first 0x1F8 bytes (127 dwords)
fn compute_header_checksum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    for i in (0..0x1F8).step_by(4) {
        sum ^= read_u32(data, i).unwrap_or(0);
    }
    sum
}

/// Decode a registry value name. Short names (<=64 bytes) are ASCII encoded,
/// while longer names are UTF-16LE encoded.
fn decode_name(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    
    // Check first byte - if it's printable ASCII, treat as ASCII
    if data[0] >= 0x20 && data[0] < 0x7F {
        // ASCII encoding - find null terminator
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..end]).trim_end_matches('\0').to_string()
    } else {
        // UTF-16LE encoding
        decode_utf16le(data)
    }
}

/// Decode a UTF-16LE byte sequence into a String.
fn decode_utf16le(data: &[u8]) -> String {
    if data.len() % 2 != 0 {
        return String::new();
    }
    let mut out = String::new();
    for i in (0..data.len()).step_by(2) {
        let cu = u16::from_le_bytes([data[i], data[i+1]]);
        if cu == 0 { break; }
        match char::from_u32(cu as u32) {
            Some(c) => out.push(c),
            None => out.push('\u{FFFD}'), // Replacement character
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct Value {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

impl Value {
    /// Decode a UTF-16LE string value.
    pub fn as_string(&self) -> Option<String> {
        // Support REG_SZ (type 1), REG_EXPAND_SZ (type 2), and REG_LINK (type 6)
        if self.value_type != REG_SZ && self.value_type != REG_EXPAND_SZ && self.value_type != 6 {
            return None;
        }
        let bytes = &self.data;
        if bytes.len() % 2 != 0 { return None; }
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

    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() < 4 { return None; }
        Some(u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]))
    }

    /// Decode a REG_MULTI_SZ (type 7) string list value.
    pub fn as_string_list(&self) -> Option<Vec<String>> {
        if self.value_type != REG_MULTI_SZ {
            return None;
        }
        let bytes = &self.data;
        if bytes.len() % 2 != 0 { return None; }
        let mut result = Vec::new();
        let mut current = String::new();

        for i in (0..bytes.len()).step_by(2) {
            let cu = u16::from_le_bytes([bytes[i], bytes[i+1]]);
            if cu == 0 {
                if !current.is_empty() {
                    result.push(current.clone());
                    current.clear();
                } else if !result.is_empty() {
                    break;
                }
            } else {
                match char::from_u32(cu as u32) {
                    Some(c) => current.push(c),
                    None => return None,
                }
            }
        }

        if !current.is_empty() {
            result.push(current);
        }

        Some(result)
    }
}

#[derive(Debug, Clone)]
pub struct KeyNode {
    pub offset: usize,
    pub name: String,
    pub flags: u16,
    pub nr_values: u32,
    pub nr_subkeys: u32,
    pub subkey_lf: u32,
    pub value_list_off: u32,
}

pub struct Hive<'a> {
    data: &'a [u8],
    /// HBIN base address (used for converting HBIN-relative offsets to absolute)
    hbin_base: usize,
    /// Root key offset (absolute file offset)
    root_offset: usize,
}

impl<'a> Hive<'a> {
    /// Parse a REGF v1 hive. Returns Err if the header is invalid.
    pub fn parse(data: &'a [u8]) -> Result<Self, HiveError> {
        if data.len() < REGF_HEADER_SIZE {
            return Err(HiveError::TooSmall);
        }

        // Check magic
        if &data[0..4] != REGF_MAGIC {
            return Err(HiveError::BadMagic);
        }

        // Check major version
        let major_ver = read_u32(data, 0x14).ok_or(HiveError::TooSmall)?;
        if major_ver != 1 {
            return Err(HiveError::BadVersion);
        }

        // Check checksum (optional - some hives may have invalid checksum)
        let stored_csum = read_u32(data, 0x1FC).ok_or(HiveError::TooSmall)?;
        let computed_csum = compute_header_checksum(data);
        if stored_csum != computed_csum {
            // Don't fail on checksum mismatch - some BCD files may have this
            // Return Ok but continue
        }

        // Root offset is HBIN-relative (relative to 0x1000)
        let root_offset_raw = read_u32(data, 0x24).ok_or(HiveError::TooSmall)?;
        let root_offset = HBIN_BASE + root_offset_raw as usize;

        if root_offset >= data.len() {
            return Err(HiveError::OutOfBounds);
        }

        Ok(Hive { data, hbin_base: HBIN_BASE, root_offset })
    }

    /// Get the root key node.
    pub fn root(&self) -> Result<KeyNode, HiveError> {
        self.read_nk(self.root_offset)
    }

    /// Convert a HBIN-relative offset to absolute file offset
    #[inline]
    fn hbin_to_absolute(&self, hbin_offset: u32) -> usize {
        self.hbin_base + hbin_offset as usize
    }

    /// Read an nk block at the given file offset.
    ///
    /// Cell layout (per the registry file format spec):
    /// - Offset 0: Size (i32, negative for allocated)
    /// - Offset 4: Signature "nk" (2 bytes)
    /// - Offset 6: Flags (u16)
    /// - Offset 8: Last written timestamp (i64)
    /// - Offset 16: Access bits / Spare (u32)
    /// - Offset 20: Parent key offset (u32, HBIN-relative)
    /// - Offset 24: Number of subkeys (u32)
    /// - Offset 28: Number of volatile subkeys (u32)
    /// - Offset 32: Subkeys list offset (u32, HBIN-relative)
    /// - Offset 36: Volatile subkeys list offset (u32)
    /// - Offset 40: Number of values (u32)
    /// - Offset 44: Values list offset (u32, HBIN-relative)
    /// - Offset 48: Security descriptor offset (u32)
    /// - Offset 52: Class name offset (u32)
    /// - Offset 56: Largest subkey name length (u32)
    /// - Offset 60: Largest subkey class name length (u32)
    /// - Offset 64: Largest value name length (u32)
    /// - Offset 68: Largest value data size (u32)
    /// - Offset 72: WorkVar (u32)
    /// - Offset 76: Key name length (u16, in bytes)
    /// - Offset 78: Class name length (u16)
    /// - Offset 80: Key name (ASCII or UTF-16LE)
    fn read_nk(&self, offset: usize) -> Result<KeyNode, HiveError> {
        if offset + 0x50 > self.data.len() {
            return Err(HiveError::Truncated);
        }
        let seg_len = read_i32(self.data, offset).ok_or(HiveError::Truncated)?;
        if seg_len >= 0 {
            return Err(HiveError::Truncated);
        }
        if &self.data[offset + 4..offset + 6] != NK_MAGIC {
            return Err(HiveError::Truncated);
        }

        // Offsets per the REGF spec (relative to cell start).
        let _flags = read_u16(self.data, offset + 0x06).ok_or(HiveError::Truncated)?;
        let _timestamp = read_u32(self.data, offset + 0x08).ok_or(HiveError::Truncated)?;
        let _timestamp_hi = read_u32(self.data, offset + 0x0C).ok_or(HiveError::Truncated)?;
        let _access_bits = read_u32(self.data, offset + 0x10).ok_or(HiveError::Truncated)?;
        let _parent = read_u32(self.data, offset + 0x14).ok_or(HiveError::Truncated)?;
        let nr_subkeys = read_u32(self.data, offset + 0x18).ok_or(HiveError::Truncated)?;
        let _nr_volatile = read_u32(self.data, offset + 0x1C).ok_or(HiveError::Truncated)?;
        let subkey_lf = read_u32(self.data, offset + 0x20).ok_or(HiveError::Truncated)?;
        let _vol_subkey_lf = read_u32(self.data, offset + 0x24).ok_or(HiveError::Truncated)?;
        let nr_values = read_u32(self.data, offset + 0x28).ok_or(HiveError::Truncated)?;
        let value_list_off = read_u32(self.data, offset + 0x2C).ok_or(HiveError::Truncated)?;
        let _sk = read_u32(self.data, offset + 0x30).ok_or(HiveError::Truncated)?;
        let _classname = read_u32(self.data, offset + 0x34).ok_or(HiveError::Truncated)?;
        let _max_subkey_nlen = read_u32(self.data, offset + 0x38).ok_or(HiveError::Truncated)?;
        let _max_subkey_clen = read_u32(self.data, offset + 0x3C).ok_or(HiveError::Truncated)?;
        let _max_vk_nlen = read_u32(self.data, offset + 0x40).ok_or(HiveError::Truncated)?;
        let _max_vk_dlen = read_u32(self.data, offset + 0x44).ok_or(HiveError::Truncated)?;
        let _workvar = read_u32(self.data, offset + 0x48).ok_or(HiveError::Truncated)?;
        let name_len = read_u16(self.data, offset + 0x4C).ok_or(HiveError::Truncated)? as usize;

        // Read name (starts at offset + 0x50)
        let name_start = offset + 0x50;
        if name_start + name_len > self.data.len() {
            return Err(HiveError::Truncated);
        }

        // Decode name (supports both ASCII and UTF-16LE)
        let name = decode_name(&self.data[name_start..name_start + name_len]);

        Ok(KeyNode {
            offset,
            name,
            flags: _flags,
            nr_values,
            nr_subkeys,
            subkey_lf,
            value_list_off,
        })
    }

    /// Read an lf/lh block and return list of child key absolute offsets.
    ///
    /// Cell layout (per the registry file format spec):
    /// - Offset 0: Size (i32, negative for allocated cells)
    /// - Offset 4: Signature "lf" or "lh" (2 bytes)
    /// - Offset 6: Number of elements (u16)
    /// - Offset 8: List elements (each 8 bytes: 4 byte key offset + 4 byte hint/hash)
    fn read_lf(&self, offset: usize) -> Result<Vec<usize>, HiveError> {
        if offset + 8 > self.data.len() {
            return Err(HiveError::Truncated);
        }
        let seg_len = read_i32(self.data, offset).ok_or(HiveError::Truncated)?;
        if seg_len == 0 {
            return Err(HiveError::Truncated);
        }
        let id = &self.data[offset + 4..offset + 6];
        if id != LF_MAGIC && id != LH_MAGIC {
            return Err(HiveError::Truncated);
        }

        let nr_keys = read_u16(self.data, offset + 6).ok_or(HiveError::Truncated)? as usize;
        let mut offsets = Vec::with_capacity(nr_keys);

        let entry_start = offset + 8;
        for i in 0..nr_keys {
            let entry_off = entry_start + i * 8;
            // Bounds check for each entry
            if entry_off + 8 > self.data.len() {
                break;
            }
            let key_off = read_u32(self.data, entry_off).ok_or(HiveError::Truncated)?;
            // Convert HBIN-relative offset to absolute
            offsets.push(self.hbin_to_absolute(key_off));
        }

        Ok(offsets)
    }

    /// Read an ri block and return list of lf/lh block absolute offsets.
    ///
    /// Cell layout (per the registry file format spec):
    /// - Offset 0: Size (i32, negative for allocated cells)
    /// - Offset 4: Signature "ri" (2 bytes)
    /// - Offset 6: Number of elements (u16)
    /// - Offset 8: List elements (each 4 bytes: lf/lh offset, HBIN-relative)
    fn read_ri(&self, offset: usize) -> Result<Vec<usize>, HiveError> {
        if offset + 8 > self.data.len() {
            return Err(HiveError::Truncated);
        }
        let id = &self.data[offset + 4..offset + 6];
        if id != RI_MAGIC {
            return Err(HiveError::Truncated);
        }

        let nr_offsets = read_u16(self.data, offset + 6).ok_or(HiveError::Truncated)? as usize;
        let mut offsets = Vec::with_capacity(nr_offsets);

        for i in 0..nr_offsets {
            let entry_off = offset + 8 + i * 4;
            if entry_off + 4 > self.data.len() {
                break;
            }
            let lf_off = read_u32(self.data, entry_off).ok_or(HiveError::Truncated)?;
            offsets.push(self.hbin_to_absolute(lf_off));
        }

        Ok(offsets)
    }

    /// Enumerate immediate subkeys of a node.
    pub fn subkeys(&self, node: &KeyNode) -> Result<Vec<KeyNode>, HiveError> {
        if node.nr_subkeys == 0 || node.subkey_lf == 0 {
            return Ok(Vec::new());
        }

        let lf_offset = self.hbin_to_absolute(node.subkey_lf);
        if lf_offset >= self.data.len() {
            return Ok(Vec::new());
        }

        let id = &self.data[lf_offset + 4..lf_offset + 6];
        if id == RI_MAGIC {
            let ri_offsets = self.read_ri(lf_offset)?;
            let mut all_keys = Vec::new();
            for &off in &ri_offsets {
                if let Ok(keys) = self.read_lf(off) {
                    for &nk_off in &keys {
                        if let Ok(nk) = self.read_nk(nk_off) {
                            all_keys.push(nk);
                        }
                    }
                }
            }
            Ok(all_keys)
        } else {
            let lf_offsets = self.read_lf(lf_offset)?;
            let mut nodes = Vec::with_capacity(lf_offsets.len());
            for &nk_off in &lf_offsets {
                if let Ok(nk) = self.read_nk(nk_off) {
                    nodes.push(nk);
                }
            }
            Ok(nodes)
        }
    }

    /// Enumerate values attached to a node.
    pub fn values(&self, node: &KeyNode) -> Result<Vec<Value>, HiveError> {
        if node.nr_values == 0 || node.value_list_off == 0 {
            return Ok(Vec::new());
        }

        let vl_offset = self.hbin_to_absolute(node.value_list_off);
        // Skip the 4-byte cell header (seg_len) at the start of the values list.
        let list_start = vl_offset + 4;
        if list_start + (node.nr_values as usize) * 4 > self.data.len() {
            return Err(HiveError::Truncated);
        }

        let mut vk_offsets = Vec::with_capacity(node.nr_values as usize);
        for i in 0..node.nr_values as usize {
            let off = list_start + i * 4;
            let vk_off = read_u32(self.data, off).ok_or(HiveError::Truncated)?;
            vk_offsets.push(self.hbin_to_absolute(vk_off));
        }

        let mut values = Vec::with_capacity(vk_offsets.len());
        for &vk_off in &vk_offsets {
            if let Ok(v) = self.read_vk(vk_off) {
                values.push(v);
            }
        }

        Ok(values)
    }

    /// Read a vk (value) block.
    ///
    /// Cell layout (per the registry file format spec):
    /// - Offset 0: Size (i32, negative for allocated)
    /// - Offset 4: Signature "vk" (2 bytes)
    /// - Offset 6: Name length (u16)
    /// - Offset 8: Name (variable, ASCII or UTF-16LE)
    /// - After name: Data size (u32)
    /// - After name+4: Data offset (u32, HBIN-relative, or inline if top bit of size is set)
    /// - After name+8: Data type (u32)
    /// - After name+12: Flags (u16)
    /// - After name+14: Spare (u16)
    fn read_vk(&self, offset: usize) -> Result<Value, HiveError> {
        if offset + 8 > self.data.len() {
            return Err(HiveError::Truncated);
        }
        let seg_len = read_i32(self.data, offset).ok_or(HiveError::Truncated)?;
        if seg_len >= 0 {
            return Err(HiveError::Truncated);
        }
        if &self.data[offset + 4..offset + 6] != VK_MAGIC {
            return Err(HiveError::Truncated);
        }

        let name_len = read_u16(self.data, offset + 6).ok_or(HiveError::Truncated)? as usize;
        let name_start = offset + 8;
        let (name, data_start) = if name_len > 0 {
            let name_end = name_start + name_len;
            if name_end > self.data.len() {
                return Err(HiveError::Truncated);
            }
            let name = decode_name(&self.data[name_start..name_end]);
            (name, name_end)
        } else {
            (String::new(), name_start)
        };

        if data_start + 16 > self.data.len() {
            return Err(HiveError::Truncated);
        }

        let data_len_raw = read_u32(self.data, data_start).ok_or(HiveError::Truncated)?;
        let data_offset_raw = read_u32(self.data, data_start + 4).ok_or(HiveError::Truncated)?;
        let data_type = read_u32(self.data, data_start + 8).ok_or(HiveError::Truncated)?;

        // Top bit of data_len indicates inline data
        let inline = (data_len_raw & 0x8000_0000) != 0;
        let data_len = if inline {
            data_len_raw & 0x7FFF_FFFF
        } else {
            data_len_raw
        } as usize;

        let data = if inline {
            data_offset_raw.to_le_bytes()[..data_len.min(4)].to_vec()
        } else {
            let data_off = self.hbin_to_absolute(data_offset_raw);
            if data_off + data_len > self.data.len() {
                return Err(HiveError::Truncated);
            }
            self.data[data_off..data_off + data_len].to_vec()
        };

        Ok(Value {
            name,
            value_type: data_type,
            data,
        })
    }

    /// Get a single value by name from a node.
    pub fn get_value(&self, node: &KeyNode, name: &str) -> Result<Option<Value>, HiveError> {
        let vals = self.values(node)?;
        for v in vals {
            if v.name.eq_ignore_ascii_case(name) {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    /// Open a key by path (e.g., "System/Objects/{guid}")
    /// Supports both "/" and "\" as path separators.
    pub fn open(&self, path: &str) -> Result<KeyNode, HiveError> {
        let root = self.root()?;
        let parts: Vec<&str> = path
            .split(|c| c == '/' || c == '\\')
            .filter(|s| !s.is_empty())
            .collect();
        let mut current = root;
        for part in parts {
            let subkeys = self.subkeys(&current)?;
            let next = subkeys.iter().find(|k| {
                k.name.eq_ignore_ascii_case(part)
            });
            match next {
                Some(n) => current = n.clone(),
                None => return Err(HiveError::OutOfBounds),
            }
        }
        Ok(current)
    }

    /// Open a key relative to another key.
    /// Supports both "/" and "\" as path separators.
    pub fn open_at(&self, base: &KeyNode, relative_path: &str) -> Result<KeyNode, HiveError> {
        let parts: Vec<&str> = relative_path
            .split(|c| c == '/' || c == '\\')
            .filter(|s| !s.is_empty())
            .collect();
        let mut current = base.clone();
        for part in parts {
            let subkeys = self.subkeys(&current)?;
            let next = subkeys.iter().find(|k| {
                k.name.eq_ignore_ascii_case(part)
            });
            match next {
                Some(n) => current = n.clone(),
                None => return Err(HiveError::OutOfBounds),
            }
        }
        Ok(current)
    }
}
