//! Hive writer — serialise an in-memory key tree back into our
//! on-disk `REGF` format.
//!
//! The writer is intentionally minimal: it accepts a `KeyNode`
//! tree (root + child `KeyNode`s + `Value`s) and lays out a single
//! HBIN that contains exactly the cells needed to round-trip back
//! through `hive::Hive::parse`. Round-trip is sufficient for our
//! smoke tests and for the "save registry changes to disk" path
//! requested by the user — it is *not* a full registry editor.
//!
//! ## On-disk layout
//!
//! ```text
//! REGF v1 header (4 KiB)
//!   magic       "REGF"
//!   version     1
//!   root_cell   offset of root `nk`
//!   cell_count  number of cells in the body
//!   timestamp   now (set by caller)
//!   checksum    XOR of preceding 28 bytes
//!
//! HBIN (4 KiB)
//!   sig         "HBIN"
//!   offset_next 0   (single HBIN)
//!   _pad        [u8; 24]
//!   cells (8-byte aligned)
//! ```
//!
//! `nk` cells hold flags, subkey count, subkey-list offset, value
//! count, value-list offset, name length, and UTF-16 name.
//! `vk` cells hold name length, UTF-16 name, type, length, and
//! payload. `lk` cells hold child `nk` offsets.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::hive::{
    CELL_HEADER, CELL_MAGIC_LK, CELL_MAGIC_NK, CELL_MAGIC_VK, HBIN_MAGIC, HBIN_SIZE,
    REGF_HEADER_SIZE, REGF_MAGIC, REGF_VERSION, ValueType,
};

#[derive(Debug, Clone)]
pub struct HiveValue {
    pub name: String,
    pub value_type: ValueType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HiveKey {
    pub name: String,
    pub flags: u16,
    pub subkeys: Vec<HiveKey>,
    pub values: Vec<HiveValue>,
}

/// Builder API. Reuse a single instance per hive to amortise the
/// allocation cost.
pub struct HiveWriter {
    body: Vec<u8>,
}

impl HiveWriter {
    pub fn new() -> Self {
        Self {
            // Start the body after the REGF header so `body_off`
            // is also a valid file offset for the cells.
            body: Vec::with_capacity(HBIN_SIZE - REGF_HEADER_SIZE),
        }
    }

    fn align_up(offset: usize, alignment: usize) -> usize {
        (offset + alignment - 1) & !(alignment - 1)
    }

    /// Append a single cell and return its file offset.
    fn append_cell(&mut self, kind: u8, payload: &[u8]) -> u32 {
        let total = CELL_HEADER + payload.len();
        let total_aligned = Self::align_up(total, 8);
        let pad = total_aligned - total;

        let file_off = (REGF_HEADER_SIZE + self.body.len()) as u32;

        // size (i32, LE) — header + payload, *positive* = allocated.
        let size = total_aligned as i32;
        self.body.extend_from_slice(&size.to_le_bytes());
        // kind (1 byte)
        self.body.push(kind);
        // pad (3 bytes)
        self.body.extend_from_slice(&[0, 0, 0]);
        // payload
        self.body.extend_from_slice(payload);
        // tail padding
        self.body.extend(core::iter::repeat(0u8).take(pad));

        file_off
    }

    /// Encode a UTF-16LE string with no NUL terminator (the
    /// cell-size field is what marks the end).
    fn encode_utf16le(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() * 2);
        for ch in s.encode_utf16() {
            out.extend_from_slice(&ch.to_le_bytes());
        }
        out
    }

    /// Serialise `key` (recursively) and return the file offset of
    /// its `nk` cell.
    fn write_key(&mut self, key: &HiveKey) -> Result<u32, &'static str> {
        // ---- subkeys (recursively) -----------------------------------
        let mut sub_offsets: Vec<u32> = Vec::with_capacity(key.subkeys.len());
        for child in &key.subkeys {
            sub_offsets.push(self.write_key(child)?);
        }
        // ---- values ---------------------------------------------------
        let mut value_offsets: Vec<u32> = Vec::with_capacity(key.values.len());
        for v in &key.values {
            value_offsets.push(self.write_value(v)?);
        }
        // ---- lk cell (subkey list) ------------------------------------
        let subk_off = if sub_offsets.is_empty() {
            0u32
        } else {
            // payload = count(u32) + [u32; count]
            let mut payload = Vec::with_capacity(4 + sub_offsets.len() * 4);
            payload.extend_from_slice(&(sub_offsets.len() as u32).to_le_bytes());
            for o in &sub_offsets {
                payload.extend_from_slice(&o.to_le_bytes());
            }
            self.append_cell(CELL_MAGIC_LK, &payload)
        };
        // ---- nk cell -------------------------------------------------
        // payload layout (matches `tools::hive_gen`):
        //   +0x00: u16 flags
        //   +0x02: u32 num_subkeys
        //   +0x06: u32 subkeys_off
        //   +0x0A: u32 num_values
        //   +0x0E: u32 values_off
        //   +0x12: u16 name_len (chars)
        //   +0x14: [u16; name_len]
        let name_utf16 = Self::encode_utf16le(&key.name);
        let mut nk_payload = Vec::with_capacity(20 + name_utf16.len());
        nk_payload.extend_from_slice(&key.flags.to_le_bytes());
        nk_payload.extend_from_slice(&(key.subkeys.len() as u32).to_le_bytes());
        nk_payload.extend_from_slice(&subk_off.to_le_bytes());
        nk_payload.extend_from_slice(&(key.values.len() as u32).to_le_bytes());
        let first_value_off = value_offsets.first().copied().unwrap_or(0);
        nk_payload.extend_from_slice(&first_value_off.to_le_bytes());
        nk_payload.extend_from_slice(&(key.name.len() as u16).to_le_bytes());
        nk_payload.extend_from_slice(&name_utf16);

        let nk_off = self.append_cell(CELL_MAGIC_NK, &nk_payload);
        Ok(nk_off)
    }

    fn write_value(&mut self, v: &HiveValue) -> Result<u32, &'static str> {
        // payload layout:
        //   +0x00: u16 name_len (chars)
        //   +0x02: [u16; name_len]
        //   +0x??: u32 data_type
        //   +0x??: u32 data_len
        //   +0x??: [u8; data_len]
        let name_utf16 = Self::encode_utf16le(&v.name);
        let mut payload = Vec::with_capacity(2 + name_utf16.len() + 4 + 4 + v.data.len());
        payload.extend_from_slice(&(v.name.len() as u16).to_le_bytes());
        payload.extend_from_slice(&name_utf16);
        payload.extend_from_slice(&v.value_type.to_u32().to_le_bytes());
        payload.extend_from_slice(&(v.data.len() as u32).to_le_bytes());
        payload.extend_from_slice(&v.data);
        Ok(self.append_cell(CELL_MAGIC_VK, &payload))
    }

    /// Compute the XOR checksum of the first 28 bytes of `header`.
    fn compute_checksum(header: &[u8]) -> u32 {
        let mut cs: u32 = 0;
        for off in (0..28).step_by(4) {
            let mut b = [0u8; 4];
            b.copy_from_slice(&header[off..off + 4]);
            cs ^= u32::from_le_bytes(b);
        }
        cs
    }

    /// Serialise the tree starting from `root` into a fresh hive
    /// byte buffer. The buffer is a full REGF file: 4 KiB header
    /// + one HBIN + cells. The total file size is always
    /// `REGF_HEADER_SIZE + HBIN_SIZE`.
    pub fn serialise(&mut self, root: &HiveKey, timestamp: u64) -> Result<Vec<u8>, &'static str> {
        self.body.clear();
        let root_off = self.write_key(root)?;
        // If the body overflowed one HBIN we'd need to emit more;
        // for our small registry trees it always fits in 4 KiB.
        if REGF_HEADER_SIZE + self.body.len() > HBIN_SIZE {
            return Err("hive too large for one HBIN");
        }
        let cell_count = count_cells(&self.body);

        // ---- Build the REGF header -----------------------------------
        let mut header = [0u8; REGF_HEADER_SIZE];
        header[0..4].copy_from_slice(REGF_MAGIC);
        header[4..8].copy_from_slice(&REGF_VERSION.to_le_bytes());
        // flags = 0
        header[12..16].copy_from_slice(&root_off.to_le_bytes());
        header[16..20].copy_from_slice(&(cell_count as u32).to_le_bytes());
        header[20..28].copy_from_slice(&timestamp.to_le_bytes());
        let checksum = Self::compute_checksum(&header);
        header[28..32].copy_from_slice(&checksum.to_le_bytes());

        // ---- Build the HBIN ------------------------------------------
        let mut hbin = [0u8; HBIN_SIZE];
        hbin[0..4].copy_from_slice(HBIN_MAGIC);
        // offset_next = 0 (single HBIN)
        hbin[8..32].copy_from_slice(&[0u8; 24]);
        hbin[REGF_HEADER_SIZE - REGF_HEADER_SIZE..].copy_from_slice(&self.body);
        // hbin[0..32] is the HBIN header; the cells start at HBIN[32].

        // ---- Concatenate ---------------------------------------------
        let mut out = Vec::with_capacity(REGF_HEADER_SIZE + HBIN_SIZE);
        out.extend_from_slice(&header);
        out.extend_from_slice(&hbin);
        Ok(out)
    }
}

impl Default for HiveWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Count cells by scanning the cell header's leading `i32 size`
/// field and the `kind` byte. Cells we recognise are `n`, `v`, `l`.
fn count_cells(body: &[u8]) -> usize {
    let mut count = 0;
    let mut off = 0;
    while off + CELL_HEADER <= body.len() {
        let size = i32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
        let kind = body[off + 4];
        if size <= 0 {
            break;
        }
        if matches!(kind, CELL_MAGIC_NK | CELL_MAGIC_VK | CELL_MAGIC_LK) {
            count += 1;
        }
        // Align up to 8 bytes (matching `append_cell`'s pad).
        let total = ((size as usize) + 7) & !7;
        off += total;
    }
    count
}

// =============================================================================
// Disk persistence (load / save a hive from a file path)
// =============================================================================

#[cfg(target_arch = "x86_64")]
pub mod disk {
    //! Disk-backed hive load/save helpers. We use the existing
    //! `crate::fs` VFS to read/write files — this keeps the
    //! implementation portable across NTFS and FAT32 mounts and
    //! lets us hand the bytes directly to `hive::Hive::parse`.
    use super::*;

    /// Open the file at `path` and read up to `max_bytes` into a
    /// heap buffer. Returns `None` if the file cannot be opened.
    pub fn load_hive_file(path: &str, max_bytes: usize) -> Option<Vec<u8>> {
        // Lazy FS open: walk the path through the VFS.
        let mut buffer = alloc::vec![0u8; max_bytes];
        let n = crate::fs::vfs::vfs_read(path, &mut buffer).ok()?;
        buffer.truncate(n);
        Some(buffer)
    }

    /// Persist `bytes` to `path`. Returns `true` on success.
    pub fn save_hive_file(path: &str, bytes: &[u8]) -> bool {
        crate::fs::vfs::vfs_write(path, bytes).is_ok()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_round_trips() {
        let mut w = HiveWriter::new();
        let root = HiveKey {
            name: String::new(),
            flags: 0,
            subkeys: vec![],
            values: vec![],
        };
        let bytes = w.serialise(&root, 0xDEAD_BEEF_CAFE_BABE).unwrap();
        assert_eq!(bytes.len(), REGF_HEADER_SIZE + HBIN_SIZE);

        // Re-parse with the existing parser.
        let parsed = super::super::hive::Hive::parse(&bytes).unwrap();
        let n = parsed.root().unwrap();
        assert_eq!(n.name, "");
        assert!(parsed.subkeys(&n).unwrap().is_empty());
    }

    #[test]
    fn value_round_trips() {
        let mut w = HiveWriter::new();
        let root = HiveKey {
            name: String::new(),
            flags: 0,
            subkeys: vec![],
            values: vec![HiveValue {
                name: "FriendlyName".into(),
                value_type: ValueType::String,
                data: {
                    let s: Vec<u16> = "hello".encode_utf16().collect();
                    let mut b = Vec::with_capacity(s.len() * 2);
                    for c in &s {
                        b.extend_from_slice(&c.to_le_bytes());
                    }
                    b
                },
            }],
        };
        let bytes = w.serialise(&root, 0).unwrap();
        let parsed = super::super::hive::Hive::parse(&bytes).unwrap();
        let n = parsed.root().unwrap();
        let vs = parsed.values(&n).unwrap();
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].name, "FriendlyName");
        assert_eq!(vs[0].as_utf16_string().as_deref(), Some("hello"));
    }

    #[test]
    fn subkeys_round_trip() {
        let mut w = HiveWriter::new();
        let root = HiveKey {
            name: String::new(),
            flags: 0,
            subkeys: vec![
                HiveKey {
                    name: "A".into(),
                    flags: 0,
                    subkeys: vec![],
                    values: vec![],
                },
                HiveKey {
                    name: "B".into(),
                    flags: 0,
                    subkeys: vec![],
                    values: vec![],
                },
            ],
            values: vec![],
        };
        let bytes = w.serialise(&root, 0).unwrap();
        let parsed = super::super::hive::Hive::parse(&bytes).unwrap();
        let n = parsed.root().unwrap();
        let subs = parsed.subkeys(&n).unwrap();
        assert_eq!(subs.len(), 2);
        let names: alloc::vec::Vec<&str> = subs.iter().map(|k| k.name.as_str()).collect();
        assert!(names.contains(&"A"));
        assert!(names.contains(&"B"));
    }
}