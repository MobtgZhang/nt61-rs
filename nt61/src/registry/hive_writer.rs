//! Hive writer — serialise an in-memory key tree into a real
//! Windows `regf` on-disk format.
//!
//! Produces output compatible with `registry::hive::Hive::parse`:
//! lowercase magic, 8-byte aligned cells with negative seg_len,
//! nk/vk field offsets matching the real NT 6.1 layout.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::hive::{
    ValueType, HBIN_BASE, HBIN_HEADER_SIZE, HBIN_MAGIC, HBIN_SIZE, REGF_HEADER_SIZE, REGF_MAGIC,
    REGF_MAJOR_VERSION,
};

const ID_NK: &[u8; 2] = b"nk";
const ID_VK: &[u8; 2] = b"vk";
const ID_LH: &[u8; 2] = b"lh";

const LH_ENTRY_SIZE: usize = 8;

// nk field offsets (relative to cell start)
const NK_FLAGS: usize = 0x06;
const NK_PARENT: usize = 0x14;
const NK_NR_SUBKEYS: usize = 0x18;
const NK_SUBKEY_LF: usize = 0x20;
const NK_NR_VALUES: usize = 0x28;
const NK_VALLIST: usize = 0x2C;
const NK_NAME_LEN: usize = 0x4C;
const NK_NAME: usize = 0x50;
const NK_FLAG_ASCII_NAME: u16 = 0x0020;

// vk field offsets (relative to cell start)
const VK_NAME_LEN: usize = 0x06;
const VK_DATA_SIZE: usize = 0x08;
const VK_DATA_OFFSET: usize = 0x0C;
const VK_DATA_TYPE: usize = 0x10;
const VK_FLAGS: usize = 0x14;
const VK_NAME: usize = 0x18;
const VK_FLAG_ASCII_NAME: u32 = 0x0000_0001;
const VK_DATA_INLINE_FLAG: u32 = 0x8000_0000;
const VK_INLINE_MAX: usize = 4;

const CHECKSUM_OFFSET: usize = 0x1FC;

pub struct HiveValue {
    pub name: String,
    pub value_type: ValueType,
    pub data: Vec<u8>,
}

pub struct HiveKey {
    pub name: String,
    pub flags: u16,
    pub subkeys: Vec<HiveKey>,
    pub values: Vec<HiveValue>,
}

impl HiveKey {
    pub fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            flags: 0,
            subkeys: Vec::new(),
            values: Vec::new(),
        }
    }
}

pub struct HiveWriter {
    /// Data area bytes, with each HBIN header embedded at
    /// `hbin_headers[i]`. File offset of body[i] is HBIN_BASE + i.
    body: Vec<u8>,
    /// Body offsets where each HBIN header starts.
    hbin_headers: Vec<usize>,
}

impl HiveWriter {
    pub fn new() -> Self {
        Self {
            body: Vec::with_capacity(HBIN_SIZE),
            hbin_headers: Vec::new(),
        }
    }

    /// Make room for one cell of `total_aligned` bytes. Cells never cross
    /// an HBIN boundary (the parser walks cells strictly inside one HBIN),
    /// so a cell that does not fit closes the current HBIN and opens a
    /// fresh one. A cell larger than a whole HBIN cannot be represented.
    fn ensure_room(&mut self, total_aligned: usize) -> Result<(), &'static str> {
        let hbin_data_cap = HBIN_SIZE - HBIN_HEADER_SIZE;
        if total_aligned > hbin_data_cap {
            return Err("cell too large for one HBIN");
        }
        let cur_header = match self.hbin_headers.last() {
            Some(pos) => *pos,
            None => {
                self.hbin_headers.push(0);
                self.body.extend(core::iter::repeat(0u8).take(HBIN_HEADER_SIZE));
                0
            }
        };
        let hbin_end = cur_header + HBIN_SIZE;
        if self.body.len() + total_aligned > hbin_end {
            // Close the current HBIN (padded to its full declared size) and
            // open a new one.
            self.body.resize(hbin_end, 0);
            self.hbin_headers.push(self.body.len());
            self.body.extend(core::iter::repeat(0u8).take(HBIN_HEADER_SIZE));
        }
        Ok(())
    }

    fn align_up(offset: usize, alignment: usize) -> usize {
        (offset + alignment - 1) & !(alignment - 1)
    }

    fn append_cell(&mut self, id: &[u8; 2], payload: &[u8]) -> Result<u32, &'static str> {
        let total = 8 + payload.len();
        let total_aligned = Self::align_up(total, 8);
        let pad = total_aligned - total;

        self.ensure_room(total_aligned)?;

        // body includes the embedded HBIN headers, so the file offset of
        // the next byte is HBIN_BASE + body.len().
        let file_off = (HBIN_BASE + self.body.len()) as u32;

        self.body
            .extend_from_slice(&(-(total_aligned as i32)).to_le_bytes());
        self.body.extend_from_slice(id);
        self.body.extend_from_slice(&[0, 0]);
        self.body.extend_from_slice(payload);
        self.body.extend(core::iter::repeat(0u8).take(pad));

        Ok(file_off)
    }

    /// Append a raw cell: seg_len(4) + data, no ID field.
    /// Used for vallist and data blocks which have no 2-byte ID.
    fn append_raw_cell(&mut self, total_size: usize) -> Result<u32, &'static str> {
        self.ensure_room(total_size)?;
        let file_off = (HBIN_BASE + self.body.len()) as u32;
        self.body
            .extend_from_slice(&(-(total_size as i32)).to_le_bytes());
        self.body
            .extend(core::iter::repeat(0u8).take(total_size - 4));
        Ok(file_off)
    }

    fn to_hbin_rel(abs: u32) -> u32 {
        if abs == 0 {
            0
        } else {
            abs - HBIN_BASE as u32
        }
    }

    /// Encode a name as on-disk bytes plus the ASCII-name flag.
    ///
    /// Pure-ASCII names are written as their bytes with the ASCII flag
    /// set (matching real compressed hives); anything else MUST be
    /// written as UTF-16LE with the flag clear. The old behaviour of
    /// stuffing `s.as_bytes()` into the name cell corrupted every
    /// non-ASCII name: the UTF-8 bytes were stored verbatim, the name
    /// length no longer matched the character count, and the reader
    /// reinterpreted the bytes as ASCII garbage.
    fn encode_name(s: &str) -> (Vec<u8>, bool) {
        if s.chars().all(|c| (c as u32) < 0x80) {
            (s.as_bytes().to_vec(), true)
        } else {
            let units: Vec<u8> = s
                .encode_utf16()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            (units, false)
        }
    }

    /// FOUR-CC style hash over the first four name characters, the
    /// convention Windows lh cells use. The local parser ignores the
    /// field, but real hive consumers (regf tools) use it for lookups,
    /// so a deterministic non-zero value is written instead of 0.
    fn entry_hash(name: &str) -> u32 {
        let mut hash: u32 = 0;
        for (i, c) in name.chars().take(4).enumerate() {
            hash |= (c.to_ascii_lowercase() as u32) << (8 * i);
        }
        hash
    }

    fn write_key(&mut self, key: &HiveKey, parent_off: u32) -> Result<u32, &'static str> {
        let (name_bytes, name_is_ascii) = Self::encode_name(&key.name);
        let nk_cell_size = Self::align_up(NK_NAME + name_bytes.len(), 8);
        let payload_len = nk_cell_size - 8;

        // Reserve the nk cell (fill in fields after children are written)
        let nk_off = self.append_cell(ID_NK, &alloc::vec![0u8; payload_len])?;

        // Write values first (so we can patch vallist offset)
        let mut vk_offsets: Vec<u32> = Vec::with_capacity(key.values.len());
        for v in &key.values {
            vk_offsets.push(self.write_value(v)?);
        }

        // Write value list cell
        let vallist_off = if !vk_offsets.is_empty() {
            let vl_size = Self::align_up(4 + vk_offsets.len() * 4, 8);
            let vl_off = self.append_raw_cell(vl_size)?;
            // Fill in vk offsets (HBIN-relative) starting at vl_off + 4
            for (i, &vk_abs) in vk_offsets.iter().enumerate() {
                let entry = (vl_off + 4 + (i as u32) * 4) as usize;
                let rel = Self::to_hbin_rel(vk_abs);
                self.body[entry - HBIN_BASE..entry - HBIN_BASE + 4]
                    .copy_from_slice(&rel.to_le_bytes());
            }
            vl_off
        } else {
            0
        };

        // Write subkeys (lh cell)
        let subk_off = if !key.subkeys.is_empty() {
            let mut child_offsets = Vec::with_capacity(key.subkeys.len());
            let mut child_names: Vec<&str> = Vec::with_capacity(key.subkeys.len());
            for child in &key.subkeys {
                let child_off = self.write_key(child, nk_off)?;
                child_offsets.push(child_off);
                child_names.push(child.name.as_str());
            }

            let lh_size = Self::align_up(8 + child_offsets.len() * LH_ENTRY_SIZE, 8);
            let lh_payload_len = lh_size - 8;
            let lh_off = self.append_cell(ID_LH, &alloc::vec![0u8; lh_payload_len])?;

            // Write nr at +6 (in the pad field)
            let nr_pos = (lh_off + 6) as usize;
            self.body[nr_pos - HBIN_BASE..nr_pos - HBIN_BASE + 2]
                .copy_from_slice(&(child_offsets.len() as u16).to_le_bytes());

            // Fill in child offsets at +8 (payload start)
            let lh_body_start = (lh_off + 8) as usize;
            for (i, &child_abs) in child_offsets.iter().enumerate() {
                let entry = lh_body_start + i * LH_ENTRY_SIZE;
                let rel = Self::to_hbin_rel(child_abs);
                self.body[entry - HBIN_BASE..entry - HBIN_BASE + 4]
                    .copy_from_slice(&rel.to_le_bytes());
                // hash (4 bytes): FOUR-CC over the child name so real
                // hive consumers can use their lookup path.
                let hash_pos = entry - HBIN_BASE + 4;
                self.body[hash_pos..hash_pos + 4]
                    .copy_from_slice(&Self::entry_hash(child_names[i]).to_le_bytes());
            }
            lh_off
        } else {
            0
        };

        // Patch the nk cell fields
        self.patch_nk_cell(
            nk_off,
            key,
            parent_off,
            subk_off,
            vallist_off,
            &vk_offsets,
            name_is_ascii,
        );

        Ok(nk_off)
    }

    fn patch_nk_cell(
        &mut self,
        nk_off: u32,
        key: &HiveKey,
        parent_off: u32,
        subk_off: u32,
        vallist_off: u32,
        vk_offsets: &[u32],
        name_is_ascii: bool,
    ) {
        let nk_body = (nk_off - HBIN_BASE as u32) as usize;

        // flags (u16 at 0x06): bit 5 = ASCII name; UTF-16LE names
        // leave the bit clear so the reader decodes the right encoding.
        let nk_flags: u16 = if name_is_ascii {
            NK_FLAG_ASCII_NAME
        } else {
            0
        };
        self.body[nk_body + NK_FLAGS..nk_body + NK_FLAGS + 2]
            .copy_from_slice(&nk_flags.to_le_bytes());

        // parent (u32 at 0x14): HBIN-relative
        let parent_rel = Self::to_hbin_rel(parent_off);
        self.body[nk_body + NK_PARENT..nk_body + NK_PARENT + 4]
            .copy_from_slice(&parent_rel.to_le_bytes());

        // nr_subkeys (u32 at 0x18)
        self.body[nk_body + NK_NR_SUBKEYS..nk_body + NK_NR_SUBKEYS + 4]
            .copy_from_slice(&(key.subkeys.len() as u32).to_le_bytes());

        // subkey_lf (u32 at 0x20): HBIN-relative
        let subk_rel = if subk_off != 0 {
            Self::to_hbin_rel(subk_off)
        } else {
            0xFFFF_FFFF
        };
        self.body[nk_body + NK_SUBKEY_LF..nk_body + NK_SUBKEY_LF + 4]
            .copy_from_slice(&subk_rel.to_le_bytes());

        // nr_values (u32 at 0x28)
        self.body[nk_body + NK_NR_VALUES..nk_body + NK_NR_VALUES + 4]
            .copy_from_slice(&(vk_offsets.len() as u32).to_le_bytes());

        // vallist (u32 at 0x2C): HBIN-relative
        let vallist_rel = if vallist_off != 0 {
            Self::to_hbin_rel(vallist_off)
        } else {
            0xFFFF_FFFF
        };
        self.body[nk_body + NK_VALLIST..nk_body + NK_VALLIST + 4]
            .copy_from_slice(&vallist_rel.to_le_bytes());

        // name_len (u16 at 0x4C)
        let (name_bytes, _) = Self::encode_name(&key.name);
        self.body[nk_body + NK_NAME_LEN..nk_body + NK_NAME_LEN + 2]
            .copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());

        // name (at 0x50)
        self.body[nk_body + NK_NAME..nk_body + NK_NAME + name_bytes.len()]
            .copy_from_slice(&name_bytes);
    }

    fn write_value(&mut self, v: &HiveValue) -> Result<u32, &'static str> {
        let (name_bytes, name_is_ascii) = Self::encode_name(&v.name);
        let vk_cell_size = Self::align_up(VK_NAME + name_bytes.len(), 8);
        let payload_len = vk_cell_size - 8;

        let vk_off = self.append_cell(ID_VK, &alloc::vec![0u8; payload_len])?;

        // Write data block if not inline
        let inline = v.data.len() <= VK_INLINE_MAX;
        let (data_size, data_offset) = if inline {
            let ds = VK_DATA_INLINE_FLAG | (v.data.len() as u32);
            let mut le = [0u8; 4];
            for (j, &b) in v.data.iter().enumerate() {
                if j < VK_INLINE_MAX {
                    le[j] = b;
                }
            }
            (ds, u32::from_le_bytes(le))
        } else {
            let ds_size = Self::align_up(4 + v.data.len(), 8);
            let ds_off = self.append_raw_cell(ds_size)?;

            // Fill data bytes starting at ds_off + 4 (right after seg_len)
            let ds_body = (ds_off + 4) as usize;
            for (j, &b) in v.data.iter().enumerate() {
                self.body[ds_body - HBIN_BASE + j] = b;
            }

            (v.data.len() as u32, Self::to_hbin_rel(ds_off + 4))
        };

        // Patch the vk cell fields
        let vk_body = (vk_off - HBIN_BASE as u32) as usize;

        self.body[vk_body + VK_NAME_LEN..vk_body + VK_NAME_LEN + 2]
            .copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        self.body[vk_body + VK_DATA_SIZE..vk_body + VK_DATA_SIZE + 4]
            .copy_from_slice(&data_size.to_le_bytes());
        self.body[vk_body + VK_DATA_OFFSET..vk_body + VK_DATA_OFFSET + 4]
            .copy_from_slice(&data_offset.to_le_bytes());
        self.body[vk_body + VK_DATA_TYPE..vk_body + VK_DATA_TYPE + 4]
            .copy_from_slice(&v.value_type.to_u32().to_le_bytes());
        let vk_flags: u32 = if name_is_ascii {
            VK_FLAG_ASCII_NAME
        } else {
            0
        };
        self.body[vk_body + VK_FLAGS..vk_body + VK_FLAGS + 4]
            .copy_from_slice(&vk_flags.to_le_bytes());
        self.body[vk_body + VK_NAME..vk_body + VK_NAME + name_bytes.len()]
            .copy_from_slice(&name_bytes);

        Ok(vk_off)
    }

    pub fn serialise(&mut self, root: &HiveKey, timestamp: u64) -> Result<Vec<u8>, &'static str> {
        self.body.clear();
        self.hbin_headers.clear();
        // Reserve the first HBIN header; magic and size are stamped in
        // below once the final HBIN count is known.
        self.hbin_headers.push(0);
        self.body.extend(core::iter::repeat(0u8).take(HBIN_HEADER_SIZE));

        // Write the tree (returns absolute file offset of root nk)
        let root_abs = self.write_key(root, 0)?;

        // Pad the last HBIN to its full declared size so the file is
        // header + n * HBIN_SIZE, then stamp every HBIN header.
        let hbin_count = self.hbin_headers.len();
        let data_len = hbin_count * HBIN_SIZE;
        self.body.resize(data_len, 0);
        for &pos in &self.hbin_headers {
            self.body[pos..pos + 4].copy_from_slice(HBIN_MAGIC);
            self.body[pos + 4..pos + 8]
                .copy_from_slice(&((HBIN_BASE + pos) as u32).to_le_bytes());
            self.body[pos + 8..pos + 12].copy_from_slice(&(HBIN_SIZE as u32).to_le_bytes());
        }

        // Build the REGF header (4096 bytes)
        let mut header = alloc::vec![0u8; REGF_HEADER_SIZE];
        header[0..4].copy_from_slice(REGF_MAGIC);
        // Sequence numbers: on a cleanly flushed hive both counters are
        // equal (Windows bumps 0x04 first, then copies it to 0x08).
        header[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
        header[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes());
        // Last-write timestamp (FILETIME).
        header[0x0C..0x14].copy_from_slice(&timestamp.to_le_bytes());
        header[0x14..0x18].copy_from_slice(&REGF_MAJOR_VERSION.to_le_bytes());
        // Minor version: 5 on every NT 6.1 hive (format 1.5).
        header[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes());
        // File type: 0 = primary hive. File format: 1.
        header[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        // Root offset is HBIN-relative
        let root_rel = Self::to_hbin_rel(root_abs);
        header[0x24..0x28].copy_from_slice(&root_rel.to_le_bytes());
        // Cluster size / hive data length: header plus every HBIN.
        header[0x28..0x2C]
            .copy_from_slice(&((REGF_HEADER_SIZE + data_len) as u32).to_le_bytes());
        header[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());

        // Compute checksum (XOR of all dwords [0, 0x1FC))
        let checksum = Self::compute_checksum(&header);
        header[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());

        let mut out = Vec::with_capacity(REGF_HEADER_SIZE + data_len);
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    fn compute_checksum(data: &[u8]) -> u32 {
        let mut sum = 0u32;
        let mut off = 0;
        while off + 4 <= CHECKSUM_OFFSET {
            if off + 4 <= data.len() {
                let b = [data[off], data[off + 1], data[off + 2], data[off + 3]];
                sum ^= u32::from_le_bytes(b);
            }
            off += 4;
        }
        sum
    }
}

impl Default for HiveWriter {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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
    fn non_ascii_names_round_trip_via_utf16() {
        // Non-ASCII names must be written as UTF-16LE with the ASCII
        // flag clear, and survive a serialise/parse round trip.
        let root = HiveKey {
            name: String::new(),
            flags: 0,
            subkeys: vec![HiveKey {
                name: "\u{7cfb}\u{7edf}".into(),
                flags: 0,
                subkeys: vec![],
                values: vec![HiveValue {
                    name: "Cl\u{00e9}".into(),
                    value_type: ValueType::Binary,
                    data: vec![1u8, 2, 3],
                }],
            }],
            values: vec![],
        };

        let mut w = HiveWriter::new();
        let bytes = w.serialise(&root, 0).unwrap();

        // The nk name flag must not claim ASCII for the UTF-16 name.
        let parsed = super::super::hive::Hive::parse(&bytes).unwrap();
        let n = parsed.root().unwrap();
        let subs = parsed.subkeys(&n).unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(
            subs[0].flags & 0x0020,
            0,
            "UTF-16 name must not carry the ASCII flag: flags=0x{:x}",
            subs[0].flags
        );
        assert_eq!(subs[0].name, "\u{7cfb}\u{7edf}");
        let vs = parsed.values(&subs[0]).unwrap();
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].name, "Cl\u{00e9}");
        assert_eq!(vs[0].data, vec![1u8, 2, 3]);
    }

    #[test]
    fn multi_hbin_tree_round_trips() {
        // Enough subkeys with non-inline values to spill past one HBIN's
        // data capacity (4064 bytes).
        let count = 40;
        let mut subkeys = Vec::new();
        for i in 0..count {
            subkeys.push(HiveKey {
                name: alloc::format!("Key{:03}", i),
                flags: 0,
                subkeys: vec![],
                values: vec![HiveValue {
                    name: alloc::format!("Val{:03}", i),
                    value_type: ValueType::Binary,
                    data: vec![0xABu8; 64],
                }],
            });
        }
        let root = HiveKey {
            name: String::new(),
            flags: 0,
            subkeys,
            values: vec![],
        };

        let mut w = HiveWriter::new();
        let bytes = w.serialise(&root, 0).unwrap();

        // The tree must actually span more than one HBIN for this test to
        // exercise the multi-HBIN path.
        assert!(
            bytes.len() > REGF_HEADER_SIZE + HBIN_SIZE,
            "tree unexpectedly fits one HBIN: {}",
            bytes.len()
        );
        assert_eq!(bytes.len() % HBIN_SIZE, REGF_HEADER_SIZE % HBIN_SIZE);

        // Every HBIN slot carries the hbin magic.
        let hbin_count = (bytes.len() - REGF_HEADER_SIZE) / HBIN_SIZE;
        for k in 0..hbin_count {
            let off = HBIN_BASE + k * HBIN_SIZE;
            assert_eq!(&bytes[off..off + 4], super::super::hive::HBIN_MAGIC);
        }

        let parsed = super::super::hive::Hive::parse(&bytes).unwrap();
        let n = parsed.root().unwrap();
        let subs = parsed.subkeys(&n).unwrap();
        assert_eq!(subs.len(), count);
        for (i, sub) in subs.iter().enumerate() {
            assert_eq!(sub.name, alloc::format!("Key{:03}", i));
            let vs = parsed.values(sub).unwrap();
            assert_eq!(vs.len(), 1);
            assert_eq!(vs[0].name, alloc::format!("Val{:03}", i));
            assert_eq!(vs[0].data.len(), 64);
            assert!(vs[0].data.iter().all(|&b| b == 0xAB));
        }
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
        assert_eq!(subs[0].name, "A");
        assert_eq!(subs[1].name, "B");
    }
}
