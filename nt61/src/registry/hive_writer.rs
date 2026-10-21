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
    body: Vec<u8>,
}

impl HiveWriter {
    pub fn new() -> Self {
        Self {
            body: Vec::with_capacity(HBIN_SIZE - HBIN_HEADER_SIZE),
        }
    }

    fn align_up(offset: usize, alignment: usize) -> usize {
        (offset + alignment - 1) & !(alignment - 1)
    }

    fn append_cell(&mut self, id: &[u8; 2], payload: &[u8]) -> u32 {
        let total = 8 + payload.len();
        let total_aligned = Self::align_up(total, 8);
        let pad = total_aligned - total;

        let file_off = (HBIN_BASE + HBIN_HEADER_SIZE + self.body.len()) as u32;

        self.body
            .extend_from_slice(&(-(total_aligned as i32)).to_le_bytes());
        self.body.extend_from_slice(id);
        self.body.extend_from_slice(&[0, 0]);
        self.body.extend_from_slice(payload);
        self.body.extend(core::iter::repeat(0u8).take(pad));

        file_off
    }

    /// Append a raw cell: seg_len(4) + data, no ID field.
    /// Used for vallist and data blocks which have no 2-byte ID.
    fn append_raw_cell(&mut self, total_size: usize) -> u32 {
        let file_off = (HBIN_BASE + HBIN_HEADER_SIZE + self.body.len()) as u32;
        self.body
            .extend_from_slice(&(-(total_size as i32)).to_le_bytes());
        self.body
            .extend(core::iter::repeat(0u8).take(total_size - 4));
        file_off
    }

    fn to_hbin_rel(abs: u32) -> u32 {
        if abs == 0 {
            0
        } else {
            abs - HBIN_BASE as u32
        }
    }

    /// Encode a string as bytes. Uses ASCII for names that fit;
    /// the parser handles both ASCII and UTF-16LE via the flag bit.
    fn encode_name(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    fn write_key(&mut self, key: &HiveKey, parent_off: u32) -> Result<u32, &'static str> {
        let name_bytes = Self::encode_name(&key.name);
        let nk_cell_size = Self::align_up(NK_NAME + name_bytes.len(), 8);
        let payload_len = nk_cell_size - 8;

        // Reserve the nk cell (fill in fields after children are written)
        let nk_off = self.append_cell(ID_NK, &alloc::vec![0u8; payload_len]);

        // Write values first (so we can patch vallist offset)
        let mut vk_offsets: Vec<u32> = Vec::with_capacity(key.values.len());
        for v in &key.values {
            vk_offsets.push(self.write_value(v)?);
        }

        // Write value list cell
        let vallist_off = if !vk_offsets.is_empty() {
            let vl_size = Self::align_up(4 + vk_offsets.len() * 4, 8);
            let vl_off = self.append_raw_cell(vl_size);
            // Fill in vk offsets (HBIN-relative) starting at vl_off + 4
            for (i, &vk_abs) in vk_offsets.iter().enumerate() {
                let entry = (vl_off + 4 + (i as u32) * 4) as usize;
                let rel = Self::to_hbin_rel(vk_abs);
                self.body[entry - HBIN_BASE - HBIN_HEADER_SIZE
                    ..entry - HBIN_BASE - HBIN_HEADER_SIZE + 4]
                    .copy_from_slice(&rel.to_le_bytes());
            }
            vl_off
        } else {
            0
        };

        // Write subkeys (lh cell)
        let subk_off = if !key.subkeys.is_empty() {
            let mut child_offsets = Vec::with_capacity(key.subkeys.len());
            for child in &key.subkeys {
                let child_off = self.write_key(child, nk_off)?;
                child_offsets.push(child_off);
            }

            let lh_size = Self::align_up(8 + child_offsets.len() * LH_ENTRY_SIZE, 8);
            let lh_payload_len = lh_size - 8;
            let lh_off = self.append_cell(ID_LH, &alloc::vec![0u8; lh_payload_len]);

            // Write nr at +6 (in the pad field)
            let nr_pos = (lh_off + 6) as usize;
            self.body
                [nr_pos - HBIN_BASE - HBIN_HEADER_SIZE..nr_pos - HBIN_BASE - HBIN_HEADER_SIZE + 2]
                .copy_from_slice(&(child_offsets.len() as u16).to_le_bytes());

            // Fill in child offsets at +8 (payload start)
            let lh_body_start = (lh_off + 8) as usize;
            for (i, &child_abs) in child_offsets.iter().enumerate() {
                let entry = lh_body_start + i * LH_ENTRY_SIZE;
                let rel = Self::to_hbin_rel(child_abs);
                self.body[entry - HBIN_BASE - HBIN_HEADER_SIZE
                    ..entry - HBIN_BASE - HBIN_HEADER_SIZE + 4]
                    .copy_from_slice(&rel.to_le_bytes());
                // hash (4 bytes) — set to 0 (parser ignores it)
            }
            lh_off
        } else {
            0
        };

        // Patch the nk cell fields
        self.patch_nk_cell(nk_off, key, parent_off, subk_off, vallist_off, &vk_offsets);

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
    ) {
        let nk_body = (nk_off - HBIN_BASE as u32 - HBIN_HEADER_SIZE as u32) as usize;

        // flags (u16 at 0x06): bit 5 = ASCII name
        self.body[nk_body + NK_FLAGS..nk_body + NK_FLAGS + 2]
            .copy_from_slice(&NK_FLAG_ASCII_NAME.to_le_bytes());

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
        let name_bytes = Self::encode_name(&key.name);
        self.body[nk_body + NK_NAME_LEN..nk_body + NK_NAME_LEN + 2]
            .copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());

        // name (at 0x50)
        self.body[nk_body + NK_NAME..nk_body + NK_NAME + name_bytes.len()]
            .copy_from_slice(&name_bytes);
    }

    fn write_value(&mut self, v: &HiveValue) -> Result<u32, &'static str> {
        let name_bytes = Self::encode_name(&v.name);
        let vk_cell_size = Self::align_up(VK_NAME + name_bytes.len(), 8);
        let payload_len = vk_cell_size - 8;

        let vk_off = self.append_cell(ID_VK, &alloc::vec![0u8; payload_len]);

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
            let ds_off = self.append_raw_cell(ds_size);

            // Fill data bytes starting at ds_off + 4 (right after seg_len)
            let ds_body = (ds_off + 4) as usize;
            for (j, &b) in v.data.iter().enumerate() {
                self.body[ds_body - HBIN_BASE - HBIN_HEADER_SIZE + j] = b;
            }

            (v.data.len() as u32, Self::to_hbin_rel(ds_off + 4))
        };

        // Patch the vk cell fields
        let vk_body = (vk_off - HBIN_BASE as u32 - HBIN_HEADER_SIZE as u32) as usize;

        self.body[vk_body + VK_NAME_LEN..vk_body + VK_NAME_LEN + 2]
            .copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        self.body[vk_body + VK_DATA_SIZE..vk_body + VK_DATA_SIZE + 4]
            .copy_from_slice(&data_size.to_le_bytes());
        self.body[vk_body + VK_DATA_OFFSET..vk_body + VK_DATA_OFFSET + 4]
            .copy_from_slice(&data_offset.to_le_bytes());
        self.body[vk_body + VK_DATA_TYPE..vk_body + VK_DATA_TYPE + 4]
            .copy_from_slice(&v.value_type.to_u32().to_le_bytes());
        self.body[vk_body + VK_FLAGS..vk_body + VK_FLAGS + 4]
            .copy_from_slice(&VK_FLAG_ASCII_NAME.to_le_bytes());
        self.body[vk_body + VK_NAME..vk_body + VK_NAME + name_bytes.len()]
            .copy_from_slice(&name_bytes);

        Ok(vk_off)
    }

    pub fn serialise(&mut self, root: &HiveKey, _timestamp: u64) -> Result<Vec<u8>, &'static str> {
        self.body.clear();

        // Write the tree (returns absolute file offset of root nk)
        let root_abs = self.write_key(root, 0)?;

        if self.body.len() > HBIN_SIZE - HBIN_HEADER_SIZE {
            return Err("hive too large for one HBIN");
        }

        // Build the REGF header (4096 bytes)
        let mut header = alloc::vec![0u8; REGF_HEADER_SIZE];
        header[0..4].copy_from_slice(REGF_MAGIC);
        header[0x14..0x18].copy_from_slice(&REGF_MAJOR_VERSION.to_le_bytes());
        // Root offset is HBIN-relative
        let root_rel = Self::to_hbin_rel(root_abs);
        header[0x24..0x28].copy_from_slice(&root_rel.to_le_bytes());

        // Compute checksum (XOR of all dwords [0, 0x1FC))
        let checksum = Self::compute_checksum(&header);
        header[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());

        // Build the HBIN
        let mut hbin = alloc::vec![0u8; HBIN_SIZE];
        hbin[0..4].copy_from_slice(HBIN_MAGIC);
        hbin[8..12].copy_from_slice(&(HBIN_SIZE as u32).to_le_bytes());
        hbin[HBIN_HEADER_SIZE..HBIN_HEADER_SIZE + self.body.len()].copy_from_slice(&self.body);

        let mut out = Vec::with_capacity(REGF_HEADER_SIZE + HBIN_SIZE);
        out.extend_from_slice(&header);
        out.extend_from_slice(&hbin);
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
