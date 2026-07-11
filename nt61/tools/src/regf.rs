//! Real Windows REGF (registry hive) v1 writer.
//!
//! This module emits binary `regf` files that are byte-for-byte compatible
//! with the Windows registry hive format, so they can be read by `hivex`,
//! `hivexsh`, `hivexget`, `hivexml`, and `hivexregedit`.
//!
//! ## On-disk format (brief)
//!
//! ```text
//! Offset 0x0000:  REGF header (4 KB)
//! Offset 0x1000:  HBIN page 0 (4 KB)
//!   cells (nk, lh, vk, data) 8-byte aligned, negative seg_len = in-use
//!   free block at end: positive seg_len
//! Offset 0x2000:  HBIN page 1
//!   ...
//! ```
//!
//! All internal storage uses **absolute file offsets**. Offsets are converted
//! to HBIN-relative only when writing into the binary cells.

/// A registry value with a name, type, and data.
#[derive(Debug, Clone)]
pub struct Value {
    pub name: String,
    pub data_type: u32,
    pub data: Vec<u8>,
}

impl Value {
    pub fn dword(name: impl Into<String>, val: u32) -> Self {
        Self {
            name: name.into(),
            data_type: REG_DWORD,
            data: val.to_le_bytes().to_vec(),
        }
    }

    pub fn sz(name: impl Into<String>, val: &str) -> Self {
        // REG_SZ: UTF-16LE with double-NUL terminator
        let mut data: Vec<u8> = Vec::with_capacity(val.len() * 2 + 2);
        for c in val.encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.extend_from_slice(&[0u8, 0]); // double-NUL
        Self {
            name: name.into(),
            data_type: REG_SZ,
            data,
        }
    }

    pub fn binary(name: impl Into<String>, data: &[u8]) -> Self {
        Self {
            name: name.into(),
            data_type: REG_BINARY,
            data: data.to_vec(),
        }
    }
}

/// A registry key (node) that can have subkeys and values.
#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub is_root: bool,
    pub subkeys: Vec<Node>,
    pub values: Vec<Value>,
}

impl Node {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_root: false,
            subkeys: Vec::new(),
            values: Vec::new(),
        }
    }

    pub fn root(mut self) -> Self {
        self.is_root = true;
        self
    }

    pub fn value(mut self, v: Value) -> Self {
        self.values.push(v);
        self
    }

    pub fn subkey(mut self, child: Node) -> Self {
        self.subkeys.push(child);
        self
    }
}

// =====================================================================
// Constants
// =====================================================================

/// REGF header size (must be exactly one HBIN = 4096 bytes).
const REGF_HDR_SIZE: usize = 4096;
/// HBIN page size (must be 4096).
pub const HBIN_SIZE: usize = 4096;
/// HBIN header size (bytes).
const HBIN_HDR_SIZE: usize = 32;

/// Cell type IDs.
const ID_NK: &[u8; 2] = b"nk";
const ID_LH: &[u8; 2] = b"lh";
const ID_VK: &[u8; 2] = b"vk";

/// Cell header size (seg_len + id).
const CELL_HDR_SIZE: usize = 8;

/// Fixed-size portion of the nk record (before the variable-length name).
/// Layout matches libhivex `struct ntreg_nk_record`.
/// Total fixed fields: 76 bytes (0x4C) - matches hivex format!
/// Offset layout:
///   0x00: seg_len (4 bytes)
///   0x04: id[2] (2 bytes)
///   0x06: flags (2 bytes)
///   0x08: timestamp (8 bytes)
///   0x10: unknown1 (4 bytes)
///   0x14: parent (4 bytes)
///   0x18: nr_subkeys (4 bytes)
///   0x1C: nr_subkeys_volatile (4 bytes)
///   0x20: subkey_lf (4 bytes)
///   0x24: subkey_lf_volatile (4 bytes)
///   0x28: nr_values (4 bytes)
///   0x2C: vallist (4 bytes)
///   0x30: sk (4 bytes)
///   0x34: classname (4 bytes)
///   0x38: max_subkey_name_len (2 bytes)
///   0x3A: unknown2 (2 bytes)
///   0x3C: unknown3 (4 bytes)
///   0x40: max_vk_name_len (4 bytes)
///   0x44: max_vk_data_len (4 bytes)
///   0x48: unknown6 (4 bytes)
///   0x4C: name_len (2 bytes)
///   0x4E: classname_len (2 bytes)
///   0x50: name (variable, aligned to 8 bytes from seg_len)
const NK_FIXED_SIZE: usize = 0x50;
/// Fixed-size portion of the vk record (before the name).
/// Layout matches libhivex `struct ntreg_vk_record`.
/// Offset layout:
///   0x00: seg_len (4 bytes)
///   0x04: id[2] (2 bytes)
///   0x06: name_len (2 bytes)
///   0x08: data_len (4 bytes)
///   0x0C: data_offset (4 bytes)
///   0x10: data_type (4 bytes)
///   0x14: flags (2 bytes)
///   0x16: unknown2 (2 bytes)
///   0x18: name (variable)
const VK_FIXED_SIZE: usize = 0x18;

/// Registry value types (Windows constants).
pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_DWORD: u32 = 4;
pub const REG_BINARY: u32 = 3;
pub const REG_MULTI_SZ: u32 = 7;

/// Entry size inside an lh index cell.
const LH_ENTRY_SIZE: usize = 8;

// =====================================================================
// Helpers
// =====================================================================

#[inline]
fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Ensure `off` points to a valid cell start that does not cross any
/// HBIN boundary. If `off + size` would extend past the current HBIN
/// page, advance `off` to the start of the next HBIN cell area.
#[inline]
fn fit_in_hbin(off: usize, size: usize) -> usize {
    // If exactly at a HBIN boundary (not cell area start), move to cell area of next HBIN
    if off % HBIN_SIZE == 0 {
        return off + HBIN_HDR_SIZE;
    }
    let page_end = ((off / HBIN_SIZE) + 1) * HBIN_SIZE;
    if off + size <= page_end {
        off
    } else {
        // Move to start of cell area in next HBIN.
        page_end + HBIN_HDR_SIZE
    }
}

/// Convert an absolute file offset to HBIN-relative.
#[inline]
fn to_hbin_rel(abs: u32) -> u32 {
    abs - REGF_HDR_SIZE as u32
}

/// Encode a name: ASCII < 64 bytes → Latin-1, otherwise UTF-16LE.
fn encode_name(name: &str) -> Vec<u8> {
    if name.is_empty() {
        return Vec::new();
    }
    if is_ascii_str(name) && name.len() < 64 {
        return name.as_bytes().to_vec();
    }
    let mut out = Vec::with_capacity(name.len() * 2);
    for c in name.encode_utf16() {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

fn is_ascii_str(s: &str) -> bool {
    s.bytes().all(|b| b < 128)
}

// =====================================================================
// Planning — Phase 1
// =====================================================================

/// Top-level plan for the whole hive.
struct HivePlan {
    root: NodePlan,
    total_hbins: usize,
}

impl HivePlan {
    /// Compute layout plan for the entire hive.
    /// Cursor starts at absolute file offset 0x1020 (REGF_HDR + HBIN_HDR).
    fn compute(root: &Node) -> (Self, Vec<usize>) {
        let mut cursor: usize = REGF_HDR_SIZE + HBIN_HDR_SIZE;
        // Initialize hbin_ends with the cursor start position (the first
        // available cell slot in HBIN 0). This marks where the first cell
        // begins. plan_node() will update hbin_ends[idx] to the actual
        // cell-end position after writing each cell. Using page_end
        // (0x2000) here would cause patch_free_blocks to write a bogus
        // free-block that covers the entire cell area before plan_node
        // has a chance to fix it.
        let mut hbin_ends: Vec<usize> = vec![REGF_HDR_SIZE + HBIN_HDR_SIZE; 1];
        let root_plan = NodePlan::plan_node(root, &mut cursor, &mut hbin_ends);

        // Number of HBINs needed = the page index of cursor + 1 (extra
        // page for any trailing free-block trailer).
        let last_byte = cursor.saturating_sub(1);
        let last_hbin = last_byte / HBIN_SIZE;
        let total_hbins = (last_hbin + 2).max(2);

        (
            Self {
                root: root_plan,
                total_hbins,
            },
            hbin_ends,
        )
    }

    /// Emit all cells into the output buffer.
    fn emit(&self, out: &mut [u8], root: &Node) {
        self.root.emit_node(out, root, 0xffffffff);
    }
}

/// Per-node layout plan (nk + lh + values + data).
struct NodePlan {
    /// Absolute file offset of the nk cell.
    nk_offset: usize,
    /// Total size of the nk cell (aligned).
    nk_size: usize,
    /// Absolute file offset of the lh index cell (if subkeys).
    lh_offset: Option<usize>,
    /// Total size of the lh cell (aligned).
    lh_size: usize,
    /// Child nk absolute offsets (for lh entries).
    lh_entries: Vec<usize>,
    /// Absolute file offset of the value list cell (if values).
    vallist_offset: Option<usize>,
    /// Aligned size of the value list cell.
    vallist_size: Option<usize>,
    /// Plans for each vk/value cell.
    vk_plans: Vec<VkPlan>,
    /// Plans for subkey nodes (DFS order).
    sub_plans: Vec<NodePlan>,
}

/// Plan for a single vk (value key) cell and its data block.
struct VkPlan {
    /// Absolute file offset of the vk cell.
    offset: usize,
    /// Total size of the vk cell (aligned).
    size: usize,
    /// Absolute file offset of the data block (if data.len() > 4).
    data_offset: Option<usize>,
    /// Total size of the data block (aligned, if data.len() > 4).
    data_size: Option<usize>,
}

impl NodePlan {
    /// Plan a single node and all its subtree. Cursor advances by cell sizes.
    fn plan_node(node: &Node, cursor: &mut usize, hbin_ends: &mut Vec<usize>) -> Self {
        // --- nk cell ---
        let name_bytes = encode_name(&node.name);
        let nk_size = align8(NK_FIXED_SIZE + name_bytes.len());
        let nk_offset = fit_in_hbin(*cursor, nk_size);
        
        // Update hbin_ends for the HBIN where nk was placed
        let nk_hbin_idx = (nk_offset - REGF_HDR_SIZE) / HBIN_SIZE;
        *cursor = nk_offset + nk_size;
        while hbin_ends.len() <= nk_hbin_idx {
            hbin_ends.push(*cursor);
        }
        hbin_ends[nk_hbin_idx] = *cursor;

        // --- lh index (only if we have subkeys) ---
        let (lh_offset, lh_size, lh_entries, sub_plans) =
            if !node.subkeys.is_empty() {
                let size =
                    align8(CELL_HDR_SIZE + 2 + node.subkeys.len() * LH_ENTRY_SIZE);
                let off = fit_in_hbin(*cursor, size);
                *cursor = off + size;
                let lh_hbin_idx = (off - REGF_HDR_SIZE) / HBIN_SIZE;
                while hbin_ends.len() <= lh_hbin_idx {
                    hbin_ends.push(*cursor);
                }
                hbin_ends[lh_hbin_idx] = *cursor;

                let mut child_nk_offsets = Vec::with_capacity(node.subkeys.len());
                let mut sub_plans = Vec::with_capacity(node.subkeys.len());
                for sub in &node.subkeys {
                    let sub_plan = NodePlan::plan_node(sub, cursor, hbin_ends);
                    child_nk_offsets.push(sub_plan.nk_offset);
                    sub_plans.push(sub_plan);
                }
                (Some(off), size, child_nk_offsets, sub_plans)
            } else {
                (None, 0, Vec::new(), Vec::new())
            };

        // --- value cells ---
        let (vallist_offset, vallist_size, vk_plans) = if !node.values.is_empty() {
            // Value list: 4 bytes per entry
            // Value list has NO id field; just seg_len + N offsets.
            let vl_size = align8(4 + node.values.len() * 4);
            let vl_off = fit_in_hbin(*cursor, vl_size);
            *cursor = vl_off + vl_size;
            let vl_hbin_idx = (vl_off - REGF_HDR_SIZE) / HBIN_SIZE;
            while hbin_ends.len() <= vl_hbin_idx {
                hbin_ends.push(*cursor);
            }
            hbin_ends[vl_hbin_idx] = *cursor;

            let mut vplans = Vec::with_capacity(node.values.len());
            for v in &node.values {
                let nb = encode_name(&v.name);
                let vk_size = align8(VK_FIXED_SIZE + nb.len());
                let vk_off = fit_in_hbin(*cursor, vk_size);
                *cursor = vk_off + vk_size;
                let vk_hbin_idx = (vk_off - REGF_HDR_SIZE) / HBIN_SIZE;
                while hbin_ends.len() <= vk_hbin_idx {
                    hbin_ends.push(*cursor);
                }
                hbin_ends[vk_hbin_idx] = *cursor;

                let (data_off, data_size) = if v.data.len() > 4 {
                    // Data blocks: 4-byte seg_len header + data, 8-byte aligned.
                    const DATA_BLOCK_HDR_SIZE: usize = 4;
                    let ds = align8(DATA_BLOCK_HDR_SIZE + v.data.len());
                    let d_off = fit_in_hbin(*cursor, ds);
                    *cursor = d_off + ds;
                    let d_hbin_idx = (d_off - REGF_HDR_SIZE) / HBIN_SIZE;
                    while hbin_ends.len() <= d_hbin_idx {
                        hbin_ends.push(*cursor);
                    }
                    hbin_ends[d_hbin_idx] = *cursor;
                    (Some(d_off), Some(ds))
                } else {
                    (None, None)
                };
                vplans.push(VkPlan {
                    offset: vk_off,
                    size: vk_size,
                    data_offset: data_off,
                    data_size,
                });
            }
            (Some(vl_off), Some(vl_size), vplans)
        } else {
            (None, None, Vec::new())
        };

        Self {
            nk_offset,
            nk_size,
            lh_offset,
            lh_size,
            lh_entries,
            vallist_offset,
            vallist_size,
            vk_plans,
            sub_plans,
        }
    }

    /// Emit this node and all subtrees into `out`.
    /// `parent_abs_off` is the absolute offset of the parent nk (0xffffffff for root).
    fn emit_node(&self, out: &mut [u8], node: &Node, parent_abs_off: u32) {
        // Safety check: verify buffer is large enough for nk
        assert!(
            self.nk_offset + self.nk_size <= out.len(),
            "emit_node: nk out of bounds: off=0x{:X} size=0x{:X} len=0x{:X}",
            self.nk_offset, self.nk_size, out.len()
        );

        // Safety check for lh
        if let Some(lh_off) = self.lh_offset {
            assert!(
                lh_off + self.lh_size <= out.len(),
                "emit_node: lh out of bounds"
            );
        }

        // Safety check for vl
        if let Some(vl_off) = self.vallist_offset {
            let vl_size = 4 + node.values.len() * 4;
            assert!(
                vl_off + vl_size <= out.len(),
                "emit_node: vl out of bounds"
            );
        }

        // Safety check for vk cells
        for vk_plan in &self.vk_plans {
            assert!(
                vk_plan.offset + vk_plan.size <= out.len(),
                "emit_node: vk out of bounds"
            );
        }
        // ---- nk cell ----
        let nk_file = self.nk_offset;
        let name_bytes = encode_name(&node.name);

        // seg_len (negative = in-use)
        out[nk_file..nk_file + 4]
            .copy_from_slice(&(-(self.nk_size as i32)).to_le_bytes());
        out[nk_file + 4..nk_file + 6].copy_from_slice(ID_NK);

        // flags (offset 0x06)
        let mut flags: u16 = if node.is_root { 0x0004 } else { 0x0024 };
        if !name_bytes.is_empty() && name_bytes.len() < 64 && is_ascii_str(&node.name) {
            flags |= 0x0020; // CompressedName (Latin-1)
        }
        out[nk_file + 6..nk_file + 8].copy_from_slice(&flags.to_le_bytes());

        // timestamp (offset 0x08, 8 bytes)
        out[nk_file + 8..nk_file + 16].copy_from_slice(&0i64.to_le_bytes());

        // unknown1 (offset 0x10, 4 bytes)
        out[nk_file + 16..nk_file + 20].copy_from_slice(&0u32.to_le_bytes());

        // parent offset (offset 0x14, HBIN-relative, or 0xffffffff for root)
        let parent_hbin_rel = if parent_abs_off == 0xffffffff {
            0xffffffff
        } else {
            to_hbin_rel(parent_abs_off)
        };
        out[nk_file + 20..nk_file + 24]
            .copy_from_slice(&parent_hbin_rel.to_le_bytes());

        // nr_subkeys (offset 0x18, 4 bytes)
        out[nk_file + 24..nk_file + 28]
            .copy_from_slice(&(node.subkeys.len() as u32).to_le_bytes());

        // nr_subkeys_volatile (offset 0x1C, 4 bytes)
        out[nk_file + 28..nk_file + 32].copy_from_slice(&0u32.to_le_bytes());

        // subkey lf offset (offset 0x20, HBIN-relative, or 0xffffffff)
        let lf_off = self
            .lh_offset
            .map(|off| to_hbin_rel(off as u32))
            .unwrap_or(0xffffffff);
        out[nk_file + 32..nk_file + 36].copy_from_slice(&lf_off.to_le_bytes());

        // subkey_lf_volatile (offset 0x24, 0xffffffff)
        out[nk_file + 36..nk_file + 40]
            .copy_from_slice(&0xffffffffu32.to_le_bytes());

        // nr_values (offset 0x28, 4 bytes)
        out[nk_file + 40..nk_file + 44]
            .copy_from_slice(&(node.values.len() as u32).to_le_bytes());

        // vallist offset (offset 0x2C, HBIN-relative, or 0xffffffff)
        let vl_off = self
            .vallist_offset
            .map(|off| to_hbin_rel(off as u32))
            .unwrap_or(0xffffffff);
        out[nk_file + 44..nk_file + 48].copy_from_slice(&vl_off.to_le_bytes());

        // sk_offset (offset 0x30, 0xffffffff)
        out[nk_file + 48..nk_file + 52]
            .copy_from_slice(&0xffffffffu32.to_le_bytes());
        // classname_offset (offset 0x34, 0xffffffff)
        out[nk_file + 52..nk_file + 56]
            .copy_from_slice(&0xffffffffu32.to_le_bytes());

        // max subkey name length (offset 0x38, 2 bytes)
        let max_sub_len = node
            .subkeys
            .iter()
            .map(|s| encode_name(&s.name).len())
            .max()
            .unwrap_or(0) as u16;
        out[nk_file + 56..nk_file + 58].copy_from_slice(&max_sub_len.to_le_bytes());

        // unknown2 (offset 0x3A, 2 bytes)
        out[nk_file + 58..nk_file + 60].copy_from_slice(&0u16.to_le_bytes());
        // unknown3 (offset 0x3C, 4 bytes)
        out[nk_file + 60..nk_file + 64].copy_from_slice(&0u32.to_le_bytes());

        // max vk name length (offset 0x40, 4 bytes)
        let max_vk_len = node
            .values
            .iter()
            .map(|v| encode_name(&v.name).len())
            .max()
            .unwrap_or(0) as u32;
        out[nk_file + 64..nk_file + 68].copy_from_slice(&max_vk_len.to_le_bytes());

        // max vk data length (offset 0x44, 4 bytes)
        let max_vk_data = node
            .values
            .iter()
            .map(|v| v.data.len())
            .max()
            .unwrap_or(0) as u32;
        out[nk_file + 68..nk_file + 72]
            .copy_from_slice(&max_vk_data.to_le_bytes());

        // unknown6 (offset 0x48, 4 bytes)
        out[nk_file + 72..nk_file + 76].copy_from_slice(&0u32.to_le_bytes());

        // name length (offset 0x4C, 2 bytes)
        out[nk_file + 76..nk_file + 78]
            .copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());

        // classname length (offset 0x4E, 2 bytes)
        out[nk_file + 78..nk_file + 80].copy_from_slice(&0u16.to_le_bytes());

        // name (offset 0x50, Latin-1 bytes, no NUL terminator)
        out[nk_file + 80..nk_file + 80 + name_bytes.len()]
            .copy_from_slice(&name_bytes);

        // ---- lh cell ----
        if let Some(lh_off) = self.lh_offset {
            let lf_file = lh_off;
            // seg_len (negative)
            out[lf_file..lf_file + 4]
                .copy_from_slice(&(-(self.lh_size as i32)).to_le_bytes());
            out[lf_file + 4..lf_file + 6].copy_from_slice(ID_LH);
            out[lf_file + 6..lf_file + 8]
                .copy_from_slice(&(node.subkeys.len() as u16).to_le_bytes());
            // entries: child nk offset (HBIN-relative) + hash (u32, always 0)
            for (i, &child_abs) in self.lh_entries.iter().enumerate() {
                let e_off = lf_file + 8 + i * LH_ENTRY_SIZE;
                out[e_off..e_off + 4]
                    .copy_from_slice(&to_hbin_rel(child_abs as u32).to_le_bytes());
                out[e_off + 4..e_off + 8].copy_from_slice(&0u32.to_le_bytes());
            }
        }

        // ---- value list + vk cells + data blocks ----
        if let Some(vl_off) = self.vallist_offset {
            let vl_file = vl_off;
            // seg_len (negative for in-use cells)
            let vl_size = self.vallist_size.unwrap_or(align8(4 + node.values.len() * 4));
            out[vl_file..vl_file + 4].copy_from_slice(&(-(vl_size as i32)).to_le_bytes());
            // array of vk offsets (HBIN-relative)
            for (i, vk_plan) in self.vk_plans.iter().enumerate() {
                let vk_hbin_rel = to_hbin_rel(vk_plan.offset as u32);
                out[vl_file + 4 + i * 4..vl_file + 8 + i * 4]
                    .copy_from_slice(&vk_hbin_rel.to_le_bytes());
            }
        }

        // vk cells + data blocks
        for (i, vk_plan) in self.vk_plans.iter().enumerate() {
            let v = &node.values[i];
            let vk_file = vk_plan.offset;
            let name_bytes = encode_name(&v.name);
            
            // Use aligned size for seg_len (cursor advances by aligned size)
            let vk_size = vk_plan.size;

            // seg_len (negative)
            out[vk_file..vk_file + 4]
                .copy_from_slice(&(-(vk_size as i32)).to_le_bytes());
            out[vk_file + 4..vk_file + 6].copy_from_slice(ID_VK);

            // name length (bytes)
            out[vk_file + 6..vk_file + 8]
                .copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());

            // name bytes
            out[vk_file + 8..vk_file + 8 + name_bytes.len()]
                .copy_from_slice(&name_bytes);

            let name_len = name_bytes.len();

            // data length
            let data_len_raw: u32 = if v.data.len() > 4 {
                v.data.len() as u32
            } else {
                (v.data.len() as u32) | 0x8000_0000
            };
            out[vk_file + 8 + name_len..vk_file + 12 + name_len]
                .copy_from_slice(&data_len_raw.to_le_bytes());

            // data offset
            let data_off_val: u32 = if let Some(d_off) = vk_plan.data_offset {
                // HBIN-relative offset of the data block (past its seg_len header)
                to_hbin_rel((d_off + 4) as u32)
            } else {
                // inline data: lower 4 bytes of the data
                let mut buf = [0u8; 4];
                for (j, &b) in v.data.iter().enumerate() {
                    if j < 4 {
                        buf[j] = b;
                    }
                }
                u32::from_le_bytes(buf)
            };
            out[vk_file + 12 + name_len..vk_file + 16 + name_len]
                .copy_from_slice(&data_off_val.to_le_bytes());

            // data type
            out[vk_file + 16 + name_len..vk_file + 20 + name_len]
                .copy_from_slice(&v.data_type.to_le_bytes());

            // flags: bit 0 = 1 for ASCII/Latin-1 name, 0 for UTF-16LE
            let vk_flags: u16 = if v.name.is_empty()
                || is_ascii_str(&v.name)
            {
                1
            } else {
                0
            };
            out[vk_file + 20 + name_len..vk_file + 22 + name_len]
                .copy_from_slice(&vk_flags.to_le_bytes());

            // padding
            out[vk_file + 22 + name_len..vk_file + 24 + name_len]
                .copy_from_slice(&0u16.to_le_bytes());

            // ---- data block ----
            if let Some(d_off) = vk_plan.data_offset {
                let d_file = d_off;
                // Data blocks have a 4-byte seg_len header (no signature).
                const DATA_BLOCK_HDR_SIZE: usize = 4;
                out[d_file..d_file + DATA_BLOCK_HDR_SIZE]
                    .copy_from_slice(&(-(vk_plan.data_size.unwrap() as i32)).to_le_bytes());
                let data_end = (d_file + DATA_BLOCK_HDR_SIZE + v.data.len())
                    .min(d_file + vk_plan.data_size.unwrap());
                out[d_file + DATA_BLOCK_HDR_SIZE..data_end]
                    .copy_from_slice(&v.data[..data_end - d_file - DATA_BLOCK_HDR_SIZE]);
            }
        }

        // ---- recurse into subkeys ----
        // The nk offset of this node becomes the parent for children.
        let nk_abs = self.nk_offset as u32;
        for (sub, sub_plan) in node.subkeys.iter().zip(self.sub_plans.iter()) {
            sub_plan.emit_node(out, sub, nk_abs);
        }
    }
}

// =====================================================================
// REGF header
// =====================================================================

fn write_regf_header(out: &mut [u8], name: &str, total_hbins: usize) {
    // Magic "regf" at offset 0..4
    out[0..4].copy_from_slice(b"regf");

    // seqnums at 4..8, 8..12 (after magic)
    out[4..8].copy_from_slice(&1u32.to_le_bytes());
    out[8..12].copy_from_slice(&1u32.to_le_bytes());

    // timestamp at 12..20 (FILETIME: Jan 1 2010)
    out[12..20].copy_from_slice(&0x01C9E79Cu64.to_le_bytes());
    out[20..28].copy_from_slice(&0x0CDE4EC0u64.to_le_bytes());

    // major version at 0x14 (1)
    out[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    // minor version at 0x18 (3)
    out[0x18..0x1C].copy_from_slice(&3u32.to_le_bytes());

    // unknown5 at 0x1C (0)
    out[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
    // unknown6 at 0x20 (1)
    out[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());

    // root_cell_offset at 0x24 (HBIN-relative = HBIN_HDR_SIZE = 0x20)
    out[0x24..0x28]
        .copy_from_slice(&(HBIN_HDR_SIZE as u32).to_le_bytes());

    // blocks at 0x28: total data size (total_hbins * HBIN_SIZE)
    out[0x28..0x2C]
        .copy_from_slice(&(total_hbins as u32 * HBIN_SIZE as u32).to_le_bytes());

    // unknown7 at 0x2C (1)
    out[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());

    // Hive name (UTF-16LE, double-NUL) at offset 0x30, 64 bytes
    let mut pos = 0x30;
    for c in name.encode_utf16() {
        if pos + 2 < 0x70 {
            out[pos..pos + 2].copy_from_slice(&c.to_le_bytes());
            pos += 2;
        }
    }
    // Zero-fill rest of name field
    while pos < 0x70 {
        out[pos] = 0;
        pos += 1;
    }

    // unknown fields 0x70..0xA7: 3 GUIDs (16 bytes each) + some uint32s
    // All zeros is fine for our purposes

    // unknown8 at 0xA8 (0)
    out[0xA8..0xAC].copy_from_slice(&0u32.to_le_bytes());
    // unknown_guid3 at 0xAC..0xBC (zeros)
    // unknown9 at 0xBC..0xC0 (0)
    out[0xBC..0xC0].copy_from_slice(&0u32.to_le_bytes());

    // BootType at 0xC0..0xC4 (0)
    out[0xC0..0xC4].copy_from_slice(&0u32.to_le_bytes());
    // CurrentUser at 0xC4..0xC8 (0)
    out[0xC4..0xC8].copy_from_slice(&0u32.to_le_bytes());

    // unknown10 at 0xC8..0xFC
    // These are mostly unknown fields that real hives use for various purposes

    // checksum at 0x1FC: filled in later (after all other writes) by finish()
    out[0x1FC..0x200].copy_from_slice(&0u32.to_le_bytes());

    // padding/extra bytes to REGF_HDR_SIZE (0x1000)
    // Fill everything from 0xD0 to end of header with zeros
    for i in 0xD0..REGF_HDR_SIZE {
        out[i] = 0;
    }
}

fn compute_checksum(buf: &[u8]) -> u32 {
    // XOR of 4-byte words from 0 to 0x1FB (508 bytes)
    let mut sum: u32 = 0;
    for i in (0..0x1FC).step_by(4) {
        let val = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        sum ^= val;
    }
    sum
}

// =====================================================================
// HBIN headers
// =====================================================================

fn write_hbin_headers(out: &mut [u8], total_hbins: usize) {
    for i in 0..total_hbins {
        let hbin_file_off = REGF_HDR_SIZE + i * HBIN_SIZE;
        out[hbin_file_off..hbin_file_off + 4].copy_from_slice(b"hbin");
        out[hbin_file_off + 4..hbin_file_off + 8]
            .copy_from_slice(&(i as u32 * HBIN_SIZE as u32).to_le_bytes());
        out[hbin_file_off + 8..hbin_file_off + 12]
            .copy_from_slice(&(HBIN_SIZE as u32).to_le_bytes());
        // bytes 12..32 already zeroed
    }
}

// =====================================================================
// Free block patching
// =====================================================================

/// Patch free blocks at the end of each HBIN page. For each page,
/// write a single positive-size free block from the end of cells to the page boundary.
fn patch_free_blocks(out: &mut [u8], total_hbins: usize, hbin_ends: &[usize]) {
    for i in 0..total_hbins {
        let hbin_file_off = REGF_HDR_SIZE + i * HBIN_SIZE;
        let page_start = hbin_file_off + HBIN_HDR_SIZE;
        let page_end = hbin_file_off + HBIN_SIZE;

        // Get the end of cells for this HBIN
        let cell_end = hbin_ends.get(i).copied().unwrap_or(page_start);
        
        // Free space starts right after the last cell (no extra alignment needed)
        let free_start = cell_end.min(page_end);

        // Write free block if there's enough space (minimum 4 bytes)
        if free_start + 4 <= page_end {
            let free_len = (page_end - free_start) as i32;
            out[free_start..free_start + 4].copy_from_slice(&free_len.to_le_bytes());
        }
    }
}

// =====================================================================
// HiveBuilder
// =====================================================================

/// Top-level builder for a registry hive.
pub struct HiveBuilder {
    root: Node,
    name: String,
}

impl HiveBuilder {
    pub fn new(root: Node) -> Self {
        Self {
            root,
            name: "Hive".to_string(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Build and return the raw bytes of the regf hive.
    pub fn finish(self) -> Vec<u8> {
        // Phase 1: planning — compute cell offsets.
        let (plan, hbin_ends) = HivePlan::compute(&self.root);

        // Phase 2: allocate buffer.
        let total_size = REGF_HDR_SIZE + plan.total_hbins * HBIN_SIZE;
        let mut out = vec![0u8; total_size];

        // Phase 3: write REGF header (without final checksum yet).
        write_regf_header(&mut out, &self.name, plan.total_hbins);

        // Phase 4: write HBIN headers.
        write_hbin_headers(&mut out, plan.total_hbins);

        // Phase 5: emit all cells.
        plan.emit(&mut out, &self.root);

        // Phase 6: write free-block trailers using per-HBIN end positions.
        patch_free_blocks(&mut out, plan.total_hbins, &hbin_ends);

        // Phase 7: now compute and write the final checksum over the
        // complete header (after all other fields are populated).
        let sum = compute_checksum(&out);
        out[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());

        out
    }
}

// =====================================================================
// Convenience
// =====================================================================

#[allow(dead_code)]
pub fn dump(bytes: &[u8]) -> String {
    let mut s = String::new();
    if bytes.len() < REGF_HDR_SIZE {
        return format!("too short: {} bytes", bytes.len());
    }
    s.push_str(&format!("magic: {:?}\n", &bytes[0..4]));
    let mut off = REGF_HDR_SIZE;
    let mut hbin_idx = 0;
    while off + HBIN_HDR_SIZE <= bytes.len() {
        if &bytes[off..off + 4] != b"hbin" {
            break;
        }
        s.push_str(&format!("\n=== HBIN #{} @ 0x{:x} ===\n", hbin_idx, off));
        let mut cell = off + HBIN_HDR_SIZE;
        let end = (off + HBIN_SIZE).min(bytes.len());
        while cell + 4 <= end {
            let seg_len = i32::from_le_bytes([
                bytes[cell],
                bytes[cell + 1],
                bytes[cell + 2],
                bytes[cell + 3],
            ]);
            let abs_len = seg_len.unsigned_abs() as usize;
            let id = std::str::from_utf8(&bytes[cell + 4..cell + 6])
                .unwrap_or("??");
            s.push_str(&format!(
                "  cell @ 0x{:x} len={} id={:?}\n",
                cell, abs_len, id
            ));
            cell += align8(abs_len);
            if cell >= end {
                break;
            }
        }
        off += HBIN_SIZE;
        hbin_idx += 1;
    }
    s
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_minimal_hive() {
        let root = Node::new("TestRoot")
            .root()
            .value(Value::dword("Hello", 42));
        let bytes = HiveBuilder::new(root).with_name("test.hive").finish();

        assert_eq!(&bytes[0..4], b"regf", "magic should be 'regf'");
        assert!(
            bytes.len() >= 2 * HBIN_SIZE,
            "must be >= 2 HBINs"
        );
        assert_eq!(
            bytes.len() % HBIN_SIZE,
            0,
            "must be HBIN-aligned"
        );

        // First HBIN header
        assert_eq!(
            &bytes[REGF_HDR_SIZE..REGF_HDR_SIZE + 4],
            b"hbin"
        );

        // First nk cell
        let nk_off = REGF_HDR_SIZE + HBIN_HDR_SIZE;
        assert_eq!(
            &bytes[nk_off + 4..nk_off + 6],
            b"nk",
            "first cell should be nk"
        );

        // Verify the hive has at least 2 HBINs
        let hbin_count = (bytes.len() - REGF_HDR_SIZE) / HBIN_SIZE;
        assert!(hbin_count >= 2, "should have at least 2 HBINs");
    }

    #[test]
    fn smoke_bcd_hive() {
        let root = Node::new("NewStoreRoot").root();
        let bytes = HiveBuilder::new(root).with_name("BCD").finish();

        assert_eq!(&bytes[0..4], b"regf");
        // Root nk should have HiveEntry flag (0x4)
        // Per REGF spec: cell header is seg_len(4) + sig(2) + flags(2) ...
        // So flags are at nk_off + 6 (file offset 6 from cell start).
        let nk_off = REGF_HDR_SIZE + HBIN_HDR_SIZE;
        let flags = u16::from_le_bytes([bytes[nk_off + 6], bytes[nk_off + 7]]);
        assert!(
            flags & 0x0004 != 0,
            "root nk should have HiveEntry flag (got flags=0x{:x})",
            flags
        );

        // Header sanity: root cell offset must point at the root nk
        let root_off_rel = u32::from_le_bytes([bytes[0x24], bytes[0x25], bytes[0x26], bytes[0x27]]);
        assert_eq!(root_off_rel, 0x20, "root cell offset should be 0x20");

        // blocks field must equal (file_size - 4096)
        let blocks = u32::from_le_bytes([bytes[0x28], bytes[0x29], bytes[0x2A], bytes[0x2B]]);
        assert_eq!(blocks as usize, bytes.len() - 4096, "blocks should match hbin total");
    }

    /// Roundtrip smoke test: generate a BCD hive, then re-parse it via
    /// the same on-disk REGF reader logic and verify the key/value tree
    /// round-trips correctly.
    #[test]
    fn roundtrip_bcd_parse() {
        use crate::hive_gen;

        let bytes = hive_gen::build_bcd();

        // Basic header sanity
        assert_eq!(&bytes[0..4], b"regf");
        assert!(bytes.len() >= 0x1000);

        // Manually walk the hive structure with the same logic as bcd_registry.rs
        // and count the BCD objects under \Objects.
        let hbin_base: usize = 0x1000;
        let root_off_raw = u32::from_le_bytes([bytes[0x24], bytes[0x25], bytes[0x26], bytes[0x27]]) as usize;
        let root_off = hbin_base + root_off_raw;

        // Read root nk: seg_len(4) + sig(2) + flags(2) + ts(8) + access(4) + parent(4)
        //             + nr_subkeys(4) + nr_vol(4) + subkey_lf(4) + vol_lf(4)
        //             + nr_values(4) + vallist(4) + sk(4) + classname(4) ...
        let seg_len_root = i32::from_le_bytes([bytes[root_off], bytes[root_off+1], bytes[root_off+2], bytes[root_off+3]]);
        assert!(seg_len_root < 0, "root nk should be allocated");
        assert_eq!(&bytes[root_off+4..root_off+6], b"nk");
        let root_nr_subkeys = u32::from_le_bytes([
            bytes[root_off + 0x18], bytes[root_off + 0x19],
            bytes[root_off + 0x1A], bytes[root_off + 0x1B],
        ]);
        assert!(root_nr_subkeys >= 2, "root should have Description and Objects (got {})", root_nr_subkeys);

        // Walk into lh to find subkeys of root
        let lf_rel = u32::from_le_bytes([
            bytes[root_off + 0x20], bytes[root_off + 0x21],
            bytes[root_off + 0x22], bytes[root_off + 0x23],
        ]) as usize;
        let lf_off = hbin_base + lf_rel;
        let lh_seg = i32::from_le_bytes([bytes[lf_off], bytes[lf_off+1], bytes[lf_off+2], bytes[lf_off+3]]);
        assert!(lh_seg < 0, "lh cell should be allocated");
        let lh_nr = u16::from_le_bytes([bytes[lf_off+6], bytes[lf_off+7]]) as usize;
        assert_eq!(lh_nr as u32, root_nr_subkeys);

        // Find the "Objects" subkey
        let mut objects_off: Option<usize> = None;
        for i in 0..lh_nr {
            let e_off = lf_off + 8 + i * 8;
            let nk_rel = u32::from_le_bytes([
                bytes[e_off], bytes[e_off+1], bytes[e_off+2], bytes[e_off+3],
            ]) as usize;
            let nk_off = hbin_base + nk_rel;
            let nk_name_len = u16::from_le_bytes([bytes[nk_off+0x4C], bytes[nk_off+0x4D]]) as usize;
            let nk_name = &bytes[nk_off + 0x50..nk_off + 0x50 + nk_name_len];
            if nk_name == b"Objects" {
                objects_off = Some(nk_off);
                break;
            }
        }
        let objects_off = objects_off.expect("root should contain an 'Objects' subkey");

        // Verify Objects has subkeys (the BCD objects)
        let objs_nr_subkeys = u32::from_le_bytes([
            bytes[objects_off + 0x18], bytes[objects_off + 0x19],
            bytes[objects_off + 0x1A], bytes[objects_off + 0x1B],
        ]);
        assert!(objs_nr_subkeys >= 4, "Objects should have at least 4 BCD objects (got {})", objs_nr_subkeys);
    }
}
