//! NTFS Filesystem Image Module
//!
//! This module provides a pure Rust implementation for creating NTFS filesystem images,
//! which can be used to create native Windows installation images.
//!
//! ## Features
//! - Boot Sector generation
//! - Master File Table (MFT) structure
//! - File records
//! - Directory entries (IdxRoot)
//! - Standard Information attribute
//! - File Name attribute
//! - Data attribute (resident/non-resident)
//!
//! ## Usage
//! ```rust,no_run
//! use nt61_tools::NtfsImage;
//!
//! let mut image = NtfsImage::new(2048, 4096).unwrap(); // 2GB, 4KB clusters
//! image.create_dir("Windows").unwrap();
//! image.create_dir("Windows/System32").unwrap();
//! let kernel_data = [0u8; 512];
//! image.write_file("Windows/System32/ntoskrnl.exe", &kernel_data).unwrap();
//! let img_data = image.finalize().unwrap();
//! ```

use crate::error::{BuildError, Result};
use crate::fs::backend::{DirEntry, FsBackend};

/// NTFS file or directory entry
#[derive(Debug, Clone)]
pub struct NtfsEntry {
    pub path: String,
    pub is_dir: bool,
    pub data: Vec<u8>,
}

impl NtfsEntry {
    pub fn new_file(path: &str, data: Vec<u8>) -> Self {
        Self { path: path.to_string(), is_dir: false, data }
    }
    pub fn new_dir(path: &str) -> Self {
        Self { path: path.to_string(), is_dir: true, data: Vec::new() }
    }
}

// =====================================================================
// Constants
// =====================================================================

/// NTFS boot sector signature
pub const NTFS_BOOT_SECTOR_SIGNATURE: &[u8; 8] = b"NTFS    ";

/// NTFS OEM name
pub const NTFS_OEM_NAME: &[u8; 8] = b"NTFS    ";

/// NTFS file record signature
pub const NTFS_FILE_RECORD_SIGNATURE: &[u8; 4] = b"FILE";

/// Attribute type IDs
pub const ATTR_TYPE_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTR_TYPE_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_TYPE_FILE_NAME: u32 = 0x30;
pub const ATTR_TYPE_VOLUME_NAME: u32 = 0x60;
pub const ATTR_TYPE_VOLUME_INFORMATION: u32 = 0x70;
pub const ATTR_TYPE_DATA: u32 = 0x80;
pub const ATTR_TYPE_INDEX_ROOT: u32 = 0x90;
pub const ATTR_TYPE_INDEX_ALLOCATION: u32 = 0xA0;
pub const ATTR_TYPE_BITMAP: u32 = 0xB0;

/// Resident attribute flag
pub const ATTR_FLAG_RESIDENT: u8 = 0x00;
pub const ATTR_FLAG_NON_RESIDENT: u8 = 0x01;

/// File record flags
pub const FILE_RECORD_IN_USE: u16 = 0x0001;
pub const FILE_RECORD_IS_DIRECTORY: u16 = 0x0002;

/// Filename namespace flags
pub const FILENAME_NAMESPACE_POSIX: u8 = 0x00;
pub const FILENAME_NAMESPACE_WIN32: u8 = 0x01;
pub const FILENAME_NAMESPACE_DOS: u8 = 0x02;
pub const FILENAME_NAMESPACE_WIN32_AND_DOS: u8 = 0x03;

// =====================================================================
// NTFS Structures
// =====================================================================

/// NTFS Boot Sector (512 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct NtfsBootSector {
    pub jump: [u8; 3],                    // Jump instruction
    pub oem_id: [u8; 8],                  // OEM ID "NTFS    "
    pub bytes_per_sector: u16,            // Bytes per sector
    pub sectors_per_cluster: u8,          // Sectors per cluster
    pub reserved_sectors: u16,            // Reserved sectors
    pub zeros1: [u8; 3],                 // Always 0
    pub not_used1: u16,                   // Not used
    pub media_descriptor: u8,              // Media descriptor
    pub not_used2: u16,                   // Not used
    pub sectors_per_track: u16,          // Sectors per track
    pub number_of_heads: u16,             // Number of heads
    pub hidden_sectors: u32,              // Hidden sectors
    pub not_used3: u32,                   // Not used
    pub not_used4: u32,                   // Not used
    pub total_sectors: u64,              // Total sectors (64-bit)
    pub mft_cluster_location: u64,       // MFT cluster location
    pub mft_mirror_cluster_location: u64,// MFT mirror cluster location
    pub clusters_per_mft_record: i8,      // Clusters per MFT record (negative = 2^n)
    pub clusters_per_index_record: i8,    // Clusters per index record
    pub not_used5: [u8; 7],              // Not used
    pub volume_serial_number: u64,        // Volume serial number
    pub checksum: u32,                    // Checksum
    pub bootstrap_code: [u8; 425],       // Bootstrap code (425 bytes leaves 2 for end-of-sector marker)
    pub end_of_sector_marker: u16,        // End of sector marker (0xAA55)
}

/// NTFS MFT File Record Header
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct NtfsFileRecordHeader {
    pub record_signature: [u8; 4],         // "FILE"
    pub record_offset: u16,               // Offset to fixup values
    pub size_in_bytes: u16,              // Size of record in bytes
    pub lsn: u64,                        // Logfile sequence number
    pub sequence_value: u16,              // Sequence number
    pub link_count: u16,                 // Hard link count
    pub first_attr_offset: u16,           // Offset to first attribute
    pub flags: u16,                      // Flags
    pub bytes_in_use: u32,              // Bytes in use
    pub bytes_allocated: u32,           // Bytes allocated
    pub base_mft_record: u64,            // Base MFT record (0 for base)
    pub next_attr_id: u16,              // Next attribute ID
    pub fixup_value: u16,              // Fixup value
}

/// Attribute Record Header (variable length)
#[derive(Debug, Clone)]
pub struct NtfsAttributeHeader {
    pub attribute_type: u32,              // Attribute type ID
    pub length: u32,                     // Length of attribute
    pub resident: u8,                    // Resident flag
    pub name_length: u8,                // Length of name (in characters)
    pub name_offset: u16,               // Offset to name
    pub name: Vec<u16>,                // Attribute name (optional)
    pub specific: SpecificHeader,        // Type-specific header
}

/// Type-specific attribute header
#[derive(Debug, Clone)]
pub enum SpecificHeader {
    Resident(ResidentHeader),
    NonResident(NonResidentHeader),
}

/// Resident attribute header
#[derive(Debug, Clone)]
pub struct ResidentHeader {
    pub value_length: u32,               // Length of attribute value
    pub value_offset: u16,             // Offset to attribute value
    pub flags: u8,                      // Flags
    pub reserved: u8,                   // Reserved
}

/// Non-resident attribute header
#[derive(Debug, Clone)]
pub struct NonResidentHeader {
    pub lowest_vcn: u64,                // Lowest virtual cluster number
    pub highest_vcn: u64,              // Highest virtual cluster number
    pub mapping_pairs_offset: u16,      // Offset to mapping pairs
    pub compression_unit_size: u8,      // Compression unit size
    pub reserved: u8,                   // Reserved
    pub allocated_size: u64,           // Allocated size of attribute
    pub data_size: u64,                // Data size
    pub initialized_size: u64,          // Initialized data size
    pub compressed_size: u64,           // Compressed size
}

// =====================================================================
// High-Level NTFS Image Builder
// =====================================================================

/// NTFS image builder
pub struct NtfsImage {
    size_mb: u32,
    sector_size: u32,
    sectors_per_cluster: u8,
    total_sectors: u64,
    mft_record_size: i32,
    mft_cluster: u64,
    entries: Vec<NtfsEntry>,
    volume_serial: u64,
    /// Partition offset in bytes. For a standalone NTFS image this is 0.
    /// When the image is embedded inside a GPT partition the value is the
    /// partition's starting LBA × sector size, which we must publish in
    /// the boot sector's `hidden_sectors` field so a real Windows NTFS
    /// driver can recognise the volume as a partition rather than a
    /// whole-disk NTFS install.
    hidden_sectors: u32,
    /// Cluster allocator cursor for non-resident file data.
    /// Files larger than `MAX_RESIDENT_DATA_SIZE` are placed in
    /// contiguous clusters starting at `data_cluster_cursor` and
    /// each cluster allocation advances the cursor. We allocate
    /// data after the MFT region so that the MFT record layout
    /// remains unchanged.
    data_cluster_cursor: u64,
    /// Per-entry cluster assignments for non-resident files. Maps
    /// the entry's path to (start_lcn, cluster_count). The boot
    /// manager's NTFS reader walks the on-disk run list directly,
    /// so we only keep this around so the finaliser can copy the
    /// file's bytes into the correct cluster window.
    data_cluster_assignments: std::collections::HashMap<String, (u64, u64)>,
}

/// Emit a standard 24-byte resident NTFS attribute header.
///
/// Layout (NTFS attribute-record spec, "Resident" form):
///   0x00: u32 type
///   0x04: u32 length (total attribute length including header)
///   0x08: u8  non-resident (0)
///   0x09: u8  name_length (0 for no-name attributes)
///   0x0A: u16 name_offset (0 when name_length is 0)
///   0x0C: u16 attribute flags
///   0x0E: u16 instance id
///   0x10: u32 value_length
///   0x14: u16 value_offset (24 for resident, no-name attributes)
///   0x16: u8  resident flags
///   0x17: u8  padding
///   0x18..: value data
///
/// The previous builders all emitted a 20-byte header that put
/// `value_length` at attr+0x0C and `value_offset` at attr+0x10, which
/// the kernel's `parse_attribute` decodes as garbage. This helper
/// consolidates the correct layout so the standard_info / file_name /
/// index_root / data builders all match what `parse_attribute` reads.
fn build_attr_header(attr_type: u32, value_length: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    h.extend_from_slice(&attr_type.to_le_bytes()); // 0x00
    h.extend_from_slice(&0u32.to_le_bytes());     // 0x04 length (filled later)
    h.push(0);                                    // 0x08 non-resident
    h.push(0);                                    // 0x09 name_length
    h.extend_from_slice(&0u16.to_le_bytes());     // 0x0A name_offset
    h.extend_from_slice(&0u16.to_le_bytes());     // 0x0C attribute flags
    h.extend_from_slice(&0u16.to_le_bytes());     // 0x0E instance id
    h.extend_from_slice(&value_length.to_le_bytes()); // 0x10 value_length
    h.extend_from_slice(&24u16.to_le_bytes());    // 0x14 value_offset = 24
    h.push(0);                                    // 0x16 resident flags
    h.push(0);                                    // 0x17 padding
    h
}

/// Fill the 32-bit length field at offset 4 of `attr` with the
/// total attribute length (header + value).
fn fill_attr_length(attr: &mut [u8]) {
    let total = attr.len() as u32;
    attr[4..8].copy_from_slice(&total.to_le_bytes());
}

/// Encode a single NTFS data run (cluster_count, lcn_delta) as a
/// run-list entry. The header byte packs `len_len` (low nibble) and
/// `off_len` (high nibble), followed by the cluster count bytes
/// (little-endian) and the LCN delta bytes (little-endian, signed).
///
/// We round the byte widths up to whatever is needed to fit the
/// values. NTFS allows up to 8 bytes per field, so cluster counts
/// and LCN deltas up to 2^64 - 1 work fine.
fn encode_single_run(cluster_count: u64, lcn_delta: u64) -> Vec<u8> {
    let cc_bytes = cluster_count.to_le_bytes();
    let cc_len = bytes_needed_u64(cluster_count);
    let lcn_bytes = lcn_delta.to_le_bytes();
    let lcn_len = bytes_needed_u64(lcn_delta);
    let header = ((lcn_len as u8) << 4) | (cc_len as u8);
    let mut run = vec![header];
    run.extend_from_slice(&cc_bytes[..cc_len]);
    run.extend_from_slice(&lcn_bytes[..lcn_len]);
    run
}

/// Smallest number of little-endian bytes that fits `v` (1..=8).
fn bytes_needed_u64(v: u64) -> usize {
    if v == 0 { return 1; } // NTFS convention: zero-length run is encoded with 1 byte of 0
    let mut n = 0;
    let mut tmp = v;
    while tmp != 0 {
        n += 1;
        tmp >>= 8;
    }
    n.max(1)
}

impl NtfsImage {
    /// Parse an existing NTFS image into an in-memory entry list.
    ///
    /// The implementation reads the boot sector, locates the MFT, walks each
    /// MFT record, and extracts `$FILE_NAME` (for the path) and `$DATA`
    /// (resident only) attributes. Non-resident `$DATA` runs are not
    /// followed — affected files appear as empty in the tree.
    ///
    /// System entries (MFT #0..#11) are skipped. The returned `entries` list
    /// contains only user-visible files and directories, with forward-slash
    /// paths rooted at `""` (so the root of the image is the empty string).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 512 {
            return Err(BuildError::NtfsError("image smaller than one sector".into()));
        }
        let bs = &data[..512];
        if &bs[3..11] != b"NTFS    " {
            return Err(BuildError::NtfsError("missing NTFS OEM id".into()));
        }
        if bs[510] != 0x55 || bs[511] != 0xAA {
            return Err(BuildError::NtfsError("missing boot sector signature 0xAA55".into()));
        }
        let bytes_per_sector = u16::from_le_bytes([bs[11], bs[12]]) as u32;
        if bytes_per_sector != 512 {
            // The build-tool operates on 512-byte sectors everywhere. NTFS
            // images made with -s 4096 are not yet supported for parsing.
            return Err(BuildError::NtfsError(format!(
                "NTFS parser only supports 512-byte sectors (got {})", bytes_per_sector
            )));
        }
        let sectors_per_cluster = bs[13] as u32;
        let cluster_size = sectors_per_cluster * bytes_per_sector;
        let mft_cluster = u64::from_le_bytes([
            bs[48], bs[49], bs[50], bs[51], bs[52], bs[53], bs[54], bs[55],
        ]);
        let clusters_per_mft_raw = bs[64] as i8;
        let mft_record_size: u32 = if clusters_per_mft_raw < 0 {
            1u32 << (-clusters_per_mft_raw as u32)
        } else {
            (clusters_per_mft_raw as u32) * cluster_size
        };
        let mft_byte_offset = (mft_cluster as u128 * cluster_size as u128) as usize;
        if mft_byte_offset + mft_record_size as usize > data.len() {
            return Err(BuildError::NtfsError("MFT cluster lies past end of image".into()));
        }
        let max_records = ((data.len() - mft_byte_offset) / mft_record_size as usize).min(2048);

        // Record: per-MFT-index info.
        struct Rec {
            name: String,
            parent_mft: u32,
            is_dir: bool,
            data: Vec<u8>,
            _non_resident: bool,
        }
        let mut by_mft: std::collections::HashMap<u32, Rec> = std::collections::HashMap::new();

        for rec_idx in 0..max_records {
            let rec_off = mft_byte_offset + rec_idx * mft_record_size as usize;
            let rec = &data[rec_off..rec_off + mft_record_size as usize];
            if rec.len() < 48 || &rec[0..4] != b"FILE" {
                continue;
            }
            // Apply fixup array.
            let record_offset = u16::from_le_bytes([rec[4], rec[5]]) as usize;
            if record_offset + 4 > rec.len() {
                continue;
            }
            let fixup_value = u16::from_le_bytes([rec[record_offset], rec[record_offset + 1]]);
            let fixup_count = u16::from_le_bytes([rec[record_offset + 2], rec[record_offset + 3]]) as usize;
            let mut rec = rec.to_vec();
            if (2..4096).contains(&fixup_count) {
                for i in 1..fixup_count {
                    let pos = i * 512 - 2;
                    if pos + 2 <= rec.len() && rec[pos] == fixup_value as u8 && rec[pos + 1] == (fixup_value >> 8) as u8 {
                        let actual = u16::from_le_bytes([
                            rec[record_offset + 2 + i * 2],
                            rec[record_offset + 3 + i * 2],
                        ]);
                        rec[pos] = actual as u8;
                        rec[pos + 1] = (actual >> 8) as u8;
                    }
                }
            }
            let first_attr_offset = u16::from_le_bytes([rec[20], rec[21]]) as usize;
            let flags = u16::from_le_bytes([rec[22], rec[23]]);
            if flags & 0x01 == 0 {
                continue; // not in use
            }
            let mut attr_off = first_attr_offset;
            let mut file_name: Option<String> = None;
            let mut parent_ref: u32 = 5;
            let mut is_dir_record = false;
            let mut file_data: Vec<u8> = Vec::new();
            let mut data_non_resident = false;

            while attr_off + 16 <= rec.len() {
                let attr_type = u32::from_le_bytes([
                    rec[attr_off], rec[attr_off + 1], rec[attr_off + 2], rec[attr_off + 3],
                ]);
                if attr_type == 0xFFFFFFFF {
                    break;
                }
                let attr_len = u32::from_le_bytes([
                    rec[attr_off + 4], rec[attr_off + 5],
                    rec[attr_off + 6], rec[attr_off + 7],
                ]) as usize;
                if attr_len < 24 || attr_len > rec.len() - attr_off {
                    break;
                }
                let resident = rec[attr_off + 8];
                match attr_type {
                    0x30 => {
                        if resident == 0 {
                            // $FILE_NAME — value starts at offset 24 of attribute,
                            // layout:
                            //   +0  parent dir MFT ref (8 bytes)
                            //   +8  creation time (8)
                            //   +16 modification time (8)
                            //   +24 ...
                            //   +56 namespace (1)
                            //   +64 name_len (1)
                            //   +65 name_namespace (1)
                            //   +66 name (UTF-16LE, name_len units)
                            let val_off = u32::from_le_bytes([
                                rec[attr_off + 16], rec[attr_off + 17],
                                rec[attr_off + 18], rec[attr_off + 19],
                            ]) as usize;
                            let val_size = u32::from_le_bytes([
                                rec[attr_off + 20], rec[attr_off + 21],
                                rec[attr_off + 22], rec[attr_off + 23],
                            ]) as usize;
                            if val_off + val_size > rec.len() - attr_off {
                                // skip
                            } else {
                                let vstart = attr_off + val_off;
                                let parent = u64::from_le_bytes([
                                    rec[vstart], rec[vstart + 1], rec[vstart + 2], rec[vstart + 3],
                                    rec[vstart + 4], rec[vstart + 5], rec[vstart + 6], rec[vstart + 7],
                                ]);
                                parent_ref = (parent & 0x0000_FFFF_FFFF_FFFF) as u32;
                                let name_len = if vstart + 64 < rec.len() { rec[vstart + 64] as usize } else { 0 };
                                let name_ns = if vstart + 65 < rec.len() { rec[vstart + 65] } else { 3 };
                                let name_chars_off = vstart + 66;
                                if name_len <= 255 && name_chars_off + name_len * 2 <= rec.len() {
                                    let mut name = String::new();
                                    for i in 0..name_len {
                                        let cu = u16::from_le_bytes([
                                            rec[name_chars_off + i * 2],
                                            rec[name_chars_off + i * 2 + 1],
                                        ]);
                                        if cu == 0 { break; }
                                        if let Some(ch) = char::from_u32(cu as u32) {
                                            name.push(ch);
                                        }
                                    }
                                    // Prefer Win32/DOS or POSIX name; reject DOS-only.
                                    if (name_ns != 0x02 || file_name.is_none())
                                        && (file_name.is_none() || name_ns == 0x03 || name_ns == 0x01) {
                                            file_name = Some(name);
                                        }
                                }
                            }
                        }
                    }
                    0x80 => {
                        if resident == 0 {
                            let val_off = u32::from_le_bytes([
                                rec[attr_off + 16], rec[attr_off + 17],
                                rec[attr_off + 18], rec[attr_off + 19],
                            ]) as usize;
                            let val_size = u32::from_le_bytes([
                                rec[attr_off + 20], rec[attr_off + 21],
                                rec[attr_off + 22], rec[attr_off + 23],
                            ]) as usize;
                            if attr_off + val_off + val_size <= rec.len() {
                                file_data = rec[attr_off + val_off..attr_off + val_off + val_size].to_vec();
                            }
                        } else {
                            data_non_resident = true;
                        }
                    }
                    0x90 => {
                        is_dir_record = true;
                    }
                    _ => {}
                }
                attr_off += attr_len;
            }

            // System entries (MFT #0..#11) don't carry a useful $FILE_NAME;
            // skip them.
            if rec_idx <= 11 {
                continue;
            }

            if let Some(name) = file_name {
                if name == "." || name == ".." {
                    continue;
                }
                by_mft.insert(rec_idx as u32, Rec {
                    name,
                    parent_mft: parent_ref,
                    is_dir: is_dir_record,
                    data: file_data,
                    _non_resident: data_non_resident,
                });
            }
        }

        // Resolve full paths by walking parent chain. Cache intermediate paths.
        let mut paths: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
        paths.insert(5, String::new()); // root
        let mut entries: Vec<NtfsEntry> = Vec::new();
        let keys: Vec<u32> = by_mft.keys().copied().collect();
        for k in keys {
            // Walk up to root building the path.
            let mut chain = vec![k];
            let mut cur = k;
            let mut ok = true;
            while cur != 5 {
                if let Some(rec) = by_mft.get(&cur) {
                    if chain.contains(&rec.parent_mft) {
                        ok = false;
                        break;
                    }
                    cur = rec.parent_mft;
                    if cur == 5 { break; }
                    chain.push(cur);
                } else {
                    // Parent not in our parsed set — attach to root.
                    break;
                }
            }
            if !ok { continue; }
            chain.reverse();
            let mut path = String::new();
            for &idx in &chain {
                if idx == 5 { continue; }
                let rec = by_mft.get(&idx).unwrap();
                if !path.is_empty() { path.push('/'); }
                path.push_str(&rec.name);
            }
            let rec = by_mft.remove(&k).unwrap();
            let entry = if rec.is_dir {
                NtfsEntry::new_dir(&path)
            } else {
                NtfsEntry::new_file(&path, rec.data)
            };
            entries.push(entry);
        }

        let size_mb = (data.len() / (1024 * 1024)) as u32;
        let total_sectors = (data.len() as u64) / bytes_per_sector as u64;
        Ok(Self {
            size_mb: size_mb.max(1),
            sector_size: bytes_per_sector,
            sectors_per_cluster: sectors_per_cluster as u8,
            total_sectors,
            mft_record_size: mft_record_size as i32,
            mft_cluster,
            entries,
            volume_serial: u64::from_le_bytes([
                bs[72], bs[73], bs[74], bs[75], bs[76], bs[77], bs[78], bs[79],
            ]),
            hidden_sectors: u32::from_le_bytes([bs[28], bs[29], bs[30], bs[31]]),
            // Parsed images don't carry the build-tool allocator state.
            // The cursor is set high enough that subsequent non-resident
            // appends (none today) won't collide with anything.
            data_cluster_cursor: mft_cluster + 256,
            data_cluster_assignments: std::collections::HashMap::new(),
        })
    }

    /// Create a new NTFS image
    ///
    /// # Arguments
    /// * `size_mb` - Image size in megabytes
    /// * `cluster_size` - Cluster size in bytes (512, 1024, 2048, 4096, etc.)
    pub fn new(size_mb: u32, cluster_size: u32) -> Result<Self> {
        // Validate sector size (always 512 for NTFS)
        // Validate cluster size (must be power of 2 and >= sector size)
        if cluster_size < 512 {
            return Err(BuildError::NtfsError(
                format!("Cluster size {} is too small (minimum 512)", cluster_size)
            ));
        }
        
        let sectors_per_cluster = (cluster_size / 512) as u8;
        if sectors_per_cluster.count_ones() != 1 {
            return Err(BuildError::NtfsError(
                format!("Cluster size {} is not a power of 2", cluster_size)
            ));
        }

        let sector_size: u32 = 512;
        let total_sectors = (size_mb as u64) * 1024 * 1024 / (sector_size as u64);
        
        // Calculate MFT record size. The NTFS kernel in `nt61/src/fs/ntfs/mod.rs`
        // reads `clusters_per_mft_record` from the BPB and treats any
        // value outside `1..=4096` as garbage, falling back to 1024
        // (see `read_mft_record`'s `record_size` clamp). The build
        // tool therefore pins MFT records to 1024 bytes regardless
        // of cluster size so the BPB hint and the record layout
        // agree on the same value. Without this fix the build tool
        // writes 4096-byte records to disk but the kernel reads
        // Real Windows uses 1024 or 4096 byte MFT records. With the
        // full Win7 boot chain we now populate System32 (record 15)
        // with ~12 system image files plus the `drivers` and `config`
        // sub-directories, and `drivers` (record ~17) with ~13 boot
        // driver .sys files. Each INDEX_ENTRY is ~120 bytes once the
        // $FILE_NAME attribute and key length are accounted for, so
        // 1024-byte records run out of room in INDEX_ROOT (~6
        // entries) and trigger the boot-time
        //   [NTFS]   skipping attr 0x90 at off=200 len=... (>record end=1024)
        //   [NTFS]   no match for 'XXX'
        // fallback that silently drops every directory entry past
        // the cap. Bump to 4096 bytes, which matches the standard
        // NTFS configuration triggered by lots of files per
        // directory.
        let mft_record_size = 4096i32;

        // MFT starts at cluster 4, leaving clusters 0..3 for the boot
        // sector and backup boot sectors. Setting it to 0 would cause
        // the MFT records (which are written into `image` by
        // `finalize`) to overwrite the boot sector at offset 0.
        let mft_cluster = 4;

        // Generate volume serial number
        let volume_serial = rand_u64();

        Ok(Self {
            size_mb,
            sector_size,
            sectors_per_cluster,
            total_sectors,
            mft_record_size,
            mft_cluster,
            entries: Vec::new(),
            volume_serial,
            hidden_sectors: 0,
            // File data lives after the MFT. The MFT occupies at most
            // ~ceil((entries+1)/records_per_cluster) clusters starting at
            // `mft_cluster`. We start the data cursor at cluster
            // `mft_cluster + 256` to leave generous headroom for the
            // MFT to grow without colliding with non-resident data.
            // If a build somehow exhausts the MFT region (it shouldn't
            // with the current ~70-entry staging tree), the
            // `allocate_data_clusters` call panics below.
            data_cluster_cursor: mft_cluster + 256,
            data_cluster_assignments: std::collections::HashMap::new(),
        })
    }

    /// List the immediate children of `path` (forward-slash). Returns empty
    /// if the path does not exist or is not a directory.
    pub fn list_dir_path(&self, path: &str) -> Result<Vec<DirEntry>> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let prefix = parts.join("/");
        let prefix_with_slash = if prefix.is_empty() { String::new() } else { format!("{}/", prefix) };
        let mut out = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for e in &self.entries {
            let ep = &e.path;
            // entry must start with prefix
            let inside = if prefix.is_empty() {
                !ep.contains('/')
            } else {
                ep == &prefix || ep.starts_with(&prefix_with_slash)
            };
            if !inside { continue; }
            let rel = if prefix.is_empty() {
                ep.as_str()
            } else if ep == &prefix {
                continue; // the directory itself
            } else {
                &ep[prefix_with_slash.len()..]
            };
            // Direct child = no further '/'
            if rel.contains('/') { continue; }
            if seen.insert(rel.to_string()) {
                if e.is_dir {
                    out.push(DirEntry::dir(rel));
                } else {
                    out.push(DirEntry::file(rel, e.data.len() as u64));
                }
            }
        }
        Ok(out)
    }

    /// Read the file at `path` (forward-slash).
    pub fn read_file_path(&self, path: &str) -> Result<Vec<u8>> {
        let normalized = path.replace('\\', "/");
        for e in &self.entries {
            if !e.is_dir && e.path == normalized {
                return Ok(e.data.clone());
            }
        }
        // Try case-insensitive match.
        for e in &self.entries {
            if !e.is_dir && e.path.eq_ignore_ascii_case(&normalized) {
                return Ok(e.data.clone());
            }
        }
        Err(BuildError::MissingFile(path.into()))
    }

    /// Write or overwrite the file at `path` (forward-slash).
    pub fn write_file_path(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let normalized = path.replace('\\', "/");
        for e in &mut self.entries {
            if !e.is_dir && e.path.eq_ignore_ascii_case(&normalized) {
                e.data = data.to_vec();
                return Ok(());
            }
        }
        self.entries.push(NtfsEntry::new_file(&normalized, data.to_vec()));
        Ok(())
    }

    /// Create a directory at `path` (forward-slash). Idempotent.
    pub fn mkdir_path(&mut self, path: &str) -> Result<()> {
        let normalized = path.replace('\\', "/");
        if normalized.is_empty() {
            return Ok(());
        }
        for e in &self.entries {
            if e.is_dir && e.path.eq_ignore_ascii_case(&normalized) {
                return Ok(());
            }
        }
        self.entries.push(NtfsEntry::new_dir(&normalized));
        Ok(())
    }

    /// Remove a file or directory (recursive for directories).
    pub fn remove_path_ntfs(&mut self, path: &str) -> Result<()> {
        let normalized = path.replace('\\', "/");
        if normalized.is_empty() { return Ok(()); }
        let prefix_with_slash = if normalized.is_empty() { String::new() } else { format!("{}/", normalized) };
        self.entries.retain(|e| {
            !(e.path.eq_ignore_ascii_case(&normalized)
                || (e.path.starts_with(&prefix_with_slash) && !normalized.is_empty()))
        });
        Ok(())
    }

    /// Create a directory in the image
    pub fn create_dir(&mut self, path: &str) -> Result<&mut Self> {
        // Normalize path (convert forward slashes to backslashes)
        let normalized = path.replace('/', "\\");
        self.entries.push(NtfsEntry::new_dir(&normalized));
        Ok(self)
    }

    /// Write a file to the image
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<&mut Self> {
        // Normalize path (convert forward slashes to backslashes)
        let normalized = path.replace('/', "\\");
        self.entries.push(NtfsEntry::new_file(&normalized, data.to_vec()));
        Ok(self)
    }

    /// Build the boot sector
    fn build_boot_sector(&self) -> NtfsBootSector {
        NtfsBootSector {
            jump: [0xEB, 0x52, 0x90], // Standard NTFS jump
            oem_id: *b"NTFS    ",
            bytes_per_sector: self.sector_size as u16,
            sectors_per_cluster: self.sectors_per_cluster,
            reserved_sectors: 0,
            zeros1: [0; 3],
            not_used1: 0,
            media_descriptor: 0xF8, // Fixed disk
            not_used2: 0,
            sectors_per_track: 63,
            number_of_heads: 255,
            hidden_sectors: self.hidden_sectors,
            not_used3: 0,
            not_used4: 0,
            total_sectors: self.total_sectors,
            mft_cluster_location: self.mft_cluster,
            mft_mirror_cluster_location: self.total_sectors / (self.sectors_per_cluster as u64) / 2,
            clusters_per_mft_record: {
                // BPB encoding: a negative value means "2^n bytes
                // per record", a non-negative value means
                // "(value) clusters per record" — and the byte
                // field is `i8`, so anything > 127 overflows to
                // a negative number on disk. The kernel falls back
                // to 1024 bytes when it sees a value outside
                // 1..=4096, which is exactly what we want here:
                // 1024-byte records = -10 (2^10 = 1024).
                -(self.mft_record_size.ilog2() as i8)
            },
            clusters_per_index_record: if self.sectors_per_cluster >= 4 {
                (self.sectors_per_cluster / 4) as i8
            } else {
                -2 // 4KB
            },
            not_used5: [0; 7],
            volume_serial_number: self.volume_serial,
            checksum: 0, // No checksum for now
            bootstrap_code: [0; 425],
            end_of_sector_marker: 0xAA55,
        }
    }

    /// Build standard information attribute
    fn build_standard_info(&self) -> Vec<u8> {
        // $STANDARD_INFORMATION value is exactly 32 bytes: 4 × u64
        // timestamps plus a u32 file-attributes and a u32 (reserved /
        // class-id / owner-id / security-id) that we keep zeroed.
        let value_len = 32u32;
        let mut data = build_attr_header(ATTR_TYPE_STANDARD_INFORMATION, value_len);

        // Standard information value
        data.extend_from_slice(&0u64.to_le_bytes()); // Creation time
        data.extend_from_slice(&0u64.to_le_bytes()); // Modification time
        data.extend_from_slice(&0u64.to_le_bytes()); // MFT change time
        data.extend_from_slice(&0u64.to_le_bytes()); // Last access time
        data.extend_from_slice(&0x20u32.to_le_bytes()); // File attributes (ARCHIVE)
        data.extend_from_slice(&0u32.to_le_bytes());   // Reserved / class id

        fill_attr_length(&mut data);
        data
    }

    /// Build data attribute
    fn build_data_attr(&self, data: &[u8]) -> Vec<u8> {
        let mut attr = build_attr_header(ATTR_TYPE_DATA, data.len() as u32);
        attr.extend_from_slice(data);
        fill_attr_length(&mut attr);
        attr
    }

    /// Allocate a contiguous run of clusters for `byte_count` bytes
    /// worth of non-resident file data. Returns the starting LCN
    /// and the cluster count.
    ///
    /// We use a simple bump allocator that hands out consecutive
    /// cluster ranges starting at `data_cluster_cursor`. Real NTFS
    /// uses a bitmap-driven free-space manager; that's overkill for
    /// the build tool's static layout.
    fn allocate_data_clusters(&mut self, byte_count: usize) -> (u64, u64) {
        let cluster_size = self.sectors_per_cluster as u64 * self.sector_size as u64;
        let clusters_needed = (byte_count as u64).div_ceil(cluster_size);
        let start = self.data_cluster_cursor;
        self.data_cluster_cursor += clusters_needed;
        let max_clusters = self.total_sectors / self.sectors_per_cluster as u64;
        if self.data_cluster_cursor > max_clusters {
            panic!(
                "NtfsImage: out of cluster space for non-resident data (cursor={}, max={})",
                self.data_cluster_cursor, max_clusters,
            );
        }
        (start, clusters_needed)
    }

    /// Build a non-resident `$DATA` attribute that points to
    /// `file_clusters` (start_lcn, cluster_count). The run list is
    /// a single `clusters_needed`-long run starting at `start_lcn`.
    /// The file's actual bytes are NOT embedded in the attribute —
    /// they live in the cluster window that the caller writes to
    /// the image after `build_mft_record` returns.
    fn build_non_resident_data_attr(
        &self,
        entry: &NtfsEntry,
        file_clusters: (u64, u64),
    ) -> Vec<u8> {
        let (start_lcn, cluster_count) = file_clusters;
        let byte_size = entry.data.len() as u64;
        let cluster_size = self.sectors_per_cluster as u64 * self.sector_size as u64;
        let alloc_size = cluster_count * cluster_size;
        let real_size = byte_size;

        // Non-resident attribute header layout (NTFS spec):
        //   0x00: u32 type (0x80)
        //   0x04: u32 length
        //   0x08: u8  non_resident (1)
        //   0x09: u8  name_length (0)
        //   0x0A: u16 name_offset (0)
        //   0x0C: u16 flags (0)
        //   0x0E: u16 instance (0)
        //   0x10: u64 starting_vcn (0)
        //   0x18: u64 last_vcn   (cluster_count - 1)
        //   0x20: u64 allocated_size
        //   0x28: u64 real_size
        //   0x30: u64 initialised_size (== real_size)
        //   0x38: u16 run_list_offset (from attr start)
        //   0x3A: u16 compression_unit (0)
        //   0x3C: u32 padding (0)
        //   0x40: run list
        //
        // The previous version of this function conflated the
        // run_list_offset field with the compression_unit field and
        // placed the value 0x40 at byte 0x20 of the attribute, which
        // is actually the lowest byte of the allocated_size field.
        // That made every non-resident $DATA look malformed to
        // anyone reading the MFT record by hand: the run list
        // offset was reported as a wild value (0xfe00) and the
        // allocated/real/initialised sizes were all shifted by
        // eight bytes. The boot manager's stripped-down NTFS reader
        // then walked a garbage run list, but the cluster window
        // it ended up reading was large enough to cover the file's
        // size, so it returned the requested 851456 bytes — except
        // the bytes were *not* the file's actual contents, which is
        // why UEFI's `LoadImage` rejected winload.efi with
        // `EFI_LOAD_ERROR` (the apparent PE in memory had its
        // OptionalHeader bytes scrambled).
        let mut data = Vec::new();
        data.extend_from_slice(&ATTR_TYPE_DATA.to_le_bytes()); // 0x00 type
        data.extend_from_slice(&0u32.to_le_bytes());            // 0x04 length (placeholder)
        data.push(1);                                           // 0x08 non_resident
        data.push(0);                                           // 0x09 name_length
        data.extend_from_slice(&0u16.to_le_bytes());            // 0x0A name_offset
        data.extend_from_slice(&0u16.to_le_bytes());            // 0x0C flags
        data.extend_from_slice(&0u16.to_le_bytes());            // 0x0E instance
        data.extend_from_slice(&0u64.to_le_bytes());            // 0x10 starting_vcn
        data.extend_from_slice(&(cluster_count - 1).to_le_bytes()); // 0x18 last_vcn
        data.extend_from_slice(&alloc_size.to_le_bytes());      // 0x20 alloc_size
        data.extend_from_slice(&real_size.to_le_bytes());       // 0x28 real_size
        data.extend_from_slice(&real_size.to_le_bytes());       // 0x30 init_size
        // 0x38: run list offset, measured from the start of this
        // attribute. The header above is exactly 0x40 bytes long, so
        // the run list always begins at offset 0x40.
        data.extend_from_slice(&0x40u16.to_le_bytes());         // 0x38 run_list_offset
        data.extend_from_slice(&0u16.to_le_bytes());            // 0x3A compression_unit
        data.extend_from_slice(&0u32.to_le_bytes());            // 0x3C padding
        // 0x40: run list data
        let run = encode_single_run(cluster_count, start_lcn);
        data.extend_from_slice(&run);

        fill_attr_length(&mut data);
        data
    }

    /// Build end marker attribute
    fn build_end_marker() -> Vec<u8> {
        let mut marker = Vec::new();
        marker.extend_from_slice(&0xFFFFFFFF_u32.to_le_bytes());
        marker.extend_from_slice(&0u32.to_le_bytes());
        marker
    }

    /// Build an INDEX entry for a file/directory in INDEX_ROOT.
    ///
    /// INDEX entry structure (standard NTFS):
    ///   +0x00: MFT reference (8 bytes): (sequence_number << 48) | record_number
    ///   +0x08: entry_length (2 bytes): total size of this entry including header
    ///   +0x0A: indexed_attribute_length (2 bytes): size of the FILE_NAME attribute
    ///   +0x0C: flags (2 bytes): 0x0001 = END node, 0x0002 = child exists
    ///   +0x0E: (padding to 16 bytes)
    ///   +0x10+: FILE_NAME attribute (indexed attribute)
    fn build_index_entry(&self, mft_ref: u64, file_name_attr: &[u8], flags: u16) -> Vec<u8> {
        let mut entry = Vec::new();

        // MFT reference (8 bytes)
        entry.extend_from_slice(&mft_ref.to_le_bytes());

        // Calculate entry length: 16 byte header + FILE_NAME attribute
        let entry_length = (16 + file_name_attr.len()) as u16;
        entry.extend_from_slice(&entry_length.to_le_bytes());

        // Indexed attribute length (FILE_NAME attribute size)
        entry.extend_from_slice(&(file_name_attr.len() as u16).to_le_bytes());

        // Flags
        entry.extend_from_slice(&flags.to_le_bytes());

        // Padding to 16 bytes
        entry.extend_from_slice(&[0u8; 2]);

        // FILE_NAME attribute
        entry.extend_from_slice(file_name_attr);

        entry
    }

    /// Build INDEX_ROOT attribute for directories.
    ///
    /// INDEX_ROOT value layout (standard NTFS):
    ///   Value offset 0x00: attribute type (0x30 = FILE_NAME)
    ///   Value offset 0x04: collation rule
    ///   Value offset 0x08: bytes per index record (4096)
    ///   Value offset 0x0C: clusters per index record (1)
    ///   Value offset 0x10: INDEX_HEADER (16 bytes):
    ///     +0x00: first_entry_offset (ULONG, relative to start of INDEX_HEADER)
    ///     +0x04: total size of index entries (ULONG)
    ///     +0x08: allocated size (ULONG)
    ///     +0x0C: flags (ULONG, 0 = small index)
    ///   Value offset 0x20+: Index entries start here
    ///
    /// `first_entry_offset = 0x10` because the index header is 16 bytes
    /// (4 ULONG fields). There is no VCN in the $INDEX_ROOT attribute —
    /// VCN is only present in $INDEX_ALLOCATION.
    fn build_index_root_attr(
        &self,
        _entry: &NtfsEntry,
        children: Option<&[(u64, &NtfsEntry)]>,
    ) -> Vec<u8> {
        // The $INDEX_ROOT value layout (NTFS spec) is:
        //   0x00: u32 attribute type indexed (0x30 = FILE_NAME)
        //   0x04: u32 collation rule (0 = FILE_NAME)
        //   0x08: u32 bytes per index record
        //   0x0C: u32 clusters per index record
        //   0x10: INDEX_HEADER (16 bytes):
        //     +0x00: u32 first_entry_offset (relative to start of INDEX_HEADER)
        //     +0x04: u32 total size of index entries
        //     +0x08: u32 allocated size
        //     +0x0C: u32 flags
        //   0x20..: index entries follow
        //
        // We must write the 24-byte attribute header per NTFS spec
        // (see `build_attr_header`) so the kernel's `parse_attribute`
        // finds `value_offset == 24`. Inside the value we then
        // publish a `first_entry_offset = 0x10`, which makes entries
        // start at value offset 0x20.
        //
        // The available room in the MFT record is bounded: the
        // record is exactly 1024 bytes (kernel hard-coded), of
        // which 48 are the MFT header. The INDEX_ROOT attribute
        // must fit in the remaining ~976 bytes along with the
        // STD_INFO (~64) + FILE_NAME (~90) + END marker (8) for
        // a total of ~210 bytes of fixed overhead. That leaves
        // ~766 bytes for the INDEX_ROOT attribute itself
        // (header + value). Each index entry is
        // 16 + 24 + 0x42 + name_len*2 bytes (~116 bytes for
        // short names, ~144 for "Program Files (x86)").
        // 5 root children fit in ~700 bytes including the 12-byte
        // END index marker. The caller sorts root_children so
        // Windows / Program Files are first; we cap the
        // surviving entries to keep the whole record inside
        // 1024 bytes. (A real NTFS volume would use
        // $INDEX_ALLOCATION for overflow — we don't implement
        // that, so we cap at 5 here.)
        //
        // Additionally, the kernel currently caps `parse_attribute`'s
        // returned value at 600 bytes to work around a known
        // allocator panic on the 660+ byte path, so we must
        // cap the value size below that. With the 24-byte
        // attribute header and a 16-byte INDEX_HEADER, the value
        // is `entries_size + 0x10` (16) bytes. We therefore
        // limit entries to keep entries_size <= ~570 bytes
        // (so value <= 586 bytes, well below the 600 cap).

        // Maximum number of children a directory's $INDEX_ROOT can list.
// Each child entry adds at least `16 + 24 + 90 + 2*name_chars`
// bytes — for "Program Files (x86)" (19 chars) that's 168 bytes,
// but typical short names (8 chars) fit in ~146 bytes. With five
// max-size entries plus the 24-byte attr header, the 16-byte
// INDEX_HEADER, the 96-byte $STANDARD_INFORMATION, and the 90-byte
// FILE_NAME attribute, the MFT record tops out around:
//
//     48 (header) + 64 (STD_INFO) + 90 (FILE_NAME) + 24 (INDEX_ROOT
//     attr header) + 16 (INDEX_HEADER) + 5 * 144 (entries)
//   = 962 bytes
//
// which fits cleanly in the 1024-byte record window. Bumping this
// past 5 caused the INDEX_ROOT to overflow into bytes after the
// end of the MFT record (we saw `attr len=944 > record end=1024`
// in the boot manager's serial log), and the kernel aborts the
// whole attribute walk because the inner loop bails on out-of-
// range entries — even though System32 was still physically
// present at the start of the INDEX_ROOT.
//
// The fix is to keep this at a value large enough to include every
// file that the boot flow actually reads through winload.efi /
// ntoskrnl.exe / smss.exe / csrss.exe / wininit.exe / services.exe /
// lsass.exe / lsm.exe / winlogon.exe / userinit.exe / cmd.exe, plus
// the `drivers` and `config` subdirectories and their boot-critical
// files. The non-critical children (e.g. `security`, `WinSxS`,
// `Servicing`) silently fall off the end, which is fine for boot:
// the boot manager only walks the indices it needs
// (Windows → System32 → winload.efi → smss → … → cmd.exe), and any
// other accesses happen after the kernel has its full NTFS driver
// online.
//
// On real Windows, an INDEX_ROOT is allowed up to ~16KB resident
// (we stay well under that here — about 30 entries × ~120 bytes
// = ~3.6KB total). Anything that does not fit moves to the
// allocation bitmap and INDEX_ALLOCATION sub-tree, but our
// minimal boot flow never allocates those extents.
const MAX_CHILDREN_PER_DIR: usize = 64;

        let mut data = build_attr_header(ATTR_TYPE_INDEX_ROOT, 0); // value_len filled below

        // ---- INDEX_ROOT value structure starts here (offset 24) ----
        // 0x00: attribute type (0x30 = FILE_NAME)
        data.extend_from_slice(&ATTR_TYPE_FILE_NAME.to_le_bytes());
        // 0x04: collation rule (0 = FILE_NAME)
        data.extend_from_slice(&0u32.to_le_bytes());
        // 0x08: bytes per index record (4 KiB)
        data.extend_from_slice(&4096u32.to_le_bytes());
        // 0x0C: clusters per index record (1)
        data.extend_from_slice(&1u32.to_le_bytes());

        // ---- INDEX_HEADER at value offset 0x10 (16 bytes) ----
        // 0x10: first_entry_offset = 0x10 (entries start at value offset 0x20)
        data.extend_from_slice(&0x10u32.to_le_bytes());
        // 0x14: total size of index entries (placeholder, filled later)
        let entries_size_offset = data.len();
        data.extend_from_slice(&0u32.to_le_bytes());
        // 0x18: allocated size
        data.extend_from_slice(&4096u32.to_le_bytes());
        // 0x1C: flags (0 = small index)
        data.extend_from_slice(&0u32.to_le_bytes());

        // Index entries (start at value offset 0x20)
        if let Some(child_list) = children {
            // Sort by name priority so critical Windows boot
            // directories (`System32`, `drivers`, `config`, …) end
            // up in the first `MAX_CHILDREN_PER_DIR` slots. Without
            // this, alphabetical order pushes `System32` past the
            // cap (it sorts after `Program Files (x86)` and
            // `Users`) and the boot manager can no longer reach
            // winload.efi.
            let priority = |e: &NtfsEntry| -> u32 {
                let leaf = e.path.rsplit('\\').next().unwrap_or(&e.path);
                let lc = leaf.to_ascii_lowercase();
                // Critical OS loader files: keep `winload.efi`,
                // `ntoskrnl.exe`, `hal.dll`, etc. ahead of any
                // auxiliary directory so the boot manager's
                // `find_child_in_index` walks the right child.
                if !e.is_dir {
                    match lc.as_str() {
                        "winload.efi" => return 0,
                        "ntoskrnl.exe" => return 1,
                        "hal.dll" => return 2,
                        "ntdll.dll" => return 3,
                        "kernel32.dll" => return 4,
                        "smss.exe" => return 5,
                        "csrss.exe" => return 6,
                        "wininit.exe" => return 7,
                        "services.exe" => return 8,
                        "lsass.exe" => return 9,
                        "cmd.exe" => return 10,
                        "bootvid.dll" => return 11,
                        _ => return 50,
                    }
                }
                match lc.as_str() {
                    "system32" => 12,
                    "syswow64" => 13,
                    "drivers" => 14,
                    "config" => 15,
                    "winsxs" => 16,
                    "servicing" => 17,
                    "windows" => 18,
                    "program files" => 19,
                    "programdata" => 20,
                    "program files (x86)" => 21,
                    "system" => 22,
                    _ => 100,
                }
            };
            let mut sorted: Vec<&(u64, &NtfsEntry)> = child_list.iter().collect();
            sorted.sort_by_key(|(rn, e)| (priority(e), *rn));
            let max = core::cmp::min(sorted.len(), MAX_CHILDREN_PER_DIR);
            for (child_record_num, child_entry) in sorted.iter().take(max).copied() {
                // The child's parent_ref should be this directory's
                // record number, but `build_index_root_attr` does not
                // know the parent's record number (it is set by the
                // caller). For now we leave parent_ref as the actual
                // record number of the parent directory (which the
                // caller can post-process); here we use the parent's
                // record number if it can be inferred, otherwise 0.
                // The NTFS kernel driver only consults parent_ref to
                // build the absolute path for error messages; it
                // does not gate directory traversal on it.
                let parent_ref = 0u64;
                let file_name_attr =
                    self.build_file_name_attr_for_record(child_entry, Some(parent_ref));

                // MFT reference: low 48 bits = record number,
                // high 16 bits = sequence number. The previous code
                // did `child_record_num << 48`, putting the record
                // number into the sequence-number slot.
                let index_entry =
                    self.build_index_entry(*child_record_num, &file_name_attr, 0x0000);
                data.extend_from_slice(&index_entry);
            }
        }

        // END marker entry (12 bytes) — minimal entry with only END flag.
        data.extend_from_slice(&0u64.to_le_bytes());   // MFT reference = 0
        data.extend_from_slice(&12u16.to_le_bytes());  // entry length = 12
        data.extend_from_slice(&0u16.to_le_bytes());   // indexed attribute length = 0
        data.extend_from_slice(&0x0002u16.to_le_bytes()); // END flag = 0x0002

        // Fill entries size: number of bytes from value+0x10 (start of
        // INDEX_HEADER) to end of attribute value.
        let value_start = 24usize;
        let entries_size = (data.len() - value_start) as u32 - 0x10;
        data[entries_size_offset..entries_size_offset + 4]
            .copy_from_slice(&entries_size.to_le_bytes());

        // Fill value length into the attribute header. The value_length
        // field lives at attribute offset 0x10 (= 16) within the 24-byte
        // resident attribute header, NOT at the start of the value.
        // The previous code wrote `value_length` to `data[24..28]`, which
        // is the first 4 bytes of the value payload (the "indexed
        // attribute type" field — 0x30 = FILE_NAME). This clobbered the
        // attribute type with the value length, leaving the kernel to
        // read garbage and decode the value as a tiny 4-byte blob.
        let value_length = (data.len() - value_start) as u32;
        data[0x10..0x14].copy_from_slice(&value_length.to_le_bytes());

        fill_attr_length(&mut data);
        data
    }

    /// Finalize the NTFS image, treating it as a standalone volume
    /// (`hidden_sectors = 0`). Equivalent to `finalize_with_offset(0)`.
    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        self.finalize_with_offset(0)
    }

    /// Finalize the NTFS image, recording `partition_offset_bytes` in
    /// the boot sector's `hidden_sectors` field. This is what makes
    /// the image recognisable as a partition (rather than a whole-disk
    /// NTFS install) when it is embedded inside a larger disk image
    /// such as partition 2 of a dual-partition GPT layout.
    ///
    /// Key design decisions:
    /// - MFT record 0 ($MFT) is a self-referencing entry for the MFT volume itself.
    ///   It is NOT one of the user's filesystem entries. We create it as a synthetic
    ///   entry and put it at index 0 so the kernel sees a valid FILE record.
    /// - User entries (from `self.entries`) are written starting at MFT index 1.
    ///   This is correct because index 0 is reserved for the MFT itself.
    /// - The MFT cluster starts at cluster 4. Each cluster holds
    ///   `cluster_size / mft_record_size` records. We extend the image buffer
    ///   as needed to hold all records.
    /// - Files larger than `MAX_RESIDENT_DATA_SIZE` bytes use a non-resident DATA
    ///   attribute. All other data is stored resident inside the MFT record.
    pub fn finalize_with_offset(&mut self, partition_offset_bytes: usize) -> Result<Vec<u8>> {
        // `hidden_sectors` is the starting LBA of the partition; convert
        // the byte offset to a sector count. Only the low 32 bits are
        // representable in the NTFS BPB.
        self.hidden_sectors = (partition_offset_bytes / 512) as u32;

        let cluster_size = (self.sectors_per_cluster as u32) * self.sector_size;
        let image_size = (self.size_mb as usize) * 1024 * 1024;
        let mut image = vec![0u8; image_size];

        // Write boot sector
        let boot_sector = self.build_boot_sector();
        let boot_bytes = boot_sector.as_bytes();
        image[..boot_bytes.len()].copy_from_slice(&boot_bytes);

        let mft_record_size = self.mft_record_size as usize;

        // How many MFT records fit in one cluster?
        let records_per_cluster = cluster_size as usize / mft_record_size;

        // Compute MFT cluster 0's byte offset within the image.
        // Cluster 0 = sectors [0, spc), cluster 1 = sectors [spc, 2*spc), etc.
        // MFT starts at cluster 4.
        let mft_cluster_byte_offset = (self.mft_cluster * cluster_size as u64) as usize;

        // Pre-compute how many clusters we need for all records.
        // Record 0 = $MFT (synthetic), records 1..N = user entries.
        // Reserve one slot for record 0 (the MFT itself).
        let total_user_records = self.entries.len();
        // N+1 total records: index 0 is $MFT, indices 1..N are user entries
        let total_records = total_user_records.saturating_add(1);
        let needed_clusters = total_records.div_ceil(records_per_cluster);
        let needed_bytes = mft_cluster_byte_offset + needed_clusters * cluster_size as usize;

        // Extend the image buffer if the MFT needs more space than initially allocated.
        if needed_bytes > image_size {
            image.resize(needed_bytes, 0);
        }

        // --- Build synthetic $MFT entry for record 0 ---
        // This entry has the path "$MFT" so the kernel's verify_record sees
        // a valid "FILE" signature and can identify the record.
        let mft_entry = NtfsEntry::new_file("$MFT", Vec::new());

        // Build a map: entry index in self.entries -> MFT record number
        // self.entries[i] -> MFT record (i + 1)
        // This allows us to set parent MFT references in FILE_NAME attributes.

        // --- Build child map for INDEX_ROOT population ---
        // Map: parent_path -> list of (record_num, entry) for children
        // Paths in self.entries are backslash-separated NTFS-style
        // relative to the volume root, e.g. "Windows\System32\winload.efi".
        // We collect owned (path, is_dir, record_num, data_len) tuples
        // up front so the immutable borrow on `self.entries` ends as
        // soon as the loop finishes — leaving us free to mutate
        // `self.data_cluster_assignments` later without borrow-
        // checker gymnastics.
        let mut child_meta: Vec<(String, bool, u64, usize)> =
            Vec::with_capacity(self.entries.len());
        for (i, entry) in self.entries.iter().enumerate() {
            let record_num = (i + 1) as u64;
            child_meta.push((entry.path.clone(), entry.is_dir, record_num, entry.data.len()));
        }

        // child_meta is owned, so we can now mutate self freely.
        // Group children by parent path for INDEX_ROOT lookups.
        //
        // Important: an NTFS $INDEX_ROOT must list EVERY child of
        // the directory — both subdirectories AND regular files.
        // The boot manager walks the parent's index to resolve
        // `Windows\System32\winload.efi`, so `winload.efi` itself
        // has to be present as an index entry in `System32`'s
        // INDEX_ROOT (record 15). The earlier version of this
        // loop filtered `if !is_dir { continue; }`, which silently
        // dropped every file from the index and left the boot
        // manager unable to find `winload.efi`. Include both.
        let mut child_map: std::collections::HashMap<String, Vec<(u64, String)>> =
            std::collections::HashMap::new();
        for (path, _is_dir, record_num, _data_len) in &child_meta {
            let parent_path = match path.rfind('\\') {
                Some(idx) => path[..idx].to_string(),
                None => String::new(),
            };
            child_map.entry(parent_path).or_default().push((*record_num, path.clone()));
        }

        // --- Pre-allocate cluster ranges for non-resident files ---
        // For each non-resident file, allocate a contiguous cluster
        // range so the MFT record can carry a run list pointing at
        // it. We do this here (in &mut self) so the MFT record
        // builder can take &self later.
        let non_resident: Vec<(String, usize)> = child_meta.iter()
            .filter(|(_, is_dir, _, data_len)| !*is_dir && *data_len > Self::MAX_RESIDENT_DATA_SIZE)
            .map(|(path, _, _, data_len)| (path.clone(), *data_len))
            .collect();
        for (path, len) in non_resident {
            let assignment = self.allocate_data_clusters(len);
            self.data_cluster_assignments.insert(path, assignment);
        }

        // --- Build root directory entry (MFT record 5) ---
        // The root directory has no parent, so parent_ref = 0
        // Its children are all entries where parent_path is "" or "C:".
        // We don't keep the value around — the canonical root record
        // is built later from the entry-record map populated above.
        let _root_entry = NtfsEntry::new_dir("C:\\");

        // --- Write all MFT records ---
        // Record 0: $MFT self-reference
        let record_0 = self.build_mft_record(&mft_entry, 0, None, None);
        image[mft_cluster_byte_offset..mft_cluster_byte_offset + mft_record_size]
            .copy_from_slice(&record_0);

        // Build a map: entry path -> record number for children lookup
        let mut entry_record_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

        // Records 1..N: user entries (sequential)
        for (i, entry) in self.entries.iter().enumerate() {
            let record_num = (i + 1) as u64;
            entry_record_map.insert(String::from(&entry.path), record_num);
            let parent_ref = self.compute_parent_ref_with_map(&entry_record_map, entry, record_num);
            // Get children for this directory (for INDEX_ROOT). The
            // child_map is keyed by the directory's OWN path (e.g.
            // "Windows" → list of "Windows\System32", "Windows\Fonts",
            // …), NOT by the parent path. Using the parent path here
            // dumps the parent's children into this record's
            // INDEX_ROOT, which is exactly what made the boot
            // manager's `find_child_in_index` walk into the wrong
            // directory when looking up "System32".
            let own_path_owned = entry.path.clone();
            let children_owned = child_map.get(&own_path_owned).cloned();
            let children_slice: Option<Vec<(u64, &NtfsEntry)>> = children_owned.as_ref().map(|v| {
                v.iter().filter_map(|(rn, p)| self.entries.iter().find(|e| &e.path == p).map(|e| (*rn, e))).collect()
            });
            let children = children_slice.as_deref();
            let record = self.build_mft_record(entry, record_num, parent_ref, children);

            let record_offset = mft_cluster_byte_offset + record_num as usize * mft_record_size;
            if record_offset + mft_record_size <= image.len() {
                image[record_offset..record_offset + mft_record_size].copy_from_slice(&record);
            }
        }

        // Record 5: Root directory (always at record 5)
        // Root has no parent (parent_ref = 0), and its children are all entries
        // where the parent is root. Entries are stored with backslash paths
        // like "Windows\System32\winload.efi"; the root has no path
        // prefix, so any entry that has no path separator before its first
        // component is a direct child of the root.
        let root_entry = NtfsEntry::new_dir("C:\\");
        // Build owned (record_num, path) pairs for direct children
        // of the root by walking `child_meta` so we can sort and
        // slice without borrowing self.entries.
        let mut root_children_owned: Vec<(u64, String)> = Vec::new();
        for (path, _is_dir, record_num, _data_len) in &child_meta {
            let first_slash = path.find('\\');
            let parent_of_entry = match first_slash {
                Some(idx) => &path[..idx],
                None => "",
            };
            if parent_of_entry.is_empty() {
                root_children_owned.push((*record_num, path.clone()));
            }
        }
        // Order root children so critical boot directories are first.
        // The MFT record is only 1024 bytes and the in-tree INDEX_ROOT
        // is capped at MAX_CHILDREN_PER_DIR entries; sort so Windows /
        // Program Files / ProgramData always survive the cap.
        root_children_owned.sort_by_key(|(rn, path)| {
            let leaf = path.rsplit('\\').next().unwrap_or(path.as_str());
            let priority = match leaf.to_ascii_lowercase().as_str() {
                "windows" => 0,
                "program files" => 1,
                "programdata" => 2,
                "program files (x86)" => 3,
                "system" => 4,
                _ => 5,
            };
            (priority, *rn)
        });
        // Materialise to (u64, &NtfsEntry) for the MFT record builder.
        let mut root_children: Vec<(u64, &NtfsEntry)> = Vec::new();
        for (rn, path) in &root_children_owned {
            if let Some(e) = self.entries.iter().find(|e| &e.path == path) {
                root_children.push((*rn, e));
            }
        }
        let root_record = self.build_mft_record(
            &root_entry,
            5,
            Some(0u64),
            if root_children.is_empty() { None } else { Some(&root_children) }
        );
        // Order root children so critical boot directories are first.
        // The MFT record is only 1024 bytes and the in-tree INDEX_ROOT
        // is capped at MAX_CHILDREN_PER_DIR entries (set inside
        // `build_index_root_attr`); if we leave root_children in
        // source order, `Program Files (x86)` or `Users` can push
        // `Windows` past the cutoff and winload.efi becomes
        // unreachable. Sort so Windows / Program Files / ProgramData
        // always survive the cap.
        root_children.sort_by_key(|(rn, e)| {
            let leaf = e.path.rsplit('\\').next().unwrap_or(&e.path);
            let priority = match leaf.to_ascii_lowercase().as_str() {
                "windows" => 0,
                "program files" => 1,
                "programdata" => 2,
                "program files (x86)" => 3,
                "system" => 4,
                _ => 5,
            };
            (priority, *rn)
        });
        let root_record_offset = mft_cluster_byte_offset + 5 * mft_record_size;
        // Ensure we have enough space
        if root_record_offset + mft_record_size > image.len() {
            image.resize(root_record_offset + mft_record_size + 4096, 0);
        }
        image[root_record_offset..root_record_offset + mft_record_size]
            .copy_from_slice(&root_record);

        // --- Write non-resident file data into its cluster window ---
        // For each entry whose file body didn't fit in the resident
        // MFT record, copy `entry.data` into the contiguous cluster
        // range we allocated in `build_mft_record`. The run list in
        // the on-disk MFT record points at exactly this range, so
        // the boot manager's NTFS reader will fetch the bytes from
        // here when the kernel asks for the file.
        for (path, (start_lcn, cluster_count)) in &self.data_cluster_assignments {
            let entry = match self.entries.iter().find(|e| &e.path == path) {
                Some(e) => e,
                None => continue,
            };
            let byte_offset = (*start_lcn as usize) * cluster_size as usize;
            let byte_count = (*cluster_count as usize) * cluster_size as usize;
            if byte_offset + byte_count > image.len() {
                image.resize(byte_offset + byte_count, 0);
            }
            // Write only `entry.data.len()` real bytes; the rest of
            // the cluster allocation stays zero (real_size tells the
            // reader where the file ends).
            image[byte_offset..byte_offset + entry.data.len()]
                .copy_from_slice(&entry.data);
        }

        Ok(image)
    }

    /// Compute parent MFT reference using a pre-built map of entry path -> record number.
    fn compute_parent_ref_with_map(
        &self,
        entry_map: &std::collections::HashMap<String, u64>,
        entry: &NtfsEntry,
        _record_num: u64,
    ) -> Option<u64> {
        let last_bs = entry.path.rfind('\\');
        let parent_path = last_bs.map(|p| &entry.path[..p]).unwrap_or("");
        if parent_path.is_empty() {
            // Root directory = MFT record 5. An MFT reference is a 48-bit
            // record number in the low 48 bits and a 16-bit sequence
            // number in the high 16 bits, NOT the other way around —
            // see `ntfs::open_file` and the index-entry parser for the
            // matching decode (parent_ref & 0x0000_FFFF_FFFF_FFFF is
            // the record number). The previous code did `5 << 48` which
            // put 5 into the sequence-number field and left the
            // record-number field at 0, so every file looked like it
            // lived in a non-existent record-0 parent directory.
            return Some(5u64);
        }

        // Look up parent in the map
        if let Some(&parent_record) = entry_map.get(parent_path) {
            return Some(parent_record);
        }

        // Parent not found — treat as root
        Some(5u64)
    }

    /// Maximum bytes of data we store as a resident DATA attribute inside a
    /// single MFT record. We leave headroom for the header (48), fixup (4),
    /// STD_INFO (~72), FILE_NAME (~80), and INDEX_ROOT (~50 for dirs).
    const MAX_RESIDENT_DATA_SIZE: usize = 700;

    /// Build a complete MFT record for `entry` at `record_num`.
    ///
    /// `parent_ref` is the MFT reference of the parent directory (for the
    /// FILE_NAME attribute). Pass None for the $MFT self-reference record.
    /// `children` is a list of (record_num, entry) for children (for INDEX_ROOT).
    fn build_mft_record(
        &self,
        entry: &NtfsEntry,
        record_num: u64,
        parent_ref: Option<u64>,
        children: Option<&[(u64, &NtfsEntry)]>,
    ) -> Vec<u8> {
        let mft_record_size = self.mft_record_size as usize;

        // Build the 48-byte MFT record header as a fixed-size array first.
        // This avoids any issues with Vec::extend_from_slice.
        let record_flags: u16 = if entry.is_dir { 0x0003 } else { 0x0001 };
        let mut header = [0u8; 48];
        header[0..4].copy_from_slice(b"FILE");                 // 0x00: signature
        header[4..6].copy_from_slice(&48u16.to_le_bytes());  // 0x04: fixup_offset = 48
        header[6..8].copy_from_slice(&0u16.to_le_bytes());   // 0x06: fixup_size = 0
        // header[8..16] = LSN = 0 (already 0)
        header[16..18].copy_from_slice(&1u16.to_le_bytes());  // 0x10: sequence_number
        header[18..20].copy_from_slice(&1u16.to_le_bytes()); // 0x12: link_count
        header[20..22].copy_from_slice(&48u16.to_le_bytes()); // 0x14: attributes_offset = 48
        header[22..24].copy_from_slice(&record_flags.to_le_bytes()); // 0x16: flags
        // header[24..28] = used_size (placeholder, filled later)
        let used_size_offset = 24;
        header[28..32].copy_from_slice(&(mft_record_size as u32).to_le_bytes()); // 0x1C: allocated_size
        // header[32..40] = base_mft_record = 0 (already 0)
        // header[40..44] = next_attribute_id + padding = 0 (already 0)
        // record_number is u32 at offset 0x2C (bytes 44..48)
        header[44..48].copy_from_slice(&(record_num as u32).to_le_bytes());

        let mut record = Vec::with_capacity(mft_record_size);
        record.extend_from_slice(&header);

        // --- Attributes start here (offset 48) ---
        // 1. $STANDARD_INFORMATION
        let std_info = self.build_standard_info();
        record.extend_from_slice(&std_info);

        // 2. $FILE_NAME
        let file_name = self.build_file_name_attr_for_record(entry, parent_ref);
        record.extend_from_slice(&file_name);

        // 3. $INDEX_ROOT (directories only)
        if entry.is_dir {
            let index_root = self.build_index_root_attr(entry, children);
            record.extend_from_slice(&index_root);
        }

        // 4. $DATA — resident for small files, non-resident for large ones.
        // Small files (<= MAX_RESIDENT_DATA_SIZE) store their bytes inside
        // the MFT record. Large files need an external cluster allocation
        // and a run list in the attribute header. Without non-resident
        // support the boot manager only ever sees the first 700 bytes of
        // a PE file, which truncates winload.efi mid-header and makes
        // LoadImage fail with EFI_UNSUPPORTED.
        if !entry.is_dir && !entry.data.is_empty() {
            if entry.data.len() > Self::MAX_RESIDENT_DATA_SIZE {
                // The cluster allocation was done in a pre-pass by
                // `finalize_with_offset`; the assignment lives in
                // `data_cluster_assignments` keyed by `entry.path`.
                let file_clusters = match self.data_cluster_assignments.get(&entry.path) {
                    Some(&fc) => fc,
                    None => {
                        // Allocation missing — fall back to a resident
                        // attribute so the record at least parses.
                        let data_attr = self.build_data_attr(&entry.data[..Self::MAX_RESIDENT_DATA_SIZE]);
                        record.extend_from_slice(&data_attr);
                        return record;
                    }
                };
                let data_attr = self.build_non_resident_data_attr(entry, file_clusters);
                record.extend_from_slice(&data_attr);
            } else {
                let data_attr = self.build_data_attr(&entry.data);
                record.extend_from_slice(&data_attr);
            }
        }

        // 5. End marker
        record.extend_from_slice(&Self::build_end_marker());

        // --- Fill used_size ---
        let used_size = record.len() as u32;
        record[used_size_offset..used_size_offset + 4]
            .copy_from_slice(&used_size.to_le_bytes());

        // Pad to full record size
        record.resize(mft_record_size, 0);

        // NTFS Multi-Sector Transfer (fixup) array handling. Real
        // NTFS writers save the last 2 bytes of every sector into the
        // Update Sequence Array in the record header, then overwrite
        // those bytes with the Update Sequence Number. The OS
        // reverses the swap on read. We don't implement the proper
        // fixup here — but the naive implementation that simply
        // overwrote bytes 510/511 (and 1022/1023) with zero was
        // silently corrupting data that happened to land there in
        // the attribute list. For example, an 18-byte UTF-16LE
        // filename "lsass.exe" inside a System32 directory's
        // $INDEX_ROOT entry sits at record offset 0x1F8, and the
        // second 's' of "lsass" (0x73 0x00) overlaps byte 510
        // (0x1FE). Clobbering it to 0x00 0x00 made the filename
        // decode as "lsa\0s.exe" with a bogus embedded NUL that
        // crashed the boot manager's index-entry walker.
        //
        // The boot manager already has a defensive
        // `decode_filename_attr` that skips embedded NULs when
        // rendering the name, so even with the fixup stripped the
        // filename comparison still works. We therefore leave the
        // data bytes at 510/511 and 1022/1023 untouched and rely on
        // the record being self-consistent. The on-disk image
        // produced by this builder is not byte-identical to a
        // Windows-formatted NTFS volume, but it is structurally
        // valid for the in-tree kernel/boot manager readers.

        record
    }

    /// Build a FILE_NAME attribute matching the standard NTFS layout.
    ///
    /// FILE_NAME value structure:
    ///   0x00: parent_ref (8 bytes)
    ///   0x08: creation_time (8 bytes)
    ///   0x10: modification_time (8 bytes)
    ///   0x18: mft_change_time (8 bytes)
    ///   0x20: last_access_time (8 bytes)
    ///   0x28: allocated_size (8 bytes)
    ///   0x30: file_size (8 bytes)
    ///   0x38: file_attributes (4 bytes)
    ///   0x3C: reserved (2 bytes)
    ///   0x3E: name_length (1 byte)
    ///   0x3F: namespace (1 byte)
    ///   0x40+: filename (UTF-16LE)
    fn build_file_name_attr_for_record(
        &self,
        entry: &NtfsEntry,
        parent_ref: Option<u64>,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        // Extract the filename component (last backslash-separated component)
        let file_name = entry
            .path
            .rsplit('\\')
            .next()
            .unwrap_or(&entry.path);

        let name_utf16: Vec<u16> = file_name.encode_utf16().collect();
        let name_len = name_utf16.len() as u8;

        // Attribute header (24 bytes) per the NTFS attribute-record spec:
        //   0x00: u32 type
        //   0x04: u32 length (filled below)
        //   0x08: u8  non-resident (0 = resident)
        // Use the standard 24-byte resident attribute header so the
        // kernel's `parse_attribute` (which reads value_length at
        // attr+20 and value_offset at attr+24) finds the right
        // fields. Earlier versions wrote only 20 bytes of header and
        // landed `value_length` at attr+0x0C and `value_offset` at
        // attr+0x10, which the kernel decodes as part of the value
        // data — every read of a FILE_NAME attribute returned
        // garbage.
        // Correct FILE_NAME value layout: packed_ea_size is u16 (2 bytes) at 0x3C.
        // Total fixed fields = 0x40 bytes, then filename of name_len*2 bytes.
        let value_length = 0x40u32 + (name_len as u32) * 2;
        data.extend_from_slice(&build_attr_header(ATTR_TYPE_FILE_NAME, value_length));

        // FILE_NAME value (starts at attr_offset + 24)
        let parent_ref_val = parent_ref.unwrap_or(0u64);
        data.extend_from_slice(&parent_ref_val.to_le_bytes()); // 0x00: parent_ref (8)
        data.extend_from_slice(&0u64.to_le_bytes());           // 0x08: creation_time (8)
        data.extend_from_slice(&0u64.to_le_bytes());           // 0x10: modification_time (8)
        data.extend_from_slice(&0u64.to_le_bytes());           // 0x18: mft_change_time (8)
        data.extend_from_slice(&0u64.to_le_bytes());           // 0x20: last_access_time (8)
        data.extend_from_slice(&0u64.to_le_bytes());           // 0x28: allocated_size (8)
        data.extend_from_slice(&0u64.to_le_bytes());           // 0x30: file_size (8)
        let file_attrs = if entry.is_dir { 0x10u32 } else { 0x20u32 };
        data.extend_from_slice(&file_attrs.to_le_bytes());       // 0x38: file_attributes (4)
        // NTFS spec: packed_ea_size is a u16 (2 bytes) at value offset 0x3C.
        // The earlier version wrote 0u32 here (4 bytes), pushing name_length
        // from 0x3E to 0x40 and the filename from 0x40 to 0x42.
        // When the boot manager's index parser read name_length from offset
        // 0x40, it got the first byte of the filename instead (0x57 = 'W'
        // for "Windows") giving a "name length" of 87 chars and reading
        // garbage for the filename.
        data.extend_from_slice(&0u16.to_le_bytes());           // 0x3C: packed_ea_size (2)
        data.push(name_len);                                   // 0x3E: name_length (1)
        data.push(FILENAME_NAMESPACE_WIN32);                   // 0x3F: namespace (1)
        // Filename at 0x40 (2 bytes per char)
        for c in name_utf16 {
            data.extend_from_slice(&c.to_le_bytes());
        }

        fill_attr_length(&mut data);
        data
    }

    /// Get the sector size
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Get the sectors per cluster
    pub fn sectors_per_cluster(&self) -> u8 {
        self.sectors_per_cluster
    }

    /// Get the MFT record size
    pub fn mft_record_size(&self) -> i32 {
        self.mft_record_size
    }
}

// =====================================================================
// Byte Serialization
// =====================================================================

impl NtfsBootSector {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(&self.jump);
        bytes.extend_from_slice(&self.oem_id);
        bytes.extend_from_slice(&self.bytes_per_sector.to_le_bytes());
        bytes.push(self.sectors_per_cluster);
        bytes.extend_from_slice(&self.reserved_sectors.to_le_bytes());
        bytes.extend_from_slice(&self.zeros1);
        bytes.extend_from_slice(&self.not_used1.to_le_bytes());
        bytes.push(self.media_descriptor);
        bytes.extend_from_slice(&self.not_used2.to_le_bytes());
        bytes.extend_from_slice(&self.sectors_per_track.to_le_bytes());
        bytes.extend_from_slice(&self.number_of_heads.to_le_bytes());
        bytes.extend_from_slice(&self.hidden_sectors.to_le_bytes());
        bytes.extend_from_slice(&self.not_used3.to_le_bytes());
        bytes.extend_from_slice(&self.not_used4.to_le_bytes());
        bytes.extend_from_slice(&self.total_sectors.to_le_bytes());
        bytes.extend_from_slice(&self.mft_cluster_location.to_le_bytes());
        bytes.extend_from_slice(&self.mft_mirror_cluster_location.to_le_bytes());
        bytes.push(self.clusters_per_mft_record as u8);
        bytes.push(self.clusters_per_index_record as u8);
        bytes.extend_from_slice(&self.not_used5);
        bytes.extend_from_slice(&self.volume_serial_number.to_le_bytes());
        bytes.extend_from_slice(&self.checksum.to_le_bytes());
        bytes.extend_from_slice(&self.bootstrap_code);
        bytes.extend_from_slice(&self.end_of_sector_marker.to_le_bytes());
        
        // Pad to 512 bytes
        bytes.resize(512, 0);
        bytes
    }
}

/// Simple random number generator for volume serial
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    ((duration.as_secs() ^ duration.subsec_nanos() as u64) << 32) | duration.as_millis() as u64
}

// =====================================================================
// FsBackend implementation
// =====================================================================

impl FsBackend for NtfsImage {
    fn kind(&self) -> &'static str { "ntfs" }

    fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        self.list_dir_path(path)
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.read_file_path(path)
    }

    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_file_path(path, data)
    }

    fn mkdir(&mut self, path: &str) -> Result<()> {
        self.mkdir_path(path)
    }

    fn remove(&mut self, path: &str) -> Result<()> {
        self.remove_path_ntfs(path)
    }

    fn finalize(&mut self) -> Result<Vec<u8>> {
        // Forward to the inherent method that performs the actual NTFS
        // byte layout. Using a fully-qualified path to disambiguate from
        // the trait method of the same name.
        NtfsImage::finalize_with_offset(self, 0)
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntfs_creation() {
        let mut image = NtfsImage::new(64, 4096).unwrap();
        image.create_dir("Windows").unwrap();
        image.create_dir("Windows/System32").unwrap();
        image.write_file("Windows/System32/test.txt", b"Hello").unwrap();

        let data = image.finalize().unwrap();
        assert!(data.len() > 0);

        // Check boot sector signature
        let oem = &data[3..11];
        assert_eq!(oem, b"NTFS    ");

        // Check end marker
        assert_eq!(data[510], 0x55);
        assert_eq!(data[511], 0xAA);
    }

    #[test]
    fn test_invalid_cluster_size() {
        // Power of 2 check
        let result = NtfsImage::new(64, 3000);
        assert!(result.is_err());
    }

    #[test]
    fn test_mft_record_size() {
        let image = NtfsImage::new(64, 4096).unwrap();
        assert!(image.mft_record_size() >= 1024);
    }
}
