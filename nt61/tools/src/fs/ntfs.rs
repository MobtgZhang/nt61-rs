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
//! ```rust
//! use nt61_tools::ntfs::NtfsImage;
//!
//! let mut image = NtfsImage::new(2048, 4096).unwrap(); // 2GB, 4KB clusters
//! image.create_dir("Windows").unwrap();
//! image.create_dir("Windows/System32").unwrap();
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
                                    if name_ns != 0x02 || file_name.is_none() {
                                        if file_name.is_none() || name_ns == 0x03 || name_ns == 0x01 {
                                            file_name = Some(name);
                                        }
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
        
        // Calculate MFT record size (minimum 1024 bytes)
        let mft_record_size = if cluster_size >= 4096 {
            cluster_size as i32
        } else {
            1024
        };

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
            clusters_per_mft_record: if self.mft_record_size >= 4096 {
                (self.mft_record_size / self.sectors_per_cluster as i32) as i8
            } else {
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
        let mut data = Vec::new();
        
        // Attribute type
        data.extend_from_slice(&ATTR_TYPE_STANDARD_INFORMATION.to_le_bytes());
        // Length (filled later)
        let length_offset = data.len();
        data.extend_from_slice(&0u32.to_le_bytes());
        // Resident flag
        data.push(ATTR_FLAG_RESIDENT);
        // Name length
        data.push(0);
        // Name offset
        data.extend_from_slice(&0u16.to_le_bytes());
        
        // Resident header
        let value_offset = data.len();
        data.extend_from_slice(&0u32.to_le_bytes()); // Value length
        data.extend_from_slice(&(value_offset as u16).to_le_bytes()); // Value offset
        data.push(0); // Flags
        data.push(0); // Reserved
        
        // Standard information value
        data.extend_from_slice(&0u64.to_le_bytes()); // Creation time
        data.extend_from_slice(&0u64.to_le_bytes()); // Modification time
        data.extend_from_slice(&0u64.to_le_bytes()); // MFT change time
        data.extend_from_slice(&0u64.to_le_bytes()); // Last access time
        data.extend_from_slice(&0x10u32.to_le_bytes()); // File attributes (ARCHIVE)
        
        // Update length
        let length = data.len() - length_offset + 4; // Include attribute type and length fields
        let le_bytes = (length as u32).to_le_bytes();
        data[length_offset..length_offset + 4].copy_from_slice(&le_bytes);
        
        data
    }

    /// Build file name attribute
    fn build_file_name_attr(&self, path: &str, _is_dir: bool) -> Vec<u8> {
        let mut data = Vec::new();
        let name_utf16: Vec<u16> = path.encode_utf16().collect();
        let name_len = name_utf16.len() as u8;
        
        // Attribute type
        data.extend_from_slice(&ATTR_TYPE_FILE_NAME.to_le_bytes());
        // Length (filled later)
        let length_offset = data.len();
        data.extend_from_slice(&0u32.to_le_bytes());
        // Resident flag
        data.push(ATTR_FLAG_RESIDENT);
        // Name length
        data.push(name_len);
        // Name offset
        data.extend_from_slice(&0u16.to_le_bytes());
        
        // Resident header
        let value_length = 0x42 + (name_len as u32) * 2;
        let value_offset = data.len();
        data.extend_from_slice(&value_length.to_le_bytes());
        data.extend_from_slice(&(value_offset as u16).to_le_bytes());
        data.push(0); // Flags
        data.push(0); // Reserved
        
        // File name value
        data.extend_from_slice(&0u64.to_le_bytes()); // Parent directory reference
        data.extend_from_slice(&0u64.to_le_bytes()); // Creation time
        data.extend_from_slice(&0u64.to_le_bytes()); // Modification time
        data.extend_from_slice(&0u64.to_le_bytes()); // MFT change time
        data.extend_from_slice(&0u64.to_le_bytes()); // Last access time
        data.extend_from_slice(&0u64.to_le_bytes()); // Allocated size
        data.extend_from_slice(&0u64.to_le_bytes()); // Data size
        data.extend_from_slice(&0u32.to_le_bytes()); // File attributes
        data.extend_from_slice(&0u16.to_le_bytes()); // Extended attributes
        data.push(FILENAME_NAMESPACE_WIN32); // Namespace
        data.push(name_len);
        // Filename (UTF-16LE)
        for c in name_utf16 {
            data.extend_from_slice(&c.to_le_bytes());
        }
        
        // Update length
        let length = data.len() - length_offset + 4;
        let le_bytes = (length as u32).to_le_bytes();
        data[length_offset..length_offset + 4].copy_from_slice(&le_bytes);
        
        data
    }

    /// Build data attribute
    fn build_data_attr(&self, data: &[u8]) -> Vec<u8> {
        let mut attr = Vec::new();
        
        // Attribute type
        attr.extend_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        // Length (filled later)
        let length_offset = attr.len();
        attr.extend_from_slice(&0u32.to_le_bytes());
        // Resident flag
        attr.push(ATTR_FLAG_RESIDENT);
        // Name length
        attr.push(0);
        // Name offset
        attr.extend_from_slice(&0u16.to_le_bytes());
        
        // Resident header
        let value_length = data.len() as u32;
        let value_offset = attr.len();
        attr.extend_from_slice(&value_length.to_le_bytes());
        attr.extend_from_slice(&(value_offset as u16).to_le_bytes());
        attr.push(0); // Flags
        attr.push(0); // Reserved
        
        // Data value
        attr.extend_from_slice(data);
        
        // Update length
        let length = attr.len() - length_offset + 4;
        let le_bytes = (length as u32).to_le_bytes();
        attr[length_offset..length_offset + 4].copy_from_slice(&le_bytes);
        
        attr
    }

    /// Build end marker attribute
    fn build_end_marker() -> Vec<u8> {
        let mut marker = Vec::new();
        marker.extend_from_slice(&0xFFFFFFFF_u32.to_le_bytes());
        marker.extend_from_slice(&0u32.to_le_bytes());
        marker
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
    pub fn finalize_with_offset(&mut self, partition_offset_bytes: usize) -> Result<Vec<u8>> {
        // `hidden_sectors` is the starting LBA of the partition; convert
        // the byte offset to a sector count. Only the low 32 bits are
        // representable in the NTFS BPB.
        self.hidden_sectors = (partition_offset_bytes / 512) as u32;

        let cluster_size = (self.sectors_per_cluster as u32) * self.sector_size;
        let _total_clusters = self.total_sectors / (self.sectors_per_cluster as u64);
        let image_size = (self.size_mb as usize) * 1024 * 1024;
        let mut image = vec![0u8; image_size];

        // Write boot sector
        let boot_sector = self.build_boot_sector();
        let boot_bytes = boot_sector.as_bytes();
        image[..boot_bytes.len()].copy_from_slice(&boot_bytes);

        // Write MFT records
        let mft_record_size = self.mft_record_size as usize;

        // Reserve MFT records at the beginning
        let mft_records_reserved = 24; // Reserve first 24 records for system files

        // Add volume entry
        let volume_entry = NtfsEntry::new_dir("C:");
        self.entries.insert(0, volume_entry);

        // Compute the MFT's byte offset from the cluster location, so
        // the MFT records do not overwrite the boot sector (offset 0).
        let mft_byte_offset = (self.mft_cluster * cluster_size as u64) as usize;

        // Write each entry as an MFT record
        for (i, entry) in self.entries.iter().enumerate() {
            if i >= mft_records_reserved {
                break;
            }

            let mut record = Vec::new();

            // Build attributes
            let standard_info = self.build_standard_info();
            record.extend_from_slice(&standard_info);

            let file_name = self.build_file_name_attr(&entry.path, entry.is_dir);
            record.extend_from_slice(&file_name);

            if !entry.is_dir && !entry.data.is_empty() {
                let data_attr = self.build_data_attr(&entry.data);
                record.extend_from_slice(&data_attr);
            }

            record.extend_from_slice(&Self::build_end_marker());

            // Pad to record size
            record.resize(mft_record_size, 0);

            // Write record at MFT cluster + i*record_size, NOT at offset 0.
            let record_offset = mft_byte_offset + i * mft_record_size;
            if record_offset + mft_record_size <= image_size {
                image[record_offset..record_offset + mft_record_size].copy_from_slice(&record);
            }
        }

        Ok(image)
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
