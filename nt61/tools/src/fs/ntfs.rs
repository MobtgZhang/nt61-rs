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
        // Kernel `parse_index_entry` reads name_length from
        // `value_offset + 64` and namespace from `value_offset + 65`.
        // Write name_len first, then namespace.
        data.push(name_len);                          // offset 64: name_length
        data.push(FILENAME_NAMESPACE_WIN32);           // offset 65: namespace
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
    ///   Value offset 0x08: bytes per index record
    ///   Value offset 0x0C: clusters per index record
    ///   Value offset 0x10: index header size (24 bytes)
    ///   Value offset 0x14: (padding until index header starts)
    ///   ...
    ///   Value offset 0x28: INDEX_HEADER starts here
    ///     +0x00: first_entry_offset (relative to start of INDEX_HEADER)
    ///     +0x04: total size of index entries
    ///     +0x08: allocated size
    ///     +0x0C: flags
    ///     +0x10: VCN (8 bytes) - Virtual Cluster Number for this index buffer
    ///   Value offset 0x38+: Index entries start here
    fn build_index_root_attr(
        &self,
        entry: &NtfsEntry,
        children: Option<&[(u64, &NtfsEntry)]>,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // Attribute header (24 bytes)
        data.extend_from_slice(&ATTR_TYPE_INDEX_ROOT.to_le_bytes());
        let length_offset = data.len();
        data.extend_from_slice(&0u32.to_le_bytes()); // length (filled later)
        data.push(ATTR_FLAG_RESIDENT);
        data.push(0); // name length
        data.extend_from_slice(&0u16.to_le_bytes()); // name offset

        // Resident header (24 bytes)
        let value_offset = data.len();
        data.extend_from_slice(&0u32.to_le_bytes()); // value length (filled later)
        data.extend_from_slice(&(value_offset as u16).to_le_bytes()); // value offset
        data.push(0); // flags
        data.push(0); // reserved

        // INDEX_ROOT value structure:
        // 0x00: attribute type (0x30 = FILE_NAME)
        data.extend_from_slice(&ATTR_TYPE_FILE_NAME.to_le_bytes());
        // 0x04: collation rule (0 = DWORD)
        data.extend_from_slice(&0u32.to_le_bytes());
        // 0x08: bytes per index record
        data.extend_from_slice(&4096u32.to_le_bytes()); // 4KB
        // 0x0C: clusters per index record
        data.extend_from_slice(&1u32.to_le_bytes());
        // 0x10: index header size (24 bytes)
        data.extend_from_slice(&24u32.to_le_bytes());

        // Padding from 0x14 to 0x27 (20 bytes) - this space is between
        // index_header_size field and where INDEX_HEADER actually starts
        data.resize(data.len() + 20, 0);

        // INDEX_HEADER starts at value offset 0x28
        // first_entry_offset: offset from start of INDEX_HEADER to first entry
        // INDEX_HEADER is 24 bytes (0x18), VCN is 8 bytes, so entries at 0x18 + 0x18 = 0x30
        data.extend_from_slice(&0x30u32.to_le_bytes()); // first_entry_offset = 0x30
        // 0x04: total size of index entries (placeholder, filled later)
        let entries_size_offset = data.len();
        data.extend_from_slice(&0u32.to_le_bytes());
        // 0x08: allocated size
        data.extend_from_slice(&4096u32.to_le_bytes());
        // 0x0C: flags (0 = small)
        data.extend_from_slice(&0u32.to_le_bytes());
        // 0x10: VCN (8 bytes)
        data.extend_from_slice(&0u64.to_le_bytes()); // VCN = 0

        // Index entries (start at value offset 0x38)
        // If we have children, add them before the END marker
        if let Some(child_list) = children {
            for &(child_record_num, child_entry) in child_list {
                // Build FILE_NAME attribute for this child
                // The child's parent_ref should be this directory's record number
                // But we don't have the current entry's record number here.
                // For now, use 0 as parent_ref (kernel may not use it)
                let parent_ref = 0u64; // TODO: pass current record number
                let file_name_attr =
                    self.build_file_name_attr_for_record(child_entry, Some(parent_ref));

                // Build index entry with child exists flag
                let index_entry =
                    self.build_index_entry(child_record_num << 48, &file_name_attr, 0x0000);
                data.extend_from_slice(&index_entry);
            }
        }

        // END marker entry (12 bytes) - minimal entry with only END flag
        data.extend_from_slice(&0u64.to_le_bytes()); // MFT reference = 0
        data.extend_from_slice(&12u16.to_le_bytes()); // entry length = 12
        data.extend_from_slice(&0u16.to_le_bytes()); // indexed attribute length = 0
        data.extend_from_slice(&0x0002u16.to_le_bytes()); // END flag = 0x0002

        // Fill entries size
        let entries_size = data.len() - (value_offset + 0x28);
        data[entries_size_offset..entries_size_offset + 4].copy_from_slice(&(entries_size as u32).to_le_bytes());

        // Fill value length
        let value_length = data.len() - value_offset;
        data[value_offset..value_offset + 4].copy_from_slice(&(value_length as u32).to_le_bytes());

        // Fill attribute length
        let total_len = data.len();
        data[length_offset..length_offset + 4].copy_from_slice(&(total_len as u32).to_le_bytes());

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
        let needed_clusters = (total_records + records_per_cluster - 1) / records_per_cluster;
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
        // Note: root directory entries have parent_path "" or "C:"
        let mut child_map: std::collections::HashMap<String, Vec<(u64, &NtfsEntry)>> =
            std::collections::HashMap::new();
        for (i, entry) in self.entries.iter().enumerate() {
            let record_num = (i + 1) as u64;
            let last_bs = entry.path.rfind('\\');
            let parent_path = last_bs.map(|p| &entry.path[..p]).unwrap_or("");
            // Normalize parent_path: empty string or "C:" -> ""
            let normalized_parent = if parent_path.is_empty() || parent_path == "C:" {
                String::new()
            } else {
                String::from(parent_path)
            };
            child_map.entry(normalized_parent).or_default().push((record_num, entry));
        }

        // --- Build root directory entry (MFT record 5) ---
        // The root directory has no parent, so parent_ref = 0
        // Its children are all entries where parent_path is "" or "C:"
        let root_entry = NtfsEntry::new_dir("C:\\");
        let root_children = child_map.get("").map(|v| v.as_slice());
        let record_5 = self.build_mft_record(&root_entry, 5, Some(0u64), root_children);

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
            // Get children for this directory (for INDEX_ROOT)
            let children = child_map.get(&entry.path).map(|v| v.as_slice());
            let record = self.build_mft_record(entry, record_num, parent_ref, children);

            let record_offset = mft_cluster_byte_offset + record_num as usize * mft_record_size;
            if record_offset + mft_record_size <= image.len() {
                image[record_offset..record_offset + mft_record_size].copy_from_slice(&record);
            }
        }

        // Record 5: Root directory (always at record 5)
        // Root has no parent (parent_ref = 0), and its children are all entries
        // where the parent is root
        let root_entry = NtfsEntry::new_dir("C:\\");
        let root_children: Vec<(u64, &NtfsEntry)> = self.entries.iter()
            .filter_map(|e| {
                let last_bs = e.path.rfind('\\');
                let parent_path = last_bs.map(|p| &e.path[..p]).unwrap_or("");
                if parent_path.is_empty() || parent_path == "C:" || parent_path == "C" {
                    // This entry's parent is root
                    if let Some(&rn) = entry_record_map.get(&e.path) {
                        return Some((rn, e));
                    }
                }
                None
            })
            .collect();
        let root_record = self.build_mft_record(
            &root_entry,
            5,
            Some(0u64),
            if root_children.is_empty() { None } else { Some(&root_children) }
        );
        let root_record_offset = mft_cluster_byte_offset + 5 * mft_record_size;
        // Ensure we have enough space
        if root_record_offset + mft_record_size > image.len() {
            image.resize(root_record_offset + mft_record_size + 4096, 0);
        }
        image[root_record_offset..root_record_offset + mft_record_size]
            .copy_from_slice(&root_record);

        Ok(image)
    }

    /// Compute the parent MFT reference (sequence_number << 48 | record_number) for
    /// the FILE_NAME attribute of `entry`. Returns None for the root entry (which
    /// has no parent).
    fn compute_parent_ref(&self, entry: &NtfsEntry, _record_num: u64) -> Option<u64> {
        // entry.path is a full NTFS path with backslashes, e.g. "C:\Windows\System32"
        // Parent is the path without the last component.
        let last_bs = entry.path.rfind('\\');
        let parent_path = last_bs.map(|p| &entry.path[..p]).unwrap_or("");
        if parent_path.is_empty() || parent_path == "C:" {
            return Some(5u64 << 48); // Root directory = MFT record 5
        }

        // Look up the parent in self.entries to find its record number.
        // parent_path is like "C:\Windows\System32", we search for it.
        for (i, e) in self.entries.iter().enumerate() {
            if e.path == parent_path {
                // record_num = index + 1 (index 0 is $MFT)
                return Some(((i + 1) as u64) << 48 | 0u64);
            }
        }

        // Parent not found in entries — treat as root
        Some(5u64 << 48)
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
        if parent_path.is_empty() || parent_path == "C:" || parent_path == "C" {
            return Some(5u64 << 48); // Root directory = MFT record 5
        }

        // Look up parent in the map
        if let Some(&parent_record) = entry_map.get(parent_path) {
            return Some(parent_record << 48 | 0u64);
        }

        // Parent not found — treat as root
        Some(5u64 << 48)
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

        // 4. $DATA (resident only; large files are truncated to MAX_RESIDENT_DATA_SIZE)
        if !entry.is_dir && !entry.data.is_empty() {
            let truncated = if entry.data.len() > Self::MAX_RESIDENT_DATA_SIZE {
                &entry.data[..Self::MAX_RESIDENT_DATA_SIZE]
            } else {
                &entry.data
            };
            let data_attr = self.build_data_attr(truncated);
            record.extend_from_slice(&data_attr);
        }

        // 5. End marker
        record.extend_from_slice(&Self::build_end_marker());

        // --- Fill used_size ---
        let used_size = record.len() as u32;
        record[used_size_offset..used_size_offset + 4]
            .copy_from_slice(&used_size.to_le_bytes());

        // Pad to full record size
        record.resize(mft_record_size, 0);

        // Apply fixup: sector 0 byte 510, sector 1 byte 1022
        if record.len() > 510 {
            record[510] = 0x00;
            record[511] = 0x00;
        }
        if record.len() > 1022 {
            record[1022] = 0x00;
            record[1023] = 0x00;
        }

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

        // Attribute header (24 bytes)
        data.extend_from_slice(&ATTR_TYPE_FILE_NAME.to_le_bytes());
        let length_offset = data.len();
        data.extend_from_slice(&0u32.to_le_bytes()); // length (filled later)
        data.push(ATTR_FLAG_RESIDENT);
        data.push(0); // name_length in header = 0
        data.extend_from_slice(&0u16.to_le_bytes()); // name offset

        // Resident header (24 bytes) — value data starts at attr_offset + 24
        let value_offset = 24u16;
        let value_length = 66 + (name_len as u32) * 2; // 66 fixed + name
        data.extend_from_slice(&value_length.to_le_bytes());
        data.extend_from_slice(&value_offset.to_le_bytes());
        data.push(0); // flags
        data.push(0); // reserved

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
        data.extend_from_slice(&0u16.to_le_bytes());           // 0x3C: reserved (2)
        data.push(name_len);                                   // 0x3E: name_length (1)
        data.push(FILENAME_NAMESPACE_WIN32);                    // 0x3F: namespace (1)
        // Filename at 0x40 (2 bytes per char)
        for c in name_utf16 {
            data.extend_from_slice(&c.to_le_bytes());
        }

        // Fill attribute length
        let total_len = data.len();
        let le = (total_len as u32).to_le_bytes();
        data[length_offset..length_offset + 4].copy_from_slice(&le);
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
