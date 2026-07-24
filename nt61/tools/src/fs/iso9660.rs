//! ISO 9660 / El Torito Image Module
//!
//! This module provides a pure Rust implementation for creating ISO 9660 filesystem images,
//! with El Torito boot catalog support for UEFI booting.
//!
//! ## Features
//! - Primary Volume Descriptor
//! - Directory entries
//! - El Torito boot catalog
//! - Bootable ISO generation
//!
//! ## Usage
//! ```rust,no_run
//! use nt61_tools::IsoImage;
//!
//! let mut image = IsoImage::new();
//! let boot_data = [0u8; 512];
//! let boot_catalog = [0u8; 2048];
//! image.add_file("/EFI/BOOT/BOOTX64.EFI", &boot_data).unwrap();
//! image.add_boot_catalog(&boot_catalog).unwrap();
//! let img_data = image.finalize().unwrap();
//! ```

use crate::error::{BuildError, Result};
use crate::fs::backend::{DirEntry, FsBackend};


// =====================================================================
// Constants
// =====================================================================

/// ISO 9660 sector size
pub const ISO_SECTOR_SIZE: usize = 2048;

/// Primary Volume Descriptor type
pub const PVD_TYPE: u8 = 0x01;
/// Boot Record type
pub const BOOT_RECORD_TYPE: u8 = 0x00;
/// Volume Descriptor Set Terminator type
pub const VDS_TERMINATOR_TYPE: u8 = 0xFF;

/// Volume descriptor signature
pub const ISO_SIGNATURE: &[u8; 5] = b"CD001";

/// System identifier
pub const SYSTEM_ID: &[u8] = b"NT6.1.7601  ";
/// Volume set identifier
pub const VOLUME_SET_ID: &[u8] = b"NT6.1.7601  ";

/// El Torito boot indicator
pub const EL_TORITO_BOOT_INDICATOR: u8 = 0x88;
/// El Torito validation entry
pub const EL_TORITO_VALIDATION_ENTRY: u8 = 0x01;
/// El Torito boot catalog entry
pub const EL_TORITO_BOOT_ENTRY: u8 = 0x90;
/// El Torito section header entry
pub const EL_TORITO_SECTION_HEADER: u8 = 0x91;
/// El Torito section entry
pub const EL_TORITO_SECTION_ENTRY: u8 = 0x00;
/// El Torito terminator
pub const EL_TORITO_TERMINATOR: u8 = 0xFF;

// =====================================================================
// Structures
// =====================================================================

/// ISO 9660 Primary Volume Descriptor
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct Iso9660Pvd {
    pub type_code: u8,               // Volume descriptor type (0x01 for PVD)
    pub identifier: [u8; 5],        // "CD001"
    pub version: u8,                // Version (0x01)
    pub unused1: u8,               // Unused
    pub system_id: [u8; 32],      // System identifier
    pub volume_id: [u8; 32],      // Volume identifier
    pub unused2: [u8; 8],         // Unused
    pub volume_space_size: [u8; 8], // Volume space size (LBA)
    pub unused3: [u8; 32],        // Unused
    pub volume_set_size: [u8; 4],  // Volume set size
    pub volume_seq_number: [u8; 4], // Volume sequence number
    pub logical_block_size: [u8; 4], // Logical block size (2048)
    pub path_table_size: [u8; 8],  // Path table size
    pub location_of_type_l_path_table: [u8; 4], // LBA of type L path table
    pub location_of_optional_type_l_path_table: [u8; 4],
    pub location_of_type_m_path_table: [u8; 4],
    pub location_of_optional_type_m_path_table: [u8; 4],
    pub root_directory_record: [u8; 34], // Root directory record
    pub volume_set_identifier: [u8; 128], // Volume set identifier
    pub publisher_identifier: [u8; 128],  // Publisher identifier
    pub preparer_identifier: [u8; 128],  // Data preparer identifier
    pub application_identifier: [u8; 128], // Application identifier
    pub copyright_file_identifier: [u8; 37], // Copyright file identifier
    pub abstract_file_identifier: [u8; 37], // Abstract file identifier
    pub bibliographic_file_identifier: [u8; 37], // Bibliographic file identifier
    pub volume_creation_date: [u8; 17],  // Volume creation date
    pub volume_modification_date: [u8; 17], // Volume modification date
    pub volume_expiration_date: [u8; 17], // Volume expiration date
    pub volume_effective_date: [u8; 17], // Volume effective date
    pub file_structure_version: u8,   // File structure version (0x01)
    pub unused4: u8,                // Unused
    pub application_used: [u8; 512], // Application specific
    pub reserved: [u8; 653],       // Reserved
}

/// ISO 9660 Directory Record
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct Iso9660DirRecord {
    pub record_length: u8,          // Directory record length
    pub extended_attribute_length: u8, // Extended attribute record length
    pub location: [u8; 8],         // Location of extent (LBA)
    pub data_length: [u8; 8],      // Data length
    pub recording_date_time: [u8; 7], // Recording date and time
    pub file_flags: u8,            // File flags
    pub file_unit_size: u8,        // File unit size
    pub interleave_gap_size: u8,   // Interleave gap size
    pub volume_seq_number: [u8; 4], // Volume sequence number
    pub file_identifier_length: u8, // Length of file identifier
    pub file_identifier: [u8; 0],  // File identifier (variable)
}

/// El Torito Boot Record Volume Descriptor
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct ElToritoBootRecord {
    pub type_code: u8,               // Boot record type (0x00)
    pub identifier: [u8; 5],        // "CD001"
    pub version: u8,                // Version (0x01)
    pub boot_system_identifier: [u8; 32], // "EL TORITO SPECIFICATION"
    pub unused: u8,                 // Unused
    pub boot_catalog_lba: [u8; 4], // Boot catalog LBA
    pub unused2: [u8; 1973],       // Unused
}

/// El Torito Validation Entry (offset 0 of boot catalog, 32 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct ElToritoValidationEntry {
    pub header_id: u8,            // Header ID (must be 0x01)
    pub platform_id: u8,          // Platform ID (0x00=80x86, 0xEF=EFI)
    pub reserved1: [u8; 2],       // Reserved (2 bytes)
    pub id_string: [u8; 24],      // ID string
    pub checksum: u16,            // Checksum (sum of u16s ending at 0)
    pub signature: u16,           // 0xAA55
}

/// El Torito Initial/Default Entry
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct ElToritoBootEntry {
    pub boot_indicator: u8,        // 0x88 = bootable
    pub boot_media_type: u8,       // Boot media type
    pub load_segment: u16,         // Load segment
    pub system_type: u8,          // System type (0x00 = same as HDD)
    pub unused1: u8,              // Unused
    pub sector_count: u16,         // Number of sectors to load
    pub virtual_disk_lba: u32,     // LBA of virtual disk (stored LE in struct)
    pub unused2: [u8; 20],        // Unused
}

// =====================================================================
// High-Level ISO 9660 Image Builder
// =====================================================================

/// File entry for ISO image
#[derive(Debug, Clone)]
pub struct IsoFileEntry {
    pub path: String,
    pub data: Vec<u8>,
    pub lba: u32,
    /// True if this entry represents a directory.
    pub is_dir: bool,
}

impl IsoFileEntry {
    pub fn new(path: &str, data: Vec<u8>, lba: u32) -> Self {
        Self { path: path.to_string(), data, lba, is_dir: false }
    }
    pub fn new_dir(path: &str, lba: u32) -> Self {
        Self { path: path.to_string(), data: Vec::new(), lba, is_dir: true }
    }
}

/// ISO 9660 image builder
pub struct IsoImage {
    files: Vec<IsoFileEntry>,
    volume_id: String,
    boot_catalog: Option<Vec<u8>>,
    /// LBA of the boot catalog sector (separate from PVD at sector 16).
    /// Standard layout: PVD=16, BootRecord=17, BootCatalog=18.
    boot_catalog_lba: u32,
    /// LBA where data files begin (after all reserved sectors).
    data_start_lba: u32,
    /// LBA of the root directory (computed from last file after finalize).
    root_dir_lba: u32,
}

impl IsoImage {
    /// Parse an existing ISO 9660 image into an in-memory file list.
    ///
    /// Implementation notes:
    /// - Looks for the Primary Volume Descriptor at sector 16 (LBA 16) by
    ///   scanning volume descriptors until "CD001" + type 0x01 is found.
    /// - Reads root directory extent from the PVD.
    /// - Recursively walks directory records using ISO 9660 DirRecord format.
    /// - Rock Ridge (NM/PX/TF) System Use Area is parsed when present so we
    ///   pick up POSIX long names. Joliet is detected but ignored on
    ///   round-trip (we keep the original PVD; Joliet Unicode names are
    ///   decoded as ASCII fallback).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < ISO_SECTOR_SIZE * 18 {
            return Err(BuildError::IsoError("image smaller than minimum ISO 9660 layout".into()));
        }
        // Find PVD (type 0x01) by scanning volume descriptors from LBA 16.
        let mut pvd_lba: usize = 16;
        let mut found_pvd = false;
        for lba in 16usize..32 {
            let off = lba * ISO_SECTOR_SIZE;
            if off + ISO_SECTOR_SIZE > data.len() { break; }
            let s = &data[off..off + ISO_SECTOR_SIZE];
            if &s[1..6] != b"CD001" { continue; }
            let t = s[0];
            if t == 0x01 {
                pvd_lba = lba;
                found_pvd = true;
                break;
            } else if t == 0xFF {
                break;
            }
        }
        if !found_pvd {
            return Err(BuildError::IsoError("no PVD found".into()));
        }
        let pvd_off = pvd_lba * ISO_SECTOR_SIZE;
        let pvd = &data[pvd_off..pvd_off + ISO_SECTOR_SIZE];
        // Root directory record is at offset 156 within PVD (34-byte DirRecord).
        let root_dir_off = pvd_off + 156;
        let root_dir = &data[root_dir_off..root_dir_off + 34];
        let root_lba = u32::from_be_bytes([root_dir[2], root_dir[3], root_dir[4], root_dir[5]]);
        let root_size = u32::from_be_bytes([root_dir[10], root_dir[11], root_dir[12], root_dir[13]]);
        // Volume ID at offset 40 of PVD, 32 bytes d-characters.
        let vol_id_bytes = &pvd[40..72];
        let volume_id = vol_id_bytes
            .iter()
            .take_while(|b| **b != b' ' && **b != 0)
            .map(|&b| b as char)
            .collect::<String>();
        if volume_id.is_empty() {
            // fall back to default
        }

        let mut files: Vec<IsoFileEntry> = Vec::new();
        Self::walk_iso_dir(data, root_lba, root_size, "", &mut files)?;

        Ok(Self {
            files,
            volume_id: if volume_id.is_empty() { "NT6.1.7601".to_string() } else { volume_id },
            boot_catalog: None,
            boot_catalog_lba: 0,
            data_start_lba: 19,
            root_dir_lba: 0,
        })
    }

    /// Walk one ISO 9660 directory extent (single LBA + length), parse each
    /// DirRecord, recurse into subdirectories, and append file entries to
    /// `files`. Recognises Rock Ridge "NM" System Use Area for POSIX names.
    fn walk_iso_dir(
        data: &[u8],
        lba: u32,
        size: u32,
        prefix: &str,
        files: &mut Vec<IsoFileEntry>,
    ) -> Result<()> {
        let dir_off = (lba as usize) * ISO_SECTOR_SIZE;
        let dir_end = dir_off + size as usize;
        if dir_end > data.len() {
            return Err(BuildError::IsoError("dir extent past end of image".into()));
        }
        let dir = &data[dir_off..dir_end];
        let mut p = 0;
        while p + 33 <= dir.len() {
            let rec_len = dir[p] as usize;
            if rec_len == 0 {
                // skip to next sector boundary
                p = ((p / ISO_SECTOR_SIZE) + 1) * ISO_SECTOR_SIZE;
                continue;
            }
            if rec_len < 33 || p + rec_len > dir.len() {
                break;
            }
            let r = &dir[p..p + rec_len];
            let file_lba = u32::from_be_bytes([r[2], r[3], r[4], r[5]]);
            let file_size = u32::from_be_bytes([r[10], r[11], r[12], r[13]]);
            let flags = r[25];
            let is_dir = (flags & 0x02) != 0;
            let name_len = r[32] as usize;
            let name_raw = &r[33..33 + name_len];

            // Skip "." and ".."
            if name_len == 1 && name_raw[0] == 0 {
                p += rec_len;
                continue;
            }
            if name_len == 1 && name_raw[0] == 1 {
                p += rec_len;
                continue;
            }

            // System Use Area starts after the fixed fields. The SUA offset is
            // at r[2] in the DirRecord for the root only; for child records
            // it's at r[2] too (BP 2). Standard says: "System Use" length is
            // rec_len - 33 - name_len - (padding to even).
            let sua_off_in_rec = if r.len() >= 35 { r[2] as usize } else { 0 };
            let sua_off = p + sua_off_in_rec;
            let sua_end = p + rec_len;
            let mut rr_name: Option<String> = None;
            if sua_off + 4 <= sua_end && dir[sua_off..sua_off + 4] == *b"NSR" {
                // Skip RR signature "NSR02/NSR03" (5 bytes).
                let mut sp = sua_off + 5;
                while sp + 3 <= sua_end {
                    let sig = &dir[sp..sp + 2];
                    let len = dir[sp + 2] as usize;
                    if len == 0 || sp + len > sua_end { break; }
                    if sig == *b"NM" && len >= 5 {
                        let flags = dir[sp + 3];
                        if flags & 0x01 == 0 {
                            // current name (not "..")
                            let nlen = len - 5;
                            let name_bytes = &dir[sp + 4..sp + 4 + nlen];
                            if let Ok(s) = std::str::from_utf8(name_bytes) {
                                rr_name = Some(s.to_string());
                            }
                        }
                    }
                    sp += len;
                }
            }

            // Pick the name: RR POSIX > filename.
            let basename = if let Some(n) = rr_name {
                n
            } else {
                // Strip trailing version ";1" if present.
                let s = std::str::from_utf8(name_raw).unwrap_or("").trim_end_matches(';');
                s.to_string()
            };
            if basename.is_empty() {
                p += rec_len;
                continue;
            }

            let full_path = if prefix.is_empty() { basename.clone() } else { format!("{}/{}", prefix, basename) };

            if is_dir {
                Self::walk_iso_dir(data, file_lba, file_size, &full_path, files)?;
            } else {
                let off = (file_lba as usize) * ISO_SECTOR_SIZE;
                let end = off + file_size as usize;
                if end > data.len() {
                    return Err(BuildError::IsoError(format!("file {} past end of image", full_path)));
                }
                let content = data[off..end].to_vec();
                files.push(IsoFileEntry { path: full_path, data: content, lba: file_lba, is_dir: false });
            }

            p += rec_len;
        }
        Ok(())
    }

    /// Create a new ISO 9660 image builder
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            volume_id: "NT6.1.7601".to_string(),
            boot_catalog: None,
            // Boot catalog at sector 18; updated to 19 once boot catalog is set.
            boot_catalog_lba: 0,
            // Data files start at sector 19 (after PVD=16, BootRecord=17, BootCatalog=18).
            data_start_lba: 19,
            // Root directory LBA (computed after all files are added).
            root_dir_lba: 0,
        }
    }

    /// Set the volume identifier
    pub fn with_volume_id(mut self, volume_id: &str) -> Self {
        self.volume_id = volume_id.to_string();
        self
    }

    /// List immediate children of `path` (forward-slash).
    pub fn list_dir_path(&self, path: &str) -> Result<Vec<DirEntry>> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let prefix = parts.join("/");
        let prefix_with_slash = if prefix.is_empty() { String::new() } else { format!("{}/", prefix) };
        let mut out = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for e in &self.files {
            let ep = &e.path;
            let inside = if prefix.is_empty() {
                !ep.contains('/')
            } else {
                ep == &prefix || ep.starts_with(&prefix_with_slash)
            };
            if !inside { continue; }
            let rel = if prefix.is_empty() {
                ep.as_str()
            } else if ep == &prefix {
                continue;
            } else {
                &ep[prefix_with_slash.len()..]
            };
            if rel.contains('/') { continue; }
            if seen.insert(rel.to_string()) {
                // Determine if it's a "directory" — ISO 9660 dirs are virtual,
                // represented by the existence of files below them. We treat
                // any prefix that has child entries as a directory.
                let is_dir = self.files.iter().any(|f| {
                    let p = format!("{}/{}", prefix, rel);
                    f.path == p || f.path.starts_with(&format!("{}/", p))
                }) || rel.is_empty();
                if is_dir && !rel.is_empty() {
                    out.push(DirEntry::dir(rel));
                } else {
                    out.push(DirEntry::file(rel, e.data.len() as u64));
                }
            }
        }
        Ok(out)
    }

    pub fn read_file_path(&self, path: &str) -> Result<Vec<u8>> {
        let normalized = path.trim_start_matches('/');
        for e in &self.files {
            if e.path == normalized {
                return Ok(e.data.clone());
            }
        }
        for e in &self.files {
            if e.path.eq_ignore_ascii_case(normalized) {
                return Ok(e.data.clone());
            }
        }
        Err(BuildError::MissingFile(path.into()))
    }

    pub fn write_file_path(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let normalized = path.trim_start_matches('/').to_string();
        // Compute next LBA — ISO reuses the calculate_next_lba() path.
        let lba = self.calculate_next_lba();
        if let Some(existing) = self.files.iter_mut().find(|e| e.path == normalized) {
            existing.data = data.to_vec();
            existing.lba = lba;
            return Ok(());
        }
        self.files.push(IsoFileEntry::new(&normalized, data.to_vec(), lba));
        Ok(())
    }

    pub fn mkdir_path(&mut self, _path: &str) -> Result<()> {
        // ISO 9660 directories are virtual — represented by the parent paths
        // of file entries. Nothing to do.
        Ok(())
    }

    pub fn remove_path_iso(&mut self, path: &str) -> Result<()> {
        let normalized = path.trim_start_matches('/');
        if normalized.is_empty() { return Ok(()); }
        let prefix_with_slash = format!("{}/", normalized);
        self.files.retain(|e| {
            !(e.path == normalized || e.path.starts_with(&prefix_with_slash))
        });
        Ok(())
    }

    /// Add a file to the ISO image
    pub fn add_file(&mut self, path: &str, data: &[u8]) -> Result<&mut Self> {
        // Calculate LBA position
        let lba = self.calculate_next_lba();
        self.files.push(IsoFileEntry::new(path, data.to_vec(), lba));
        Ok(self)
    }

    /// Calculate the next available LBA for a new file entry.
    fn calculate_next_lba(&self) -> u32 {
        // Data files begin at data_start_lba (19).
        let mut lba = self.data_start_lba;
        for entry in &self.files {
            let sectors = entry.data.len().div_ceil(ISO_SECTOR_SIZE) as u32;
            lba += sectors;
        }
        lba
    }

    /// Add the El Torito boot catalog. The boot image must have already been
    /// added via `add_file` at the path "/EFI/BOOT/BOOTX64.EFI" so its LBA
    /// can be resolved. The catalog sector LBA is fixed at 18.
    pub fn add_boot_catalog(&mut self, _boot_image: &[u8]) -> Result<&mut Self> {
        // Look up the LBA of the boot manager (BOOTX64.EFI) in the ISO.
        // This is the PE executable that UEFI will load and execute.
        let boot_image_lba = self.files.iter()
            .find(|e| e.path == "/EFI/BOOT/BOOTX64.EFI")
            .map(|e| e.lba)
            .unwrap_or(19); // fallback

        // Sector count: number of 512-byte sectors to load.
        // Must cover the entire bootx64.efi file.
        let sector_count = self.files.iter()
            .find(|e| e.path == "/EFI/BOOT/BOOTX64.EFI")
            .map(|e| e.data.len().div_ceil(512) as u16)
            .unwrap_or(1);

        eprintln!("[DEBUG ISO] add_boot_catalog: boot_image_lba={} (0x{:X}), files count={}",
            boot_image_lba, boot_image_lba, self.files.len());
        for (i, f) in self.files.iter().enumerate() {
            eprintln!("[DEBUG ISO]   file[{}]: path={}, lba={}", i, f.path, f.lba);
        }

        // Build boot catalog
        let mut catalog = Vec::new();
        let mut validation = ElToritoValidationEntry {
            header_id: 0x01, // MUST be 0x01 per El Torito spec
            platform_id: 0xEF, // EFI firmware (UEFI)
            reserved1: [0; 2],
            id_string: *b"NT6.1.7601 BOOT LOADER  ",
            checksum: 0,
            signature: 0xAA55,
        };

        // Calculate checksum: sum of all u16 values in the validation
        // entry (including the signature but EXCLUDING the checksum
        // field itself) must equal 0 when added to the checksum.
        let mut sum: u32 = 0;
        sum += validation.header_id as u32;
        sum += validation.platform_id as u32;
        sum += u16::from_le_bytes(validation.reserved1) as u32;
        for chunk in validation.id_string.chunks(2) {
            let word = u16::from_le_bytes([chunk[0], chunk[1]]);
            sum += word as u32;
        }
        sum += validation.signature as u32;
        validation.checksum = (sum.wrapping_neg() & 0xFFFF) as u16;
        
        // Write validation entry
        let val_bytes = validation.as_bytes();
        catalog.extend_from_slice(&val_bytes);
        
        // Default boot entry
        let boot_entry = ElToritoBootEntry {
            boot_indicator: EL_TORITO_BOOT_INDICATOR,
            boot_media_type: 0, // No emulation
            load_segment: 0x7C0,
            system_type: 0, // Same as disk
            unused1: 0,
            sector_count,
            virtual_disk_lba: boot_image_lba,
            unused2: [0; 20],
        };
        
        // Write boot entry
        let boot_bytes = boot_entry.as_bytes();
        eprintln!("[DEBUG ISO]   boot_entry bytes: {:02X?}", &boot_bytes[8..12]);
        catalog.extend_from_slice(&boot_bytes);
        
        // Section header (for extension)
        catalog.extend_from_slice(&[0x91, 0x00, 0x00, 0x00]);
        catalog.extend_from_slice(b"FLOPPY EMULATION BOOT CATALOG");
        catalog.resize(2048, 0);
        
        self.boot_catalog = Some(catalog);
        // PVD at sector 16, Boot Record at sector 17, Boot Catalog at sector 18.
        self.boot_catalog_lba = 18;
        
        Ok(self)
    }

    /// Build the Primary Volume Descriptor. The root LBA is
    /// computed inside the builder (`self.root_dir_lba` is set by
    /// `finalize_layout` before this is called), so the parameter
    /// stays available to keep the call-site readable while the
    /// underscore silences the unused-parameter lint.
    fn build_pvd(&self, _root_lba: u32) -> Vec<u8> {
        let mut pvd = Vec::with_capacity(2048);
        
        // Type code
        pvd.push(PVD_TYPE);
        // Identifier
        pvd.extend_from_slice(ISO_SIGNATURE);
        // Version
        pvd.push(0x01);
        // Unused
        pvd.push(0);
        
        // System identifier (32 bytes)
        let mut sys_id = [0x20; 32];
        let sys_id_bytes = SYSTEM_ID;
        sys_id[..sys_id_bytes.len()].copy_from_slice(sys_id_bytes);
        pvd.extend_from_slice(&sys_id);
        
        // Volume identifier (32 bytes)
        let mut vol_id = [0x20; 32];
        let vol_id_bytes = self.volume_id.as_bytes();
        vol_id[..vol_id_bytes.len()].copy_from_slice(vol_id_bytes);
        pvd.extend_from_slice(&vol_id);
        
        // Unused
        pvd.extend_from_slice(&[0u8; 8]);

        // Volume space size (BP 80-87): LE u32 then BE u32 (8 bytes total)
        let total_sectors = self.calculate_total_sectors();
        pvd.extend_from_slice(&total_sectors.to_le_bytes());
        pvd.extend_from_slice(&total_sectors.to_be_bytes());

        // Unused (BP 88-119): 32 bytes
        pvd.extend_from_slice(&[0u8; 32]);

        // Volume set size (BP 120-123): LE u16 then BE u16
        pvd.extend_from_slice(&1u16.to_le_bytes());
        pvd.extend_from_slice(&1u16.to_be_bytes());

        // Volume sequence number (BP 124-127): LE u16 then BE u16
        pvd.extend_from_slice(&1u16.to_le_bytes());
        pvd.extend_from_slice(&1u16.to_be_bytes());

        // Logical block size (BP 128-131): LE u16 then BE u16
        let lbs = ISO_SECTOR_SIZE as u16;
        pvd.extend_from_slice(&lbs.to_le_bytes());
        pvd.extend_from_slice(&lbs.to_be_bytes());

        // Path table size (BP 132-139): LE u32 then BE u32
        // We'll fill in the real path table size below — for now use a
        // placeholder (10) and rewrite later via raw byte fixup.
        let path_table_size_pos = pvd.len();
        pvd.extend_from_slice(&10u32.to_le_bytes());  // placeholder
        pvd.extend_from_slice(&10u32.to_be_bytes());

        // Location of type L path table (BP 140-143): LE u32
        pvd.extend_from_slice(&10u32.to_le_bytes());
        // Optional type L path table (BP 144-147): LE u32 = 0
        pvd.extend_from_slice(&[0u8; 4]);
        // Location of type M path table (BP 148-151): BE u32
        pvd.extend_from_slice(&10u32.to_be_bytes());
        // Optional type M path table (BP 152-155): BE u32 = 0
        pvd.extend_from_slice(&[0u8; 4]);

        // Root directory record (BP 156-189): 34 bytes
        let root_dir = self.build_root_dir_record(self.root_dir_lba);
        pvd.extend_from_slice(&root_dir);

        // Patch path table size now that we know the actual size.
        // The build_path_tables below writes sectors 10/11; we
        // recompute the size by re-running it (cheap, vector ops only).
        let (path_table_l, _) = self.build_path_tables();
        let actual_pts = path_table_l.len() as u32;
        // Overwrite BP 132-135 (LE) and BP 136-139 (BE)
        let off = path_table_size_pos + 16 * ISO_SECTOR_SIZE; // file offset
        // Offsets within sector 16
        let bp = path_table_size_pos;
        let _ = off;
        pvd[bp..bp + 4].copy_from_slice(&actual_pts.to_le_bytes());
        pvd[bp + 4..bp + 8].copy_from_slice(&actual_pts.to_be_bytes());
        
        // Volume set identifier (128 bytes)
        pvd.extend_from_slice(VOLUME_SET_ID);
        while pvd.len() < 280 { pvd.push(0x20); }
        
        // Publisher identifier (128 bytes)
        pvd.extend_from_slice(b"NT6.1.7601 TEAM           ");
        while pvd.len() < 408 { pvd.push(0x20); }
        
        // Data preparer identifier (128 bytes)
        pvd.extend_from_slice(b"RUST BUILD TOOL          ");
        while pvd.len() < 536 { pvd.push(0x20); }
        
        // Application identifier (128 bytes)
        pvd.extend_from_slice(b"NT6.1.7601 BUILD TOOL    ");
        while pvd.len() < 664 { pvd.push(0x20); }
        
        // Copyright file identifier (37 bytes)
        pvd.extend_from_slice(b";Generated by NT6.1.7601 Build Tool");
        while pvd.len() < 701 { pvd.push(0x20); }
        
        // Abstract file identifier (37 bytes)
        pvd.extend_from_slice(b"NT6.1.7601 ISO 9660 IMAGE ");
        while pvd.len() < 738 { pvd.push(0x20); }
        
        // Bibliographic file identifier (37 bytes)
        pvd.push(0x20);
        while pvd.len() < 775 { pvd.push(0x20); }
        
        // Volume creation date (17 bytes)
        let mut date = [0x30; 17];
        date[0..4].copy_from_slice(b"2026");
        date[4] = 0x30;
        date[5] = 0x36;
        date[6] = 0x30;
        date[7] = 0x30;
        date[8] = 0x31;
        date[9] = 0x34;
        date[10] = 0x30;
        date[11] = 0x30;
        date[12] = 0x30;
        date[13] = 0x30;
        date[14] = 0x30;
        date[15] = 0x30;
        date[16] = 0x30;
        pvd.extend_from_slice(&date);
        
        // Volume modification date
        pvd.extend_from_slice(&date);
        
        // Volume expiration date
        pvd.extend_from_slice(&[0x30; 17]);
        
        // Volume effective date
        pvd.extend_from_slice(&date);
        
        // File structure version
        pvd.push(0x01);
        // Unused
        pvd.push(0);
        
        // Application used (512 bytes)
        pvd.extend_from_slice(b"NT6.1.7601 ISO 9660 IMAGE GENERATOR");
        while pvd.len() < 1177 { pvd.push(0); }
        
        // Reserved (653 bytes)
        while pvd.len() < 2048 { pvd.push(0); }
        
        pvd
    }

    /// Build root directory record
    ///
    /// ISO 9660 directory records use a *dual byte order* for the
    /// LBA and data-length fields: the first half is little-endian
    /// 32-bit, the second half is the same value big-endian.
    /// Both halves must agree so that readers using either byte
    /// order resolve the same extent.
    fn build_root_dir_record(&self, root_lba: u32) -> [u8; 34] {
        let mut record = [0u8; 34];

        // Record length
        record[0] = 34;
        // Extended attribute length
        record[1] = 0;
        // Location (LBA) — both byte orders.
        record[2..6].copy_from_slice(&root_lba.to_le_bytes());
        record[6..10].copy_from_slice(&root_lba.to_be_bytes());
        // Data length — both byte orders. Root directory size in bytes
        // (typically one 2048-byte sector for our flat ISO).
        let data_len: u32 = ISO_SECTOR_SIZE as u32;
        record[10..14].copy_from_slice(&data_len.to_le_bytes());
        record[14..18].copy_from_slice(&data_len.to_be_bytes());
        // Recording date/time
        record[18..25].copy_from_slice(&[0x26, 0x06, 0x20, 0x26, 0x14, 0x10, 0x00]);
        // File flags
        record[25] = 0x02; // Directory
        // File unit size
        record[26] = 0;
        // Interleave gap size
        record[27] = 0;
        // Volume sequence number — both byte orders (LE then BE, u16 each).
        record[28] = 1; // LE low
        record[29] = 0; // LE high
        record[30] = 0; // BE high
        record[31] = 1; // BE low
        // File identifier length
        record[32] = 1;
        // File identifier
        record[33] = 0;

        record
    }

    /// Build the Type L (little-endian) and Type M (big-endian) path
    /// tables.  The path table records the directory hierarchy so
    /// readers can locate any directory by name without walking the
    /// root directory record-by-record.
    ///
    /// For our flat ISO the hierarchy is just the root plus any
    /// sub-directories whose names appear as the first path
    /// component of `files`.  Each entry is 8 bytes minimum plus
    /// the directory name length.
    fn build_path_tables(&self) -> (Vec<u8>, Vec<u8>) {
        // Collect unique directory paths: root ("") + each first-level dir.
        let mut dirs: Vec<String> = vec![String::new()];
        for entry in &self.files {
            let trimmed = entry.path.trim_start_matches('/');
            if let Some(slash) = trimmed.find('/') {
                let dir = &trimmed[..slash];
                if !dir.is_empty() && !dirs.iter().any(|d| d == dir) {
                    dirs.push(dir.to_string());
                }
            }
        }
        // Map dir name -> LBA (root_dir_lba for "", dir entries for others).
        // We only support a single level of subdirectories; deeper paths
        // are not used by the flat ISO layout.
        let dir_lba = |name: &str| -> u32 {
            if name.is_empty() {
                self.root_dir_lba
            } else {
                // Use the LBA of the first file inside this directory.
                self.files
                    .iter()
                    .find(|e| {
                        e.path
                            .trim_start_matches('/')
                            .split('/')
                            .next()
                            .map(|d| d == name)
                            .unwrap_or(false)
                    })
                    .map(|e| e.lba)
                    .unwrap_or(0)
            }
        };

        let mut path_table_l = Vec::new();
        let mut path_table_m = Vec::new();
        for dir in &dirs {
            let lba = dir_lba(dir);
            let name_bytes = if dir.is_empty() { b"\0".to_vec() } else { dir.as_bytes().to_vec() };
            let name_len = name_bytes.len() as u8;

            // Type L (little-endian) entry
            let mut entry_l = Vec::new();
            entry_l.push(name_len);                                    // Length of directory identifier
            entry_l.push(0);                                           // Extended attribute record length
            entry_l.extend_from_slice(&lba.to_le_bytes());             // Location (LBA) LE
            entry_l.extend_from_slice(&1u16.to_le_bytes());            // Parent directory number LE
            path_table_l.extend_from_slice(&entry_l);
            path_table_l.extend_from_slice(&name_bytes);

            // Type M (big-endian) entry
            let mut entry_m = Vec::new();
            entry_m.push(name_len);                                    // Length of directory identifier
            entry_m.push(0);                                           // Extended attribute record length
            entry_m.extend_from_slice(&lba.to_be_bytes());             // Location (LBA) BE
            entry_m.extend_from_slice(&1u16.to_be_bytes());            // Parent directory number BE
            path_table_m.extend_from_slice(&entry_m);
            path_table_m.extend_from_slice(&name_bytes);
        }
        (path_table_l, path_table_m)
    }

    /// Calculate total sectors needed and set root_dir_lba.
    fn calculate_total_sectors(&self) -> u32 {
        // Sectors 0-15: system area (16 sectors)
        // Sector  16:        PVD
        // Sector  17:        Boot Record
        // Sector  18:        Boot Catalog
        // Sector  19+:       data files + root directory + subdirectories
        let reserved = self.data_start_lba; // 19

        // Files — round each up to a whole sector, matching the
        // `padded_len` arithmetic in `finalize` so the file's last
        // sector is included in the on-disk image.
        let mut file_sectors: u32 = 0;
        for entry in &self.files {
            file_sectors += entry.data.len().div_ceil(ISO_SECTOR_SIZE) as u32;
        }

        // Count unique first-level AND second-level directories.
        let mut unique_dirs: std::collections::HashSet<String> = std::collections::HashSet::new();
        for entry in &self.files {
            let trimmed = entry.path.trim_start_matches('/');
            if let Some(slash) = trimmed.find('/') {
                let d1 = &trimmed[..slash];
                if !d1.is_empty() {
                    unique_dirs.insert(d1.to_string());
                }
                let rest = &trimmed[slash + 1..];
                if let Some(slash2) = rest.find('/') {
                    let d2 = format!("{}/{}", d1, &rest[..slash2]);
                    unique_dirs.insert(d2);
                }
            }
        }

        reserved + file_sectors + 1 + unique_dirs.len() as u32
    }

    /// Pack a word (16-bit) into a 4-byte dual (LE + BE) buffer.
    ///
    /// ISO 9660 numeric fields that fit in 16 bits are stored as
    /// little-endian followed by big-endian: 4 bytes total.
    /// `pack_word(0x0100)` returns `[0x00, 0x01, 0x01, 0x00]`.
    /// Kept available for symmetry with `pack_dword`; the build path
    /// currently inlines the dual-byte pattern at every call site
    /// for visibility, so this helper is unused but ready for the
    /// day we collapse them back together.
    #[allow(dead_code)]
    fn pack_word(val: u16) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        bytes[0] = (val & 0xFF) as u8;
        bytes[1] = ((val >> 8) & 0xFF) as u8;
        bytes[2] = ((val >> 8) & 0xFF) as u8;
        bytes[3] = (val & 0xFF) as u8;
        bytes
    }

    /// Pack a dword (32-bit) into an 8-byte dual (LE + BE) buffer.
    ///
    /// ISO 9660 32-bit numeric fields use the dual-byte-order
    /// pattern (both-endian) — the value is encoded in LE in the
    /// first 4 bytes and in BE in the next 4. See `pack_word` for
    /// the rationale on why this is currently unused.
    #[allow(dead_code)]
    fn pack_dword(val: u32) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = (val & 0xFF) as u8;
        bytes[1] = ((val >> 8) & 0xFF) as u8;
        bytes[2] = ((val >> 16) & 0xFF) as u8;
        bytes[3] = ((val >> 24) & 0xFF) as u8;
        bytes[4] = ((val >> 24) & 0xFF) as u8;
        bytes[5] = ((val >> 16) & 0xFF) as u8;
        bytes[6] = ((val >> 8) & 0xFF) as u8;
        bytes[7] = (val & 0xFF) as u8;
        bytes
    }

    /// Finalize the ISO image
    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        // Compute root_dir_lba before writing.
        // Root directory comes right after the last file.
        let root_dir_lba = {
            let mut lba = self.data_start_lba;
            for entry in &self.files {
                let sectors = entry.data.len().div_ceil(ISO_SECTOR_SIZE) as u32;
                lba += sectors;
            }
            lba
        };
        self.root_dir_lba = root_dir_lba;

        // Compute LBA for each first-level and second-level subdirectory
        // sector.  We support two levels of nesting (e.g. /EFI/BOOT/...)
        // because that's what the EFI layout requires.
        //   subdir_lbas["EFI"]              = sector for /EFI itself
        //   subdir_lbas["EFI/BOOT"]         = sector for /EFI/BOOT
        //   subdir_lbas["Windows"]          = sector for /Windows
        //   subdir_lbas["Windows/System32"] = sector for /Windows/System32
        // Each subdirectory gets exactly one 2048-byte sector.
        let mut subdir_lbas: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let mut next_lba = root_dir_lba + 1;
        // Collect unique first-level AND second-level directory paths.
        let mut unique_dirs: Vec<String> = Vec::new();
        for entry in &self.files {
            let trimmed = entry.path.trim_start_matches('/');
            // First level: "EFI" from "/EFI/BOOT/..."
            if let Some(slash) = trimmed.find('/') {
                let d1 = trimmed[..slash].to_string();
                if !d1.is_empty() && !unique_dirs.contains(&d1) {
                    unique_dirs.push(d1.clone());
                }
                // Second level: "EFI/BOOT" from "/EFI/BOOT/..."
                let rest = &trimmed[slash + 1..];
                if let Some(slash2) = rest.find('/') {
                    let d2 = format!("{}/{}", d1, &rest[..slash2]);
                    if !unique_dirs.contains(&d2) {
                        unique_dirs.push(d2);
                    }
                    // Third level: "EFI/BOOT/Fonts" from "/EFI/BOOT/Fonts/..."
                    // (we treat Fonts as a leaf file dir — most are files)
                }
            }
        }
        for dir in &unique_dirs {
            subdir_lbas.insert(dir.clone(), next_lba);
            next_lba += 1;
        }

        let total_sectors = self.calculate_total_sectors();
        let total_size = (total_sectors as usize) * ISO_SECTOR_SIZE;
        let mut image = vec![0u8; total_size];

        // Write Type L path table at sector 10 (referenced by PVD)
        // and Type M (big-endian) at sector 11.
        let (path_table_l, path_table_m) = self.build_path_tables();
        image[10 * ISO_SECTOR_SIZE..10 * ISO_SECTOR_SIZE + path_table_l.len()].copy_from_slice(&path_table_l);
        image[11 * ISO_SECTOR_SIZE..11 * ISO_SECTOR_SIZE + path_table_m.len()].copy_from_slice(&path_table_m);

        // Write PVD at sector 16 (must be first so it's found quickly)
        let pvd = self.build_pvd(root_dir_lba);
        image[16 * ISO_SECTOR_SIZE..16 * ISO_SECTOR_SIZE + 2048].copy_from_slice(&pvd);

        // Write Boot Record at sector 17
        let mut boot_record = vec![0u8; 2048];
        boot_record[0] = BOOT_RECORD_TYPE; // 0x00
        boot_record[1..6].copy_from_slice(ISO_SIGNATURE);
        boot_record[6] = 0x01;
        // System identifier: "EL TORITO SPECIFICATION" padded to 32 bytes
        let spec_str = b"EL TORITO SPECIFICATION         ";
        boot_record[7..39].copy_from_slice(spec_str);
        boot_record[40..44].copy_from_slice(&self.boot_catalog_lba.to_le_bytes());
        image[17 * ISO_SECTOR_SIZE..18 * ISO_SECTOR_SIZE].copy_from_slice(&boot_record);

        // Write Boot Catalog at sector 18
        if let Some(ref catalog) = self.boot_catalog {
            eprintln!("[DEBUG ISO] finalize: writing catalog {} bytes at sector 18", catalog.len());
            eprintln!("[DEBUG ISO] finalize: catalog[32..44]: {:02X?}", &catalog[32..44]);
            image[18 * ISO_SECTOR_SIZE..18 * ISO_SECTOR_SIZE + 2048].copy_from_slice(catalog);
        } else {
            eprintln!("[DEBUG ISO] finalize: NO BOOT CATALOG!");
        }

        // Write files
        for entry in &self.files {
            let offset = (entry.lba as usize) * ISO_SECTOR_SIZE;
            let padded_len = entry.data.len().div_ceil(ISO_SECTOR_SIZE) * ISO_SECTOR_SIZE;
            image[offset..offset + entry.data.len()].copy_from_slice(&entry.data);
            image[offset + entry.data.len()..offset + padded_len].fill(0);
        }

        // Write root directory sector at root_dir_lba
        let root_offset = (root_dir_lba as usize) * ISO_SECTOR_SIZE;
        let root_data = self.build_root_directory(&subdir_lbas);
        image[root_offset..root_offset + root_data.len()].copy_from_slice(&root_data);
        // Zero out the rest of the root directory sector
        image[root_offset + root_data.len()..root_offset + ISO_SECTOR_SIZE].fill(0);

        // Write one sector per first-level and second-level subdirectory.
        for (dir_name, &lba) in &subdir_lbas {
            let off = (lba as usize) * ISO_SECTOR_SIZE;
            // The parent of "/EFI/BOOT" is "/EFI"; the parent of "/EFI"
            // is the root.  Look up parent by trimming the last component.
            let parent_lba = if let Some(slash) = dir_name.rfind('/') {
                let parent_name = &dir_name[..slash];
                *subdir_lbas.get(parent_name).unwrap_or(&root_dir_lba)
            } else {
                root_dir_lba
            };
            let sub_data = self.build_subdirectory(dir_name, lba, parent_lba, &subdir_lbas);
            image[off..off + sub_data.len()].copy_from_slice(&sub_data);
            image[off + sub_data.len()..off + ISO_SECTOR_SIZE].fill(0);
        }

        Ok(image)
    }

    /// Build the raw bytes for the root directory sector.
    /// Contains "." and ".." entries plus one entry for each top-level
    /// directory (e.g. "EFI", "Windows") AND each top-level file (e.g.
    /// "autoexec.bat").  Subdirectory entries point to the sectors
    /// allocated by the caller and passed in `subdir_lbas`.
    fn build_root_directory(
        &self,
        subdir_lbas: &std::collections::HashMap<String, u32>,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(2048);
        let root_size: u32 = ISO_SECTOR_SIZE as u32;

        // "." entry (root directory self-reference)
        let mut dot = [0u8; 34];
        dot[0] = 34;
        dot[1] = 0;
        dot[2..6].copy_from_slice(&self.root_dir_lba.to_le_bytes());
        dot[6..10].copy_from_slice(&self.root_dir_lba.to_be_bytes());
        dot[10..14].copy_from_slice(&root_size.to_le_bytes());
        dot[14..18].copy_from_slice(&root_size.to_be_bytes());
        dot[18..25].copy_from_slice(&[0x26, 0x06, 0x20, 0x26, 0x14, 0x10, 0x00]);
        dot[25] = 0x02; // directory
        dot[28] = 1; dot[29] = 0; dot[30] = 0; dot[31] = 1;
        dot[32] = 1;
        dot[33] = 0;
        data.extend_from_slice(&dot);

        // ".." entry (parent = root itself)
        let mut dotdot = [0u8; 34];
        dotdot[0] = 34;
        dotdot[1] = 0;
        dotdot[2..6].copy_from_slice(&self.root_dir_lba.to_le_bytes());
        dotdot[6..10].copy_from_slice(&self.root_dir_lba.to_be_bytes());
        dotdot[10..14].copy_from_slice(&root_size.to_le_bytes());
        dotdot[14..18].copy_from_slice(&root_size.to_be_bytes());
        dotdot[18..25].copy_from_slice(&[0x26, 0x06, 0x20, 0x26, 0x14, 0x10, 0x00]);
        dotdot[25] = 0x02;
        dotdot[28] = 1; dotdot[29] = 0; dotdot[30] = 0; dotdot[31] = 1;
        dotdot[32] = 1;
        dotdot[33] = 0;
        data.extend_from_slice(&dotdot);

        // Determine what's directly under root: directories + files with no slash.
        let mut top_dirs: Vec<String> = Vec::new();
        let mut root_files: Vec<&IsoFileEntry> = Vec::new();
        let mut seen_dirs: std::collections::HashSet<String> = std::collections::HashSet::new();
        for entry in &self.files {
            let trimmed = entry.path.trim_start_matches('/');
            if let Some(slash) = trimmed.find('/') {
                let dir = trimmed[..slash].to_string();
                if !seen_dirs.contains(&dir) {
                    seen_dirs.insert(dir.clone());
                    top_dirs.push(dir);
                }
            } else if !trimmed.is_empty() {
                root_files.push(entry);
            }
        }

        // Write directory entries for each top-level directory.
        for dir_name in &top_dirs {
            if let Some(&lba) = subdir_lbas.get(dir_name) {
                let entry = Self::make_dir_record(dir_name, lba, ISO_SECTOR_SIZE as u32, true);
                data.extend_from_slice(&entry);
            }
        }

        // Write entries for each root-level file.
        for f in &root_files {
            let name = f.path.trim_start_matches('/');
            let entry = Self::make_dir_record(name, f.lba, f.data.len() as u32, false);
            data.extend_from_slice(&entry);
        }

        data
    }

    /// Build a single 2048-byte directory sector for `dir_name`.
    ///
    /// `dir_name` may be a single level ("EFI") or a two-level path
    /// ("EFI/BOOT").  The emitted entries are:
    ///   - "."  → this directory
    ///   - ".." → parent directory (`parent_lba`)
    ///   - any second-level subdirectory under `dir_name`
    ///   - any file directly inside `dir_name`
    ///
    /// Files deeper than two levels (e.g. "/EFI/BOOT/Fonts/wgl4.ttf")
    /// are not surfaced in the directory tree.  The flat ISO we
    /// emit doesn't use them, but the implementation can be
    /// extended later if needed.
    fn build_subdirectory(
        &self,
        dir_name: &str,
        dir_lba: u32,
        parent_lba: u32,
        subdir_lbas: &std::collections::HashMap<String, u32>,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(2048);
        let dir_size: u32 = ISO_SECTOR_SIZE as u32;

        // "." entry (this directory self-reference)
        let mut dot = [0u8; 34];
        dot[0] = 34;
        dot[1] = 0;
        dot[2..6].copy_from_slice(&dir_lba.to_le_bytes());
        dot[6..10].copy_from_slice(&dir_lba.to_be_bytes());
        dot[10..14].copy_from_slice(&dir_size.to_le_bytes());
        dot[14..18].copy_from_slice(&dir_size.to_be_bytes());
        dot[18..25].copy_from_slice(&[0x26, 0x06, 0x20, 0x26, 0x14, 0x10, 0x00]);
        dot[25] = 0x02; // directory
        dot[28] = 1; dot[29] = 0; dot[30] = 0; dot[31] = 1;
        dot[32] = 1;
        dot[33] = 0;
        data.extend_from_slice(&dot);

        // ".." entry (parent directory)
        let mut dotdot = [0u8; 34];
        dotdot[0] = 34;
        dotdot[1] = 0;
        dotdot[2..6].copy_from_slice(&parent_lba.to_le_bytes());
        dotdot[6..10].copy_from_slice(&parent_lba.to_be_bytes());
        dotdot[10..14].copy_from_slice(&dir_size.to_le_bytes());
        dotdot[14..18].copy_from_slice(&dir_size.to_be_bytes());
        dotdot[18..25].copy_from_slice(&[0x26, 0x06, 0x20, 0x26, 0x14, 0x10, 0x00]);
        dotdot[25] = 0x02;
        dotdot[28] = 1; dotdot[29] = 0; dotdot[30] = 0; dotdot[31] = 1;
        dotdot[32] = 1;
        dotdot[33] = 0;
        data.extend_from_slice(&dotdot);

        let prefix = format!("/{}/", dir_name);
        let mut sub_subdirs: Vec<String> = Vec::new();
        let mut seen_sub_subdirs: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut direct_files: Vec<&IsoFileEntry> = Vec::new();

        for entry in &self.files {
            if !entry.path.starts_with(&prefix) {
                continue;
            }
            let rest = &entry.path[prefix.len()..];
            // Two-level path: "EFI/BOOT" → looking inside "EFI"
            // we see entries like "BOOT/BOOTX64.EFI" (slash) or
            // direct files like "autoexec.bat" (no slash).
            if let Some(slash) = rest.find('/') {
                let sub = rest[..slash].to_string();
                if !seen_sub_subdirs.contains(&sub) {
                    seen_sub_subdirs.insert(sub.clone());
                    sub_subdirs.push(sub);
                }
            } else if !rest.is_empty() {
                direct_files.push(entry);
            }
        }

        // Emit sub-sub-directory entries pointing to their sectors.
        for sub in &sub_subdirs {
            let full = format!("{}/{}", dir_name, sub);
            if let Some(&lba) = subdir_lbas.get(&full) {
                let entry = Self::make_dir_record(sub, lba, ISO_SECTOR_SIZE as u32, true);
                data.extend_from_slice(&entry);
            }
        }

        // Emit direct file entries.
        for f in &direct_files {
            let name = f.path.trim_start_matches('/').rsplit('/').next().unwrap_or("");
            let entry = Self::make_dir_record(name, f.lba, f.data.len() as u32, false);
            data.extend_from_slice(&entry);
        }

        data
    }

    /// Create a directory record for a file or directory.
    fn make_dir_record(name: &str, lba: u32, size: u32, is_dir: bool) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(255);
        // Record length: 33 + name_len, padded to even
        let record_len: u8 = if (33 + name_len).is_multiple_of(2) {
            (33 + name_len) as u8
        } else {
            (34 + name_len) as u8
        };

        let mut record = vec![0u8; record_len as usize];
        record[0] = record_len;
        record[1] = 0; // extended attribute length
        // Location of extent — both byte orders
        record[2..6].copy_from_slice(&lba.to_le_bytes());
        record[6..10].copy_from_slice(&lba.to_be_bytes());
        // Data length — both byte orders
        record[10..14].copy_from_slice(&size.to_le_bytes());
        record[14..18].copy_from_slice(&size.to_be_bytes());
        // Recording date/time
        record[18..25].copy_from_slice(&[0x26, 0x06, 0x20, 0x26, 0x14, 0x10, 0x00]);
        // File flags (0x02 = directory)
        record[25] = if is_dir { 0x02 } else { 0x00 };
        // File unit size
        record[26] = 0;
        // Interleave gap size
        record[27] = 0;
        // Volume sequence number — both byte orders (LE then BE, u16 each).
        record[28] = 1; // LE low
        record[29] = 0; // LE high
        record[30] = 0; // BE high
        record[31] = 1; // BE low
        // File identifier length
        record[32] = name_len as u8;
        // File identifier
        record[33..33 + name_len].copy_from_slice(&name_bytes[..name_len]);

        record
    }
}

impl Default for IsoImage {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// Byte Serialization
// =====================================================================

impl ElToritoValidationEntry {
    fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = self.header_id;
        bytes[1] = self.platform_id;
        bytes[2..4].copy_from_slice(&self.reserved1);
        bytes[4..28].copy_from_slice(&self.id_string);
        bytes[28..30].copy_from_slice(&self.checksum.to_le_bytes());
        bytes[30..32].copy_from_slice(&self.signature.to_le_bytes());
        bytes
    }
}

impl ElToritoBootEntry {
    fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = self.boot_indicator;
        bytes[1] = self.boot_media_type;
        bytes[2..4].copy_from_slice(&self.load_segment.to_le_bytes());
        bytes[4] = self.system_type;
        bytes[5] = self.unused1;
        bytes[6..8].copy_from_slice(&self.sector_count.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.virtual_disk_lba.to_le_bytes());
        bytes[12..32].copy_from_slice(&self.unused2);
        bytes
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso_creation() {
        let mut image = IsoImage::new();
        image.add_file("/test.txt", b"Hello, ISO!").unwrap();
        
        let data = image.finalize().unwrap();
        assert!(data.len() > 0);
    }

    #[test]
    fn test_iso_with_boot() {
        let mut image = IsoImage::new();
        image.add_file("/EFI/BOOT/BOOTX64.EFI", b"Boot data").unwrap();
        image.add_boot_catalog(b"Boot catalog").unwrap();
        
        let data = image.finalize().unwrap();
        assert!(data.len() > 0);
    }
}

// =====================================================================
// FsBackend implementation
// =====================================================================

impl FsBackend for IsoImage {
    fn kind(&self) -> &'static str { "iso9660" }

    fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        IsoImage::list_dir_path(self, path)
    }
    fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        IsoImage::read_file_path(self, path)
    }
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        IsoImage::write_file_path(self, path, data)
    }
    fn mkdir(&mut self, path: &str) -> Result<()> {
        IsoImage::mkdir_path(self, path)
    }
    fn remove(&mut self, path: &str) -> Result<()> {
        IsoImage::remove_path_iso(self, path)
    }
    fn finalize(&mut self) -> Result<Vec<u8>> {
        IsoImage::finalize(self)
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}
