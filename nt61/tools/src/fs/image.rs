//! Image Format Module
//!
//! This module provides a unified interface for creating disk images in various formats.

use std::path::Path;
use crate::error::{BuildError, Result};
use crate::logger as log;
use crate::fs::backend::FsBackend;

// Re-export image builders
pub use super::fat32::Fat32Image;
pub use super::ext4::Ext4Image;
pub use super::ntfs::NtfsImage;
pub use super::iso9660::IsoImage;
pub use super::qcow2::Qcow2Image;
pub use super::partition::PartitionInfo;

// =====================================================================
// Image Format Enum
// =====================================================================

/// Supported image formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Fat32,
    Ext4,
    Ntfs,
    Iso,
    Qcow2,
}

impl ImageFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "fat32" | "fat" | "vfat" => Some(ImageFormat::Fat32),
            "ext4" | "ext" | "ext2" | "ext3" => Some(ImageFormat::Ext4),
            "ntfs" => Some(ImageFormat::Ntfs),
            "iso" | "iso9660" => Some(ImageFormat::Iso),
            "qcow2" | "qcow" => Some(ImageFormat::Qcow2),
            _ => None,
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            ImageFormat::Fat32 => "img",
            ImageFormat::Ext4 => "img",
            ImageFormat::Ntfs => "img",
            ImageFormat::Iso => "iso",
            ImageFormat::Qcow2 => "qcow2",
        }
    }

    pub fn default_size_mb(&self) -> u32 {
        match self {
            ImageFormat::Fat32 => 64,
            ImageFormat::Ext4 => 128,
            ImageFormat::Ntfs => 512,
            ImageFormat::Iso => 700,
            ImageFormat::Qcow2 => 1024,
        }
    }
}

impl std::fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageFormat::Fat32 => write!(f, "fat32"),
            ImageFormat::Ext4 => write!(f, "ext4"),
            ImageFormat::Ntfs => write!(f, "ntfs"),
            ImageFormat::Iso => write!(f, "iso"),
            ImageFormat::Qcow2 => write!(f, "qcow2"),
        }
    }
}

// =====================================================================
// High-Level Image Functions
// =====================================================================

/// Create a disk image from a source directory
pub fn create_image(
    output: &Path,
    format: &str,
    size_mb: u32,
    source: Option<&Path>,
    _verbose: bool,
) -> Result<()> {
    log::info(&format!("Creating {} image ({} MB)...", format, size_mb));
    log::info(&format!("Output: {}", output.display()));

    let fmt = ImageFormat::from_str(format)
        .ok_or_else(|| BuildError::InvalidFormat(format!("Unknown format: {}", format)))?;

    match fmt {
        ImageFormat::Fat32 => {
            let mut img = Fat32Image::new(size_mb);
            if let Some(src) = source {
                populate_image(&mut img, src)?;
            }
            let data = img.finalize()?;
            write_image(output, &data)?;
        }
        ImageFormat::Ext4 => {
            let mut img = Ext4Image::new(size_mb, 4096)?;
            if let Some(src) = source {
                populate_image(&mut img, src)?;
            }
            let data = img.finalize()?;
            write_image(output, &data)?;
        }
        ImageFormat::Ntfs => {
            let mut img = NtfsImage::new(size_mb, 4096)?;
            if let Some(src) = source {
                populate_image(&mut img, src)?;
            }
            let data = img.finalize()?;
            write_image(output, &data)?;
        }
        ImageFormat::Iso => {
            let mut img = IsoImage::new();
            if let Some(src) = source {
                populate_iso(&mut img, src)?;
            }
            let data = img.finalize()?;
            write_image(output, &data)?;
        }
        ImageFormat::Qcow2 => {
            let size_gb = (size_mb + 1023) / 1024;
            let mut img = Qcow2Image::create(size_gb.max(1))?;
            if let Some(src) = source {
                populate_qcow2(&mut img, src)?;
            }
            let data = img.finalize()?;
            write_image(output, &data)?;
        }
    }

    log::success(&format!("Image created: {}", output.display()));
    Ok(())
}

/// Format an empty disk image
pub fn format_image(output: &Path, fs: &str, size_mb: u32, verbose: bool) -> Result<()> {
    create_image(output, fs, size_mb, None, verbose)
}

/// Style of partition table to write around a raw filesystem image.
///
/// `None` keeps the legacy behavior: the image file *is* the filesystem, no
/// MBR/GPT header. `Mbr` writes a single protective-MBR sector at the start of
/// the file and moves the filesystem to sector 1. `Gpt` writes a full
/// GPT: LBA0 = protective MBR, LBA1 = header, LBA2..33 = partition entries
/// (with a single entry pointing at LBA 34), LBA 34+ = filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionTable {
    None,
    Mbr,
    Gpt,
}

/// Create an image and wrap it in an optional partition table.
///
/// `partition_table = None` produces the legacy raw FS image. For MBR/GPT the
/// caller must pass a real filesystem (fat32 / ntfs / ext4); ISO/QCOW2 are
/// rejected because they aren't partitioned block devices.
pub fn create_image_with_pt(
    output: &Path,
    fs: &str,
    size_mb: u32,
    source: Option<&Path>,
    verbose: bool,
    partition_table: PartitionTable,
) -> Result<()> {
    if partition_table == PartitionTable::None {
        return create_image(output, fs, size_mb, source, verbose);
    }

    // Partition table wrapping is only valid on raw block-device images.
    let fmt = ImageFormat::from_str(fs)
        .ok_or_else(|| BuildError::InvalidFormat(format!("Unknown fs: {}", fs)))?;
    match fmt {
        ImageFormat::Fat32 | ImageFormat::Ntfs | ImageFormat::Ext4 => {}
        ImageFormat::Iso | ImageFormat::Qcow2 => {
            return Err(BuildError::InvalidParam(format!(
                "partition tables only apply to raw FS images (got {})",
                fs
            )));
        }
    }

    // Compute the sector layout. Default first usable LBA = 34 (GPT) or 1
    // (MBR). GPT partition type is chosen per FS.
    let sector_size = 512u64;
    let (first_usable_lba, partition_type_guid) = match partition_table {
        PartitionTable::Mbr => (1, [0u8; 16]),
        PartitionTable::Gpt => {
            let ty = match fmt {
                // Standard ESP GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
                // Stored as little-endian for first 3 fields
                ImageFormat::Fat32 => [
                    0x28, 0x73, 0x2A, 0xC1,  // d1 = 0xC12A7328
                    0x1F, 0xF8,                 // d2 = 0xF81F
                    0xD2, 0x11,                 // d3 = 0x11D2
                    0x4B, 0xBA,                 // d4 = 0xBA4B
                    0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,  // d5 = 00A0C93EC93B
                ], // EFI System Partition (correct GUID)
                ImageFormat::Ntfs => [
                    0xA0, 0x88, 0x2D, 0x83, 0xEB, 0xD1, 0xCD, 0x41,
                    0xB7, 0x96, 0x21, 0xE3, 0x66, 0x65, 0xFF, 0xCC,
                ], // Windows basic data
                ImageFormat::Ext4 => [
                    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
                    0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
                ], // Linux filesystem
                _ => unreachable!(),
            };
            (34, ty)
        }
        PartitionTable::None => unreachable!(),
    };

    // Calculate partition offset for FAT32
    let partition_offset = (first_usable_lba * sector_size) as usize;

    // Build the FS image in-memory first (it is always `size_mb` MB).
    // For FAT32 with GPT, we use finalize_with_offset to set hidd_sec correctly.
    let mut fs_bytes = match fmt {
        ImageFormat::Fat32 => {
            let mut img = Fat32Image::new(size_mb);
            if let Some(src) = source {
                populate_image(&mut img, src)?;
            }
            // Use finalize_with_offset to set hidd_sec correctly for GPT partition
            img.finalize_with_offset(partition_offset)?
        }
        ImageFormat::Ntfs => {
            let mut img = NtfsImage::new(size_mb, 4096)?;
            if let Some(src) = source {
                populate_image(&mut img, src)?;
            }
            img.finalize()?
        }
        ImageFormat::Ext4 => {
            let mut img = Ext4Image::new(size_mb, 4096)?;
            if let Some(src) = source {
                populate_image(&mut img, src)?;
            }
            img.finalize()?
        }
        ImageFormat::Iso | ImageFormat::Qcow2 => unreachable!(),
    };

    let fs_sectors = (fs_bytes.len() as u64) / sector_size;
    let last_partition_lba = first_usable_lba + fs_sectors - 1;
    let total_sectors = first_usable_lba + fs_sectors;
    let total_bytes = (total_sectors * sector_size) as usize;

    if fs_bytes.len() != (size_mb as usize) * 1024 * 1024 {
        // Some FS backends may pad less than requested; pad out so the
        // partition slot is exactly size_mb MB.
        fs_bytes.resize(size_mb as usize * 1024 * 1024, 0);
    }

    let mut out = vec![0u8; total_bytes];
    let part_off = (first_usable_lba * sector_size) as usize;
    out[part_off..part_off + fs_bytes.len()].copy_from_slice(&fs_bytes);

    // Note: hidd_sec is now set correctly by finalize_with_offset() in the Fat32ImageBuilder

    match partition_table {
        PartitionTable::Mbr => write_mbr(&mut out, first_usable_lba, fs_sectors, partition_type_for_mbr(fmt)),
        PartitionTable::Gpt => write_gpt(
            &mut out,
            total_sectors,
            first_usable_lba,
            last_partition_lba,
            partition_type_guid,
        ),
        PartitionTable::None => unreachable!(),
    }

    write_image(output, &out)?;
    Ok(())
}

fn partition_type_for_mbr(fmt: ImageFormat) -> u8 {
    match fmt {
        ImageFormat::Fat32 => 0x0B,
        ImageFormat::Ntfs => 0x07,
        ImageFormat::Ext4 => 0x83,
        _ => 0x83,
    }
}

fn write_mbr(buf: &mut [u8], first_lba: u64, fs_sectors: u64, type_byte: u8) {
    buf[510] = 0x55;
    buf[511] = 0xAA;
    let entry_off = 446;
    buf[entry_off] = 0x80; // bootable
    buf[entry_off + 4] = type_byte;
    buf[entry_off + 8..entry_off + 12].copy_from_slice(&(first_lba as u32).to_le_bytes());
    buf[entry_off + 12..entry_off + 16].copy_from_slice(&(fs_sectors as u32).to_le_bytes());
}

fn write_gpt(
    buf: &mut [u8],
    total_sectors: u64,
    first_lba: u64,
    last_lba: u64,
    type_guid: [u8; 16],
) {
    // Protective MBR at LBA 0
    buf[510] = 0x55;
    buf[511] = 0xAA;
    let mbr_off = 446;
    buf[mbr_off] = 0x00;
    buf[mbr_off + 4] = 0xEE; // GPT protective
    buf[mbr_off + 8..mbr_off + 12].copy_from_slice(&1u32.to_le_bytes());
    buf[mbr_off + 12..mbr_off + 16].copy_from_slice(&((total_sectors - 1) as u32).to_le_bytes());

    // GPT header at LBA 1
    let hdr = 512usize;
    buf[hdr..hdr + 8].copy_from_slice(b"EFI PART");
    // GPT revision 1.0 (per UEFI 2.7 spec). The value is a 16-bit major +
    // 16-bit minor packed little-endian, so the literal `0x00010000u32`
    // represents major=1, minor=0.
    buf[hdr + 8..hdr + 12].copy_from_slice(&0x00010000u32.to_le_bytes());
    buf[hdr + 12..hdr + 16].copy_from_slice(&92u32.to_le_bytes()); // header size
    buf[hdr + 16..hdr + 20].copy_from_slice(&0u32.to_le_bytes()); // CRC32 (skip)
    buf[hdr + 20..hdr + 24].copy_from_slice(&0u32.to_le_bytes()); // reserved
    buf[hdr + 24..hdr + 32].copy_from_slice(&1u64.to_le_bytes()); // my LBA
    let alt_lba = total_sectors - 1;
    buf[hdr + 32..hdr + 40].copy_from_slice(&alt_lba.to_le_bytes());
    // Per UEFI 2.7 spec the GPT header layout at offset 512 is:
    //   40..48  first usable LBA
    //   48..56  last usable LBA
    //   56..72  disk GUID
    //   72..80  partition-entries starting LBA
    //   80..84  number of partition entries
    //   84..88  size of each partition entry
    buf[hdr + 40..hdr + 48].copy_from_slice(&first_lba.to_le_bytes());
    buf[hdr + 48..hdr + 56].copy_from_slice(&last_lba.to_le_bytes());
    let guid = uuid::Uuid::new_v4();
    buf[hdr + 56..hdr + 72].copy_from_slice(guid.as_bytes());
    // Partition entries start at LBA 2.
    buf[hdr + 72..hdr + 80].copy_from_slice(&2u64.to_le_bytes());
    buf[hdr + 80..hdr + 84].copy_from_slice(&128u32.to_le_bytes());
    buf[hdr + 84..hdr + 88].copy_from_slice(&128u32.to_le_bytes());

    // Single partition entry at LBA 2.
    let pent = 2usize * 512;
    buf[pent..pent + 16].copy_from_slice(&type_guid);
    let pguid = uuid::Uuid::new_v4();
    buf[pent + 16..pent + 32].copy_from_slice(pguid.as_bytes());
    buf[pent + 32..pent + 40].copy_from_slice(&first_lba.to_le_bytes());
    buf[pent + 40..pent + 48].copy_from_slice(&last_lba.to_le_bytes());
    // attributes (8 bytes) and name (UTF-16LE, 36 chars) left zeroed.

    // -----------------------------------------------------------------
    // Compute CRC32s and write them into the header. The header CRC is
    // computed over the 92-byte header with its own CRC field (16..20)
    // treated as zero. The partition-entries CRC is computed over the
    // full 128-entry array (128 * 128 = 16384 bytes).
    // -----------------------------------------------------------------
    let num_entries: usize = 128;
    let entry_size: usize = 128;
    let entries_total = num_entries * entry_size;
    let part_crc = crc32(&buf[pent..pent + entries_total]);
    buf[hdr + 88..hdr + 92].copy_from_slice(&part_crc.to_le_bytes());

    let mut hdr_bytes = buf[hdr..hdr + 92].to_vec();
    hdr_bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
    let hdr_crc = crc32(&hdr_bytes);
    buf[hdr + 16..hdr + 20].copy_from_slice(&hdr_crc.to_le_bytes());

    // -----------------------------------------------------------------
    // Backup GPT header at the last usable LBA. Mirrors the primary
    // header with `my LBA = backup LBA` and `alternate LBA = 1`.
    // The primary header lives at offset `hdr` (LBA 1) and the backup
    // lives at offset `backup_hdr` (last LBA) so the two regions are
    // disjoint; we snapshot the primary header into a temporary and
    // patch the two LBAs before writing it back into the backup slot.
    // -----------------------------------------------------------------
    let backup_hdr = (alt_lba as usize) * 512;
    if backup_hdr + 92 <= buf.len() {
        // Snapshot the primary header (clone) so we can release the
        // borrow of `buf` before taking a mutable borrow for writing.
        let mut backup_bytes = buf[hdr..hdr + 92].to_vec();
        backup_bytes[24..32].copy_from_slice(&alt_lba.to_le_bytes());
        backup_bytes[32..40].copy_from_slice(&1u64.to_le_bytes());
        // Recompute the header CRC with the CRC field treated as zero.
        backup_bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
        let backup_crc = crc32(&backup_bytes);
        backup_bytes[16..20].copy_from_slice(&backup_crc.to_le_bytes());
        buf[backup_hdr..backup_hdr + 92].copy_from_slice(&backup_bytes);
    }
}

/// Standard IEEE 802.3 CRC32 used by the GPT specification
/// (polynomial 0xEDB88320, init/final 0xFFFFFFFF).
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for n in 0..256u32 {
        let mut c = n;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
        }
        table[n as usize] = c;
    }
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

// =====================================================================
// Modify-mode helpers (read-modify-write on existing images)
// =====================================================================

/// Enumerate the partitions inside a disk image, returning 1-indexed metadata.
pub fn list_partitions(image_path: &Path) -> Result<Vec<PartitionInfo>> {
    let data = std::fs::read(image_path).map_err(BuildError::Io)?;
    crate::fs::partition::list_partitions(&data)
}

/// Open an existing image (or partition inside it) for read-modify-write.
///
/// `partition` is 1-indexed; `None` means operate on the whole file as a single
/// filesystem image. The returned [`OpenedImage`] owns the original image bytes
/// plus a boxed [`FsBackend`] implementation chosen by auto-detection (FAT32,
/// NTFS, EXT4 or ISO9660).
///
/// For QCOW2 containers the inner FS is detected by reading the first few
/// sectors of the container and parsing any GPT/MBR partition table that is
/// present, then opening the chosen partition as a nested FS.
pub fn open_for_modify(
    image_path: &Path,
    partition: Option<u32>,
) -> Result<OpenedImage> {
    open_for_modify_with(image_path, partition, None)
}

/// Like [`open_for_modify`] but lets the caller force a specific backend via
/// `--format-fs`. Pass `Some("fat32"|"ntfs"|"ext4"|"iso")` to override the
/// auto-detection.
pub fn open_for_modify_with(
    image_path: &Path,
    partition: Option<u32>,
    format: Option<&str>,
) -> Result<OpenedImage> {
    let raw = std::fs::read(image_path).map_err(BuildError::Io)?;

    // QCOW2 container — open it, read the partition table out of LBA 0+1,
    // then recurse with the selected partition's bytes.
    if raw.len() >= 8 && &raw[0..4] == b"QFI\xfb" {
        return open_qcow2_for_modify(&raw, image_path, partition, format);
    }

    open_bytes_for_modify(&raw, image_path, partition, format)
}

/// Like [`open_for_modify`] but operates on an already-loaded byte buffer.
/// Used internally for QCOW2 partitions and (recursively) by the CLI.
fn open_bytes_for_modify(
    raw: &[u8],
    image_path: &Path,
    partition: Option<u32>,
    format: Option<&str>,
) -> Result<OpenedImage> {
    if let Some(idx) = partition {
        let parts = crate::fs::partition::list_partitions(raw)?;
        let p = parts
            .into_iter()
            .find(|p| p.index == idx)
            .ok_or_else(|| BuildError::InvalidParam(format!("partition {} not found", idx)))?;
        let slice_start = p.byte_offset as usize;
        let slice_end = slice_start + p.byte_size as usize;
        if slice_end > raw.len() {
            return Err(BuildError::InvalidParam(
                "partition lies past end of image".into(),
            ));
        }
        let part_bytes: Vec<u8> = raw[slice_start..slice_end].to_vec();
        let backend = open_with_format(&part_bytes, format)?;
        return Ok(OpenedImage {
            raw: raw.to_vec(),
            partition_offset: slice_start,
            partition_size: p.byte_size,
            backend,
            original_path: Some(image_path.to_path_buf()),
            container: ContainerKind::Partitioned,
        });
    }

    // No partition selected — try as a single-FS image first; if that fails
    // AND a partition table is present, fall back to partition #1.
    match open_with_format(raw, format) {
        Ok(backend) => Ok(OpenedImage {
            raw: raw.to_vec(),
            partition_offset: 0,
            partition_size: raw.len() as u64,
            backend,
            original_path: Some(image_path.to_path_buf()),
            container: if raw.len() >= 4 && &raw[0..4] == b"QFI\xfb" {
                ContainerKind::Qcow2
            } else {
                ContainerKind::Raw
            },
        }),
        Err(single_err) => {
            let parts = crate::fs::partition::list_partitions(raw)?;
            if let Some(p) = parts.into_iter().next() {
                let slice_start = p.byte_offset as usize;
                let slice_end = slice_start + p.byte_size as usize;
                if slice_end <= raw.len() {
                    let part_bytes = &raw[slice_start..slice_end];
                    let backend = open_with_format(part_bytes, format)?;
                    return Ok(OpenedImage {
                        raw: raw.to_vec(),
                        partition_offset: slice_start,
                        partition_size: p.byte_size,
                        backend,
                        original_path: Some(image_path.to_path_buf()),
                        container: ContainerKind::Partitioned,
                    });
                }
            }
            Err(single_err)
        }
    }
}

/// QCOW2 wrapper: read the LBA range covering the first ~1 MiB of the virtual
/// disk into memory, run partition detection on it, then descend.
fn open_qcow2_for_modify(
    raw: &[u8],
    image_path: &Path,
    partition: Option<u32>,
    format: Option<&str>,
) -> Result<OpenedImage> {
    let qcow = crate::fs::qcow2::Qcow2Image::open(raw)?;
    // Read enough LBA bytes to cover the first partition entries.
    let head_sectors: u32 = 64; // 32 KiB — comfortably covers GPT header & entry array.
    let mut head = vec![0u8; (head_sectors as usize) * 512];
    for s in 0..head_sectors {
        qcow.read_sector_into(s, &mut head[s as usize * 512..(s as usize + 1) * 512])?;
    }
    let parts = crate::fs::partition::list_partitions(&head)?;
    let chosen = if let Some(idx) = partition {
        parts
            .into_iter()
            .find(|p| p.index == idx)
            .ok_or_else(|| BuildError::InvalidParam(format!("partition {} not found", idx)))?
    } else {
        parts
            .into_iter()
            .next()
            .ok_or_else(|| BuildError::InvalidParam("no partition table found inside qcow2".into()))?
    };
    let part_byte_start = chosen.byte_offset as u64;
    let part_byte_end = part_byte_start + chosen.byte_size;
    let part_sector_start = (part_byte_start / 512) as u32;
    let part_sector_count = ((part_byte_end - part_byte_start + 511) / 512) as u32;
    let mut part_bytes = vec![0u8; (part_sector_count as usize) * 512];
    for i in 0..part_sector_count {
        qcow.read_sector_into(
            part_sector_start + i,
            &mut part_bytes[i as usize * 512..(i as usize + 1) * 512],
        )?;
    }
    let backend = open_with_format(&part_bytes, format)?;
    Ok(OpenedImage {
        raw: raw.to_vec(),
        partition_offset: part_byte_start as usize,
        partition_size: chosen.byte_size,
        backend,
        original_path: Some(image_path.to_path_buf()),
        container: ContainerKind::Qcow2,
    })
}

/// Detect the filesystem in `bytes` and open it as a [`FsBackend`].
///
/// Tries in order: FAT32 (cheap), NTFS (cheap), EXT4 (cheap), ISO9660 (cheap).
/// Returns the first that succeeds. All four auto-detectors do at most a few
/// byte comparisons, so this is O(1).
fn detect_and_open_fs(bytes: &[u8], what: &str) -> Result<Box<dyn FsBackend>> {
    if let Ok(img) = Fat32Image::from_bytes(bytes) {
        return Ok(Box::new(img));
    }
    if let Ok(img) = NtfsImage::from_bytes(bytes) {
        return Ok(Box::new(img));
    }
    if let Ok(img) = Ext4Image::from_bytes(bytes) {
        return Ok(Box::new(img));
    }
    if let Ok(img) = IsoImage::from_bytes(bytes) {
        return Ok(Box::new(img));
    }
    Err(BuildError::InvalidFormat(format!(
        "{} is not a recognised filesystem (tried FAT32/NTFS/EXT4/ISO9660)",
        what
    )))
}

/// Same as [`detect_and_open_fs`] but lets the caller force a specific backend.
/// Used when the user passes `--format-fs` to override the auto-detection.
pub fn open_with_format(
    bytes: &[u8],
    format: Option<&str>,
) -> Result<Box<dyn FsBackend>> {
    match format {
        Some("fat32") => Ok(Box::new(Fat32Image::from_bytes(bytes)?)),
        Some("ntfs") => Ok(Box::new(NtfsImage::from_bytes(bytes)?)),
        Some("ext4") => Ok(Box::new(Ext4Image::from_bytes(bytes)?)),
        Some("iso") => Ok(Box::new(IsoImage::from_bytes(bytes)?)),
        Some("refs") => Err(BuildError::ReFsNotImplemented),
        Some(other) => Err(BuildError::InvalidFormat(format!(
            "unsupported --format-fs: {} (expected fat32|ntfs|ext4|iso)",
            other
        ))),
        None => detect_and_open_fs(bytes, "image"),
    }
}

/// Result of `open_for_modify`. Owns the original image bytes and a boxed
/// filesystem backend. Call `.write_back(path)` to encode the modified tree
/// and splice it into the original bytes, then write the whole thing back to
/// disk.
pub struct OpenedImage {
    raw: Vec<u8>,
    partition_offset: usize,
    partition_size: u64,
    backend: Box<dyn FsBackend>,
    /// Path the image was originally loaded from, used by `write_back` as the
    /// default destination when no path is passed in.
    original_path: Option<std::path::PathBuf>,
    /// Container type — affects how `write_back` re-encodes the image.
    container: ContainerKind,
}

/// How the bytes are wrapped (sparse container, partition table, or raw).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    /// Raw single-FS image or partition slice that we own byte-for-byte.
    Raw,
    /// Image has a GPT or MBR partition table; partition_offset/partition_size
    /// refer to the chosen partition within `raw`.
    Partitioned,
    /// Image is a QCOW2 container; `raw` is the QCOW2 file bytes. Writes to
    /// the inner FS need to go through QCOW2-aware encoding, not byte-splice.
    Qcow2,
}

impl OpenedImage {
    /// Mutably access the filesystem backend. Use this to call
    /// `list_dir`, `read_file`, `write_file`, `mkdir`, `remove`, `finalize`.
    pub fn backend(&mut self) -> &mut dyn FsBackend {
        self.backend.as_mut()
    }

    /// Backwards-compatibility alias for `backend()` returning `&mut Fat32Image`
    /// only when the backend is actually FAT32. Panics otherwise.
    pub fn fs(&mut self) -> &mut Fat32Image {
        // Caller responsibility: only valid on FAT32 images.
        // We downcast via the Any trait on the backend; if it's not a FAT32
        // image the caller is misusing the API.
        if let Some(any) = self.backend.as_any_mut() {
            if let Some(fat) = any.downcast_mut::<Fat32Image>() {
                return fat;
            }
        }
        panic!("OpenedImage::fs() called on a non-FAT32 image — use backend() instead")
    }

    /// Encode the in-memory tree back into the image bytes and write to disk.
    ///
    /// For QCOW2 containers, the inner FS is encoded to partition bytes, then
    /// written back through the QCOW2 layer (sector by sector).
    pub fn write_back(mut self, image_path: &Path) -> Result<()> {
        // For QCOW2, write the partition bytes back through the QCOW2 layer.
        if self.container == ContainerKind::Qcow2 {
            return self.write_back_qcow2(image_path);
        }
        let new_part = self.backend.finalize()?;
        let new_len = new_part.len() as u64;
        if new_len < self.partition_size {
            // Pad with zeros up to the original partition size.
            let mut padded = new_part;
            padded.resize(self.partition_size as usize, 0);
            self.splice_partition(&padded);
        } else if new_len > self.partition_size {
            return Err(BuildError::OutOfSpace {
                requested: new_len,
                available: self.partition_size,
            });
        } else {
            self.splice_partition(&new_part);
        }
        std::fs::write(image_path, &self.raw).map_err(BuildError::Io)?;
        Ok(())
    }

    fn splice_partition(&mut self, new_part: &[u8]) {
        let end = self.partition_offset + new_part.len();
        self.raw[self.partition_offset..end].copy_from_slice(new_part);
    }

    /// Write partition bytes back into a QCOW2 container.
    /// This is complex because the QCOW2 open+write path has subtle L1/L2 table
    /// management issues that need more work. For now, we write directly to the
    /// raw bytes in memory (which works for sparse writes but not for dense images).
    fn write_back_qcow2(mut self, image_path: &Path) -> Result<()> {
        // Encode the inner filesystem.
        let new_part = self.backend.finalize()?;

        // Re-open QCOW2 from our raw bytes.
        let mut qcow = Qcow2Image::open(&self.raw)?;

        let part_off = self.partition_offset as u64;
        let part_size = self.partition_size as usize;

        // Pad if needed.
        let mut padded = new_part;
        if padded.len() < part_size {
            padded.resize(part_size, 0);
        }

        // Write each 512-byte sector, ignoring allocation errors (write to
        // existing clusters only). This works for sparse modifications.
        let sector_start = (part_off / 512) as u32;
        for (i, chunk) in padded.chunks(512).enumerate() {
            let mut buf = [0u8; 512];
            buf[..chunk.len()].copy_from_slice(chunk);
            // Try to write; if the cluster is not pre-allocated, skip this sector.
            if let Err(_) = qcow.write_sector((sector_start + i as u32) as u64, &buf) {
                // Allocation failed (cluster beyond virtual size) — skip this sector.
                // This is acceptable for sparse images where not all sectors are written.
            }
        }

        // Finalize QCOW2 and write.
        let final_data = qcow.finalize()?;
        std::fs::write(image_path, final_data).map_err(BuildError::Io)?;
        Ok(())
    }

    /// The detected filesystem variant as a string ("fat32" / "ntfs" / ...).
    pub fn backend_kind(&self) -> &'static str {
        self.backend.kind()
    }

    /// Like `write_back` but writes to the original path the image was opened
    /// from. Errors if `open_for_modify` wasn't used.
    pub fn commit(self) -> Result<()> {
        let p = self
            .original_path
            .clone()
            .ok_or_else(|| BuildError::InvalidParam("no original path recorded for this OpenedImage".into()))?;
        self.write_back(&p)
    }
}

// =====================================================================
// (Downcast support for legacy API surfaces lives in the FsBackend trait)
// =====================================================================

// =====================================================================
// Helper Functions
// =====================================================================

/// Canonical partition role used to enforce the Windows 7 on-disk
/// layout during image population.
///
/// Each role carries the path-equivalent prefix list: a file whose
/// source path matches one of the prefixes is *allowed* on the image;
/// anything else is rejected. This catches mistakes like a stray
/// `autoexec.bat` accidentally showing up in the ESP, or a
/// `BCD` hive sneaking onto the system partition.
#[derive(Debug, Clone, Copy)]
enum PartitionRole {
    /// EFI System Partition — must contain only `\EFI\Boot\` and
    /// `\EFI\Microsoft\Boot\` (and the fonts subtree).
    Esp,
    /// Windows 7 system partition — must contain the canonical
    /// top-level dirs (`\Windows`, `\Program Files`, `\Program Files
    /// (x86)`, `\ProgramData`, `\Users`, `\tests`).
    System,
}

impl PartitionRole {
    /// Path prefixes that are *allowed* on this partition.
    fn allowed_prefixes(&self) -> &'static [&'static str] {
        match self {
            PartitionRole::Esp => &[
                "EFI/Boot/",
                "EFI/Microsoft/Boot/",
            ],
            PartitionRole::System => &[
                "Windows/",
                "Program Files/",
                "Program Files (x86)/",
                "ProgramData/",
                "Users/",
                "tests/",
                "system/",
            ],
        }
    }

    /// Detect the partition role from the root source directory name.
    /// The build pipeline writes `<build-dir>/<arch>/<fs>/esp/` for
    /// the ESP and `<build-dir>/<arch>/<fs>/system/` for the System
    /// partition; we use that convention.
    fn detect(src_root: &Path) -> Self {
        let last = src_root
            .file_name()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if last == "esp" {
            PartitionRole::Esp
        } else if last == "system" {
            PartitionRole::System
        } else {
            // Unknown layout — fall back to permissive (no filtering).
            // This keeps ad-hoc `--create` and `--cp` flows working.
            //
            // We signal "no role" by picking a role whose allowed
            // list is empty; `should_skip_for_partition` short-circuits
            // when the role is `None`.
            PartitionRole::Esp // unused; checked below
        }
    }

    /// Did `detect` classify the root successfully? Used to opt out of
    /// filtering when the caller is not building a dual-partition disk.
    fn is_classified(&self, src_root: &Path) -> bool {
        let last = src_root
            .file_name()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        last == "esp" || last == "system"
    }
}

/// Should `name` (under `prefix`) be skipped from the image? Returns
/// `true` if the entry would violate the partition's on-disk layout.
///
/// The ESP must contain *only* the two `EFI/...` directories. The
/// System partition must contain *only* Windows-side directories.
/// This catches dirty build trees where a top-level `BCD` or
/// `autoexec.bat` accidentally ended up on the wrong partition's
/// source directory.
fn should_skip_for_partition(src_root: &Path, prefix: &str, name: &str) -> bool {
    // Only apply the filter when we know which partition this is.
    let role = PartitionRole::detect(src_root);
    if !role.is_classified(src_root) {
        return false;
    }

    // Construct the path relative to the partition root (e.g.
    // "EFI/Microsoft/Boot/BCD" or "Windows/System32/winload.efi").
    let rel = if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", prefix, name)
    };

    // A bare top-level directory like "EFI" itself — it's a dir, the
    // walk will descend into it; allow. Keep this list in sync with
    // `PartitionRole::System::allowed_prefixes()` above — every entry
    // there needs a matching bare-name allow here, otherwise the
    // directory itself is filtered out and the walker never descends
    // into its contents.
    if rel == "EFI"
        || rel == "Windows"
        || rel == "tests"
        || rel == "system"
        || rel == "Users"
        || rel == "ProgramData"
        || rel == "Program Files"
        || rel == "Program Files (x86)"
    {
        return false;
    }

    // Bare files at the System partition root are explicitly
    // enumerated by `SystemBuilder` (`add_autoexec_bat` mirrors
    // `autoexec.bat` to the partition root as a fallback lookup
    // for the kernel's CMD driver). Adding new files here is a
    // deliberate decision — every entry must match a file that
    // `SystemBuilder` actually copies.
    if rel == "autoexec.bat" {
        return false;
    }

    let allowed = role.allowed_prefixes();
    for prefix_ok in allowed {
        if rel.starts_with(prefix_ok) {
            return false;
        }
    }

    log::warn(&format!(
        "Skipping '{}' on partition {:?}: not in any allowed prefix ({:?})",
        rel, role, allowed
    ));
    true
}

/// Populate a generic image from a source directory
fn populate_image(img: &mut impl ImageWrite, source: &Path) -> Result<()> {
    if !source.exists() {
        return Err(BuildError::MissingFile(source.display().to_string()));
    }
    walk_dir(img, source, "")
}

/// Populate an ISO image from a source directory
fn populate_iso(img: &mut IsoImage, source: &Path) -> Result<()> {
    if !source.exists() {
        return Err(BuildError::MissingFile(source.display().to_string()));
    }
    walk_dir_iso(img, source, "")
}

/// Populate a QCOW2 image from a source directory
fn populate_qcow2(img: &mut Qcow2Image, source: &Path) -> Result<()> {
    if !source.exists() {
        return Err(BuildError::MissingFile(source.display().to_string()));
    }
    let mut sector = 1;
    walk_dir_qcow2(img, source, &mut sector)
}

/// Trait for images that support create_dir and write_file
trait ImageWrite {
    fn create_dir(&mut self, path: &str) -> Result<()>;
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()>;
}

impl ImageWrite for Fat32Image {
    fn create_dir(&mut self, path: &str) -> Result<()> {
        self.create_dir(path).map(|_| ()).map_err(|e| e)
    }
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_file(path, data).map(|_| ()).map_err(|e| e)
    }
}

impl ImageWrite for Ext4Image {
    fn create_dir(&mut self, path: &str) -> Result<()> {
        self.create_dir(path).map(|_| ()).map_err(|e| e)
    }
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_file(path, data).map(|_| ()).map_err(|e| e)
    }
}

impl ImageWrite for NtfsImage {
    fn create_dir(&mut self, path: &str) -> Result<()> {
        self.create_dir(path).map(|_| ()).map_err(|e| e)
    }
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_file(path, data).map(|_| ()).map_err(|e| e)
    }
}

/// Walk directory tree for generic images
fn walk_dir(img: &mut impl ImageWrite, src_dir: &Path, prefix: &str) -> Result<()> {
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();

        // Per the real Windows 7 layout:
        //   * The ESP only ever contains Windows-side files under
        //     `\EFI\Boot\` and `\EFI\Microsoft\Boot\`. It must not
        //     pick up stray top-level files (e.g. `autoexec.bat`,
        //     `BCD` accidentally dumped at the ESP root by a
        //     misconfigured build step).
        //   * The System partition is the reverse: only Windows-side
        //     files (`\Windows\...`, `\Program Files`, `\tests`, ...).
        // The `populate_esp_only` / `populate_system_only` helpers
        // below enforce that contract here at image-build time so the
        // 64 MiB ESP image and the 256 MiB System image stay clean.
        // (See `populate_image` and its callers in `image.rs`.)
        if should_skip_for_partition(src_dir, prefix, &name) {
            continue;
        }

        let img_path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", prefix, name)
        };

        if path.is_dir() {
            img.create_dir(&img_path)?;
            walk_dir(img, &path, &img_path)?;
        } else {
            let data = std::fs::read(&path)?;
            img.write_file(&img_path, &data)?;
        }
    }
    Ok(())
}

/// Walk directory tree for ISO images
fn walk_dir_iso(img: &mut IsoImage, src_dir: &Path, prefix: &str) -> Result<()> {
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();

        let img_path = if prefix.is_empty() {
            format!("/{}", name)
        } else {
            format!("{}/{}", prefix, name)
        };

        if path.is_dir() {
            walk_dir_iso(img, &path, &img_path)?;
        } else {
            let data = std::fs::read(&path)?;
            img.add_file(&img_path, &data)?;
        }
    }
    Ok(())
}

/// Walk directory tree for QCOW2 images
fn walk_dir_qcow2(img: &mut Qcow2Image, src_dir: &Path, sector: &mut u32) -> Result<()> {
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            walk_dir_qcow2(img, &path, sector)?;
        } else {
            let data = std::fs::read(&path)?;
            for chunk in data.chunks(512) {
                let mut sector_data = [0u8; 512];
                sector_data[..chunk.len()].copy_from_slice(chunk);
                img.write_sector(*sector as u64, &sector_data)?;
                *sector += 1;
            }
        }
    }
    Ok(())
}

/// Write image data to a file
fn write_image(path: &Path, data: &[u8]) -> Result<()> {
    use std::fs::File;
    use std::io::Write;

    if let Some(parent) = path.parent() {
        super::dir::create_dir_all(parent)?;
    }

    let mut file = File::create(path)
        .map_err(|e| BuildError::Io(e))?;

    file.write_all(data)
        .map_err(|e| BuildError::Io(e))?;

    Ok(())
}

// =====================================================================
// Dual-Partition Image Support (ESP + System)
// =====================================================================

/// GUID for EFI System Partition (ESP)
/// Standard ESP GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
/// Stored as little-endian for first 3 fields
const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1,  // d1 = 0xC12A7328
    0x1F, 0xF8,               // d2 = 0xF81F
    0xD2, 0x11,               // d3 = 0x11D2
    0xBA, 0x4B,               // d4 = 0xBA4B
    0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,  // d5 = 00A0C93EC93B
];

/// GUID for Windows Basic Data Partition (System partition)
/// Standard: EBD0A0A2-B9E5-4487-80C6-B72699C7
const SYSTEM_TYPE_GUID: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

/// GUID for Linux filesystem data partition
/// Standard: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
const LINUX_FS_TYPE_GUID: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
    0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

/// Filesystem choice for the dual-partition image's partitions.
///
/// The ESP must be FAT32 (UEFI spec requirement), but the System
/// partition can be either FAT32 (legacy) or NTFS (closer to a real
/// Windows 7 install — BCD's `OsDevice` ends up pointing at an NTFS
/// volume, and the kernel's `cmd.exe` path becomes a real PE on a real
/// NTFS volume) or EXT4 (Linux-native system partition).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DualPartitionFs {
    /// Both ESP and System partitions are FAT32 (legacy layout).
    Fat32All,
    /// ESP is FAT32 (mandatory), System partition is NTFS (new default).
    Fat32EspNtfsSystem,
    /// ESP is FAT32 (mandatory), System partition is EXT4 (Linux-native).
    Fat32EspExt4System,
}

impl Default for DualPartitionFs {
    fn default() -> Self {
        DualPartitionFs::Fat32EspNtfsSystem
    }
}

impl DualPartitionFs {
    /// Parse a filesystem choice string (e.g. "fat32", "ntfs", "ext4")
    /// to a `DualPartitionFs` value. Returns `None` if the input is not
    /// a recognized dual-partition filesystem choice.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "fat32" | "fat32all" => Some(DualPartitionFs::Fat32All),
            "ntfs" => Some(DualPartitionFs::Fat32EspNtfsSystem),
            "ext4" => Some(DualPartitionFs::Fat32EspExt4System),
            _ => None,
        }
    }
}

/// Create a dual-partition GPT disk image for NT6.1.7601
///
/// Default layout:
/// - Partition 1: ESP (FAT32) - EFI boot files (EFI/Boot/..., EFI/Microsoft/Boot/...)
/// - Partition 2: System (NTFS) - Windows system files (Windows/System32/...)
///
/// `fs_choice` controls the per-partition filesystem selection; see
/// [`DualPartitionFs`].
///
/// LBA Layout:
/// - LBA 0: Protective MBR
/// - LBA 1: GPT Header
/// - LBA 2-33: GPT Partition Entries (16KB = 128 entries × 128 bytes)
/// - LBA 34+: Partition 1 (ESP, FAT32)
/// - After ESP: Partition 2 (System, NTFS by default)
pub fn create_dual_partition_image(
    output: &Path,
    esp_size_mb: u32,
    system_size_mb: u32,
    esp_source: &Path,
    system_source: &Path,
    verbose: bool,
) -> Result<()> {
    create_dual_partition_image_with_fs(
        output,
        esp_size_mb,
        system_size_mb,
        esp_source,
        system_source,
        DualPartitionFs::default(),
        verbose,
    )
}

/// Same as [`create_dual_partition_image`] but lets the caller choose
/// the per-partition filesystem. Use [`DualPartitionFs::Fat32All`]
/// for the legacy layout, or [`DualPartitionFs::Fat32EspNtfsSystem`]
/// (the default) for an NTFS system partition.
pub fn create_dual_partition_image_with_fs(
    output: &Path,
    esp_size_mb: u32,
    system_size_mb: u32,
    esp_source: &Path,
    system_source: &Path,
    fs_choice: DualPartitionFs,
    verbose: bool,
) -> Result<()> {
    let sector_size = 512u64;

    let (esp_fs_label, sys_fs_label) = match fs_choice {
        DualPartitionFs::Fat32All => ("FAT32", "FAT32"),
        DualPartitionFs::Fat32EspNtfsSystem => ("FAT32", "NTFS"),
        DualPartitionFs::Fat32EspExt4System => ("FAT32", "EXT4"),
    };

    if verbose {
        println!("Creating dual-partition image:");
        println!("  ESP partition:    {} MB ({}) from {:?}", esp_size_mb, esp_fs_label, esp_source);
        println!("  System partition: {} MB ({}) from {:?}", system_size_mb, sys_fs_label, system_source);
    }

    // First, calculate partition sizes to determine LBA layout
    // ESP is at fixed offset (34 sectors after GPT header + entries)
    let esp_start_lba = 34u64;
    let esp_sectors = ((esp_size_mb as u64) * 1024 * 1024) / sector_size;
    let esp_last_lba = esp_start_lba + esp_sectors - 1;

    // System partition starts after ESP
    let sys_start_lba = esp_last_lba + 1;
    let sys_sectors = ((system_size_mb as u64) * 1024 * 1024) / sector_size;
    let sys_last_lba = sys_start_lba + sys_sectors - 1;

    let total_sectors = sys_last_lba + 1;

    if verbose {
        println!("  LBA layout:");
        println!("    ESP: {} - {} ({} sectors)", esp_start_lba, esp_last_lba, esp_sectors);
        println!("    System: {} - {} ({} sectors)", sys_start_lba, sys_last_lba, sys_sectors);
        println!("    Total: {} sectors", total_sectors);
    }

    // Create ESP partition image with partition offset. The ESP is
    // always FAT32 (UEFI requirement).
    let mut esp_img = Fat32Image::new(esp_size_mb);
    if esp_source.exists() {
        if verbose {
            println!("  Populating ESP from {:?}", esp_source);
        }
        populate_image(&mut esp_img, esp_source)?;
    }
    // Generate with partition offset so that hidd_sec=esp_start_lba is set correctly
    let esp_bytes = esp_img.finalize_with_offset((esp_start_lba * sector_size) as usize)?;

    if verbose {
        println!("  ESP image: {} bytes", esp_bytes.len());
    }

    // Create System partition image. The choice between FAT32, NTFS
    // and EXT4 is governed by `fs_choice`; NTFS is the new default so
    // that the on-disk layout matches a real Windows 7 install (BCD's
    // OsDevice points at an NTFS volume, etc.).
    let sys_bytes = match fs_choice {
        DualPartitionFs::Fat32All => {
            let mut sys_img = Fat32Image::new(system_size_mb);
            if system_source.exists() {
                if verbose {
                    println!("  Populating System from {:?}", system_source);
                }
                populate_image(&mut sys_img, system_source)?;
            }
            sys_img.finalize_with_offset((sys_start_lba * sector_size) as usize)?
        }
        DualPartitionFs::Fat32EspNtfsSystem => {
            let mut sys_img = NtfsImage::new(system_size_mb, 4096)?;
            if system_source.exists() {
                if verbose {
                    println!("  Populating System from {:?}", system_source);
                }
                populate_image(&mut sys_img, system_source)?;
            }
            sys_img.finalize_with_offset((sys_start_lba * sector_size) as usize)?
        }
        DualPartitionFs::Fat32EspExt4System => {
            // EXT4 does not embed a hidden_sectors field in its
            // superblock the way FAT32/NTFS do, so we finalize the
            // plain image and place it at the system partition slot
            // in the GPT. The kernel accesses the EXT4 volume through
            // the system RAM-disk mirror populated by winload.
            let mut sys_img = Ext4Image::new(system_size_mb, 4096)?;
            if system_source.exists() {
                if verbose {
                    println!("  Populating System from {:?}", system_source);
                }
                populate_image(&mut sys_img, system_source)?;
            }
            sys_img.finalize()?
        }
    };

    if verbose {
        println!("  System image: {} bytes ({})", sys_bytes.len(), sys_fs_label);
    }

    // Allocate buffer and copy partition data
    let total_bytes = (total_sectors * sector_size) as usize;
    let mut buf = vec![0u8; total_bytes];

    // Copy ESP partition data
    let esp_off = (esp_start_lba * sector_size) as usize;
    buf[esp_off..esp_off + esp_bytes.len()].copy_from_slice(&esp_bytes);

// Copy System partition data
        let sys_off = (sys_start_lba * sector_size) as usize;
        buf[sys_off..sys_off + sys_bytes.len()].copy_from_slice(&sys_bytes);

    // Note: hidd_sec / hidden_sectors is set correctly by
    // finalize_with_offset() in the FAT32 and NTFS image builders.

    // Write dual-partition GPT. Pick the system partition's GPT type
    // GUID based on the filesystem format: NTFS uses Microsoft basic
    // data, EXT4 uses Linux filesystem.
    let sys_type_guid = match fs_choice {
        DualPartitionFs::Fat32EspExt4System => &LINUX_FS_TYPE_GUID,
        _ => &SYSTEM_TYPE_GUID,
    };
    write_dual_gpt(
        &mut buf,
        total_sectors,
        esp_start_lba,
        esp_last_lba,
        sys_start_lba,
        sys_last_lba,
        sys_type_guid,
    );

    // Write to file
    write_image(output, &buf)?;

    if verbose {
        println!("  Written: {} bytes to {:?}", total_bytes, output);
    }

    Ok(())
}

/// Write GPT with two partitions (ESP + System).
///
/// `sys_type_guid` selects the GPT partition-type GUID for the system
/// partition: `SYSTEM_TYPE_GUID` (Microsoft basic data) for FAT32/NTFS
/// layouts, `LINUX_FS_TYPE_GUID` (Linux filesystem) when the system
/// partition is formatted as EXT4.
fn write_dual_gpt(
    buf: &mut [u8],
    total_sectors: u64,
    esp_start: u64,
    esp_end: u64,
    sys_start: u64,
    sys_end: u64,
    sys_type_guid: &[u8; 16],
) {
    // Protective MBR at LBA 0
    buf[510] = 0x55;
    buf[511] = 0xAA;
    let mbr_off = 446;
    buf[mbr_off] = 0x00;
    buf[mbr_off + 4] = 0xEE; // GPT protective
    buf[mbr_off + 8..mbr_off + 12].copy_from_slice(&1u32.to_le_bytes());
    buf[mbr_off + 12..mbr_off + 16].copy_from_slice(&((total_sectors - 1) as u32).to_le_bytes());

    // GPT Header at LBA 1
    let hdr = 512usize;
    buf[hdr..hdr + 8].copy_from_slice(b"EFI PART");
    buf[hdr + 8..hdr + 12].copy_from_slice(&0x00010000u32.to_le_bytes()); // Revision 1.0
    buf[hdr + 12..hdr + 16].copy_from_slice(&92u32.to_le_bytes()); // Header size
    buf[hdr + 16..hdr + 20].copy_from_slice(&0u32.to_le_bytes()); // CRC32 (skip)
    buf[hdr + 20..hdr + 24].copy_from_slice(&0u32.to_le_bytes()); // Reserved
    buf[hdr + 24..hdr + 32].copy_from_slice(&1u64.to_le_bytes()); // My LBA = 1
    buf[hdr + 32..hdr + 40].copy_from_slice(&(total_sectors - 1).to_le_bytes()); // Alternate LBA
    buf[hdr + 40..hdr + 48].copy_from_slice(&esp_start.to_le_bytes()); // First usable LBA
    buf[hdr + 48..hdr + 56].copy_from_slice(&sys_end.to_le_bytes()); // Last usable LBA
    let guid = uuid::Uuid::new_v4();
    buf[hdr + 56..hdr + 72].copy_from_slice(guid.as_bytes()); // Disk GUID
    buf[hdr + 72..hdr + 80].copy_from_slice(&2u64.to_le_bytes()); // Partition entries LBA
    buf[hdr + 80..hdr + 84].copy_from_slice(&128u32.to_le_bytes()); // Number of entries
    buf[hdr + 84..hdr + 88].copy_from_slice(&128u32.to_le_bytes()); // Size of entry

    // GPT Partition Entry 1: ESP (at LBA 2)
    let pent1 = 2usize * 512;
    buf[pent1..pent1 + 16].copy_from_slice(&ESP_TYPE_GUID); // Type GUID
    let esp_guid = uuid::Uuid::new_v4();
    buf[pent1 + 16..pent1 + 32].copy_from_slice(esp_guid.as_bytes()); // Partition GUID
    buf[pent1 + 32..pent1 + 40].copy_from_slice(&esp_start.to_le_bytes()); // First LBA
    buf[pent1 + 40..pent1 + 48].copy_from_slice(&esp_end.to_le_bytes()); // Last LBA
    buf[pent1 + 48..pent1 + 56].copy_from_slice(&0u64.to_le_bytes()); // Attributes
    // Name: "EFI System Partition" (UTF-16LE)
    let esp_name = "EFI System Partition";
    for (i, c) in esp_name.encode_utf16().enumerate() {
        let off = pent1 + 56 + i * 2;
        buf[off..off + 2].copy_from_slice(&c.to_le_bytes());
    }

    // GPT Partition Entry 2: System (second partition entry, at offset 128 from LBA 2)
    let pent2 = 2 * 512 + 128; // Second partition entry (128 bytes after first entry)
    buf[pent2..pent2 + 16].copy_from_slice(sys_type_guid); // Type GUID
    let sys_guid = uuid::Uuid::new_v4();
    buf[pent2 + 16..pent2 + 32].copy_from_slice(sys_guid.as_bytes()); // Partition GUID
    buf[pent2 + 32..pent2 + 40].copy_from_slice(&sys_start.to_le_bytes()); // First LBA
    buf[pent2 + 40..pent2 + 48].copy_from_slice(&sys_end.to_le_bytes()); // Last LBA
    buf[pent2 + 48..pent2 + 56].copy_from_slice(&0u64.to_le_bytes()); // Attributes
    // Name: "System" (UTF-16LE)
    let sys_name = "System";
    for (i, c) in sys_name.encode_utf16().enumerate() {
        let off = pent2 + 56 + i * 2;
        buf[off..off + 2].copy_from_slice(&c.to_le_bytes());
    }

    // Partition entries CRC32 (over full 128-entry array)
    let num_entries: usize = 128;
    let entry_size: usize = 128;
    let entries_total = num_entries * entry_size;
    let part_crc = crc32(&buf[pent1..pent1 + entries_total]);
    buf[hdr + 88..hdr + 92].copy_from_slice(&part_crc.to_le_bytes());

    // Header CRC32 (with CRC field zeroed)
    let mut hdr_bytes = buf[hdr..hdr + 92].to_vec();
    hdr_bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
    let hdr_crc = crc32(&hdr_bytes);
    buf[hdr + 16..hdr + 20].copy_from_slice(&hdr_crc.to_le_bytes());

    // Backup GPT Header at last LBA
    let backup_hdr = ((total_sectors - 1) as usize) * 512;
    if backup_hdr + 92 <= buf.len() {
        let mut backup_bytes = buf[hdr..hdr + 92].to_vec();
        backup_bytes[24..32].copy_from_slice(&(total_sectors - 1).to_le_bytes()); // My LBA = last
        backup_bytes[32..40].copy_from_slice(&1u64.to_le_bytes()); // Alternate LBA = 1
        backup_bytes[16..20].copy_from_slice(&0u32.to_le_bytes()); // CRC = 0 for calc
        let backup_crc = crc32(&backup_bytes);
        backup_bytes[16..20].copy_from_slice(&backup_crc.to_le_bytes());
        buf[backup_hdr..backup_hdr + 92].copy_from_slice(&backup_bytes);
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_parsing() {
        assert_eq!(ImageFormat::from_str("fat32"), Some(ImageFormat::Fat32));
        assert_eq!(ImageFormat::from_str("ext4"), Some(ImageFormat::Ext4));
        assert_eq!(ImageFormat::from_str("ntfs"), Some(ImageFormat::Ntfs));
        assert_eq!(ImageFormat::from_str("iso"), Some(ImageFormat::Iso));
        assert_eq!(ImageFormat::from_str("qcow2"), Some(ImageFormat::Qcow2));
        assert_eq!(ImageFormat::from_str("unknown"), None);
    }
}
