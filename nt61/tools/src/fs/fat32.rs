//! FAT32 Filesystem Image Module
//!
//! This module provides a pure Rust implementation for creating FAT32 filesystem images,
//! replacing `mkfs.fat`, `mcopy`, and `mmd` shell commands.
//!
//! ## Features
//! - GPT partition table generation
//! - FAT32 filesystem formatting
//! - Long filename (LFN) support
//! - Directory recursion
//! - File writing
//!
//! ## Usage
//! ```rust
//! use nt61_tools::fat32::Fat32Image;
//!
//! let mut image = Fat32Image::new(64); // 64 MB
//! image.create_dir("EFI").unwrap();
//! image.create_dir("EFI/Boot").unwrap();
//! image.write_file("EFI/Boot/BOOTX64.EFI", &boot_data).unwrap();
//! let img_data = image.finalize().unwrap();
//! ```

use crate::error::{BuildError, Result};
use crate::fs::backend::{DirEntry, FsBackend};

/// Discriminator for `emit_named_entry` so file vs. directory branches share
/// one LFN/SFN writer instead of drifting apart as they used to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    File,
    Directory,
}

// =====================================================================
// Constants
// =====================================================================

/// Sector size (512 bytes)
pub const SECTOR_SIZE: u32 = 512;
/// Sectors per cluster
pub const SECTS_PER_CLUSTER: u8 = 1;
/// Number of FAT tables
pub const NUM_FATS: u8 = 2;
/// Reserved sectors
pub const RESERVED_SECTORS: u32 = 32;
/// FAT size in sectors (for FAT32, this is 32-bit).
///
/// Sized to cover the worst-case image we generate (currently 64 MiB =
/// 131072 clusters). With 4 bytes per FAT entry that's 524288 bytes =
/// 1024 sectors. We round up to 1280 sectors to leave headroom and
/// align to a 64-sector boundary. The same value is written into
/// BPB_FATSz32 in the boot sector.
pub const FAT_SIZE_SECTORS: u32 = 1280;

/// GPT partition type for EFI System Partition
pub const PARTITION_TYPE_EFI: [u8; 16] = [
    0x28, 0x73, 0x9A, 0xC6, 0x8B, 0x14, 0x28, 0x4F,
    0xB9, 0x18, 0x60, 0xDA, 0x0B, 0x27, 0xCC, 0xE2,
];

/// GPT partition type for Linux filesystem
pub const PARTITION_TYPE_LINUX: [u8; 16] = [
    0x0F, 0x0D, 0xC5, 0x3D, 0x4F, 0x0E, 0xDE, 0x4F,
    0x8E, 0x66, 0x04, 0x20, 0xC9, 0x18, 0xE3, 0x3F,
];

// =====================================================================
// FAT32 Structures
// =====================================================================

/// FAT32 Directory Entry
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct Fat32DirEntry {
    pub name: [u8; 11],
    pub attr: u8,
    pub reserved: u8,
    pub crt_time_tenths: u8,
    pub crt_time: u16,
    pub crt_date: u16,
    pub last_acc_date: u16,
    pub clus_hi: u16,
    pub mtime: u16,
    pub mdate: u16,
    pub clus_lo: u16,
    pub size: u32,
}

/// FAT32 Long Filename Entry
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct Fat32LfnEntry {
    pub seq: u8,
    pub name1: [u16; 5],
    pub attr: u8,
    pub lfn_type: u8,
    pub checksum: u8,
    pub name2: [u16; 6],
    pub reserved: u16,
    pub name3: [u16; 2],
}

/// FAT32 Boot Sector (BPB)
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct Fat32Bpb {
    pub jmp_boot: [u8; 3],
    pub oem_name: [u8; 8],
    pub bytes_per_sec: u16,
    pub sec_per_clus: u8,
    pub reserved_sec_cnt: u16,
    pub num_fats: u8,
    pub root_ent_cnt: u16,
    pub tot_sec16: u16,
    pub media: u8,
    pub fat_sz16: u16,
    pub sec_per_trk: u16,
    pub num_heads: u16,
    pub hidd_sec: u32,
    pub tot_sec32: u32,
    pub fat_sz32: u32,
    pub ext_flags: u16,
    pub fs_ver: u16,
    pub root_clus: u32,
    pub fs_info: u16,
    pub bk_boot_sec: u16,
    pub reserved: [u8; 12],
    pub drv_num: u8,
    pub reserved1: u8,
    pub boot_sig: u8,
    pub volume_id: u32,
    pub volume_label: [u8; 11],
    pub fs_type: [u8; 8],
}

// =====================================================================
// Helper Functions
// =====================================================================

/// Pad data to cluster boundary
fn pad_to_cluster(data: &[u8], cluster_size: u32) -> Vec<u8> {
    let rem = data.len() as u32 % cluster_size;
    if rem == 0 {
        return data.to_vec();
    }
    let mut out = data.to_vec();
    out.resize((data.len() as u32 + cluster_size - rem) as usize, 0);
    out
}

/// Calculate checksum for 8.3 filename
fn checksum_83(name: &[u8; 11]) -> u8 {
    let mut s: u8 = 0;
    for &c in name {
        s = s.rotate_right(1).wrapping_add(c);
    }
    s
}

/// Convert filename to 8.3 SFN format
fn to_sfn(name: &str) -> [u8; 11] {
    let mut n = [b' '; 11];
    if name == "." {
        n[0] = b'.';
    } else if name == ".." {
        n[0] = b'.';
        n[1] = b'.';
    } else {
        let (base, ext) = if let Some(p) = name.rfind('.') {
            (&name[..p], Some(&name[p + 1..]))
        } else {
            (name, None)
        };
        for (i, c) in base.bytes().take(8).enumerate() {
            n[i] = if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'~' {
                c.to_ascii_uppercase()
            } else {
                c
            };
        }
        if let Some(e) = ext {
            for (i, c) in e.bytes().take(3).enumerate() {
                n[8 + i] = if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
                    c.to_ascii_uppercase()
                } else {
                    c
                };
            }
        }
    }
    n
}

/// Decode an 8.3 SFN back to a displayable name.
fn decode_sfn(raw: &[u8; 11]) -> String {
    let base = std::str::from_utf8(&raw[..8]).unwrap_or("").trim_end();
    let ext = std::str::from_utf8(&raw[8..]).unwrap_or("").trim_end();
    if ext.is_empty() {
        base.to_string()
    } else {
        format!("{}.{}", base, ext)
    }
}

/// Decode an LFN sequence (in correct order — first char first) into a String.
fn decode_lfn(chars: &[u16]) -> String {
    let mut out = String::new();
    for &c in chars {
        if c == 0x0000 || c == 0xFFFF {
            break;
        }
        if let Some(ch) = char::from_u32(c as u32) {
            out.push(ch);
        }
    }
    out
}

/// Translate (cluster number, BPB layout) to a byte offset in the image. Returns
/// None if the offset would lie outside the buffer.
fn cluster_offset_in_image(
    data_start: u32,
    cluster: u32,
    spc: u32,
    sector_size: u32,
) -> Option<usize> {
    let lba = data_start + (cluster - 2) * spc;
    Some((lba * sector_size) as usize)
}

/// Walk a directory starting at `cluster`, parse all 32-byte entries (collapsing
/// preceding LFN entries back into the long name), and recursively descend into
/// subdirectories. All BPB layout parameters are passed explicitly so this
/// function does not need to capture any closure environment.
fn parse_dir_static<'a>(
    data: &'a [u8],
    data_start: u32,
    spc: u32,
    cluster_size: u32,
    fat_start: u32,
    cluster: u32,
    read_cluster: &dyn Fn(u32) -> Option<&'a [u8]>,
) -> Result<Vec<FsNode>> {
    let mut children: Vec<FsNode> = Vec::new();
    let mut lfn_buf: Vec<u16> = Vec::new();
    let buf = match read_cluster(cluster) {
        Some(b) => b,
        None => return Ok(children),
    };
    for entry in buf.chunks_exact(32) {
        if entry[0] == 0x00 {
            break;
        }
        if entry[0] == 0xE5 {
            continue;
        }
        let attr = entry[11];
        if attr == 0x0F {
            let seq = entry[0] & 0x1F;
            let mut chars = Vec::with_capacity(13 * seq as usize);
            for i in 0..5 {
                let v = u16::from_le_bytes([entry[1 + i * 2], entry[2 + i * 2]]);
                chars.push(v);
            }
            for i in 0..6 {
                let v = u16::from_le_bytes([entry[14 + i * 2], entry[15 + i * 2]]);
                chars.push(v);
            }
            for i in 0..2 {
                let v = u16::from_le_bytes([entry[28 + i * 2], entry[29 + i * 2]]);
                chars.push(v);
            }
            lfn_buf.splice(0..0, chars);
            continue;
        }
        let name_raw: &[u8; 11] = entry[0..11].try_into().expect("entry[0..11] is exactly 11 bytes");
        let cluster_no = (u16::from_le_bytes([entry[20], entry[21]]) as u32) << 16
            | u16::from_le_bytes([entry[26], entry[27]]) as u32;
        let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
        let lfn_name = decode_lfn(&lfn_buf);
        lfn_buf.clear();
        let mut name = if !lfn_name.is_empty() {
            lfn_name
        } else {
            decode_sfn(name_raw)
        };
        if name == "." || name == ".." {
            continue;
        }
        while name.ends_with(' ') || name.ends_with('.') {
            name.pop();
        }
        if attr & 0x10 != 0 {
            let sub = parse_dir_static(data, data_start, spc, cluster_size, fat_start, cluster_no, read_cluster)?;
            children.push(FsNode::Dir { name, children: sub });
        } else {
            let data_bytes = if cluster_no >= 2 {
                let mut acc = Vec::new();
                let mut cur = cluster_no;
                let mut remaining = size;
                for _ in 0..0x100000u32 {
                    if cur < 2 || remaining == 0 {
                        break;
                    }
                    let off = cluster_offset_in_image(data_start, cur, spc, SECTOR_SIZE);
                    let off = match off {
                        Some(o) => o,
                        None => break,
                    };
                    let take = (remaining as usize).min(cluster_size as usize);
                    if off + take > data.len() {
                        break;
                    }
                    acc.extend_from_slice(&data[off..off + take]);
                    remaining = remaining.saturating_sub(take as u32);
                    let fat_off = (fat_start * SECTOR_SIZE) as usize + cur as usize * 4;
                    if fat_off + 4 > data.len() {
                        break;
                    }
                    let next = u32::from_le_bytes([
                        data[fat_off],
                        data[fat_off + 1],
                        data[fat_off + 2],
                        data[fat_off + 3],
                    ]);
                    if next >= 0x0FFF_FFF8 {
                        break;
                    }
                    cur = next;
                }
                acc
            } else {
                Vec::new()
            };
            children.push(FsNode::File { name, data: data_bytes });
        }
    }
    Ok(children)
}

impl Fat32DirEntry {

    /// Create a new file directory entry
    pub fn new_file(name: &str, cluster: u32, size: u32) -> Self {
        Self {
            name: to_sfn(name),
            attr: 0x20,
            reserved: 0,
            crt_time_tenths: 0,
            crt_time: 0,
            crt_date: 0x5A4E,
            last_acc_date: 0x5A4E,
            clus_hi: ((cluster >> 16) & 0xFFFF) as u16,
            mtime: 0x0000,
            mdate: 0x5A4E,
            clus_lo: (cluster & 0xFFFF) as u16,
            size,
        }
    }

    /// Create a new file entry from existing SFN
    pub fn new_file_from_sfn(sfn: &[u8; 11], cluster: u32, size: u32) -> Self {
        let mut n = [b' '; 11];
        n.copy_from_slice(sfn);
        Self {
            name: n,
            attr: 0x20,
            reserved: 0,
            crt_time_tenths: 0,
            crt_time: 0,
            crt_date: 0x5A4E,
            last_acc_date: 0x5A4E,
            clus_hi: ((cluster >> 16) & 0xFFFF) as u16,
            mtime: 0x0000,
            mdate: 0x5A4E,
            clus_lo: (cluster & 0xFFFF) as u16,
            size,
        }
    }

    /// Create a new directory entry
    pub fn new_dir(name: &str, cluster: u32) -> Self {
        let mut e = Self::new_file(name, cluster, 0);
        e.attr = 0x10;
        e.size = 0;
        e
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let clus_hi = self.clus_hi;
        let clus_lo = self.clus_lo;
        let attr = self.attr;
        let mut out = [0u8; 32];
        out[0..11].copy_from_slice(&self.name);
        out[11] = attr;
        out[12] = self.reserved;
        out[13] = self.crt_time_tenths;
        out[14..16].copy_from_slice(&self.crt_time.to_le_bytes());
        out[16..18].copy_from_slice(&self.crt_date.to_le_bytes());
        out[18..20].copy_from_slice(&self.last_acc_date.to_le_bytes());
        out[20..22].copy_from_slice(&clus_hi.to_le_bytes());
        out[22..24].copy_from_slice(&self.mtime.to_le_bytes());
        out[24..26].copy_from_slice(&self.mdate.to_le_bytes());
        out[26..28].copy_from_slice(&clus_lo.to_le_bytes());
        out[28..32].copy_from_slice(&self.size.to_le_bytes());
        out
    }
}

impl Fat32LfnEntry {
    /// Create a new LFN entry
    ///
    /// `chars` holds up to 13 UTF-16 characters of the LFN. The function
    /// packs them into the 13-char slot (name1[5] + name2[6] + name3[2])
    /// and writes a U+0000 terminator in the first unused slot, with the
    /// remaining slots filled with U+FFFF padding. This matches the
    /// FAT specification ("If the last part does not fit 13 characters,
    /// it is terminated with a null character (U+0000) and rest of name
    /// field must be filled with U+FFFF").
    ///
    /// `last_piece` is `true` when this entry holds the LAST 13 characters
    /// of the LFN (i.e. sequence number equals the total LFN count). When
    /// set, the LDIR_Ord byte is OR'd with 0x40 to mark it as the final
    /// LFN slot in the sequence.
    pub fn new(chars: &[u16], seq: u8, checksum: u8, last_piece: bool) -> Self {
        let mut e = Self {
            seq: if last_piece { seq | 0x40 } else { seq },
            name1: [0xFFFF; 5],
            attr: 0x0F,
            lfn_type: 0,
            checksum,
            name2: [0xFFFF; 6],
            reserved: 0,
            name3: [0xFFFF; 2],
        };
        // Write the actual characters first.
        for (i, &c) in chars.iter().take(13).enumerate() {
            if i < 5 {
                e.name1[i] = c;
            } else if i < 11 {
                e.name2[i - 5] = c;
            } else {
                e.name3[i - 11] = c;
            }
        }
        // Terminate: if chars.len() < 13, write a U+0000 at position chars.len()
        // (the spec mandates this so firmware knows where the LFN ends) and
        // leave the remaining slots as the U+FFFF padding set above.
        if chars.len() < 13 {
            let term_idx = chars.len();
            if term_idx < 5 {
                e.name1[term_idx] = 0x0000;
            } else if term_idx < 11 {
                e.name2[term_idx - 5] = 0x0000;
            } else {
                e.name3[term_idx - 11] = 0x0000;
            }
        }
        e
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..5 {
            out[1 + i * 2] = (self.name1[i] & 0xFF) as u8;
            out[2 + i * 2] = ((self.name1[i] >> 8) & 0xFF) as u8;
        }
        out[11] = self.attr;
        out[12] = self.lfn_type;
        out[13] = self.checksum;
        for i in 0..6 {
            out[14 + i * 2] = (self.name2[i] & 0xFF) as u8;
            out[15 + i * 2] = ((self.name2[i] >> 8) & 0xFF) as u8;
        }
        out[26..28].copy_from_slice(&self.reserved.to_le_bytes());
        for i in 0..2 {
            out[28 + i * 2] = (self.name3[i] & 0xFF) as u8;
            out[29 + i * 2] = ((self.name3[i] >> 8) & 0xFF) as u8;
        }
        out[0] = self.seq;
        out
    }
}

// =====================================================================
// Cluster Allocator
// =====================================================================

/// FAT32 cluster allocator
pub struct ClusterAlloc {
    fat: Vec<u8>,
    max_clusters: usize,
    next_free: usize,
}

impl ClusterAlloc {
    /// Create a new cluster allocator
    pub fn new() -> Self {
        let fat_bytes = (FAT_SIZE_SECTORS * SECTOR_SIZE) as usize;
        let mut fat = vec![0u8; fat_bytes];
        fat[0..4].copy_from_slice(&0x0FFFFFF8u32.to_le_bytes());
        fat[4..8].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());
        let max_clusters = (fat_bytes / 4).min(0x0FFF_FFF0);
        Self { fat, max_clusters, next_free: 2 }
    }

    /// Allocate a new cluster
    pub fn alloc(&mut self) -> Option<u32> {
        for i in self.next_free..self.max_clusters {
            let entry = u32::from_le_bytes([self.fat[i * 4], self.fat[i * 4 + 1], self.fat[i * 4 + 2], self.fat[i * 4 + 3]]);
            if entry == 0 {
                self.fat[i * 4..i * 4 + 4].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());
                self.next_free = i + 1;
                return Some(i as u32);
            }
        }
        None
    }

    /// Get a reference to the FAT table
    pub fn get_fat(&self) -> &[u8] {
        &self.fat
    }

    /// Get a mutable reference to the FAT table
    pub fn get_fat_mut(&mut self) -> &mut [u8] {
        &mut self.fat
    }
}

// =====================================================================
// FAT32 Image Builder
// =====================================================================

/// Filesystem node for building directory trees
#[derive(Debug, Clone)]
pub enum FsNode {
    /// A file node with name and data
    File { name: String, data: Vec<u8> },
    /// A directory node with name and children
    Dir { name: String, children: Vec<FsNode> },
}

impl FsNode {
    /// Create a file node
    pub fn file(name: &str, data: Vec<u8>) -> Self {
        FsNode::File { name: name.to_string(), data }
    }

    /// Create a directory node
    pub fn dir(name: &str, children: Vec<FsNode>) -> Self {
        FsNode::Dir { name: name.to_string(), children }
    }
    
    /// Get mutable children reference for directory nodes
    pub fn dir_children_mut(&mut self) -> Option<&mut Vec<FsNode>> {
        match self {
            FsNode::Dir { children, .. } => Some(children),
            _ => None,
        }
    }
}

/// FAT32 image builder
pub struct Fat32ImageBuilder {
    alloc: ClusterAlloc,
    img: Vec<u8>,
    root_cluster: u32,
    sfn_counter: u32,
    size_sectors: u32,
    /// Partition offset in bytes (used when embedding FAT32 in a GPT partition)
    /// This is added to all absolute offsets when writing to the image
    partition_offset: usize,
}

impl Fat32ImageBuilder {
    /// Create a new FAT32 image builder
    /// 
    /// `partition_offset` specifies where the FAT32 partition starts within the image buffer.
    /// For a standalone FAT32 image, this is 0. For a GPT-embedded partition, this should
    /// be the partition's starting LBA * 512.
    pub fn new(size_mb: u32, partition_offset: usize) -> Self {
        let size_sectors = size_mb * 1024 * 1024 / SECTOR_SIZE as u32;
        Self {
            alloc: ClusterAlloc::new(),
            img: vec![0u8; (size_sectors * SECTOR_SIZE) as usize],
            root_cluster: 0,
            sfn_counter: 1,
            size_sectors,
            partition_offset,
        }
    }

    /// Get cluster offset in the image (relative to partition start)
    /// Note: For GPT-embedded FAT32, this returns the offset relative to the partition,
    /// NOT including partition_offset. The partition_offset is only used for hidd_sec
    /// in the BPB and when embedding the partition into a larger disk image.
    fn cluster_offset(&self, cluster: u32) -> usize {
        let first_data = RESERVED_SECTORS + NUM_FATS as u32 * FAT_SIZE_SECTORS;
        ((first_data + (cluster - 2) * SECTS_PER_CLUSTER as u32) * SECTOR_SIZE) as usize
    }

    /// Write data spanning one or more clusters.
    ///
    /// Allocates as many consecutive clusters as needed to hold `data`,
    /// writes the (padded) contents into them, and chains them in the FAT
    /// with the last cluster marked end-of-chain. Returns the first
    /// cluster number; for an empty input the returned cluster is 0 and
    /// no FAT entries are touched (the directory entry will mark a
    /// zero-length file, which is what callers expect for empty files).
    fn write_data(&mut self, data: &[u8]) -> u32 {
        if data.is_empty() {
            return 0;
        }
        let cluster_size = SECTOR_SIZE * SECTS_PER_CLUSTER as u32;
        // Round up to the number of whole clusters required.
        let num_clusters =
            ((data.len() as u32) + cluster_size - 1) / cluster_size;
        let first = match self.alloc.alloc() {
            Some(c) => c,
            None => panic!("out of clusters"),
        };
        let mut prev = first;
        for _i in 1..num_clusters {
            let next = match self.alloc.alloc() {
                Some(c) => c,
                None => panic!("out of clusters"),
            };
            // Chain prev -> next in the FAT.
            self.alloc.get_fat_mut()
                [prev as usize * 4..prev as usize * 4 + 4]
                .copy_from_slice(&next.to_le_bytes());
            prev = next;
        }
        // Mark the last cluster in the chain as end-of-chain.
        self.alloc.get_fat_mut()
            [prev as usize * 4..prev as usize * 4 + 4]
            .copy_from_slice(&0x0FFFFFFFu32.to_le_bytes());

        // Write the data, one cluster at a time.
        let mut off_in_data = 0usize;
        let mut cur = first;
        for _ in 0..num_clusters {
            let chunk_end = (off_in_data + cluster_size as usize).min(data.len());
            let chunk = &data[off_in_data..chunk_end];
            // Pad the final cluster to a full cluster boundary so the
            // on-disk layout is uniform.
            let mut padded = chunk.to_vec();
            padded.resize(cluster_size as usize, 0);
            let off = self.cluster_offset(cur);
            self.img[off..off + padded.len()].copy_from_slice(&padded);
            off_in_data = chunk_end;
            // Advance to the next cluster using the FAT chain.
            let next_entry = u32::from_le_bytes([
                self.alloc.get_fat()[cur as usize * 4],
                self.alloc.get_fat()[cur as usize * 4 + 1],
                self.alloc.get_fat()[cur as usize * 4 + 2],
                self.alloc.get_fat()[cur as usize * 4 + 3],
            ]);
            if next_entry >= 0x0FFFFFF8 {
                break;
            }
            cur = next_entry;
        }
        first
    }

    /// Write directory data to a cluster
    fn write_dir(&mut self, data: &[u8]) -> u32 {
        let cluster = self.alloc.alloc().expect("out of clusters");
        eprintln!("[DEBUG] Fat32ImageBuilder::write_dir: allocated cluster={}", cluster);
        let padded = pad_to_cluster(data, SECTOR_SIZE);
        let off = self.cluster_offset(cluster);
        eprintln!("[DEBUG] Fat32ImageBuilder::write_dir: writing {} bytes to offset={}", padded.len(), off);
        let end_off = off + padded.len();
        if end_off > self.img.len() {
            panic!("write_dir: buffer overflow! off=0x{:x} end=0x{:x} len=0x{:x}", off, end_off, self.img.len());
        }
        self.img[off..end_off].copy_from_slice(&padded);
        cluster
    }

    /// Generate SFN for long filenames
    /// 
    /// The algorithm must be kept in sync with the LFN generation logic in
    /// add_dir_entry and add_file_entry.
    pub fn make_sfn(&mut self, name: &str) -> [u8; 11] {
        let (base, ext) = if let Some(p) = name.rfind('.') {
            (&name[..p], Some(&name[p + 1..]))
        } else {
            (name, None)
        };
        
        // Filter to valid SFN characters (must match add_dir_entry/add_file_entry)
        let filtered_base: String = base.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '~')
            .collect();
        let filtered_ext: Option<String> = ext.map(|e| e.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect());
        
        // Check if we need LFN (same logic as in add_dir_entry)
        let needs_lfn = filtered_base.len() > 8 || filtered_ext.as_ref().map(|e| e.len() > 3).unwrap_or(false);
        
        let mut sfn = [b' '; 11];
        
        if !needs_lfn {
            // Short name: use full filtered base + extension
            let base_bytes = filtered_base.to_uppercase().into_bytes();
            sfn[..base_bytes.len()].copy_from_slice(&base_bytes);
        } else {
            // Long name: truncated base + ~N suffix
            let truncated: String = filtered_base.chars().take(6).collect();
            let suffix = format!("~{}", self.sfn_counter);
            let base_bytes = truncated.to_uppercase().into_bytes();
            sfn[..base_bytes.len()].copy_from_slice(&base_bytes);
            sfn[6..6 + suffix.len()].copy_from_slice(suffix.as_bytes());
            self.sfn_counter += 1;
        }
        
        if let Some(e) = filtered_ext {
            let ext_bytes = e.to_uppercase().into_bytes();
            sfn[8..8 + ext_bytes.len()].copy_from_slice(&ext_bytes);
        }
        
        sfn
    }
    
    /// Compute 8.3 checksum (used for LFN validation)
    pub fn compute_sfn_checksum(sfn: &[u8; 11]) -> u8 {
        checksum_83(sfn)
    }

    /// Add a file entry to a directory buffer
    fn add_file_entry(&mut self, buf: &mut Vec<u8>, name: &str, cluster: u32, size: u32) {
        self.emit_named_entry(buf, name, cluster, size, EntryKind::File);
    }

    /// Add a directory entry to a directory buffer
    fn add_dir_entry(&mut self, buf: &mut Vec<u8>, name: &str, cluster: u32) {
        self.emit_named_entry(buf, name, cluster, 0, EntryKind::Directory);
    }

    /// Common helper that emits a single named directory entry plus any
    /// preceding LFN slot(s).
    ///
    /// `kind` distinguishes directory entries (ATTR=0x10) from file entries
    /// (ATTR=0x20) so the SFN slot uses the right attribute byte.
    fn emit_named_entry(&mut self, buf: &mut Vec<u8>, name: &str, cluster: u32, size: u32, kind: EntryKind) {
        // Decide whether LFN is required (mirrors make_sfn: anything whose
        // 8.3 representation can't fit in 8+3 needs an LFN slot).
        let needs_lfn = self.requires_lfn(name);
        if needs_lfn {
            let sfn = self.make_sfn(name);
            let cs = checksum_83(&sfn);
            let utf16: Vec<u16> = name.encode_utf16().collect();
            let lfn_count = ((utf16.len() + 12) / 13) as u8;
            // LFN entries are written in DESCENDING sequence-number order:
            // the entry with the highest seq (LAST piece, bit 0x40 set) goes
            // FIRST in the directory, and the entry with seq=1 (FIRST 13
            // characters) goes immediately before the SFN slot. This matches
            // the FAT specification ("LDIR_Ord must start at 1 and be
            // recorded in descending order").
            //
            // See: https://elm-chan.org/docs/fat_e.html (LDIR_Ord table).
            for i in 0..lfn_count as usize {
                let seq = lfn_count - i as u8; // 1 = first/closest-to-SFN
                // Per FAT spec, the 0x40 bit is set on the LFN entry whose
                // sequence number equals the *total* LFN count (i.e. the
                // LAST piece of the long name). The seq=1 entry (FIRST 13
                // characters) does NOT carry the 0x40 bit.
                let is_last_piece = seq == lfn_count;
                // Each LFN slot covers 13 UTF-16 chars. Slot N (1-based,
                // starting at the SFN side) holds chars (N-1)*13..N*13.
                let start = (seq as usize - 1) * 13;
                let end = (start + 13).min(utf16.len());
                let e = Fat32LfnEntry::new(&utf16[start..end], seq, cs, is_last_piece);
                buf.extend_from_slice(&e.to_bytes());
            }
            let mut e = Fat32DirEntry::new_file_from_sfn(&sfn, cluster, size);
            if kind == EntryKind::Directory {
                e.attr = 0x10;
            }
            buf.extend_from_slice(&e.to_bytes());
        } else {
            let e = match kind {
                EntryKind::Directory => Fat32DirEntry::new_dir(name, cluster),
                EntryKind::File => Fat32DirEntry::new_file(name, cluster, size),
            };
            buf.extend_from_slice(&e.to_bytes());
        }
    }

    /// True iff `name` needs an LFN slot to round-trip the SFN lossily.
    /// Mirrors the filter in `make_sfn` so callers cannot drift apart.
    fn requires_lfn(&self, name: &str) -> bool {
        let (base, ext) = match name.rfind('.') {
            Some(p) => (&name[..p], Some(&name[p + 1..])),
            None => (name, None),
        };
        let filtered_base: String = base
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '~')
            .collect();
        let filtered_ext: Option<String> = ext.map(|e| {
            e.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect()
        });
        filtered_base.len() > 8 || filtered_ext.as_ref().map(|e| e.len() > 3).unwrap_or(false)
    }

    /// Process a filesystem node - writes files and returns cluster info
    #[allow(dead_code)]
    fn process_node(&mut self, node: &FsNode) -> (u32, bool) {
        match node {
            FsNode::File { name: _, data } => (self.write_data(data), false),
            FsNode::Dir { name: _, children: _ } => {
                // Don't recursively write here - that will be done by build_directory
                // Just return 0 as placeholder
                (0, true)
            }
        }
    }
    
    /// Build the filesystem with the given root children
    pub fn build(&mut self, children: Vec<FsNode>) {
        eprintln!("[DEBUG] Fat32ImageBuilder::build: children count={}", children.len());
        eprintln!("[DEBUG] Fat32ImageBuilder::build: partition_offset={}", self.partition_offset);
        // Build root directory with parent = 0 (root's parent is itself)
        let root_cluster = self.build_dir(children, 0);
        eprintln!("[DEBUG] Fat32ImageBuilder::build: root_cluster={}", root_cluster);
        self.root_cluster = root_cluster;
        
        // NOTE: Do NOT patch "." and ".." for the root directory here.
        // The root directory's "." and ".." both point to the root itself.
        // The build_dir function already handles this correctly when parent_cluster=0
        // because patch_dotdot is called with the same cluster for both.
        
        self.write_boot_sector(root_cluster);
        eprintln!("[DEBUG] Fat32ImageBuilder::build: done");
    }
    
    /// Build a directory and its subdirectories recursively
    /// Returns the cluster number of this directory
    fn build_dir(&mut self, children: Vec<FsNode>, parent_cluster: u32) -> u32 {
        // First, build all subdirectories
        let mut subdir_entries: Vec<(String, u32)> = Vec::new();
        for child in &children {
            if let FsNode::Dir { name, children: grandchildren } = child {
                let subdir_cluster = self.build_dir(grandchildren.clone(), 0);
                subdir_entries.push((name.clone(), subdir_cluster));
            }
        }
        
        // Write files and collect their clusters
        let mut file_entries: Vec<(String, u32, u32)> = Vec::new(); // (name, cluster, size)
        for child in &children {
            if let FsNode::File { name, data } = child {
                let cluster = self.write_data(data);
                file_entries.push((name.clone(), cluster, data.len() as u32));
            }
        }
        
        // Build directory buffer
        let mut dir_buf = Vec::new();
        dir_buf.extend_from_slice(&Fat32DirEntry::new_dir(".", 0).to_bytes());
        dir_buf.extend_from_slice(&Fat32DirEntry::new_dir("..", 0).to_bytes());
        
        // Add subdirectory entries
        for (name, cluster) in &subdir_entries {
            self.add_dir_entry(&mut dir_buf, name, *cluster);
        }
        
        // Add file entries with correct clusters
        for (name, cluster, size) in &file_entries {
            self.add_file_entry(&mut dir_buf, name, *cluster, *size);
        }
        
        let cluster = self.write_dir(&dir_buf);
        
        // Patch "." and ".." - this directory's parent
        self.patch_dotdot(cluster, parent_cluster);
        
        // Patch all subdirectories' ".." to point to us
        for (_, subdir_cluster) in &subdir_entries {
            self.patch_dotdot(*subdir_cluster, cluster);
        }
        
        cluster
    }
    
    /// Patch "." and ".." entries of a directory
    fn patch_dotdot(&mut self, dir_cluster: u32, parent_cluster: u32) {
        let off = self.cluster_offset(dir_cluster);
        let cl_lo = (dir_cluster & 0xFFFF) as u16;
        let cl_hi = ((dir_cluster >> 16) & 0xFFFF) as u16;
        let pcl_lo = (parent_cluster & 0xFFFF) as u16;
        let pcl_hi = ((parent_cluster >> 16) & 0xFFFF) as u16;
        
        // "." entry
        self.img[off + 20..off + 22].copy_from_slice(&cl_hi.to_le_bytes());
        self.img[off + 26..off + 28].copy_from_slice(&cl_lo.to_le_bytes());
        // ".." entry
        self.img[off + 52..off + 54].copy_from_slice(&pcl_hi.to_le_bytes());
        self.img[off + 58..off + 60].copy_from_slice(&pcl_lo.to_le_bytes());
    }

    /// Write the FAT32 boot sector
    fn write_boot_sector(&mut self, root_cluster: u32) {
        eprintln!("[DEBUG] Fat32ImageBuilder::write_boot_sector: root_cluster={}", root_cluster);
        eprintln!("[DEBUG] Fat32ImageBuilder::write_boot_sector: partition_offset={}", self.partition_offset);
        // FAT32 BPB layout (from Microsoft's FAT spec, rev 1.03):
        //   0x00  3   Jump boot code (0xEB 0x3C 0x90)
        //   0x03  8   OEM name ("FAT32   ")
        //   0x0B  2   Bytes per sector (0x0200 = 512)
        //   0x0D  1   Sectors per cluster
        //   0x0E  2   Reserved sector count
        //   0x10  1   Number of FATs
        //   0x11  2   Root entry count (0 for FAT32)
        //   0x13  2   Total sectors 16 (0 for FAT32)
        //   0x15  1   Media descriptor
        //   0x16  2   FAT size 16 (0 for FAT32)
        //   0x18  2   Sectors per track
        //   0x1A  2   Number of heads
        //   0x1C  4   Hidden sectors
        //   0x20  4   Total sectors 32  <-- this is what was missing
        //   0x24  4   Sectors per FAT   <-- was being written at 0x24 (off by 8)
        //   0x28  2   Extended flags
        //   0x2A  2   FS version
        //   0x2C  4   Root directory first cluster
        //   0x30  2   FSInfo sector
        //   0x32  2   Backup boot sector
        //   0x34  12  Reserved
        //   0x40  1   Drive number
        //   0x41  1   Reserved1
        //   0x42  1   Extended boot signature (0x29)
        //   0x43  4   Volume serial
        //   0x47  11  Volume label
        //   0x52  8   Filesystem type ("FAT32   ")
        //   0x1FE 2   Boot sector signature (0x55 0xAA)
        // Boot sector is ALWAYS at offset 0 within the FAT32 image.
        // The partition_offset only affects hidd_sec and cluster offset calculations.
        let sector = &mut self.img[0..512];
        sector.fill(0);
        sector[0] = 0xEB; sector[1] = 0x3C; sector[2] = 0x90;
        sector[3..11].copy_from_slice(b"FAT32   ");
        // Bytes per sector = 512 (little-endian 0x0200).
        sector[11] = 0x00; sector[12] = 0x02;
        sector[13] = SECTS_PER_CLUSTER;
        sector[14] = (RESERVED_SECTORS & 0xFF) as u8;
        sector[15] = ((RESERVED_SECTORS >> 8) & 0xFF) as u8;
        sector[16] = NUM_FATS;
        // RootEntCnt (17..19) and TotSec16 (19..21) are 0 for FAT32 — already zero.
        sector[21] = 0xF8;
        // FATSz16 (22..24) is 0 for FAT32 — already zero.
        sector[24] = 63 & 0xFF; sector[25] = ((63 >> 8) & 0xFF) as u8;
        sector[26] = 16 & 0xFF; sector[27] = ((16 >> 8) & 0xFF) as u8;
        // Hidden sectors (28..32): partition offset / 512 = starting LBA of partition
        // For standalone FAT32 (partition_offset=0), this is 0
        // For GPT-embedded FAT32, this is the partition's starting LBA
        let hidd_sec = (self.partition_offset / 512) as u32;
        sector[28] = (hidd_sec & 0xFF) as u8;
        sector[29] = ((hidd_sec >> 8) & 0xFF) as u8;
        sector[30] = ((hidd_sec >> 16) & 0xFF) as u8;
        sector[31] = ((hidd_sec >> 24) & 0xFF) as u8;
        // BPB_TotSec32 (0x20): total sectors in the volume. Without this
        // OVMF and other firmware treat the BPB as malformed and refuse to
        // mount the partition.
        let tot_sec = self.size_sectors;
        sector[32] = (tot_sec & 0xFF) as u8;
        sector[33] = ((tot_sec >> 8) & 0xFF) as u8;
        sector[34] = ((tot_sec >> 16) & 0xFF) as u8;
        sector[35] = ((tot_sec >> 24) & 0xFF) as u8;
        // BPB_FATSz32 (0x24): sectors per FAT.
        let fat_sz = FAT_SIZE_SECTORS;
        sector[36] = (fat_sz & 0xFF) as u8;
        sector[37] = ((fat_sz >> 8) & 0xFF) as u8;
        sector[38] = ((fat_sz >> 16) & 0xFF) as u8;
        sector[39] = ((fat_sz >> 24) & 0xFF) as u8;
        // BPB_ExtFlags (0x28) = 0; BPB_FSVer (0x2A) = 0.0 — both zero.
        // BPB_RootClus (0x2C): first cluster of the root directory.
        sector[44] = (root_cluster & 0xFF) as u8;
        sector[45] = ((root_cluster >> 8) & 0xFF) as u8;
        sector[46] = ((root_cluster >> 16) & 0xFF) as u8;
        sector[47] = ((root_cluster >> 24) & 0xFF) as u8;
        // BPB_FSInfo (0x30) = sector 1; BPB_BkBootSec (0x32) = sector 6.
        sector[48] = 1; sector[49] = 0;
        sector[50] = 6; sector[51] = 0;
        // BPB_Reserved (0x34..0x40) left zero.
        // BS_DrvNum (0x40) = 0x80 (first HDD).
        sector[64] = 0x80;
        // BS_Reserved1 (0x41) = 0 — already zero.
        // BS_BootSig (0x42) = 0x29.
        sector[66] = 0x29;
        // BS_VolID (0x43) = 0x35363131 (placeholder serial).
        sector[67] = 0x35; sector[68] = 0x36; sector[69] = 0x31; sector[70] = 0x31;
        // BS_VolLab (0x47) = "NO LABEL   ".
        sector[71..82].copy_from_slice(b"NO LABEL   ");
        // BS_FilSysType (0x52) = "FAT32   ".
        sector[82..90].copy_from_slice(b"FAT32   ");

        // FAT table offset within the partition (relative to partition start)
        let fat_off = (RESERVED_SECTORS * SECTOR_SIZE) as usize;
        let fat_size = (FAT_SIZE_SECTORS * SECTOR_SIZE) as usize;
        // Copy FAT1 (relative to partition start)
        self.img[fat_off..fat_off + fat_size].copy_from_slice(self.alloc.get_fat());
        // Copy FAT1 to FAT2 (required for FAT32)
        self.img[fat_off + fat_size..fat_off + 2 * fat_size].copy_from_slice(self.alloc.get_fat());
        // Boot sector signature (at offset 0 within partition)
        self.img[0 + 510] = 0x55;
        self.img[0 + 511] = 0xAA;

        // Write FSInfo sector (sector 1) - required for FAT32
        self.write_fsinfo();

        // Write backup boot sector (sector 6) - required for FAT32
        self.write_backup_boot_sector();
    }

    /// Write FSInfo sector (sector 1)
    /// 
    /// FSInfo contains free cluster count and next free cluster hint.
    /// Offset layout:
    ///   0x000: 4 bytes - "RRaA" signature
    ///   0x1E8: 4 bytes - reserved (0)
    ///   0x1EC: 4 bytes - free cluster count (0xFFFFFFFF = unknown)
    ///   0x1F0: 4 bytes - next free cluster hint (0xFFFFFFFF = unknown)
    ///   0x1F4: 12 bytes - reserved (0)
    ///   0x200: 4 bytes - "rrAA" signature (trailer)
    fn write_fsinfo(&mut self) {
        let fsinfo_off = (1 * SECTOR_SIZE) as usize;  // Sector 1
        let sector = &mut self.img[fsinfo_off..fsinfo_off + SECTOR_SIZE as usize];
        sector.fill(0);
        
        // FSInfo signature "RRaA" at offset 0
        sector[0..4].copy_from_slice(b"RRaA");
        
        // Reserved (offset 0x1E8 = 488)
        // Free cluster count at offset 0x1EC = 492 (0xFFFFFFFF = unknown)
        sector[492..496].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // Next free cluster at offset 0x1F0 = 496 (0xFFFFFFFF = unknown)
        sector[496..500].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        
        // Reserved (offset 0x1F4 = 500)
        // Trailer signature "rrAa" at offset 0x1FC (508)
        sector[508..512].copy_from_slice(b"rrAa");
    }

    /// Write backup boot sector (sector 6)
    /// 
    /// FAT32 requires a backup copy of the boot sector at sector 6.
    /// We copy the boot sector we just wrote (sector 0) to sector 6.
    fn write_backup_boot_sector(&mut self) {
        let backup_off = (6 * SECTOR_SIZE) as usize;  // Sector 6
        // Copy the boot sector to backup location
        // First borrow immutably to read, then borrow mutably to write
        let boot_sector_data: [u8; 512] = self.img[0..512].try_into().unwrap();
        self.img[backup_off..backup_off + 512].copy_from_slice(&boot_sector_data);
    }


    /// Get the image data
    pub fn into_image(self) -> Vec<u8> {
        self.img
    }

    /// Get image size in MB
    pub fn size_mb(&self) -> u32 {
        self.size_sectors / (1024 * 1024 / SECTOR_SIZE)
    }
}

/// High-level FAT32 image interface
pub struct Fat32Image {
    pub(crate) root_children: Vec<FsNode>,
    size_mb: u32,
}

impl Fat32Image {
    /// Create a new FAT32 image
    pub fn new(size_mb: u32) -> Self {
        Self {
            root_children: Vec::new(),
            size_mb,
        }
    }

    /// Parse an existing FAT32 image produced by this tool (round-trip with `finalize`).
    ///
    /// Walks the cluster chain starting at the BPB root cluster, decodes 32-byte
    /// directory entries (collapsing LFN entries back into long names) and
    /// returns an in-memory `FsNode` tree ready for further `create_dir` /
    /// `write_file` / `remove_path` operations. Subtrees that cannot be parsed
    /// (deeper unknown structures) are best-effort: their LFN-merged names are
    /// preserved even if the underlying cluster chain cannot be resolved.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 512 {
            return Err(BuildError::InvalidFormat(
                "image smaller than one sector".into(),
            ));
        }
        let bs = &data[..512];
        // Verify signature
        if bs[510] != 0x55 || bs[511] != 0xAA {
            return Err(BuildError::InvalidFormat(
                "missing boot sector signature 0x55AA".into(),
            ));
        }
        let fat_type = &bs[82..90];
        if fat_type != b"FAT32   " && fat_type != b"FAT16   " && fat_type != b"FAT12   " && fat_type != b"FAT     " {
            return Err(BuildError::InvalidFormat(format!(
                "not a FAT image (type tag = {:?})",
                std::str::from_utf8(fat_type).unwrap_or("?")
            )));
        }
        let reserved = u16::from_le_bytes([bs[14], bs[15]]) as u32;
        let num_fats = bs[16] as u32;
        let fat_size = u32::from_le_bytes([bs[36], bs[37], bs[38], bs[39]]);
        let root_cluster = u32::from_le_bytes([bs[44], bs[45], bs[46], bs[47]]);
        let spc = bs[13] as u32;
        if spc == 0 {
            return Err(BuildError::InvalidFormat("sectors-per-cluster is 0".into()));
        }
        let fat_start = reserved;
        let data_start = reserved + num_fats * fat_size;
        let cluster_size = spc * SECTOR_SIZE;

        let read_cluster = |cluster: u32| -> Option<&[u8]> {
            if cluster < 2 {
                return None;
            }
            let lba = data_start + (cluster - 2) * spc;
            let off = (lba * SECTOR_SIZE) as usize;
            data.get(off..off + cluster_size as usize)
        };

        let root_children = parse_dir_static(
            data,
            data_start,
            spc,
            cluster_size,
            fat_start,
            root_cluster,
            &read_cluster,
        )?;
        let size_mb = (data.len() / (1024 * 1024)) as u32;
        Ok(Self { root_children, size_mb: size_mb.max(1) })
    }

    /// Remove a path from the in-memory image (file or directory).
    /// Returns Ok(()) whether or not the path existed.
    pub fn remove_path(&mut self, path: &str) -> Result<()> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Ok(());
        }
        Self::remove_recursive(&mut self.root_children, &parts, 0);
        Ok(())
    }

    fn remove_recursive(children: &mut Vec<FsNode>, parts: &[&str], depth: usize) -> bool {
        if depth + 1 == parts.len() {
            let target = parts[depth];
            let before = children.len();
            children.retain(|c| match c {
                FsNode::File { name, .. } => !name.eq_ignore_ascii_case(target),
                FsNode::Dir { name, .. } => !name.eq_ignore_ascii_case(target),
            });
            return children.len() != before;
        }
        let dir_name = parts[depth];
        if let Some(idx) = children.iter().position(|c| matches!(c, FsNode::Dir { name, .. } if name.eq_ignore_ascii_case(dir_name))) {
            if let FsNode::Dir { children: c, .. } = &mut children[idx] {
                return Self::remove_recursive(c, parts, depth + 1);
            }
        }
        false
    }

    /// List the children of a directory path.
    pub fn list_dir(&self, path: &str) -> Result<Vec<(String, bool)>> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut cur: &Vec<FsNode> = &self.root_children;
        for p in &parts {
            match cur.iter().find(|c| matches!(c, FsNode::Dir { name, .. } if name.eq_ignore_ascii_case(p))) {
                Some(FsNode::Dir { children, .. }) => cur = children,
                _ => return Ok(Vec::new()),
            }
        }
        Ok(cur.iter().map(|c| match c {
            FsNode::File { name, .. } => (name.clone(), false),
            FsNode::Dir { name, .. } => (name.clone(), true),
        }).collect())
    }

    /// Read a file's bytes from the in-memory image. Returns MissingFile if
    /// the path does not exist or is a directory.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Err(BuildError::InvalidParam("empty path".into()));
        }
        let filename = parts.last().unwrap();
        let dir_parts = &parts[..parts.len() - 1];
        let mut cur: &Vec<FsNode> = &self.root_children;
        for p in dir_parts {
            match cur.iter().find(|c| matches!(c, FsNode::Dir { name, .. } if name.eq_ignore_ascii_case(p))) {
                Some(FsNode::Dir { children, .. }) => cur = children,
                _ => return Err(BuildError::MissingFile(path.into())),
            }
        }
        match cur.iter().find(|c| matches!(c, FsNode::File { name, .. } if name.eq_ignore_ascii_case(filename))) {
            Some(FsNode::File { data, .. }) => Ok(data.clone()),
            _ => Err(BuildError::MissingFile(path.into())),
        }
    }

    /// Create a directory in the image
    pub fn create_dir(&mut self, path: &str) -> Result<&mut Self> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        Self::create_dir_recursive(&mut self.root_children, &parts, 0);
        Ok(self)
    }

    fn create_dir_recursive(children: &mut Vec<FsNode>, parts: &[&str], depth: usize) {
        if depth >= parts.len() {
            return;
        }
        let name = parts[depth];
        
        // Find directory with the current name
        let mut dir_idx: Option<usize> = None;
        for (i, c) in children.iter().enumerate() {
            if let FsNode::Dir { name: n, .. } = c {
                if n.eq_ignore_ascii_case(name) {
                    dir_idx = Some(i);
                    break;
                }
            }
        }
        
        if let Some(idx) = dir_idx {
            // Directory exists - recurse into it
            if let FsNode::Dir { children: ref mut sub_children, .. } = &mut children[idx] {
                Self::create_dir_recursive(sub_children, parts, depth + 1);
            }
        } else {
            // Directory doesn't exist - create all remaining directories
            for i in depth..parts.len() {
                let mut new_children = Vec::new();
                // Create all remaining parts nested
                for j in (i + 1)..parts.len() {
                    new_children.push(FsNode::Dir {
                        name: parts[j].to_string(),
                        children: if j == parts.len() - 1 { Vec::new() } else { Vec::new() },
                    });
                }
                children.push(FsNode::Dir {
                    name: parts[i].to_string(),
                    children: new_children,
                });
            }
        }
    }

    /// Write a file to the image
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<&mut Self> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Err(BuildError::InvalidParam("Empty path".to_string()));
        }
        
        let filename = parts.last().unwrap();
        let dir_parts = &parts[..parts.len() - 1];
        
        Self::write_file_recursive(&mut self.root_children, dir_parts, filename, data.to_vec());
        Ok(self)
    }

    fn write_file_recursive(children: &mut Vec<FsNode>, dir_parts: &[&str], filename: &str, data: Vec<u8>) {
        if dir_parts.is_empty() {
            children.push(FsNode::file(filename, data));
        } else {
            let dir_name = dir_parts[0];
            let remaining = &dir_parts[1..];
            
            // Find existing directory or create it (case-sensitive)
            let dir_idx = children.iter().position(|c| match c {
                FsNode::Dir { name, .. } => name == dir_name,
                _ => false,
            });
            
            match dir_idx {
                Some(idx) => {
                    // Directory exists, recurse
                    if let FsNode::Dir { children: cc, .. } = &mut children[idx] {
                        Self::write_file_recursive(cc, remaining, filename, data);
                    }
                }
                None => {
                    // Create directory and all remaining
                    let last_idx = dir_parts.len() - 1;
                    for i in 0..last_idx {
                        let mut nested = Vec::new();
                        for j in (i + 1)..dir_parts.len() {
                            nested.push(FsNode::Dir {
                                name: dir_parts[j].to_string(),
                                children: if j == dir_parts.len() - 1 { Vec::new() } else { Vec::new() },
                            });
                        }
                        children.push(FsNode::Dir {
                            name: dir_parts[i].to_string(),
                            children: nested,
                        });
                    }
                    // Last directory gets the file
                    children.push(FsNode::Dir {
                        name: dir_parts[last_idx].to_string(),
                        children: vec![FsNode::file(filename, data)],
                    });
                }
            }
        }
    }

    /// Build the FAT32 image and return the raw bytes
    /// 
    /// For a standalone FAT32 image, `partition_offset` should be 0.
    /// For a GPT-embedded partition, it should be the partition's starting LBA * 512.
    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        // For standalone FAT32 images, partition_offset is 0
        let mut builder = Fat32ImageBuilder::new(self.size_mb, 0);
        builder.build(std::mem::take(&mut self.root_children));
        Ok(builder.into_image())
    }

    /// Build the FAT32 image with a specific partition offset.
    /// This is useful when embedding FAT32 within a GPT partition.
    pub fn finalize_with_offset(&mut self, partition_offset: usize) -> Result<Vec<u8>> {
        eprintln!("[DEBUG] Fat32Image::finalize_with_offset: partition_offset={}", partition_offset);
        eprintln!("[DEBUG] Fat32Image::finalize_with_offset: root_children count={}", self.root_children.len());
        let mut builder = Fat32ImageBuilder::new(self.size_mb, partition_offset);
        builder.build(std::mem::take(&mut self.root_children));
        let img = builder.into_image();
        eprintln!("[DEBUG] Fat32Image::finalize_with_offset: image size={}", img.len());
        Ok(img)
    }

    /// Get the image size in MB
    pub fn size_mb(&self) -> u32 {
        self.size_mb
    }
}

impl FsBackend for Fat32Image {
    fn kind(&self) -> &'static str { "fat32" }

    fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        // Find the matching directory node.
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut cur: &Vec<FsNode> = &self.root_children;
        for p in &parts {
            match cur.iter().find(|c| matches!(c, FsNode::Dir { name, .. } if name.eq_ignore_ascii_case(p))) {
                Some(FsNode::Dir { children, .. }) => cur = children,
                _ => return Ok(Vec::new()),
            }
        }
        let mut out = Vec::new();
        for n in cur {
            match n {
                FsNode::File { name, data } => out.push(DirEntry::file(name.clone(), data.len() as u64)),
                FsNode::Dir { name, .. } => out.push(DirEntry::dir(name.clone())),
            }
        }
        Ok(out)
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        Fat32Image::read_file(self, path)
    }

    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        Fat32Image::write_file(self, path, data)?;
        Ok(())
    }

    fn mkdir(&mut self, path: &str) -> Result<()> {
        Fat32Image::create_dir(self, path)?;
        Ok(())
    }

    fn remove(&mut self, path: &str) -> Result<()> {
        Fat32Image::remove_path(self, path)
    }

    fn finalize(&mut self) -> Result<Vec<u8>> {
        Fat32Image::finalize(self)
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}

// =====================================================================
// GPT Header Writer
// =====================================================================

/// Write a GPT header to the image buffer
pub fn write_gpt_header(img: &mut [u8], disk_size: u64, esp_lba: u64, esp_size: u64) {
    // GPT signature
    img[0..8].copy_from_slice(b"EFI PART");
    // Revision
    img[8..12].copy_from_slice(&1u32.to_le_bytes());
    // Header size
    img[12..16].copy_from_slice(&92u32.to_le_bytes());
    // CRC32 of header (will be 0 for now)
    img[16..20].copy_from_slice(&0u32.to_le_bytes());
    // Reserved
    for i in 0..4 { img[20 + i] = 0; }
    // My LBA (1)
    img[24..32].copy_from_slice(&1u64.to_le_bytes());
    // Alternate LBA
    let alt_lba = disk_size / SECTOR_SIZE as u64 - 1;
    img[32..40].copy_from_slice(&alt_lba.to_le_bytes());
    // First usable LBA (34)
    img[48..56].copy_from_slice(&34u64.to_le_bytes());
    // Last usable LBA
    img[56..64].copy_from_slice(&(alt_lba - 34).to_le_bytes());
    // Disk GUID
    let guid = uuid::Uuid::new_v4();
    img[56..72].copy_from_slice(guid.as_bytes());
    // Partition entry LBA (2)
    img[72..80].copy_from_slice(&2u64.to_le_bytes());
    // Number of partition entries (128)
    img[80..84].copy_from_slice(&128u32.to_le_bytes());
    // Size of partition entry (128 bytes)
    img[84..88].copy_from_slice(&128u32.to_le_bytes());
    // CRC32 of partition entries (0 for now)
    img[88..92].copy_from_slice(&0u32.to_le_bytes());

    // Protective MBR at LBA 0
    img[446..510].fill(0);
    img[446] = 0x80; // Boot indicator
    img[447..451].copy_from_slice(&PARTITION_TYPE_EFI[0..4]); // Start CHS
    img[451] = 0x01; // End head
    img[452] = 0x01; // End sector/cylinder
    img[453] = 0x00;
    img[454..458].copy_from_slice(&(esp_lba as u32).to_le_bytes()); // Starting LBA
    img[458..462].copy_from_slice(&(esp_size as u32).to_le_bytes()); // Size in LBA
    img[510] = 0x55;
    img[511] = 0xAA;
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sfn_conversion() {
        let sfn = to_sfn("BOOTX64.EFI");
        assert_eq!(&sfn, b"BOOTX64 EFI");

        let sfn = to_sfn("test.txt");
        assert_eq!(&sfn, b"TEST    TXT");
    }

    #[test]
    fn test_lfn_checksum() {
        let sfn = b"BOOTX64 EFI";
        let cs = checksum_83(sfn);
        assert_eq!(cs, 0x1D); // Expected checksum for "BOOTX64 EFI"
    }

    #[test]
    fn test_fat32_image() {
        let mut img = Fat32Image::new(64);
        img.create_dir("EFI").unwrap();
        img.create_dir("EFI/Boot").unwrap();
        img.write_file("EFI/Boot/BOOTX64.EFI", b"boot data").unwrap();

        let data = img.finalize().unwrap();
        assert!(data.len() > 0);
        assert_eq!(data[510], 0x55);
        assert_eq!(data[511], 0xAA);
    }

    #[test]
    fn dir_entry_layout() {
        let e = Fat32DirEntry::new_dir("EFI", 4);
        let b = e.to_bytes();
        println!("{:02x?}", &b);
        assert_eq!(&b[0..3], b"EFI");
        assert_eq!(b[11], 0x10);
        // clus_hi (bytes 20-21) must be 0, clus_lo (bytes 26-27) must be 4
        assert_eq!(&b[20..22], &[0, 0], "clus_hi should be 0, got {:02x?}", &b[20..22]);
        assert_eq!(&b[26..28], &[4, 0], "clus_lo should be 4, got {:02x?}", &b[26..28]);
    }
}
