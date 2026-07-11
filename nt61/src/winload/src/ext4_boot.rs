//! Minimal EXT4 boot-sector reader for winload.efi and bootmgr.efi.
//!
//! UEFI's `SimpleFileSystem` protocol only supports FAT-family volumes by
//! default. When the System partition is formatted as EXT4, winload (and
//! bootmgr, when reading winload.efi) fall back to this in-tree reader
//! to resolve `\Windows\System32\...` paths.
//!
//! The design mirrors the NTFS reader (`ntfs_boot.rs`). Both walk the
//! filesystem via the partition's on-disk data structures and rely on
//! UEFI's `BlockIO` protocol for sector I/O.
//!
//! ## Layout assumptions
//!
//! The reader supports the minimal EXT4 image layout produced by our
//! build tool (`tools/src/fs/ext4.rs`):
//!
//!   * 4096-byte blocks
//!   * inode size = 256
//!   * linear directory entries (no hash-tree)
//!   * extent trees of depth 0 or 1
//!   * no journal replay, no xattr blocks
//!   * 32-bit block group descriptors
//!
//! ## Filesystem walk
//!
//! 1. Probe the boot sector at LBA 0 for `0xEF53` at byte 56 of the
//!    superblock (offset 1024 + 56 = 1080 from the partition start).
//! 2. Parse superblock fields we need (`s_log_block_size`, `s_inode_size`,
//!    `s_blocks_per_group`, `s_inodes_per_group`, `s_first_data_block`).
//! 3. Read the BGDT at the first-data-block + 1 block to find the inode
//!    table for group 0.
//! 4. Read `inode 2` (root directory), walk its extents to get the dir
//!    block, scan entries to find the next path component.
//! 5. Repeat down the tree.

use alloc::string::String;
use alloc::vec::Vec;
use uefi::proto::media::block::BlockIO;

// =====================================================================
// Constants
// =====================================================================

const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_FT_DIR: u8 = 2;
const EXT4_FT_REG_FILE: u8 = 1;
/// Inode number for the root directory. EXT4 always uses 2.
const EXT4_ROOT_INO: u32 = 2;

// =====================================================================
// BlockIO sector read helper
// =====================================================================

/// Read `count` sectors starting at `lba` from the given BlockIO handle.
fn read_partition_sectors(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    start_lba: u64,
    count: u32,
) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity((count as usize) * 512);
    buf.resize((count as usize) * 512, 0u8);
    // Read one sector at a time to avoid large stack frames.
    for i in 0..count as usize {
        let sector_buf = &mut buf[i * 512..(i + 1) * 512];
        if block_io.read_blocks(media_id, start_lba + i as u64, sector_buf).is_err() {
            return None;
        }
    }
    Some(buf)
}

// =====================================================================
// Superblock
// =====================================================================

/// Parsed EXT4 superblock (subset of fields we need).
struct Ext4Boot {
    block_size: u32,
    inode_size: u16,
    blocks_per_group: u32,
    inodes_per_group: u32,
    first_data_block: u32,
}

impl Ext4Boot {
    fn parse(buf: &[u8; 1024]) -> Option<Self> {
        // Magic is at offset 56 within the superblock.
        let magic = u16::from_le_bytes([buf[56], buf[57]]);
        if magic != EXT4_MAGIC {
            return None;
        }
        let s_log_block_size = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let block_size: u32 = 1024u32 << s_log_block_size;
        if block_size != 1024 && block_size != 2048 && block_size != 4096 {
            return None;
        }
        let inode_size = u16::from_le_bytes([buf[88], buf[89]]);
        if inode_size < 128 {
            return None;
        }
        let blocks_per_group = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let inodes_per_group = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);
        let first_data_block = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        Some(Ext4Boot {
            block_size,
            inode_size,
            blocks_per_group,
            inodes_per_group,
            first_data_block,
        })
    }
}

// =====================================================================
// Inode reading
// =====================================================================

/// Read a single EXT4 inode into a fresh buffer.
fn read_inode(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ext4: &Ext4Boot,
    inode_num: u32,
    inode_table_block: u32,
) -> Option<Vec<u8>> {
    if inode_num == 0 {
        return None;
    }
    let local = (inode_num - 1) % ext4.inodes_per_group;
    let block_in_table = (local * (ext4.inode_size as u32)) / ext4.block_size;
    let lba = inode_table_block + block_in_table;
    let sectors_per_block = (ext4.block_size / 512) as u32;
    let data = read_partition_sectors(block_io, media_id, lba as u64, sectors_per_block)?;
    let offset_in_block = ((local * (ext4.inode_size as u32)) % ext4.block_size) as usize;
    if offset_in_block + ext4.inode_size as usize > data.len() {
        return None;
    }
    Some(data[offset_in_block..offset_in_block + ext4.inode_size as usize].to_vec())
}

/// Extract the i_size_lo and i_block[15] fields from an inode buffer.
fn parse_inode(inode: &[u8]) -> Option<(u32, [u32; 15])> {
    if inode.len() < 160 {
        return None;
    }
    let i_size_lo = u32::from_le_bytes([inode[4], inode[5], inode[6], inode[7]]);
    let mut i_block = [0u32; 15];
    for i in 0..15 {
        let off = 40 + i * 4;
        i_block[i] = u32::from_le_bytes([inode[off], inode[off + 1], inode[off + 2], inode[off + 3]]);
    }
    Some((i_size_lo, i_block))
}

/// Walk an inode's extent tree and return the bytes of the file's data.
/// Supports depth-0 extents (a single extent entry describes up to
/// 32768 blocks) and depth-1 extents (an internal node points at leaf
/// blocks containing extent entries).
fn read_extents(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ext4: &Ext4Boot,
    i_block: &[u32; 15],
    size: u32,
) -> Option<Vec<u8>> {
    let eh_magic = (i_block[0] & 0xFFFF) as u16;
    if eh_magic != 0xF30A {
        // Not an extent tree; cannot read direct/indirect block pointers
        // here. Return None.
        return None;
    }
    let eh_entries = (i_block[0] >> 16) as u16;
    let eh_depth = (i_block[1] >> 16) as u16;

    let mut out = Vec::with_capacity(size as usize);
    let mut bytes_left = size as usize;

    if eh_depth == 0 {
        for i in 0..eh_entries as usize {
            let entry_start = 3 + i * 3;
            if entry_start + 3 > 15 { break; }
            let w0 = i_block[entry_start];
            let w1 = i_block[entry_start + 1];
            let w2 = i_block[entry_start + 2];
            let ee_block = w0;
            let ee_len = (w1 & 0xFFFF) as u16 as u32;
            let ee_start_hi = (w1 >> 16) & 0xFFFF;
            let ee_start_lo = w2;
            let _ = ee_block;
            if ee_len == 0 { break; }
            let physical = ((ee_start_hi << 16) | ee_start_lo) as u32;
            let blk_bytes = (ee_len as usize) * (ext4.block_size as usize);
            let sectors = ((ee_len as u32) * (ext4.block_size / 512)) as u32;
            let data = read_partition_sectors(block_io, media_id, physical as u64 * (ext4.block_size / 512) as u64, sectors)?;
            let take = blk_bytes.min(bytes_left);
            out.extend_from_slice(&data[..take]);
            bytes_left -= take;
            if bytes_left == 0 { break; }
        }
    } else if eh_depth == 1 {
        for i in 0..eh_entries as usize {
            let entry_start = 3 + i * 3;
            if entry_start + 3 > 15 { break; }
            let w0 = i_block[entry_start];
            let w1 = i_block[entry_start + 1];
            let w2 = i_block[entry_start + 2];
            let ei_block = w0 & 0xFFFF;
            let ei_leaf_lo = w1;
            let ei_leaf_hi = (w2 >> 16) & 0xFFFF;
            let leaf_block = ((ei_leaf_hi << 16) | ei_leaf_lo) as u32;
            let leaf_lba = leaf_block as u64 * (ext4.block_size / 512) as u64;
            let sectors_per_block = ext4.block_size / 512;
            let leaf = read_partition_sectors(block_io, media_id, leaf_lba, sectors_per_block)?;
            // Parse leaf extent header.
            let lh_magic = u16::from_le_bytes([leaf[0], leaf[1]]);
            if lh_magic != 0xF30A { continue; }
            let lh_entries = u16::from_le_bytes([leaf[2], leaf[3]]);
            for j in 0..lh_entries as usize {
                let e_off = 12 + j * 12;
                if e_off + 12 > leaf.len() { break; }
                let e_w0 = u32::from_le_bytes([leaf[e_off], leaf[e_off + 1], leaf[e_off + 2], leaf[e_off + 3]]);
                let e_w1 = u32::from_le_bytes([leaf[e_off + 4], leaf[e_off + 5], leaf[e_off + 6], leaf[e_off + 7]]);
                let e_w2 = u32::from_le_bytes([leaf[e_off + 8], leaf[e_off + 9], leaf[e_off + 10], leaf[e_off + 11]]);
                let _ = e_w0;
                let ee_len = (e_w1 & 0xFFFF) as u32;
                let ee_start_hi = (e_w1 >> 16) & 0xFFFF;
                let ee_start_lo = e_w2;
                if ee_len == 0 { break; }
                let physical = ((ee_start_hi << 16) | ee_start_lo) as u32;
                let blk_bytes = (ee_len as usize) * (ext4.block_size as usize);
                let sectors = ((ee_len as u32) * (ext4.block_size / 512)) as u32;
                let data = read_partition_sectors(block_io, media_id, physical as u64 * (ext4.block_size / 512) as u64, sectors)?;
                let take = blk_bytes.min(bytes_left);
                out.extend_from_slice(&data[..take]);
                bytes_left -= take;
                if bytes_left == 0 { break; }
            }
            let _ = ei_block;
            if bytes_left == 0 { break; }
        }
    } else {
        return None;
    }
    out.truncate(size as usize);
    Some(out)
}

// =====================================================================
// Directory walking
// =====================================================================

/// Scan a directory block for an entry with the given name (case
/// sensitive — EXT4 stores names verbatim). Returns the inode number
/// of the matching entry.
fn find_child_in_dir(
    dir_data: &[u8],
    target: &str,
) -> Option<u32> {
    let mut off = 0usize;
    while off + 8 <= dir_data.len() {
        let inode_num = u32::from_le_bytes([dir_data[off], dir_data[off + 1], dir_data[off + 2], dir_data[off + 3]]);
        let rec_len = u16::from_le_bytes([dir_data[off + 4], dir_data[off + 5]]) as usize;
        let name_len = dir_data[off + 6] as usize;
        let _file_type = dir_data[off + 7];
        if rec_len == 0 || rec_len > dir_data.len() - off { break; }
        if inode_num != 0 && name_len > 0 && name_len + 8 <= rec_len {
            if let Ok(name) = core::str::from_utf8(&dir_data[off + 8..off + 8 + name_len]) {
                if name == target {
                    return Some(inode_num);
                }
            }
        }
        off += rec_len;
    }
    None
}

/// Resolve a Windows-style path (e.g. `\Windows\System32\winload.efi`)
/// starting at `start_ino` to an inode number.
fn resolve_path(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ext4: &Ext4Boot,
    inode_table_block: u32,
    start_ino: u32,
    path: &str,
) -> Option<u32> {
    let parts: Vec<&str> = path
        .trim_start_matches('\\')
        .split('\\')
        .filter(|s| !s.is_empty())
        .collect();
    let mut current = start_ino;
    for part in &parts {
        let inode = read_inode(block_io, media_id, ext4, current, inode_table_block)?;
        let (size, i_block) = parse_inode(&inode)?;
        let dir_data = read_extents(block_io, media_id, ext4, &i_block, size)?;
        current = find_child_in_dir(&dir_data, part)?;
    }
    Some(current)
}

// =====================================================================
// Public entry point
// =====================================================================

/// Read a file from the EXT4 System partition by path.
/// Returns `None` if the path cannot be resolved (EXT4 not detected,
/// path not found, or I/O error).
pub fn read_ext4_system_file(path: &str) -> Option<Vec<u8>> {
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::media::block::BlockIO;

    let handles = uefi::boot::find_handles::<BlockIO>().ok()?;

    for handle in handles.iter() {
        let sp = unsafe {
            uefi::boot::open_protocol::<BlockIO>(
                OpenProtocolParams {
                    handle: *handle,
                    agent: uefi::boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        let Ok(block) = sp else { continue };
        let Some(block_ref) = block.get() else {
            core::mem::forget(block);
            continue;
        };
        let media = block_ref.media();
        if media.block_size() != 512 {
            core::mem::forget(block);
            continue;
        }
        // Skip whole-disk handle.
        if !media.is_logical_partition() {
            core::mem::forget(block);
            continue;
        }

        let this_media_id = media.media_id();

        // Read the superblock: at byte offset 1024 within the partition.
        let mut sb_buf = [0u8; 1024];
        if block_ref.read_blocks(this_media_id, 2u64, &mut sb_buf).is_err() {
            core::mem::forget(block);
            continue;
        }
        // Verify magic.
        let magic = u16::from_le_bytes([sb_buf[56], sb_buf[57]]);
        if magic != EXT4_MAGIC {
            core::mem::forget(block);
            continue;
        }
        let ext4 = match Ext4Boot::parse(&sb_buf) {
            Some(e) => e,
            None => {
                core::mem::forget(block);
                continue;
            }
        };

        // Read BGDT at block (first_data_block + 1).
        let bgdt_lba = ((ext4.first_data_block + 1) as u64) * ((ext4.block_size / 512) as u64);
        let mut bgdt = [0u8; 64];
        if block_ref.read_blocks(this_media_id, bgdt_lba, &mut bgdt).is_err() {
            core::mem::forget(block);
            continue;
        }
        let inode_table_block = u32::from_le_bytes([bgdt[8], bgdt[9], bgdt[10], bgdt[11]]);
        if inode_table_block == 0 {
            core::mem::forget(block);
            continue;
        }

        // Resolve path -> inode.
        let target_ino = match resolve_path(
            &*block_ref, this_media_id, &ext4, inode_table_block, EXT4_ROOT_INO, path
        ) {
            Some(i) => i,
            None => {
                core::mem::forget(block);
                continue;
            }
        };

        // Read target inode.
        let inode = read_inode(&*block_ref, this_media_id, &ext4, target_ino, inode_table_block)?;
        let (size, i_block) = parse_inode(&inode)?;
        let data = read_extents(&*block_ref, this_media_id, &ext4, &i_block, size);

        core::mem::forget(block);
        return data;
    }

    None
}

/// Read a file from the EXT4 partition that contains the BCD.
/// Used by bootmgr when reading `EFI\Microsoft\Boot\BCD` from an EXT4
/// ESP. Same logic as `read_ext4_system_file` but starts at root.
pub fn read_ext4_partition_file(path: &str) -> Option<Vec<u8>> {
    read_ext4_system_file(path)
}

/// Probe a BlockIO handle for an EXT4 partition and dump a brief
/// diagnostic line. Used during boot to decide whether to enable the
/// EXT4 fallback path.
pub fn probe_ext4_partition() -> Option<(u32, u32, u32)> {
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::media::block::BlockIO;

    let handles = uefi::boot::find_handles::<BlockIO>().ok()?;
    for handle in handles.iter() {
        let sp = unsafe {
            uefi::boot::open_protocol::<BlockIO>(
                OpenProtocolParams {
                    handle: *handle,
                    agent: uefi::boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        let Ok(block) = sp else { continue };
        let Some(block_ref) = block.get() else {
            core::mem::forget(block);
            continue;
        };
        let media = block_ref.media();
        if media.block_size() != 512 {
            core::mem::forget(block);
            continue;
        }
        if !media.is_logical_partition() {
            core::mem::forget(block);
            continue;
        }
        let this_media_id = media.media_id();
        let mut sb_buf = [0u8; 1024];
        if block_ref.read_blocks(this_media_id, 2u64, &mut sb_buf).is_err() {
            core::mem::forget(block);
            continue;
        }
        let magic = u16::from_le_bytes([sb_buf[56], sb_buf[57]]);
        if magic != EXT4_MAGIC {
            core::mem::forget(block);
            continue;
        }
        let ext4 = Ext4Boot::parse(&sb_buf)?;
        core::mem::forget(block);
        return Some((ext4.block_size, ext4.inode_size as u32, ext4.first_data_block));
    }
    None
}

/// Diagnostic helper that logs the EXT4 partition layout if found.
pub fn log_ext4_layout() {
    if let Some((bs, is, fdb)) = probe_ext4_partition() {
        uefi::println!("[EXT4] probe: block_size={} inode_size={} first_data_block={}",
                       bs, is, fdb);
    } else {
        uefi::println!("[EXT4] probe: no EXT4 partition found");
    }
}

// Suppress dead-code warnings for diagnostic helpers.
#[allow(dead_code)]
fn _unused(_s: &str) { let _ = String::from(_s); let _ = _unused; }