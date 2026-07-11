//! Minimal EXT4 boot-sector reader for bootmgr.efi.
//!
//! UEFI's `SimpleFileSystem` protocol only supports FAT-family volumes by
//! default. When the System partition is formatted as EXT4, bootmgr (when
//! loading `winload.efi`) falls back to this in-tree reader to resolve
//! `\Windows\System32\winload.efi`.
//!
//! This module is a *port* of `winload/src/ext4_boot.rs` to bootmgr's
//! module layout. The boot manager already classifies BlockIO handles
//! through a single partition-type probe, so we expose a handle-taking
//! helper [`read_ext4_with_block`] that the dispatcher calls once it
//! has identified an EXT4 partition. The convenience wrapper
//! [`read_ext4_system_file`] keeps the legacy "scan all handles"
//! behaviour for callers that do not yet use the dispatcher.
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
///
/// `inode_table_lba` is the **absolute** disk LBA of the start of the
/// inode table (i.e. `partition_start_lba + inode_table_block`).
fn read_inode(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ext4: &Ext4Boot,
    inode_num: u32,
    inode_table_lba: u64,
) -> Option<Vec<u8>> {
    if inode_num == 0 {
        return None;
    }
    let local = (inode_num - 1) % ext4.inodes_per_group;
    let block_in_table = (local * (ext4.inode_size as u32)) / ext4.block_size;
    let sectors_per_block = (ext4.block_size / 512) as u64;
    // inode_table_lba is the absolute disk LBA of the inode table
    // start. block_in_table is a block index (1 unit = block_size
    // bytes). Convert block_in_table to sectors before adding to the
    // LBA; otherwise we under-read by `block_in_table * 8` sectors
    // and pick up the wrong inode.
    let lba = inode_table_lba + block_in_table as u64 * sectors_per_block;
    let data = read_partition_sectors(block_io, media_id, lba, sectors_per_block as u32)?;
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
///
/// `partition_start_lba` is the disk-relative LBA of the partition's
/// first sector; it is added to every extent LBA before the disk read.
fn read_extents(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ext4: &Ext4Boot,
    i_block: &[u32; 15],
    size: u32,
    partition_start_lba: u64,
) -> Option<Vec<u8>> {
    let eh_magic = (i_block[0] & 0xFFFF) as u16;
    if eh_magic != 0xF30A {
        return None;
    }
    let eh_entries = (i_block[0] >> 16) as u16;
    let eh_depth = (i_block[1] >> 16) as u16;

    let mut out = Vec::with_capacity(size as usize);
    let mut bytes_left = size as usize;

    if eh_depth == 0 {
        for i in 0..eh_entries as usize {
            let entry_start = 3 + i * 3;
            if entry_start + 3 > 15 {
                break;
            }
            let w0 = i_block[entry_start];
            let w1 = i_block[entry_start + 1];
            let w2 = i_block[entry_start + 2];
            let _ee_block = w0;
            let ee_len = (w1 & 0xFFFF) as u32;
            let ee_start_hi = (w1 >> 16) & 0xFFFF;
            let ee_start_lo = w2;
            if ee_len == 0 {
                break;
            }
            let physical = ((ee_start_hi << 16) | ee_start_lo) as u32;
            let blk_bytes = (ee_len as usize) * (ext4.block_size as usize);
            let sectors = ((ee_len as u32) * (ext4.block_size / 512)) as u32;
            let lba = partition_start_lba + (physical as u64) * (ext4.block_size / 512) as u64;
            let data = read_partition_sectors(block_io, media_id, lba, sectors)?;
            let take = blk_bytes.min(bytes_left);
            out.extend_from_slice(&data[..take]);
            bytes_left -= take;
            if bytes_left == 0 {
                break;
            }
        }
    } else if eh_depth == 1 {
        for i in 0..eh_entries as usize {
            let entry_start = 3 + i * 3;
            if entry_start + 3 > 15 {
                break;
            }
            let w0 = i_block[entry_start];
            let w1 = i_block[entry_start + 1];
            let w2 = i_block[entry_start + 2];
            let _ei_block = w0 & 0xFFFF;
            let ei_leaf_lo = w1;
            let ei_leaf_hi = (w2 >> 16) & 0xFFFF;
            let leaf_block = ((ei_leaf_hi << 16) | ei_leaf_lo) as u32;
            let leaf_lba =
                partition_start_lba + (leaf_block as u64) * (ext4.block_size / 512) as u64;
            let sectors_per_block = ext4.block_size / 512;
            let leaf = read_partition_sectors(block_io, media_id, leaf_lba, sectors_per_block)?;
            let lh_magic = u16::from_le_bytes([leaf[0], leaf[1]]);
            if lh_magic != 0xF30A {
                continue;
            }
            let lh_entries = u16::from_le_bytes([leaf[2], leaf[3]]);
            for j in 0..lh_entries as usize {
                let e_off = 12 + j * 12;
                if e_off + 12 > leaf.len() {
                    break;
                }
                let e_w0 = u32::from_le_bytes([
                    leaf[e_off], leaf[e_off + 1], leaf[e_off + 2], leaf[e_off + 3],
                ]);
                let e_w1 = u32::from_le_bytes([
                    leaf[e_off + 4], leaf[e_off + 5], leaf[e_off + 6], leaf[e_off + 7],
                ]);
                let e_w2 = u32::from_le_bytes([
                    leaf[e_off + 8], leaf[e_off + 9], leaf[e_off + 10], leaf[e_off + 11],
                ]);
                let _ = e_w0;
                let ee_len = (e_w1 & 0xFFFF) as u32;
                let ee_start_hi = (e_w1 >> 16) & 0xFFFF;
                let ee_start_lo = e_w2;
                if ee_len == 0 {
                    break;
                }
                let physical = ((ee_start_hi << 16) | ee_start_lo) as u32;
                let blk_bytes = (ee_len as usize) * (ext4.block_size as usize);
                let sectors = ((ee_len as u32) * (ext4.block_size / 512)) as u32;
                let lba = partition_start_lba + (physical as u64) * (ext4.block_size / 512) as u64;
                let data = read_partition_sectors(block_io, media_id, lba, sectors)?;
                let take = blk_bytes.min(bytes_left);
                out.extend_from_slice(&data[..take]);
                bytes_left -= take;
                if bytes_left == 0 {
                    break;
                }
            }
            if bytes_left == 0 {
                break;
            }
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
///
/// `inode_table_lba` is the **absolute** disk LBA of the inode table.
/// `partition_start_lba` is added to every extent LBA before the disk
/// read so the path walker works with both partition-scoped and
/// disk-scoped BlockIO handles.
fn resolve_path(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ext4: &Ext4Boot,
    inode_table_lba: u64,
    start_ino: u32,
    path: &str,
    partition_start_lba: u64,
) -> Option<u32> {
    let parts: Vec<&str> = path
        .trim_start_matches('\\')
        .split('\\')
        .filter(|s| !s.is_empty())
        .collect();
    let mut current = start_ino;
    for part in &parts {
        let inode = read_inode(block_io, media_id, ext4, current, inode_table_lba)?;
        let (size, i_block) = parse_inode(&inode)?;
        let dir_data = read_extents(block_io, media_id, ext4, &i_block, size, partition_start_lba)?;
        current = find_child_in_dir(&dir_data, part)?;
    }
    Some(current)
}

// =====================================================================
// Public entry points
// =====================================================================

/// Read a file from an EXT4 partition that is already known to be EXT4,
/// using the supplied `BlockIO` handle and `media_id`. Used by the
/// bootmgr partition-type dispatcher: once the probe has classified
/// the handle as `Ext4`, the dispatcher calls this and avoids the
/// per-handle scan in [`read_ext4_system_file`].
///
/// `block_io` is borrowed for the duration of this call (the caller
/// owns the protocol handle; this function never drops it).
///
/// `partition_start_lba` is the disk-relative LBA of the EXT4
/// partition's first sector. Pass 0 for a partition-scoped handle; pass
/// the GPT start LBA for a disk-scoped handle. The EXT4 superblock
/// then lives at `partition_start_lba + 2` (sectors).
pub fn read_ext4_with_block(
    path: &str,
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    partition_start_lba: u64,
) -> Option<Vec<u8>> {
    // Read the superblock: at byte offset 1024 within the partition.
    let sb_lba = partition_start_lba + 2;
    let mut sb_buf = [0u8; 1024];
    if block_io.read_blocks(media_id, sb_lba, &mut sb_buf).is_err() {
        uefi::println!("[EXT4] read_ext4_with_block: failed to read superblock at LBA {}", sb_lba);
        return None;
    }
    let ext4 = Ext4Boot::parse(&sb_buf)?;

    // Read BGDT at block (first_data_block + 1) of the partition.
    // `BlockIO::read_blocks` requires the buffer to be a multiple of
    // the device's block size (512), so we read a full sector and
    // pick the first 64 bytes (one BGDT entry) out of it.
    let bgdt_lba = partition_start_lba
        + ((ext4.first_data_block + 1) as u64) * ((ext4.block_size / 512) as u64);
    let mut bgdt_sector = [0u8; 512];
    if block_io.read_blocks(media_id, bgdt_lba, &mut bgdt_sector).is_err() {
        uefi::println!(
            "[EXT4] read_ext4_with_block: failed to read BGDT sector at LBA {}",
            bgdt_lba
        );
        return None;
    }
    let bgdt = &bgdt_sector[..64];
    // BGDT entry #0 contains the inode table location as a block number
    // (counted from the start of the partition). Convert that block
    // count to an absolute disk LBA by adding the partition offset and
    // multiplying by sectors-per-block.
    let inode_table_block = u32::from_le_bytes([bgdt[8], bgdt[9], bgdt[10], bgdt[11]]);
    if inode_table_block == 0 {
        return None;
    }
    let inode_table_lba = partition_start_lba
        + (inode_table_block as u64) * ((ext4.block_size / 512) as u64);

    // Resolve path -> inode.
    let target_ino = match resolve_path(
        block_io,
        media_id,
        &ext4,
        inode_table_lba,
        EXT4_ROOT_INO,
        path,
        partition_start_lba,
    ) {
        Some(i) => i,
        None => {
            uefi::println!(
                "[EXT4] read_ext4_with_block: resolve_path failed for '{}'",
                path
            );
            return None;
        }
    };

    // Read target inode + extents.
    let inode = read_inode(block_io, media_id, &ext4, target_ino, inode_table_lba)?;
    let (size, i_block) = parse_inode(&inode)?;
    let data = read_extents(block_io, media_id, &ext4, &i_block, size, partition_start_lba)?;
    uefi::println!(
        "[EXT4] read_ext4_with_block: '{}' -> inode {} ({} bytes)",
        path,
        target_ino,
        data.len()
    );
    Some(data)
}

/// Legacy convenience entry: scans every BlockIO handle, picks the
/// first one whose partition-relative LBA 2 carries the EXT4 superblock
/// magic, and resolves `path` on it. Used by callers that have not yet
/// been refactored to use the partition-type probe.
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
        // Legacy path: partition-scoped handle, so partition_start_lba = 0.
        let data = read_ext4_with_block(path, block_ref, this_media_id, 0);
        core::mem::forget(block);
        if data.is_some() {
            return data;
        }
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
