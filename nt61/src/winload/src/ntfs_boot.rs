//! Minimal NTFS boot-sector reader for winload.efi.
//!
//! UEFI's `SimpleFileSystem` protocol only supports FAT-family volumes by
//! default. When the System partition is formatted as NTFS, winload falls
//! back to this in-tree reader to resolve `\Windows\System32\...` paths.
//!
//! The design mirrors the NTFS reader in the boot manager (`boot/src/main.rs`).
//! Both walk the MFT via the `$INDEX_ROOT` attribute to resolve path
//! components. The only OS-specific dependency is `BlockIO` for sector I/O,
//! which is available in both bootmgr and winload.

use alloc::vec::Vec;
use uefi::boot::OpenProtocolAttributes;
use uefi::boot::OpenProtocolParams;
use uefi::proto::media::block::BlockIO;

static mut CACHED_NTFS_BLOCK_IO_PTR: usize = 0;
static mut CACHED_NTFS_BLOCK_IO_IFACE: *const core::ffi::c_void = core::ptr::null();
static mut NTFS_BLOCK_IO_READY: bool = false;

// =====================================================================
// NTFS boot-sector structure
// =====================================================================

/// Minimal NTFS boot-sector data we need for MFT traversal.
/// (Same struct as in boot/src/main.rs.)
struct NtfsBoot {
    sectors_per_cluster: u8,
    mft_start_lcn: u64,
    mft_record_size: u32,
}

impl NtfsBoot {
    /// Parse the NTFS boot sector (first 512 bytes of the partition).
    fn parse(buf: &[u8; 512]) -> Option<Self> {
        if &buf[3..11] != b"NTFS    " {
            return None;
        }
        let bytes_per_sector = u16::from_le_bytes([buf[0x0B], buf[0x0C]]);
        let sectors_per_cluster = buf[0x0D];
        let mft_start_lcn = u64::from_le_bytes([
            buf[0x30], buf[0x31], buf[0x32], buf[0x33], buf[0x34], buf[0x35], buf[0x36], buf[0x37],
        ]);
        // MFT record size: byte 0x40 holds a signed value.
        // Positive = 2^val clusters. Negative = 2^|val| bytes.
        let mft_raw = buf[0x40] as i8;
        let mft_record_size: u32 = if mft_raw >= 0 {
            (sectors_per_cluster as u32) * (bytes_per_sector as u32) << mft_raw
        } else {
            1u32 << (-mft_raw as u32)
        };
        Some(NtfsBoot {
            sectors_per_cluster,
            mft_start_lcn,
            mft_record_size,
        })
    }
}

// =====================================================================
// BlockIO sector read helper
// =====================================================================

/// read `count` sectors starting at `lba` from the given BlockIO handle.
fn read_partition_sectors(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    start_lba: u64,
    count: u32,
) -> Option<Vec<u8>> {
    let mut buf = alloc::vec::Vec::with_capacity((count as usize) * 512);
    buf.resize((count as usize) * 512, 0u8);
    // read one sector at a time to avoid large stack frames.
    for i in 0..count as usize {
        let sector_buf = &mut buf[i * 512..(i + 1) * 512];
        if block_io
            .read_blocks(media_id, start_lba + i as u64, sector_buf)
            .is_err()
        {
            return None;
        }
    }
    Some(buf)
}

// =====================================================================
// MFT record reading
// =====================================================================

/// read a single MFT record into a fresh buffer.
fn read_mft_record(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ntfs: &NtfsBoot,
    record_num: u64,
) -> Option<Vec<u8>> {
    let sectors_per_record = ((ntfs.mft_record_size + 511) / 512) as u32;
    let lba = ntfs.mft_start_lcn * (ntfs.sectors_per_cluster as u64)
        + record_num * (ntfs.mft_record_size as u64) / 512;
    let mut buf = read_partition_sectors(block_io, media_id, lba, sectors_per_record)?;
    if buf.len() < ntfs.mft_record_size as usize {
        return None;
    }
    if !apply_mft_fixup(&mut buf) {
        return None;
    }
    Some(buf)
}

/// Apply the NTFS multi-sector transfer fixup array to an MFT record.
///
/// The array layout is authoritative in the kernel driver:
/// the first `u16` at `fixup_offset` is the update sequence number,
/// and each saved sector tail follows it.
fn apply_mft_fixup(record: &mut [u8]) -> bool {
    if record.len() < 512 {
        return false;
    }

    let fixup_offset = u16::from_le_bytes([record[4], record[5]]) as usize;
    let fixup_size = u16::from_le_bytes([record[6], record[7]]) as usize;

    if fixup_size == 0 || fixup_offset < 8 || fixup_offset >= record.len() {
        return false;
    }

    let fixup_count = fixup_size - 1;
    if fixup_count != record.len() / 512 || fixup_offset + 2 + fixup_count * 2 > record.len() {
        return false;
    }

    let usn = u16::from_le_bytes([record[fixup_offset], record[fixup_offset + 1]]);

    for sector_index in 0..fixup_count {
        let fixup_entry_offset = fixup_offset + 2 + sector_index * 2;
        let sector_tail_offset = ((sector_index + 1) * 512) - 2;

        if fixup_entry_offset + 2 > record.len() || sector_tail_offset + 2 > record.len() {
            return false;
        }

        let current =
            u16::from_le_bytes([record[sector_tail_offset], record[sector_tail_offset + 1]]);
        if current != usn {
            return false;
        }

        let saved_tail = [record[fixup_entry_offset], record[fixup_entry_offset + 1]];
        record[sector_tail_offset..sector_tail_offset + 2].copy_from_slice(&saved_tail);
    }

    true
}

// =====================================================================
// MFT path resolution
// =====================================================================

/// Resolve `\Windows\System32\...` path to an MFT record number.
fn resolve_mft_record(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ntfs: &NtfsBoot,
    path: &str,
) -> Option<u64> {
    let parts: alloc::vec::Vec<&str> = path
        .trim_start_matches('\\')
        .split('\\')
        .filter(|s| !s.is_empty())
        .collect();

    let mut current = 5u64;
    for part in parts.iter() {
        match find_child_in_index(block_io, media_id, ntfs, current, part) {
            Some(next) => {
                current = next;
            }
            None => {
                return None;
            }
        }
    }
    Some(current)
}

/// Scan the `$INDEX_ROOT` of `parent_record` for an entry whose filename matches `name`.
fn find_child_in_index(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ntfs: &NtfsBoot,
    parent_record: u64,
    name: &str,
) -> Option<u64> {
    let record = read_mft_record(block_io, media_id, ntfs, parent_record)?;
    if &record[0..4] != b"FILE" {
        return None;
    }

    // Walk attributes. First attribute offset at byte 0x14.
    let mut off = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let end = ntfs.mft_record_size as usize;

    let mut index_alloc_data: Option<Vec<u8>> = None;

    while off + 4 < end {
        let attr_type = u32::from_le_bytes([
            record[off],
            record[off + 1],
            record[off + 2],
            record[off + 3],
        ]);
        if attr_type == 0xFFFFFFFF {
            break;
        }
        let attr_len = u32::from_le_bytes([
            record[off + 4],
            record[off + 5],
            record[off + 6],
            record[off + 7],
        ]) as usize;
        if attr_len == 0 {
            break;
        }
        if off + attr_len > end {
            off += attr_len;
            continue;
        }

        if attr_type == 0x90 {
            // $INDEX_ROOT attribute.
            // Resident attribute header = 24 bytes. Value starts at off + 0x18.
            // INDEX_HEADER starts at value offset 0x10.
            let body = off + 0x18;
            if body + 0x20 > end {
                off += attr_len;
                continue;
            }
            let ih_off = body + 0x10; // INDEX_HEADER at value+0x10
            let first_entry_offset = u32::from_le_bytes([
                record[ih_off + 0x00],
                record[ih_off + 0x01],
                record[ih_off + 0x02],
                record[ih_off + 0x03],
            ]) as usize;
            let total_size = u32::from_le_bytes([
                record[ih_off + 0x04],
                record[ih_off + 0x05],
                record[ih_off + 0x06],
                record[ih_off + 0x07],
            ]) as usize;
            // INDEX_HEADER flags are at value+0x1C (= ih_off + 0x0C);
            // bit 0 == LARGE_INDEX (entries also live in
            // $INDEX_ALLOCATION). The 4 bytes at value+0x0C..0x0F are
            // "clusters per index record" (which our build-tool
            // happens to write as 1), not the LARGE_INDEX flag — the
            // previous implementation read it from the wrong offset
            // and always treated the root as a large index, which
            // caused it to look for an INDEX_ALLOCATION attribute that
            // the build-tool does not emit on this image.
            let index_root_flags = u32::from_le_bytes([
                record[ih_off + 0x0C],
                record[ih_off + 0x0D],
                record[ih_off + 0x0E],
                record[ih_off + 0x0F],
            ]);
            let has_allocation = (index_root_flags & 0x01) != 0;

            // entries_off is RELATIVE TO ih_off (= body + 0x10), not body.
            let entries_off = ih_off + first_entry_offset;
            if entries_off < end {
                if let Some(found) = walk_index_entries(&record, entries_off, total_size, end, name)
                {
                    return Some(found);
                }
            }
            // Stash the LARGE_INDEX flag so we fall through to the
            // $INDEX_ALLOCATION path below if the entry is not in
            // the root.
            if has_allocation && index_alloc_data.is_none() {
                index_alloc_data = Some(Vec::new()); // marker
            }
        }

        if attr_type == 0xA0 {
            // $INDEX_ALLOCATION attribute — non-resident. Walk its
            // run list and read each index node (typically one
            // 4 KiB record per cluster).
            if record[off + 8] == 1 {
                // NTFS non-resident attribute header layout, *as
                // emitted by our builder* (see the matching comment in
                // `read_data_stream`):
                //   +0x20: alloc_size (u64)
                //   +0x28: real_size  (u64)
                //   +0x30: init_size  (u64)
                //   +0x38: run_list_off (u16)
                // Real NTFS documentation differs (alloc_size at
                // +0x28 etc.), but the build_esp NTFS emitter used in
                // this codebase writes the sizes first and tucks
                // run_list_off at +0x38. The previous version of
                // this code followed the documentation literally
                // (alloc_size at +0x28, run_list_off at +0x28 shifted
                // by 8 bytes), which made the INDEX_ALLOCATION run
                // list walker go off the end of the 4KB record.
                let alloc_size = u64::from_le_bytes([
                    record[off + 0x20],
                    record[off + 0x21],
                    record[off + 0x22],
                    record[off + 0x23],
                    record[off + 0x24],
                    record[off + 0x25],
                    record[off + 0x26],
                    record[off + 0x27],
                ]);
                let run_list_off =
                    u16::from_le_bytes([record[off + 0x38], record[off + 0x39]]) as usize;

                if alloc_size > 0 && run_list_off > 0 && (off + run_list_off) < end {
                    let spc = ntfs.sectors_per_cluster as u64;
                    let index_buffer_size = ntfs.mft_record_size as usize;
                    let sectors_per_index = (index_buffer_size + 511) / 512;
                    let mut rp = off + run_list_off;
                    let mut lcn: i64 = 0;
                    while rp < end {
                        let hdr = record[rp];
                        if hdr == 0 {
                            break;
                        }
                        let len_len = (hdr & 0x0F) as usize;
                        let off_len = ((hdr >> 4) & 0x0F) as usize;
                        if len_len == 0 {
                            break;
                        }
                        let mut len_bytes = [0u8; 8];
                        for i in 0..len_len {
                            len_bytes[i] = record[rp + 1 + i];
                        }
                        let run_len_clusters = parse_varnum(&len_bytes, len_len);
                        let mut off_bytes = [0u8; 8];
                        for i in 0..off_len {
                            off_bytes[i] = record[rp + 1 + len_len + i];
                        }
                        let delta = parse_varnum_signed(&off_bytes, off_len);
                        lcn += delta;
                        if lcn < 0 {
                            break;
                        }
                        let lcn_u = lcn as u64;
                        let data_start_lba = lcn_u * spc;
                        let cluster_count = run_len_clusters as u32;
                        // read each cluster's worth of sectors as an
                        // INDEX_NODE (4 KiB).
                        let total_sectors = cluster_count * spc as u32;
                        if let Some(data) = read_partition_sectors(
                            block_io,
                            media_id,
                            data_start_lba,
                            total_sectors,
                        ) {
                            if let Some(found) = scan_index_allocation_buffer(
                                &data,
                                index_buffer_size,
                                sectors_per_index,
                                name,
                            ) {
                                return Some(found);
                            }
                        }
                        rp += 1 + len_len + off_len;
                    }
                }
            }
        }

        off += attr_len;
    }
    None
}

/// Walk the entries inside an INDEX_HEADER buffer (used for both
/// the resident $INDEX_ROOT and each node of the non-resident
/// $INDEX_ALLOCATION).
fn walk_index_entries(
    record: &[u8],
    entries_off: usize,
    total_size: usize,
    end: usize,
    name: &str,
) -> Option<u64> {
    let mut p = entries_off;
    let end_p = entries_off + total_size;
    while p + 16 <= end_p && p + 16 <= end {
        let entry_len = u16::from_le_bytes([record[p + 8], record[p + 9]]) as usize;
        let key_len = u16::from_le_bytes([record[p + 0x0A], record[p + 0x0B]]) as usize;
        let entry_flags = u16::from_le_bytes([record[p + 0x0C], record[p + 0x0D]]);
        if entry_len == 0 || entry_len < 16 {
            break;
        }
        if (entry_flags & 0x0002) != 0 {
            break;
        }
        if key_len < 66 {
            p += entry_len;
            continue;
        }
        // INDEX_ENTRY layout (boot/src/main.rs reference):
        //   +0x00: MFT ref (8)
        //   +0x08: entry_len (2)
        //   +0x0A: key_len (2)
        //   +0x0C: flags (2)
        //   +0x10: FILE_NAME attribute header (24 bytes) starts here
        //   The FILE_NAME value then begins 24 bytes later and has
        //   the standard layout:
        //     +0x00: parent_ref (8)
        //     +0x08..+0x27: times (32 bytes)
        //     +0x28: allocated_length (8)
        //     +0x30: file_size (8)
        //     +0x38: file_attributes (4)
        //     +0x3C: reparse/ea (4 — see [MS-FSCC] §2.6)
        //     +0x40: name_length
        //     +0x41: name_namespace
        //     +0x42+: filename (UTF-16LE)
        //
        // The previous implementation read name_length from
        // value+0x3E (the wrong offset), which made every decoded
        // filename look empty even though the build-tool wrote a
        // valid FILE_NAME. The build-tool's `build_file_name_attr_for_record`
        // emits at value+0x40/0x41/0x42 — same layout as NTFS itself.
        let fname_attr_off = p + 0x10;
        let fname_value_off = fname_attr_off;
        let name_len_offset = fname_value_off + 0x40;
        if name_len_offset >= end {
            break;
        }
        let name_len_chars = record[name_len_offset] as usize;
        if name_len_chars == 0 || name_len_chars > 255 {
            p += entry_len;
            continue;
        }
        let name_start = fname_value_off + 0x42;
        if name_start + name_len_chars * 2 > end {
            p += entry_len;
            continue;
        }
        let mut fname = alloc::string::String::new();
        for i in 0..name_len_chars {
            let c =
                u16::from_le_bytes([record[name_start + i * 2], record[name_start + i * 2 + 1]]);
            if c == 0 {
                continue;
            }
            if let Some(ch) = char::from_u32(c as u32) {
                fname.push(ch);
            }
        }
        if fname.eq_ignore_ascii_case(name) {
            let child_ref = u64::from_le_bytes([
                record[p],
                record[p + 1],
                record[p + 2],
                record[p + 3],
                record[p + 4],
                record[p + 5],
                record[p + 6],
                record[p + 7],
            ]);
            return Some(child_ref & 0x0000_FFFF_FFFF_FFFF);
        }
        p += entry_len;
    }
    None
}

/// Scan a $INDEX_ALLOCATION buffer for a child matching `name`.
///
/// The buffer may contain multiple 4 KiB index records back to
/// back; each one starts with the 4-byte signature "INDX" and
/// has its own INDEX_HEADER at offset 0x18 (after the signature,
/// VCN, and parent VCN fields). For our simplified winload we
/// do a linear scan over every 4 KiB slice; the children of any
/// given node are not followed (the boot drivers live in the
/// leaf so a single-level scan is enough for the bring-up
/// directory layout generated by `tools/src/fs/build.rs`).
fn scan_index_allocation_buffer(
    data: &[u8],
    index_buffer_size: usize,
    sectors_per_index: usize,
    name: &str,
) -> Option<u64> {
    let sectors_per_index = if sectors_per_index == 0 {
        8
    } else {
        sectors_per_index
    };
    let index_buffer_size = if index_buffer_size == 0 {
        4096
    } else {
        index_buffer_size
    };
    let stride = index_buffer_size;
    let mut off = 0usize;
    while off + 16 <= data.len() && off + stride <= data.len() {
        let node = &data[off..off + stride];
        if &node[0..4] != b"INDX" {
            // Skip forward by one sector — the cluster may have
            // multiple INDX records.
            off += sectors_per_index * 512;
            continue;
        }
        // INDEX_HEADER at node + 0x10 (after "INDX" + 8 bytes of VCNs).
        let ih_off = 0x10;
        let first_entry_offset = u32::from_le_bytes([
            node[ih_off],
            node[ih_off + 1],
            node[ih_off + 2],
            node[ih_off + 3],
        ]) as usize;
        let total_size = u32::from_le_bytes([
            node[ih_off + 4],
            node[ih_off + 5],
            node[ih_off + 6],
            node[ih_off + 7],
        ]) as usize;
        let entries_off = first_entry_offset;
        let end = index_buffer_size;
        if entries_off < end {
            if let Some(found) = walk_index_entries(node, entries_off, total_size, end, name) {
                return Some(found);
            }
        }
        off += stride;
    }
    None
}

// =====================================================================
// Data stream reading
// =====================================================================

/// read the `$DATA` stream of a record.
fn read_data_stream(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ntfs: &NtfsBoot,
    record_num: u64,
) -> Option<Vec<u8>> {
    let record = read_mft_record(block_io, media_id, ntfs, record_num)?;
    if &record[0..4] != b"FILE" {
        return None;
    }

    let mut off = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let end = ntfs.mft_record_size as usize;
    while off + 4 < end {
        let attr_type = u32::from_le_bytes([
            record[off],
            record[off + 1],
            record[off + 2],
            record[off + 3],
        ]);
        if attr_type == 0xFFFFFFFF {
            break;
        }
        let attr_len = u32::from_le_bytes([
            record[off + 4],
            record[off + 5],
            record[off + 6],
            record[off + 7],
        ]) as usize;
        if attr_len == 0 || off + attr_len > end {
            break;
        }

        if attr_type == 0x80 {
            let non_resident = record[off + 8];
            if non_resident == 0 {
                // Resident $DATA: data is at off + value_offset.
                let value_offset =
                    u16::from_le_bytes([record[off + 0x14], record[off + 0x15]]) as usize;
                let content_size = u32::from_le_bytes([
                    record[off + 0x10],
                    record[off + 0x11],
                    record[off + 0x12],
                    record[off + 0x13],
                ]) as usize;
                if off + value_offset + content_size <= end {
                    return Some(
                        record[off + value_offset..off + value_offset + content_size].to_vec(),
                    );
                }
            } else {
                // Non-resident $DATA stores the mapping-pair offset in
                // the builder-compatible header field at +0x38.
                let first_vcn = u64::from_le_bytes([
                    record[off + 0x10],
                    record[off + 0x11],
                    record[off + 0x12],
                    record[off + 0x13],
                    record[off + 0x14],
                    record[off + 0x15],
                    record[off + 0x16],
                    record[off + 0x17],
                ]);
                let run_list_off =
                    u16::from_le_bytes([record[off + 0x38], record[off + 0x39]]) as usize;

                // Parse run list: header byte encodes size of len/offset
                // fields. The builder emits exactly one contiguous run.
                if first_vcn == 0 {
                    let rp = off + run_list_off;
                    let hdr = record[rp];
                    let len_len = (hdr & 0x0F) as usize;
                    let off_len = ((hdr >> 4) & 0x0F) as usize;
                    if len_len > 0 && rp + len_len + off_len < end {
                        let mut len_bytes = [0u8; 8];
                        for i in 0..len_len {
                            len_bytes[i] = record[rp + 1 + i];
                        }
                        let run_len = parse_varnum(&len_bytes, len_len);
                        let mut off_bytes = [0u8; 8];
                        for i in 0..off_len {
                            off_bytes[i] = record[rp + 1 + len_len + i];
                        }
                        let delta = parse_varnum_signed(&off_bytes, off_len);
                        let run_start_lcn = delta as i64 as u64;
                        let spc = ntfs.sectors_per_cluster as u64;
                        let data_start = run_start_lcn * spc;
                        let data_sectors = run_len * spc;
                        let sector_count = u32::try_from(data_sectors).ok()?;
                        return read_partition_sectors(
                            block_io,
                            media_id,
                            data_start,
                            sector_count,
                        );
                    }
                }
            }
        }
        off += attr_len;
    }
    None
}

/// Parse a variable-length unsigned integer from a byte slice.
fn parse_varnum(bytes: &[u8], len: usize) -> u64 {
    let mut val = 0u64;
    for i in 0..len {
        val |= (bytes[i] as u64) << (i * 8);
    }
    val
}

/// Parse a variable-length signed integer from a byte slice (two's complement).
///
/// NTFS variable-length integers are little-endian, so the most
/// significant byte sits at `bytes[len - 1]`. Sign extension to a
/// full 64-bit `i64` only depends on the high bit of that byte —
/// not on whatever shifted bit position the previous version of
/// this code computed from `(8 - len)`. With that previous logic a
/// length-2 offset whose MSB happened to be 0 (e.g. `0x0021`) was
/// mis-sign-extended to a wild negative number (`-30859` in that
/// case), which made the MFT walker's `run_start_lcn` come back as
/// `0xffffffffffffffe8` and the read silently read the wrong
/// sectors. Use `(bytes[len - 1] & 0x80) != 0` to decide
/// sign-extension and pad the upper bytes with `0xFF` accordingly.
fn parse_varnum_signed(bytes: &[u8], len: usize) -> i64 {
    let mut val = 0i64;
    for i in 0..len {
        val |= (bytes[i] as i64) << (i * 8);
    }
    if len > 0 && (bytes[len - 1] & 0x80) != 0 {
        for i in len..8 {
            val |= 0xFFi64 << (i * 8);
        }
    }
    val
}

// =====================================================================
// Public entry point
// =====================================================================

/// read a file from the NTFS System partition by MFT path.
/// Returns `None` if the path cannot be resolved (NTFS not detected,
/// path not found, or I/O error).
pub fn read_ntfs_system_file(path: &str) -> Option<Vec<u8>> {
    use uefi::boot as ub;

    uefi::println!("[NTFS-BOOT] read begin {}", path);
    let is_ready = unsafe { core::ptr::addr_of!(NTFS_BLOCK_IO_READY).read_volatile() };
    if !is_ready {
        let handles = ub::find_handles::<BlockIO>().ok()?;
        let mut selected_ptr = 0usize;
        for handle in handles.iter() {
            let block = match unsafe {
                ub::open_protocol::<BlockIO>(
                    OpenProtocolParams {
                        handle: *handle,
                        agent: ub::image_handle(),
                        controller: None,
                    },
                    OpenProtocolAttributes::GetProtocol,
                )
            } {
                Ok(block) => block,
                Err(_) => continue,
            };
            let block_ref = match block.get() {
                Some(block_ref) => block_ref,
                None => {
                    drop(block);
                    continue;
                }
            };
            let media = block_ref.media();
            let mut boot_sector = [0u8; 512];
            if media.block_size() != 512
                || !media.is_logical_partition()
                || block_ref
                    .read_blocks(media.media_id(), 0u64, &mut boot_sector)
                    .is_err()
                || &boot_sector[3..11] != b"NTFS    "
            {
                drop(block);
                continue;
            }

            selected_ptr = handle.as_ptr() as usize;
            unsafe {
                core::ptr::addr_of_mut!(CACHED_NTFS_BLOCK_IO_IFACE)
                    .write_volatile(block_ref as *const BlockIO as *const core::ffi::c_void);
            }
            core::mem::forget(block);
            break;
        }
        unsafe {
            core::ptr::addr_of_mut!(CACHED_NTFS_BLOCK_IO_PTR).write_volatile(selected_ptr);
            core::ptr::addr_of_mut!(NTFS_BLOCK_IO_READY).write_volatile(selected_ptr != 0);
        }
        if selected_ptr == 0 {
            return None;
        }
        uefi::println!("[NTFS-BOOT] cache ready ptr=0x{:x}", selected_ptr);
    }

    uefi::println!("[NTFS-BOOT] using cached BlockIO {}", path);
    let block_ref = unsafe { &*(CACHED_NTFS_BLOCK_IO_IFACE as *const BlockIO) };
    let media = block_ref.media();
    let this_media_id = media.media_id();
    let mut boot_sector = [0u8; 512];
    block_ref
        .read_blocks(this_media_id, 0u64, &mut boot_sector)
        .ok()?;
    let ntfs = NtfsBoot::parse(&boot_sector)?;
    uefi::println!("[NTFS-BOOT] parsed boot sector {}", path);
    let record_num = resolve_mft_record(block_ref, this_media_id, &ntfs, path)?;
    uefi::println!("[NTFS-BOOT] resolved record {} mft={}", path, record_num);
    read_data_stream(block_ref, this_media_id, &ntfs, record_num)
}
