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

use alloc::string::String;
use alloc::vec::Vec;
use uefi::boot::OpenProtocolAttributes;
use uefi::boot::OpenProtocolParams;
use uefi::proto::media::block::BlockIO;

// =====================================================================
// NTFS boot-sector structure
// =====================================================================

/// Minimal NTFS boot-sector data we need for MFT traversal.
/// (Same struct as in boot/src/main.rs.)
struct NtfsBoot {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    total_sectors: u64,
    mft_start_lcn: u64,
    mft_record_size: u32,
    serial_number: u64,
}

impl NtfsBoot {
    /// Parse the NTFS boot sector (first 512 bytes of the partition).
    fn parse(buf: &[u8; 512]) -> Option<Self> {
        if &buf[3..11] != b"NTFS    " {
            return None;
        }
        let bytes_per_sector = u16::from_le_bytes([buf[0x0B], buf[0x0C]]);
        let sectors_per_cluster = buf[0x0D];
        let total_sectors = u64::from_le_bytes([
            buf[0x28], buf[0x29], buf[0x2A], buf[0x2B],
            buf[0x2C], buf[0x2D], buf[0x2E], buf[0x2F],
        ]);
        let mft_start_lcn = u64::from_le_bytes([
            buf[0x30], buf[0x31], buf[0x32], buf[0x33],
            buf[0x34], buf[0x35], buf[0x36], buf[0x37],
        ]);
        // MFT record size: byte 0x40 holds a signed value.
        // Positive = 2^val clusters. Negative = 2^|val| bytes.
        let mft_raw = buf[0x40] as i8;
        let mft_record_size: u32 = if mft_raw >= 0 {
            (sectors_per_cluster as u32) * (bytes_per_sector as u32) << mft_raw
        } else {
            1u32 << (-mft_raw as u32)
        };
        let serial_number = u64::from_le_bytes([
            buf[0x48], buf[0x49], buf[0x4A], buf[0x4B],
            buf[0x4C], buf[0x4D], buf[0x4E], buf[0x4F],
        ]);
        Some(NtfsBoot {
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors,
            mft_start_lcn,
            mft_record_size,
            serial_number,
        })
    }
}

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
    let mut buf = alloc::vec::Vec::with_capacity((count as usize) * 512);
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
// MFT record reading
// =====================================================================

/// Read a single MFT record into a fresh buffer.
fn read_mft_record(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ntfs: &NtfsBoot,
    record_num: u64,
) -> Option<Vec<u8>> {
    let sectors_per_record = ((ntfs.mft_record_size + 511) / 512) as u32;
    let lba = ntfs.mft_start_lcn * (ntfs.sectors_per_cluster as u64)
        + record_num * (ntfs.mft_record_size as u64) / 512;
    let buf = read_partition_sectors(block_io, media_id, lba, sectors_per_record)?;
    if buf.len() < ntfs.mft_record_size as usize {
        return None;
    }
    // Dump the first 16 bytes of the read so we can spot stale data
    // returned by UEFI BlockIO after multiple protocol opens.
    if record_num == 5 {
        uefi::println!(
            "[NTFS] read_mft_record({}) bytes_0x10={:02x?} bytes_0x80={:02x?} bytes_0x100={:02x?}",
            record_num,
            &buf[0x10..0x18],
            &buf[0x80..0x90],
            &buf[0x100..0x110],
        );
    }
    Some(buf)
}

// =====================================================================
// Filename attribute decoder
// =====================================================================

/// Decode a UTF-16LE filename attribute (0x30) into a Rust `String`.
fn decode_filename_attr(buf: &[u8], off: usize) -> Option<(String, u64)> {
    if off + 66 > buf.len() {
        return None;
    }
    // FILE_NAME attribute body layout (resident, starts 24 bytes into attr):
    //   0x00: parent MFT reference (8 bytes)
    //   0x08: timestamps (32 bytes)
    //   0x28: allocated size (8)
    //   0x30: real size (8)
    //   0x38: flags (4)
    //   0x3C: EA/reparse (4)
    //   0x40: name length in chars (1)
    //   0x41: namespace (1)
    //   0x42+: name (UTF-16LE)
    let name_chars = buf[off + 0x40] as usize;
    if off + 0x42 + name_chars * 2 > buf.len() {
        return None;
    }
    let mut name = String::new();
    for i in 0..name_chars {
        let c = u16::from_le_bytes([buf[off + 0x42 + i * 2], buf[off + 0x42 + i * 2 + 1]]);
        if c == 0 {
            continue; // skip embedded NULs
        }
        if let Some(ch) = char::from_u32(c as u32) {
            name.push(ch);
        }
    }
    let parent_ref = u64::from_le_bytes([
        buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
        buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7],
    ]);
    Some((name, parent_ref & 0x0000_FFFF_FFFF_FFFF))
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

    let mut current = 5u64; // Root directory = MFT record 5
    for (i, part) in parts.iter().enumerate() {
        uefi::println!("[NTFS] resolve step {}: looking up '{}' in parent={}", i, part, current);
        match find_child_in_index(block_io, media_id, ntfs, current, part) {
            Some(next) => {
                uefi::println!("[NTFS] resolve step {}: '{}' -> {}", i, part, next);
                current = next;
            }
            None => {
                uefi::println!("[NTFS] resolve step {}: '{}' not found under parent={}", i, part, current);
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
    uefi::println!(
        "[NTFS] find_child_in_index entered: parent={} name='{}'",
        parent_record, name
    );
    let record = read_mft_record(block_io, media_id, ntfs, parent_record)?;
    if &record[0..4] != b"FILE" {
        return None;
    }

    // Walk attributes. First attribute offset at byte 0x14.
    let mut off = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let end = ntfs.mft_record_size as usize;

    let mut found_index_alloc = false;
    uefi::println!(
        "[NTFS] find_child_in_index: parent_record={} name='{}' first_attr_off={} record_end={}",
        parent_record, name,
        off, end
    );

    let mut index_alloc_data: Option<Vec<u8>> = None;
    let mut did_walk_root = false;

    while off + 4 < end {
        let attr_type = u32::from_le_bytes([
            record[off], record[off + 1], record[off + 2], record[off + 3],
        ]);
        if attr_type == 0xFFFFFFFF {
            break;
        }
        let attr_len = u32::from_le_bytes([
            record[off + 4], record[off + 5], record[off + 6], record[off + 7],
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
                record[ih_off + 0x00], record[ih_off + 0x01],
                record[ih_off + 0x02], record[ih_off + 0x03],
            ]) as usize;
            let total_size = u32::from_le_bytes([
                record[ih_off + 0x04], record[ih_off + 0x05],
                record[ih_off + 0x06], record[ih_off + 0x07],
            ]) as usize;
            // INDEX_ROOT flags are at value+0x0C; bit 0 == LARGE_INDEX
            // (entries also live in $INDEX_ALLOCATION).
            let index_root_flags = u32::from_le_bytes([
                record[body + 0x0C], record[body + 0x0D],
                record[body + 0x0E], record[body + 0x0F],
            ]);
            let has_allocation = (index_root_flags & 0x01) != 0;

            // entries_off is RELATIVE TO ih_off (= body + 0x10), not body.
            let entries_off = ih_off + first_entry_offset;
            uefi::println!(
                "[NTFS] find_child_in_index: parent_record={} name='{}' entries_off={} total_size={} has_allocation={}",
                parent_record, name,
                entries_off, total_size, has_allocation
            );
            if entries_off < end {
                uefi::println!(
                    "[NTFS]   walking INDEX_ROOT entries from p=0x{:x} to end_p=0x{:x}",
                    entries_off, entries_off + total_size
                );
                if let Some(found) = walk_index_entries(&record, entries_off, total_size, end, name) {
                    return Some(found);
                }
                uefi::println!("[NTFS]   INDEX_ROOT did not contain '{}'", name);
            } else {
                uefi::println!(
                    "[NTFS]   entries_off=0x{:x} >= end=0x{:x}, skipping INDEX_ROOT",
                    entries_off, end
                );
            }
            did_walk_root = true;
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
            uefi::println!("[NTFS] found INDEX_ALLOCATION attr for parent={}", parent_record);
            let non_resident = record[off + 8];
            if non_resident == 1 {
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
                    record[off + 0x20], record[off + 0x21], record[off + 0x22],
                    record[off + 0x23], record[off + 0x24], record[off + 0x25],
                    record[off + 0x26], record[off + 0x27],
                ]);
                let run_list_off = u16::from_le_bytes([
                    record[off + 0x38], record[off + 0x39],
                ]) as usize;

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
                        // Read each cluster's worth of sectors as an
                        // INDEX_NODE (4 KiB).
                        let total_sectors = cluster_count * spc as u32;
                        if let Some(data) = read_partition_sectors(
                            block_io, media_id, data_start_lba, total_sectors,
                        ) {
                            if let Some(found) = scan_index_allocation_buffer(
                                &data, index_buffer_size, sectors_per_index, name,
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
        //   the standard 0x40 layout:
        //     +0x3E: name_length
        //     +0x40+: filename (UTF-16LE)
        //
        // CRITICAL: the FILE_NAME attribute (0x30) has a 24-byte
        // resident attribute header (type/length/non_res/name_idx/
        // flags/instance/value_length/value_offset/padding) that must
        // be skipped before the value is reached. Skipping this
        // header is what makes the lookup align with the same
        // builder output that boot/src/main.rs uses successfully —
        // the previous implementation that just added +0x10 (no
        // +24) read garbage and silently returned "not found".
        let fname_attr_off = p + 0x10;
        let fname_value_off = fname_attr_off + 24;
        let name_len_offset = fname_value_off + 0x3E;
        if name_len_offset >= end {
            break;
        }
        let name_len_chars = record[name_len_offset] as usize;
        if name_len_chars == 0 || name_len_chars > 255 {
            p += entry_len;
            continue;
        }
        let name_start = fname_value_off + 0x40;
        if name_start + name_len_chars * 2 > end {
            p += entry_len;
            continue;
        }
        let mut fname = String::new();
        for i in 0..name_len_chars {
            let c = u16::from_le_bytes([
                record[name_start + i * 2],
                record[name_start + i * 2 + 1],
            ]);
            if c == 0 { continue; }
            if let Some(ch) = char::from_u32(c as u32) { fname.push(ch); }
        }
        uefi::println!(
            "[NTFS]   decoded name='{}' (chars={}, p=0x{:x}, flags=0x{:x})",
            fname, name_len_chars, p, entry_flags
        );
        if fname.eq_ignore_ascii_case(name) {
            let child_ref = u64::from_le_bytes([
                record[p], record[p + 1], record[p + 2], record[p + 3],
                record[p + 4], record[p + 5], record[p + 6], record[p + 7],
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
    let sectors_per_index = if sectors_per_index == 0 { 8 } else { sectors_per_index };
    let index_buffer_size = if index_buffer_size == 0 { 4096 } else { index_buffer_size };
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
            node[ih_off], node[ih_off + 1], node[ih_off + 2], node[ih_off + 3],
        ]) as usize;
        let total_size = u32::from_le_bytes([
            node[ih_off + 4], node[ih_off + 5], node[ih_off + 6], node[ih_off + 7],
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

/// Read the `$DATA` stream of a record.
fn read_data_stream(
    block_io: &uefi::proto::media::block::BlockIO,
    media_id: u32,
    ntfs: &NtfsBoot,
    record_num: u64,
) -> Option<Vec<u8>> {
    let record = read_mft_record(block_io, media_id, ntfs, record_num)?;
    if &record[0..4] != b"FILE" {
        uefi::println!("[NTFS] read_data_stream(rec={}): bad FILE sig", record_num);
        return None;
    }

    let mut off = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let end = ntfs.mft_record_size as usize;
    let mut saw_data_attr = false;
    while off + 4 < end {
        let attr_type = u32::from_le_bytes([
            record[off], record[off + 1], record[off + 2], record[off + 3],
        ]);
        if attr_type == 0xFFFFFFFF {
            break;
        }
        let attr_len = u32::from_le_bytes([
            record[off + 4], record[off + 5], record[off + 6], record[off + 7],
        ]) as usize;
        if attr_len == 0 || off + attr_len > end {
            uefi::println!("[NTFS] read_data_stream(rec={}): bad attr_len={} off={} end={} (current attr_type=0x{:x})", record_num, attr_len, off, end, attr_type);
            break;
        }

        if attr_type == 0x80 {
            saw_data_attr = true;
            let non_resident = record[off + 8];
            uefi::println!("[NTFS] read_data_stream(rec={}): $DATA off={} len={} non_resident={}", record_num, off, attr_len, non_resident);
            let non_resident = record[off + 8];
            if non_resident == 0 {
                // Resident $DATA: data is at off + value_offset.
                let value_offset = u16::from_le_bytes([
                    record[off + 0x14], record[off + 0x15],
                ]) as usize;
                let content_size = u32::from_le_bytes([
                    record[off + 0x10], record[off + 0x11],
                    record[off + 0x12], record[off + 0x13],
                ]) as usize;
                if off + value_offset + content_size <= end {
                    return Some(record[off + value_offset..off + value_offset + content_size].to_vec());
                }
            } else {
                // Non-resident $DATA: walk run list.
                // For simplicity, handle a single run (our builder emits one).
                //
                // NTFS non-resident attribute header layout, *as
                // emitted by our builder* (see
                // `tools/src/fs/ntfs.rs::build_non_resident_data_attr`):
                //   +0x10: start_vcn (u64)
                //   +0x18: last_vcn  (u64)
                //   +0x20: alloc_size (u64)
                //   +0x28: real_size  (u64)
                //   +0x30: init_size  (u64)
                //   +0x38: run_list_off (u16)  ← run list start
                //   +0x3A: compression_unit (u16)
                //   +0x3C: padding (u32)
                //   +0x40: data_runs (mapping pairs)
                //
                // Real NTFS documentation places the run-list offset
                // at +0x20 and push the sizes down by 0x18, but the
                // builder that ships with this codebase writes the
                // sizes first and stashes run_list_off at +0x38 — so
                // the reader MUST use the same offsets or the
                // matching read silently returns garbage.  The
                // previous version of this code followed the Windows
                // documentation literally (alloc_size at +0x28,
                // run_list_off at +0x20), which on our disks caused
                // `alloc_size` to read `real_size` (positive but
                // nonzero) and `run_list_off` to read a stray part
                // of `real_size` (typically a large unsigned like
                // 0x1000), pushing the run-list walker's read
                // pointer to off + 0x1000 which always exceeds
                // `end`. The explicit logging in the
                // `else { uefi::println!(...) }` arms below lets us
                // see exactly which offset is wrong when the boot
                // images change.
                let first_vcn = u64::from_le_bytes([
                    record[off + 0x10], record[off + 0x11],
                    record[off + 0x12], record[off + 0x13],
                    record[off + 0x14], record[off + 0x15],
                    record[off + 0x16], record[off + 0x17],
                ]);
                let alloc_size = u64::from_le_bytes([
                    record[off + 0x20], record[off + 0x21], record[off + 0x22],
                    record[off + 0x23], record[off + 0x24], record[off + 0x25],
                    record[off + 0x26], record[off + 0x27],
                ]);
                let run_list_off = u16::from_le_bytes([
                    record[off + 0x38], record[off + 0x39],
                ]) as usize;

                if alloc_size > 0 && first_vcn == 0 {
                    // Parse run list: header byte encodes size of len/offset fields.
                    // We expect exactly one entry: `len lcn`.
                    let rp = off + run_list_off;
                    uefi::println!("[NTFS] read_data_stream(rec={}): non-res run_list_off={} rp={} alloc_size={}", record_num, run_list_off, rp, alloc_size);
                    if rp < end {
                        let hdr = record[rp];
                        let len_len = (hdr & 0x0F) as usize;
                        let off_len = ((hdr >> 4) & 0x0F) as usize;
                        uefi::println!("[NTFS] read_data_stream(rec={}): run hdr=0x{:x} len_len={} off_len={}", record_num, hdr, len_len, off_len);
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
                            // Run list offsets are signed and accumulate.
                            let delta = parse_varnum_signed(&off_bytes, off_len);
                            // LCN is always non-negative for non-corrupt images.
                            let run_start_lcn = delta as i64 as u64;
                            let spc = ntfs.sectors_per_cluster as u64;
                            let data_start = run_start_lcn * spc;
                            let data_sectors = run_len * spc;
                            uefi::println!("[NTFS] read_data_stream(rec={}): run_len={} lcn={} spc={} data_start={} data_sectors={}", record_num, run_len, run_start_lcn, spc, data_start, data_sectors);
                            return read_partition_sectors(
                                block_io, media_id, data_start, data_sectors as u32,
                            );
                        } else {
                            uefi::println!("[NTFS] read_data_stream(rec={}): run header check failed (rp+len_len+off_len={} end={})", record_num, rp + len_len + off_len, end);
                        }
                    } else {
                        uefi::println!("[NTFS] read_data_stream(rec={}): rp={} out of end={}", record_num, rp, end);
                    }
                } else {
                    uefi::println!("[NTFS] read_data_stream(rec={}): alloc_size={} first_vcn={} (need first_vcn=0)", record_num, alloc_size, first_vcn);
                }
            }
        }
        off += attr_len;
    }
    if !saw_data_attr {
        uefi::println!("[NTFS] read_data_stream(rec={}): no $DATA attribute found", record_num);
    } else {
        uefi::println!("[NTFS] read_data_stream(rec={}): failed to decode $DATA content (off out of bounds?)", record_num);
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

/// Read a file from the NTFS System partition by MFT path.
/// Returns `None` if the path cannot be resolved (NTFS not detected,
/// path not found, or I/O error).
pub fn read_ntfs_system_file(path: &str) -> Option<Vec<u8>> {
    use uefi::boot as ub;
    use core::mem::ManuallyDrop;

    // Walk BlockIO handles and find the NTFS System partition.
    let handles = ub::find_handles::<BlockIO>().ok()?;
    let esp_media_id: u32 = 0; // winload sets this; we skip by OEM ID instead

    for handle in handles.iter() {
        let sp = unsafe {
            ub::open_protocol::<BlockIO>(
                OpenProtocolParams {
                    handle: *handle,
                    agent: ub::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        let Ok(block) = sp else {
            uefi::println!("[NTFS] open_protocol failed for one BlockIO handle");
            continue;
        };
        let block = ManuallyDrop::new(block);
        let Some(block_ref) = block.get() else {
            continue;
        };
        let media = block_ref.media();
        uefi::println!(
            "[NTFS] probe: block_size={} is_logical_partition={} media_id={}",
            media.block_size(),
            media.is_logical_partition(),
            media.media_id()
        );
        if media.block_size() != 512 {
            continue;
        }
        // Skip whole-disk handle.
        if !media.is_logical_partition() {
            continue;
        }

        let this_media_id = media.media_id();
        let this_blocks = (media.last_block() as u64) + 1;

        // Read boot sector to probe filesystem type.
        let mut boot_sector = [0u8; 512];
        if block_ref.read_blocks(this_media_id, 0u64, &mut boot_sector).is_err() {
            uefi::println!("[NTFS] read_blocks(LBA=0) failed for media_id={}", this_media_id);
            continue;
        }

        // Skip non-NTFS partitions.
        if &boot_sector[3..11] != b"NTFS    " {
            uefi::println!(
                "[NTFS] partition media_id={} is not NTFS (got sig {:?})",
                this_media_id,
                core::str::from_utf8(&boot_sector[3..11]).unwrap_or("?")
            );
            continue;
        }
        uefi::println!("[NTFS] found NTFS partition: media_id={} blocks={}", this_media_id, this_blocks);

        let ntfs = NtfsBoot::parse(&boot_sector)?;
        uefi::println!(
            "[NTFS] parsed: bps={} spc={} mft_lcn={} mft_rec_sz={} sectors_per_cluster={}",
            ntfs.bytes_per_sector, ntfs.sectors_per_cluster, ntfs.mft_start_lcn,
            ntfs.mft_record_size, ntfs.sectors_per_cluster
        );
        let record_num = match resolve_mft_record(&*block_ref, this_media_id, &ntfs, path) {
            Some(n) => n,
            None => {
                uefi::println!("[NTFS] resolve_mft_record('{}') failed", path);
                core::mem::forget(block);
                continue;
            }
        };
        uefi::println!(
            "[NTFS-BOOT] '{}' -> MFT rec {} ({} bytes, h3)",
            path, record_num, ntfs.mft_record_size
        );
        let data = match read_data_stream(&*block_ref, this_media_id, &ntfs, record_num) {
            Some(d) => d,
            None => {
                uefi::println!("[NTFS] read_data_stream('{}') failed", path);
                core::mem::forget(block);
                continue;
            }
        };

        return Some(data);
    }

    None
}
