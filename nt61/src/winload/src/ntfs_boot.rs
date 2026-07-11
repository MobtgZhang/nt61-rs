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
    for part in &parts {
        current = find_child_in_index(block_io, media_id, ntfs, current, part)?;
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
            let entries_off = body + first_entry_offset;
            if entries_off >= end {
                off += attr_len;
                continue;
            }

            // Walk index entries.
            let mut p = entries_off;
            let end_p = entries_off + total_size;
            while p + 16 < end_p && p + 16 <= end {
                let entry_len = u16::from_le_bytes([
                    record[p + 8], record[p + 9],
                ]) as usize;
                // indexed_attribute_length is at p + 0x0A (NOT p + 0x10).
                let stream_len = u16::from_le_bytes([
                    record[p + 0x0A], record[p + 0x0B],
                ]) as usize;
                if entry_len == 0 {
                    break;
                }
                // FILE_NAME attribute header starts at p + 0x10.
                let fname_off = p + 0x10;
                if stream_len >= 24 && fname_off + 24 < end {
                    let inner_type = u32::from_le_bytes([
                        record[fname_off], record[fname_off + 1],
                        record[fname_off + 2], record[fname_off + 3],
                    ]);
                    let inner_len = u32::from_le_bytes([
                        record[fname_off + 4], record[fname_off + 5],
                        record[fname_off + 6], record[fname_off + 7],
                    ]) as usize;
                    if inner_type == 0x30 && inner_len >= 0x42 {
                        if let Some((fname, _)) = decode_filename_attr(&record, fname_off + 0x18) {
                            if fname.eq_ignore_ascii_case(name) {
                                let child_ref = u64::from_le_bytes([
                                    record[p], record[p + 1], record[p + 2], record[p + 3],
                                    record[p + 4], record[p + 5], record[p + 6], record[p + 7],
                                ]);
                                return Some(child_ref & 0x0000_FFFF_FFFF_FFFF);
                            }
                        }
                    }
                }
                p += entry_len;
            }
        }

        off += attr_len;
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
        return None;
    }

    let mut off = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let end = ntfs.mft_record_size as usize;
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
            break;
        }

        if attr_type == 0x80 {
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
                let first_vcn = u64::from_le_bytes([
                    record[off + 0x38], record[off + 0x39],
                    record[off + 0x3A], record[off + 0x3B],
                    record[off + 0x3C], record[off + 0x3D],
                    record[off + 0x3E], record[off + 0x3F],
                ]);
                let last_vcn = u64::from_le_bytes([
                    record[off + 0x40], record[off + 0x41],
                    record[off + 0x42], record[off + 0x43],
                    record[off + 0x44], record[off + 0x45],
                    record[off + 0x46], record[off + 0x47],
                ]);
                let alloc_size = u64::from_le_bytes([
                    record[off + 0x28], record[off + 0x29],
                    record[off + 0x2A], record[off + 0x2B],
                    record[off + 0x2C], record[off + 0x2D],
                    record[off + 0x2E], record[off + 0x2F],
                ]);
                let run_list_off = u16::from_le_bytes([
                    record[off + 0x38 + 12], record[off + 0x38 + 13],
                ]) as usize;

                if alloc_size > 0 && first_vcn == 0 {
                    // Parse run list: header byte encodes size of len/offset fields.
                    // We expect exactly one entry: `len lcn`.
                    let rp = off + run_list_off;
                    if rp < end {
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
                            // Run list offsets are signed and accumulate.
                            let delta = parse_varnum_signed(&off_bytes, off_len);
                            // LCN is always non-negative for non-corrupt images.
                            let run_start_lcn = delta as i64 as u64;
                            let spc = ntfs.sectors_per_cluster as u64;
                            let data_start = run_start_lcn * spc;
                            let data_sectors = run_len * spc;
                            return read_partition_sectors(
                                block_io, media_id, data_start, data_sectors as u32,
                            );
                        }
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
fn parse_varnum_signed(bytes: &[u8], len: usize) -> i64 {
    let mut val = 0i64;
    for i in 0..len {
        val |= (bytes[i] as i64) << (i * 8);
    }
    // Sign-extend based on the MSB of the last byte.
    let shift = (8 - len) % 8;
    if shift > 0 && len > 0 {
        let msb_bit = 7 - shift;
        if (bytes[len - 1] & (1 << msb_bit)) != 0 {
            for i in len..8 {
                val |= (0xFFi64) << (i * 8);
            }
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
        let this_blocks = (media.last_block() as u64) + 1;

        // Read boot sector to probe filesystem type.
        let mut boot_sector = [0u8; 512];
        if block_ref.read_blocks(this_media_id, 0u64, &mut boot_sector).is_err() {
            core::mem::forget(block);
            continue;
        }

        // Skip non-NTFS partitions.
        if &boot_sector[3..11] != b"NTFS    " {
            core::mem::forget(block);
            continue;
        }

        let ntfs = NtfsBoot::parse(&boot_sector)?;
        let record_num = resolve_mft_record(&*block_ref, this_media_id, &ntfs, path)?;
        let data = read_data_stream(&*block_ref, this_media_id, &ntfs, record_num)?;

        core::mem::forget(block);
        return Some(data);
    }

    None
}
