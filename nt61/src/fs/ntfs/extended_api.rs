//! NTFS Extended Features Integration
//!
//! Provides a unified surface that ties the per-feature modules
//! (`compression`, `encryption`, `reparse`, `quota`, `logfile`)
//! into the live NTFS read/write paths.
//!
//! Each operation here is a thin wrapper that:
//!   1. Inspects the MFT record / attribute layout
//!   2. Dispatches to the feature module that owns the byte layout
//!   3. Reports back enough information for `mod.rs::read_file` /
//!      `write_file` to interpret the result
//!
//! ## Design notes
//!
//! NTFS compression and encryption are *attribute-level* concerns:
//!   * The compression flag lives in $STANDARD_INFORMATION (offset
//!     +0x30 in the resident attribute header) and the
//!     `compression_unit` field of the non-resident $DATA
//!     attribute header (offset +0x3A).
//!   * EFS encryption is signalled by the `FILE_ATTRIBUTE_ENCRYPTED`
//!     bit in $STANDARD_INFORMATION; the actual FEK and DDF are
//!     stored in a named stream called `$EFS`.
//!
//! Reparse points, quota tracking and the journal are
//! *volume-level* concerns that this module coordinates.

extern crate alloc;

use alloc::vec::Vec;

use super::compression as comp;
use super::encryption as efs;
use super::logfile;
use super::logfile::LogFile;
use super::quota;
use super::reparse;

// =============================================================================
// Feature flag constants (from <winuser.h> / <winnt.h>)
// =============================================================================

pub const FILE_ATTRIBUTE_READONLY: u32         = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32           = 0x0000_0002;
pub const FILE_ATTRIBUTE_SYSTEM: u32           = 0x0000_0004;
pub const FILE_ATTRIBUTE_DIRECTORY: u32        = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32          = 0x0000_0020;
pub const FILE_ATTRIBUTE_DEVICE: u32           = 0x0000_0040;
pub const FILE_ATTRIBUTE_NORMAL: u32           = 0x0000_0080;
pub const FILE_ATTRIBUTE_TEMPORARY: u32         = 0x0000_0100;
pub const FILE_ATTRIBUTE_SPARSE_FILE: u32      = 0x0000_0200;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32    = 0x0000_0400;
pub const FILE_ATTRIBUTE_COMPRESSED: u32       = 0x0000_0800;
pub const FILE_ATTRIBUTE_OFFLINE: u32          = 0x0000_1000;
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED:u32 = 0x0000_2000;
pub const FILE_ATTRIBUTE_ENCRYPTED: u32        = 0x0000_4000;
pub const FILE_ATTRIBUTE_VIRTUAL: u32          = 0x0000_FFFF;

// =============================================================================
// Volume-level feature state
// =============================================================================

/// Aggregate state for a single mounted NTFS volume. Lives in a
/// `Spinlock` so that quota / log mutations are atomic with respect
/// to the read paths.
pub struct VolumeFeatures {
    /// Volume serial number — used as the key in `quota::init_volume`.
    pub volume_id: u64,
    /// Bytes per cluster (matches NtfsFileSystem.cluster_size).
    pub bytes_per_cluster: u32,
    /// Bytes per MFT record (typically 1024 or 4096).
    pub bytes_per_mft_record: u32,
    /// Active journal — None until `journal_begin()` is called.
    pub journal: Option<LogFile>,
    /// Quota manager handle (volume_id-keyed in `quota::*`).
    pub quota_enabled: bool,
    /// Volume label (decoded from the $Volume attribute, if any).
    pub label: [u16; 64],
    pub label_len: usize,
}

impl VolumeFeatures {
    pub const fn new(volume_id: u64, bytes_per_cluster: u32, bytes_per_mft_record: u32) -> Self {
        Self {
            volume_id,
            bytes_per_cluster,
            bytes_per_mft_record,
            journal: None,
            quota_enabled: false,
            label: [0u16; 64],
            label_len: 0,
        }
    }
}

// =============================================================================
// $STANDARD_INFORMATION attribute parsing (0x10)
// =============================================================================

/// Parsed view of a $STANDARD_INFORMATION attribute. We only model
/// the fields we need (timestamps + flags); the remaining fields
/// (`class_id`, `owner_id`, `security_id`, `quota_charged`, etc.)
/// are read past but not retained.
#[derive(Debug, Clone, Copy)]
pub struct StandardInformation {
    pub creation_time: u64,
    pub modification_time: u64,
    pub mft_modification_time: u64,
    pub access_time: u64,
    pub flags: u32,
}

impl StandardInformation {
    pub const ATTR_TYPE: u32 = 0x10;

    /// Parse the resident `$STANDARD_INFORMATION` payload starting at
    /// `data`. The on-disk layout (per [MS-FSCC] §2.3.4) is:
    ///
    ///   +0x00: u64 creation
    ///   +0x08: u64 modification
    ///   +0x10: u64 mft_modification
    ///   +0x18: u64 access
    ///   +0x20: u32 flags
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 0x24 {
            return None;
        }
        let read_u64 = |o: usize| -> u64 {
            u64::from_le_bytes([
                data[o], data[o+1], data[o+2], data[o+3],
                data[o+4], data[o+5], data[o+6], data[o+7],
            ])
        };
        Some(Self {
            creation_time: read_u64(0x00),
            modification_time: read_u64(0x08),
            mft_modification_time: read_u64(0x10),
            access_time: read_u64(0x18),
            flags: u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]),
        })
    }

    pub fn is_compressed(&self) -> bool {
        (self.flags & FILE_ATTRIBUTE_COMPRESSED) != 0
    }
    pub fn is_encrypted(&self) -> bool {
        (self.flags & FILE_ATTRIBUTE_ENCRYPTED) != 0
    }
    pub fn is_sparse(&self) -> bool {
        (self.flags & FILE_ATTRIBUTE_SPARSE_FILE) != 0
    }
    pub fn is_reparse_point(&self) -> bool {
        (self.flags & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
}

// =============================================================================
// Non-resident $DATA attribute compression-unit inspection
// =============================================================================

/// Read the `compression_unit` field from the non-resident $DATA
/// attribute header. Returns 0 (= no compression) when the field is
/// zero; a non-zero value of `2^N` clusters indicates LZNT1
/// compression units. The field lives at offset +0x3A relative to
/// the attribute header start.
pub fn data_compression_unit(data_attr: &[u8]) -> u16 {
    if data_attr.len() < 0x3C {
        return 0;
    }
    u16::from_le_bytes([data_attr[0x3A], data_attr[0x3B]])
}

/// Decode the non-resident $DATA attribute header into a
/// `DataAttrHeader` for inspection by callers.
pub fn parse_data_attr_header(data_attr: &[u8]) -> Option<DataAttrHeader> {
    if data_attr.len() < 0x40 {
        return None;
    }
    let read_u64 = |o: usize| -> u64 {
        u64::from_le_bytes([
            data_attr[o], data_attr[o+1], data_attr[o+2], data_attr[o+3],
            data_attr[o+4], data_attr[o+5], data_attr[o+6], data_attr[o+7],
        ])
    };
    let read_u16 = |o: usize| -> u16 {
        u16::from_le_bytes([data_attr[o], data_attr[o+1]])
    };
    Some(DataAttrHeader {
        starting_vcn: read_u64(0x10),
        last_vcn: read_u64(0x18),
        allocated_size: read_u64(0x20),
        real_size: read_u64(0x28),
        initialized_size: read_u64(0x30),
        mapping_pairs_offset: read_u16(0x38),
        compression_unit: read_u16(0x3A),
    })
}

#[derive(Debug, Clone, Copy)]
pub struct DataAttrHeader {
    pub starting_vcn: u64,
    pub last_vcn: u64,
    pub allocated_size: u64,
    pub real_size: u64,
    pub initialized_size: u64,
    pub mapping_pairs_offset: u16,
    pub compression_unit: u16,
}

impl DataAttrHeader {
    pub fn is_compressed(&self) -> bool {
        self.compression_unit != 0
    }
}

// =============================================================================
// Compressed read path
// =============================================================================

/// Read a range from a compressed non-resident $DATA attribute.
///
/// `data_attr` is the *payload* of the $DATA attribute (i.e. the
/// non-resident header followed by the mapping pairs).
/// `cluster_read` is a callback that copies one cluster worth of
/// bytes from the volume starting at LCN `lcn` into `out`. The
/// callback returns `true` on success.
///
/// Returns the number of bytes written into `out`. The caller is
/// responsible for verifying `start_offset + length <= file_size`
/// and for providing a buffer of at least `length` bytes.
///
/// The on-disk layout follows the Windows NTFS driver: each
/// compression unit covers `2^N` clusters where N =
/// `compression_unit`. Each unit is either stored verbatim
/// ("uncompressed chunk") or compressed with LZNT1
/// ("compressed chunk"). Within the compressed chunk, the unit is
/// further sub-divided into `comp::COMPRESSION_BLOCK_SIZE`-byte
/// sub-blocks, each prefixed with a 2-byte header that flags
/// compression and records the sub-block size.
pub fn read_compressed_data_attr<F: FnMut(u64, &mut [u8]) -> bool>(
    data_attr: &[u8],
    cluster_size: u32,
    start_offset: u64,
    length: usize,
    out: &mut [u8],
    mut cluster_read: F,
) -> Result<usize, ()> {
    let header = parse_data_attr_header(data_attr).ok_or(())?;
    if header.compression_unit == 0 {
        return Err(());
    }
    let unit_clusters: u32 = 1u32 << header.compression_unit;
    let unit_size: usize = (unit_clusters * cluster_size) as usize;
    let mapping_pairs_offset = header.mapping_pairs_offset as usize;
    if mapping_pairs_offset == 0 || mapping_pairs_offset >= data_attr.len() {
        return Err(());
    }

    let run_list = &data_attr[mapping_pairs_offset..];
    let mut runs: [(u64, u64); 256] = [(0, 0); 256];
    let num_runs = super::parse_run_list(run_list, &mut runs);
    if num_runs == 0 {
        return Err(());
    }

    let mut total_written = 0usize;
    let mut logical_offset = start_offset;
    let end_offset = start_offset + length as u64;

    // Walk compression units.
    let mut unit_index = (start_offset / unit_size as u64) as usize;
    while logical_offset < end_offset && total_written < out.len() {
        let unit_start = (unit_index * unit_size) as u64;
        let unit_vcn: u64 = unit_start / cluster_size as u64;

        // Find the LCN for this unit. The run list gives us
        // (lcn, length_in_clusters); we sum cluster offsets
        // until we cover `unit_vcn`.
        let mut cluster_offset: u64 = 0;
        let mut lcn: Option<u64> = None;
        for i in 0..num_runs {
            let (run_lcn, run_len) = runs[i];
            if cluster_offset + run_len > unit_vcn {
                lcn = Some(run_lcn + (unit_vcn - cluster_offset));
                break;
            }
            cluster_offset += run_len;
        }

        // Sparse unit (zero-fill) — write zeros into `out` for
        // the rest of this unit.
        let (compressed_unit, read) = match lcn {
            Some(unit_lcn) => {
                let mut buf: Vec<u8> = alloc::vec![0u8; unit_size];
                // Read cluster-by-cluster via the callback.
                let mut read_total = 0usize;
                let mut ok = true;
                for c in 0..unit_clusters as u64 {
                    let cluster_buf = &mut buf[(c * cluster_size as u64) as usize..];
                    if !cluster_read(unit_lcn + c, cluster_buf) {
                        ok = false;
                        break;
                    }
                    read_total += cluster_size as usize;
                }
                if !ok {
                    return Err(());
                }
                (buf, read_total)
            }
            None => {
                // Sparse — leave compressed_unit as zeros; the
                // LZNT1 decompressor will yield a zero-filled
                // buffer when handed an all-zero source.
                (alloc::vec![0u8; unit_size], unit_size)
            }
        };

        // Decompress into a staging buffer of unit_size bytes.
        let mut decompressed_unit: Vec<u8> = alloc::vec![0u8; unit_size];
        let decompressed_size = comp::decompress_lznt1(
            &compressed_unit[..read],
            &mut decompressed_unit,
        ).unwrap_or(0);

        // Copy the requested slice into `out`.
        let copy_off = (logical_offset - unit_start) as usize;
        let remaining = (end_offset - logical_offset) as usize;
        let copy_len = core::cmp::min(
            remaining.min(decompressed_size.saturating_sub(copy_off)),
            out.len() - total_written,
        );
        if copy_len == 0 {
            break;
        }
        out[total_written..total_written + copy_len].copy_from_slice(
            &decompressed_unit[copy_off..copy_off + copy_len],
        );
        total_written += copy_len;
        logical_offset += copy_len as u64;
        unit_index += 1;
    }

    Ok(total_written)
}

// =============================================================================
// Compressed write path
// =============================================================================

/// Compress `data` with LZNT1 in compression-unit granularity and
/// store the result into the supplied run-list buffer. Returns the
/// total number of bytes written (across all units). The caller is
/// responsible for allocating a destination buffer large enough to
/// hold the worst case (≈ 1.01× the input).
pub fn write_compressed_data_attr(
    data: &[u8],
    cluster_size: u32,
    compression_unit_pow2: u16,
    out: &mut [u8],
) -> Result<usize, ()> {
    let unit_clusters: u32 = 1u32 << compression_unit_pow2;
    let unit_size: usize = (unit_clusters * cluster_size) as usize;

    let mut total_written = 0usize;
    let mut offset = 0usize;
    while offset < data.len() {
        let chunk_len = core::cmp::min(unit_size, data.len() - offset);
        let chunk = &data[offset..offset + chunk_len];

        // If compression doesn't shrink the chunk, store it verbatim.
        let mut compressed = alloc::vec![0u8; chunk_len + chunk_len / 8 + 16];
        let compressed_len = comp::compress_lznt1(chunk, &mut compressed)
            .unwrap_or(chunk_len);
        let to_write: &[u8] = if compressed_len < chunk_len {
            &compressed[..compressed_len]
        } else {
            chunk
        };
        if total_written + to_write.len() > out.len() {
            return Err(());
        }
        out[total_written..total_written + to_write.len()].copy_from_slice(to_write);
        total_written += to_write.len();
        offset += chunk_len;
    }
    Ok(total_written)
}

// =============================================================================
// $EFS attribute helper
// =============================================================================

/// Parse the `$EFS` alternate data stream attached to an encrypted
/// file. Returns `Some(header, entries)` when the stream is present
/// and well-formed, `None` otherwise.
pub fn read_efs_stream(data: &[u8]) -> Option<(efs::EfsStreamHeader, Vec<efs::EfsKeyEntry>)> {
    efs::parse_efs_stream(data).ok()
}

// =============================================================================
// Reparse-point attribute helper
// =============================================================================

/// Parse a 0xC0 reparse-point attribute payload. The payload starts
/// with a u32 tag + u16 data_length + u16 reserved and is followed by
/// the tag-specific structure. Returns `None` if the attribute is
/// shorter than 8 bytes.
pub fn parse_reparse_attribute(payload: &[u8]) -> Option<reparse::ReparsePoint> {
    reparse::parse_reparse_point(payload).ok()
}

// =============================================================================
// Quota accounting
// =============================================================================

/// Record a quota charge against `user_sid`. Returns `Err(())` if
/// the quota is enforced and would be exceeded; returns `Ok(())`
/// otherwise (or if quotas are disabled).
pub fn charge_quota(volume_id: u64, user_sid: &[u8], bytes: u64) -> Result<(), ()> {
    quota::allocate_space(volume_id, user_sid, bytes)
}

/// Release a quota charge when bytes are deleted or truncated.
pub fn release_quota(volume_id: u64, user_sid: &[u8], bytes: u64) {
    quota::deallocate_space(volume_id, user_sid, bytes);
}

// =============================================================================
// Journal helpers — thin wrappers over `logfile`
// =============================================================================

/// Begin a new transaction in the volume's journal. If the journal
/// is not yet attached this is a no-op and the journal is *not*
/// implicitly created — callers that need durability must call
/// `attach_journal()` first.
pub fn journal_begin(features: &mut VolumeFeatures) -> Option<u32> {
    features.journal.as_mut().map(|j| j.begin_transaction())
}

pub fn journal_log(features: &mut VolumeFeatures, txn: u32, kind: logfile::LogRecordType, data: Vec<u8>) -> Result<(), &'static str> {
    let journal = features.journal.as_mut().ok_or("journal not attached")?;
    journal.write_record(txn, kind, data).map(|_| ())
}

pub fn journal_commit(features: &mut VolumeFeatures, txn: u32) -> Result<(), &'static str> {
    let journal = features.journal.as_mut().ok_or("journal not attached")?;
    journal.commit_transaction(txn)
}

pub fn journal_abort(features: &mut VolumeFeatures, txn: u32) -> Result<(), &'static str> {
    let journal = features.journal.as_mut().ok_or("journal not attached")?;
    journal.abort_transaction(txn)
}

/// Attach an in-memory journal to a volume. Idempotent: subsequent
/// calls drop the previous journal.
pub fn attach_journal(features: &mut VolumeFeatures, max_records: usize) {
    features.journal = Some(logfile::LogFile::new(max_records));
}

// =============================================================================
// Smoke / unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_information_flags() {
        let mut payload = [0u8; 0x30];
        // Set FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED
        payload[0x20] = 0x18;
        payload[0x21] = 0x00;
        let si = StandardInformation::parse(&payload).unwrap();
        assert!(si.is_compressed());
        assert!(si.is_encrypted());
        assert!(!si.is_sparse());
        assert!(!si.is_reparse_point());
    }

    #[test]
    fn data_attr_header_layout() {
        let mut payload = [0u8; 0x40];
        payload[0x3A] = 0x04; // 2^4 = 16 clusters per CU
        let h = parse_data_attr_header(&payload).unwrap();
        assert_eq!(h.compression_unit, 4);
        assert!(h.is_compressed());
    }
}