//! CLFS I/O Operations
//
//! Implements low-level I/O for reading and writing CLFS blocks.
//! In the real Windows kernel, this would interact with the I/O manager
//! to perform sector-aligned reads and writes to the underlying storage.

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::rtl::logging::subsystem::CLFS;

use super::context::ClfsContainerContext;
use super::format::{
    self, BlfMetadata, BlfBlockType, ClfsLogBlockHeader,
    CLFS_SECTOR_SIZE, CLFS_LOG_BLOCK_HEADER_SIZE,
};
use super::metadata::ClfsControlRecord;
use super::record::{ClfsLsn, ClfsLogRecordHeader, CLFS_LOG_RECORD_HEADER_SIZE};
use super::vcb::ClfsVcb;

// ============================================================================
// Error Types
// ============================================================================

/// CLFS error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClfsError {
    Success = 0,
    InvalidParameter,
    InvalidHandle,
    InvalidLogState,
    BufferTooSmall,
    LogFileFull,
    ChecksumMismatch,
    SectorFixupError,
    CorruptMetadata,
    ContainerNotFound,
    OutOfMemory,
    IoError,
    NotInitialized,
}

impl ClfsError {
    /// Convert to NTSTATUS.
    pub fn to_ntstatus(self) -> u32 {
        match self {
            ClfsError::Success           => 0,
            ClfsError::InvalidParameter  => 0xC000000D,
            ClfsError::InvalidHandle    => 0xC0000008,
            ClfsError::InvalidLogState  => 0xC0000188,
            ClfsError::BufferTooSmall   => 0xC0000023,
            ClfsError::LogFileFull      => 0xC0000188,
            ClfsError::ChecksumMismatch  => 0xC0000008,
            ClfsError::SectorFixupError  => 0xC0000008,
            ClfsError::CorruptMetadata   => 0xC0000008,
            ClfsError::ContainerNotFound => 0xC0000008,
            ClfsError::OutOfMemory      => 0xC0000017,
            ClfsError::IoError          => 0xC000000E,
            ClfsError::NotInitialized   => 0xC0000001,
        }
    }
}

impl Default for ClfsError {
    fn default() -> Self {
        Self::Success
    }
}

// ============================================================================
// Container Memory Buffer
// ============================================================================

/// In-memory buffer for a container.
/// In the real kernel, containers would be backed by mapped file sections.
/// In our bootstrap implementation, we keep containers in memory.
pub struct ContainerBuffer {
    /// Container ID.
    pub cid: u32,
    /// Buffer holding the container data.
    pub data: alloc::vec::Vec<u8>,
    /// Current USN for this container.
    pub usn: AtomicU32,
    /// Dirty flag — true if the buffer has been modified.
    pub dirty: AtomicU32,
}

impl ContainerBuffer {
    /// Create a new container buffer of the given size.
    pub fn new(cid: u32, size: usize) -> Option<Self> {
        Some(Self {
            cid,
            data: alloc::vec![0u8; size],
            usn: AtomicU32::new(0),
            dirty: AtomicU32::new(0),
        })
    }

    /// Read a sector from the container.
    pub fn read_sector(&self, offset_sectors: usize, buf: &mut [u8]) -> Result<(), ClfsError> {
        let byte_offset = offset_sectors * CLFS_SECTOR_SIZE;
        if byte_offset + buf.len() > self.data.len() {
            return Err(ClfsError::BufferTooSmall);
        }
        buf.copy_from_slice(&self.data[byte_offset..byte_offset + buf.len()]);
        Ok(())
    }

    /// Write a sector to the container.
    pub fn write_sector(&mut self, offset_sectors: usize, buf: &[u8]) -> Result<(), ClfsError> {
        let byte_offset = offset_sectors * CLFS_SECTOR_SIZE;
        if byte_offset + buf.len() > self.data.len() {
            return Err(ClfsError::BufferTooSmall);
        }
        self.data[byte_offset..byte_offset + buf.len()].copy_from_slice(buf);
        self.mark_dirty();
        Ok(())
    }

    /// Read multiple bytes from the container.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), ClfsError> {
        if offset + buf.len() > self.data.len() {
            return Err(ClfsError::BufferTooSmall);
        }
        buf.copy_from_slice(&self.data[offset..offset + buf.len()]);
        Ok(())
    }

    /// Write multiple bytes to the container.
    pub fn write(&mut self, offset: usize, buf: &[u8]) -> Result<(), ClfsError> {
        if offset + buf.len() > self.data.len() {
            return Err(ClfsError::BufferTooSmall);
        }
        self.data[offset..offset + buf.len()].copy_from_slice(buf);
        self.mark_dirty();
        Ok(())
    }

    /// Mark the container as dirty.
    pub fn mark_dirty(&self) {
        self.dirty.store(1, Ordering::Release);
    }

    /// Mark the container as clean.
    pub fn mark_clean(&self) {
        self.dirty.store(0, Ordering::Release);
    }

    /// Check if the container is dirty.
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire) != 0
    }

    /// Get the container size.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Increment the USN.
    pub fn advance_usn(&self) -> u32 {
        self.usn.fetch_add(1, Ordering::Relaxed)
    }
}

// ============================================================================
// Block I/O Operations
// ============================================================================

/// Read a log block from a container buffer.
pub fn read_log_block(container: &ContainerBuffer, block_offset: usize) -> Result<alloc::vec::Vec<u8>, ClfsError> {
    // Read the first sector to get the block header
    let mut header_sector = [0u8; CLFS_SECTOR_SIZE];
    container.read_sector(block_offset, &mut header_sector)?;

    // Parse the block header
    let header = parse_block_header(&header_sector)?;
    let total_size = (header.total_sector_count as usize) * CLFS_SECTOR_SIZE;

    // Read the entire block
    let mut block = alloc::vec![0u8; total_size];
    for i in 0..header.total_sector_count as usize {
        let offset = (block_offset + i) * CLFS_SECTOR_SIZE;
        let sector_buf = &mut block[i * CLFS_SECTOR_SIZE..(i + 1) * CLFS_SECTOR_SIZE];
        container.read_sector(offset, sector_buf)?;
    }

    // Verify checksum
    let stored_checksum = format::read_u32_le(&block[16..20]);
    let computed = format::compute_block_checksum(&block);
    if stored_checksum != computed {
        crate::kprintln_info!("CLFS", "  [CLFS] checksum mismatch: stored=0x{:08x} computed=0x{:08x}",
            stored_checksum, computed);
        return Err(ClfsError::ChecksumMismatch);
    }

    Ok(block)
}

/// Write a log block to a container buffer.
pub fn write_log_block(
    container: &mut ContainerBuffer,
    block_offset: usize,
    block: &[u8],
) -> Result<(), ClfsError> {
    let sector_count = block.len() / CLFS_SECTOR_SIZE;
    let usn = container.advance_usn();
    // Publish the USN advanced by this write so external observers can
    // correlate write activity with on-disk state transitions.
    LAST_WRITE_USN.store(usn, core::sync::atomic::Ordering::Relaxed);
    WRITE_BLOCKS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    // Write each sector
    for i in 0..sector_count {
        let src = &block[i * CLFS_SECTOR_SIZE..(i + 1) * CLFS_SECTOR_SIZE];
        let dest_offset = block_offset + i;
        container.write_sector(dest_offset, src)?;
    }

    container.mark_dirty();
    Ok(())
}

static LAST_WRITE_USN: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static WRITE_BLOCKS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Return `(last_write_usn, write_block_calls)` accumulators from
/// `write_log_block`.
pub fn write_diag() -> (u32, u32) {
    (
        LAST_WRITE_USN.load(core::sync::atomic::Ordering::Relaxed),
        WRITE_BLOCKS.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Parse a block header from a sector.
fn parse_block_header(sector: &[u8]) -> Result<ClfsLogBlockHeader, ClfsError> {
    if sector.len() < CLFS_LOG_BLOCK_HEADER_SIZE {
        return Err(ClfsError::CorruptMetadata);
    }

    let major_version = sector[0];
    let minor_version = sector[1];

    if major_version != 0x15 || minor_version != 0x00 {
        crate::kprintln_info!("CLFS", "  [CLFS] invalid block version: {:#x}.{:#x}", major_version, minor_version);
        return Err(ClfsError::CorruptMetadata);
    }

    Ok(ClfsLogBlockHeader {
        major_version,
        minor_version,
        usn: sector[2],
        client_id: sector[3],
        total_sector_count: format::read_u16_le(&sector[4..6]),
        valid_sector_count: format::read_u16_le(&sector[6..8]),
        padding: format::read_u32_le(&sector[8..12]),
        checksum: format::read_u32_le(&sector[12..16]),
        flags: format::read_u32_le(&sector[16..20]),
        current_lsn: format::read_u64_le(&sector[20..28]),
        next_lsn: format::read_u64_le(&sector[28..36]),
        record_offsets: {
            let mut arr = [0u32; 16];
            for i in 0..16 {
                arr[i] = format::read_u32_le(&sector[36 + i * 4..40 + i * 4]);
            }
            arr
        },
        signatures_offset: format::read_u32_le(&sector[100..104]),
    })
}

// ============================================================================
// Record I/O Operations
// ============================================================================

/// Read a record from a block at the given offset.
pub fn read_record_from_block(block: &[u8], offset: usize) -> Result<ClfsLogRecordHeader, ClfsError> {
    if offset >= block.len() {
        return Err(ClfsError::InvalidParameter);
    }

    let header = ClfsLogRecordHeader::read_from(&block[offset..])
        .ok_or(ClfsError::CorruptMetadata)?;

    if !header.is_valid() {
        return Err(ClfsError::CorruptMetadata);
    }

    Ok(header)
}

/// Read the data portion of a record.
pub fn read_record_data(block: &[u8], header: &ClfsLogRecordHeader) -> Result<alloc::vec::Vec<u8>, ClfsError> {
    let offset = CLFS_LOG_RECORD_HEADER_SIZE;
    let data_end = header.record_length as usize;
    if offset + data_end > block.len() {
        return Err(ClfsError::CorruptMetadata);
    }
    Ok(block[offset..offset + data_end].to_vec())
}

// ============================================================================
// BLF I/O Operations
// ============================================================================

/// Initialize the BLF metadata region for a new log.
pub fn initialize_blf(vcb: &mut ClfsVcb, blf_data: &mut [u8]) -> Result<(), ClfsError> {
    if blf_data.len() < 6 * CLFS_SECTOR_SIZE {
        return Err(ClfsError::BufferTooSmall);
    }

    // Zero the BLF region
    blf_data[..6 * CLFS_SECTOR_SIZE].fill(0);

    // Initialize the control record (sector 0)
    let control = ClfsControlRecord::new();
    control.write_to(&mut blf_data[..CLFS_SECTOR_SIZE]);

    // Copy to shadow (sector 1) — use temp buffer to avoid overlapping borrows
    let sector0_copy = blf_data[..CLFS_SECTOR_SIZE].to_vec();
    blf_data[CLFS_SECTOR_SIZE..2 * CLFS_SECTOR_SIZE].copy_from_slice(&sector0_copy);

    // Update the BLF metadata
    vcb.blf_metadata = BlfMetadata::new();

    crate::kprintln_info!("CLFS", "  [CLFS] BLF initialized (6 metadata sectors)");
    Ok(())
}

/// Flush all dirty containers for a VCB.
pub fn flush_vcb(_vcb: &ClfsVcb) -> Result<(), ClfsError> {
    // In the real kernel, this would write dirty container data to disk.
    // In our in-memory implementation, this is a no-op.
    crate::kprintln_info!("CLFS", "  [CLFS] VCB flushed");
    Ok(())
}

// ============================================================================
// Record Serialization
// ============================================================================

/// Serialize a record header and data to a byte buffer.
/// Returns the total bytes written.
pub fn serialize_record(header: &ClfsLogRecordHeader, data: &[u8], buf: &mut [u8]) -> usize {
    if buf.len() < header.total_size() {
        return 0;
    }

    header.write_to(buf);

    let data_offset = CLFS_LOG_RECORD_HEADER_SIZE;
    let copy_len = data.len().min(header.record_length as usize);
    buf[data_offset..data_offset + copy_len].copy_from_slice(&data[..copy_len]);

    header.total_size()
}

/// Deserialize a record header and data from a byte buffer.
pub fn deserialize_record(buf: &[u8]) -> Option<(ClfsLogRecordHeader, &[u8])> {
    let header = ClfsLogRecordHeader::read_from(buf)?;
    if !header.is_valid() {
        return None;
    }

    let data_offset = CLFS_LOG_RECORD_HEADER_SIZE;
    let data = &buf[data_offset..data_offset + header.record_length as usize];

    Some((header, data))
}

// ============================================================================
// Statistics
// ============================================================================

/// Global CLFS statistics.
#[derive(Debug, Default)]
pub struct ClfsStats {
    pub blocks_read: AtomicU64,
    pub blocks_written: AtomicU64,
    pub records_read: AtomicU64,
    pub records_written: AtomicU64,
    pub checksum_errors: AtomicU64,
    pub flushes: AtomicU64,
}

impl ClfsStats {
    pub const fn new() -> Self {
        Self {
            blocks_read: core::sync::atomic::AtomicU64::new(0),
            blocks_written: core::sync::atomic::AtomicU64::new(0),
            records_read: core::sync::atomic::AtomicU64::new(0),
            records_written: core::sync::atomic::AtomicU64::new(0),
            checksum_errors: core::sync::atomic::AtomicU64::new(0),
            flushes: core::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn record_read(&self) {
        self.records_read.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_written(&self) {
        self.records_written.fetch_add(1, Ordering::Relaxed);
    }

    pub fn block_read(&self) {
        self.blocks_read.fetch_add(1, Ordering::Relaxed);
    }

    pub fn block_written(&self) {
        self.blocks_written.fetch_add(1, Ordering::Relaxed);
    }

    pub fn checksum_error(&self) {
        self.checksum_errors.fetch_add(1, Ordering::Relaxed);
    }
}

pub static CLFS_STATS: ClfsStats = ClfsStats::new();
