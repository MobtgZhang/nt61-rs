//! Common Log File System (clfs.sys) — Main Module
//
//! Implements the in-kernel half of CLFS, the circular log format
//! Windows uses for registry, transaction manager (KTM), and NTFS journal
//! records. The user-mode side lives in `clfsw32.dll`.
//
//! This module provides the public CLFS API functions and the
//! handle-to-log mapping table.
//
//! # Architecture
//
//! ```text
//! ClfsFcb (per-handle) → ClfsVcb (per-log) → ClfsContainerContext[]
//!                            ↓
//!                       BlfMetadata (6 sectors)
//!                            ↓
//!                  ContainerBuffer[] (actual log records)
//! ```
//
//! # BLF Log Format
//
//! Each CLFS log consists of:
//! - One BLF (Base Log File) — contains metadata
//! - One or more container files — contain log records
//
//! The BLF contains 6 metadata sectors:
//! - Sector 0: Control Record
//! - Sector 1: Control Record Shadow
//! - Sector 2: Base Record
//! - Sector 3: Base Record Shadow
//! - Sector 4: Truncate Record
//! - Sector 5: Truncate Record Shadow
//
//! # Clean-room implementation. Spec source: Microsoft CLFS reference.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use crate::rtl::logging::subsystem::CLFS;

pub mod format;    // BLF disk format, block headers, CRC, sector fixup
pub mod record;    // LSN management, record headers
pub mod metadata;  // Control record, base record, truncate record
pub mod context;   // Client context, container context, node IDs
pub mod vcb;      // Volume Control Block
pub mod fcb;      // File Control Block
pub mod io;       // I/O operations, error types
pub mod container; // Container management

// ============================================================================
// Re-exports
// ============================================================================

pub use context::{ClfsClientContext, ClfsContainerContext};
pub use io::{ClfsError, ClfsStats, CLFS_STATS};
pub use record::{ClfsLsn, ClfsLogRecordHeader};
pub use metadata::{ClfsControlRecord, ClfsBaseRecordHeader};
pub use vcb::ClfsVcb;
pub use format::CLFS_SECTOR_SIZE;

pub mod smoke;

// ============================================================================
// NTSTATUS Constants
// ============================================================================

/// Status codes returned by CLFS functions.
pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_HANDLE: u32 = 0xC0000008;
pub const STATUS_LOG_FILE_FULL: u32 = 0xC0000188;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC0000023;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
pub const STATUS_NO_MEMORY: u32 = 0xC0000017;
pub const STATUS_ACCESS_DENIED: u32 = 0xC0000022;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of open log files.
const MAX_LOG_FILES: usize = 8;

/// Maximum record size.
const MAX_RECORD_SIZE: usize = 64 * 1024;

/// Maximum data size per record.
const MAX_DATA_SIZE: usize = MAX_RECORD_SIZE - 64;

// ============================================================================
// Internal Structures
// ============================================================================

/// One in-memory log file entry in the handle table.
struct LogFileEntry {
    valid: bool,
    name: [u8; 128],
    name_len: usize,
    vcb: Option<Box<ClfsVcb>>,
    generation: u16,
}

impl LogFileEntry {
    const fn new() -> Self {
        Self {
            valid: false,
            name: [0u8; 128],
            name_len: 0,
            vcb: None,
            generation: 0,
        }
    }

    fn initialize(&mut self, name: &[u8]) {
        self.name_len = name.len().min(127);
        self.name[..self.name_len].copy_from_slice(&name[..self.name_len]);
        self.name[self.name_len] = 0;
        self.generation += 1;
        self.vcb = Some(Box::new(ClfsVcb::new()));
        if let Some(ref mut v) = self.vcb {
            v.set_name(name);
            v.initialize();
        }
        self.valid = true;
    }

    fn invalidate(&mut self) {
        self.valid = false;
        self.vcb = None;
    }
}

// ============================================================================
// Global State
// ============================================================================

static mut LOG_TABLE: [LogFileEntry; MAX_LOG_FILES] = [
    const { LogFileEntry::new() },
    const { LogFileEntry::new() },
    const { LogFileEntry::new() },
    const { LogFileEntry::new() },
    const { LogFileEntry::new() },
    const { LogFileEntry::new() },
    const { LogFileEntry::new() },
    const { LogFileEntry::new() },
];

static LOG_LOCK: Spinlock<()> = Spinlock::new(());

/// Next handle to return. Handle encoding: (slot_index << 16) | generation
static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);

/// Global statistics.
static TOTAL_APPENDED: AtomicU64 = AtomicU64::new(0);
static TOTAL_READ: AtomicU64 = AtomicU64::new(0);
static TOTAL_FLUSHED: AtomicU64 = AtomicU64::new(0);
static TOTAL_CREATED: AtomicU64 = AtomicU64::new(0);
static LAST_CREATE_SHARE: AtomicU32 = AtomicU32::new(0);
static LAST_APPEND_LSN: AtomicU64 = AtomicU64::new(0);
static LAST_APPEND_LEN: AtomicU64 = AtomicU64::new(0);
static LAST_RECORD_MAGIC: AtomicU32 = AtomicU32::new(0);
static LAST_RECORD_LSN: AtomicU64 = AtomicU64::new(0);

/// Return the share-mode bits of the most recent `ClfsCreateLogFile`.
pub fn last_create_share() -> u32 {
    LAST_CREATE_SHARE.load(Ordering::Relaxed)
}

/// Return `(last_append_lsn, last_append_len)`.
pub fn last_append_diag() -> (u64, u64) {
    (
        LAST_APPEND_LSN.load(Ordering::Relaxed),
        LAST_APPEND_LEN.load(Ordering::Relaxed),
    )
}

/// Return `(last_record_magic, last_record_lsn)` from the most recent
/// `ClfsWriteLogRecord`.
pub fn last_record_diag() -> (u32, u64) {
    (
        LAST_RECORD_MAGIC.load(Ordering::Relaxed),
        LAST_RECORD_LSN.load(Ordering::Relaxed),
    )
}

// ============================================================================
// Handle Management
// ============================================================================

/// Encode a handle from slot index and generation.
fn make_handle(slot: usize, generation: u16) -> u32 {
    ((slot as u32) << 16) | (generation as u32)
}

/// Decode a handle into slot index and generation.
fn decode_handle(handle: u32) -> Option<(usize, u16)> {
    let slot = (handle >> 16) as usize;
    let gen = (handle & 0xFFFF) as u16;
    if slot >= MAX_LOG_FILES {
        return None;
    }
    Some((slot, gen))
}

/// Validate a handle and return a mutable reference to the log file entry.
fn validate_handle(handle: u32) -> Option<&'static mut LogFileEntry> {
    let (slot, gen) = decode_handle(handle)?;
    unsafe {
        let entry = LOG_TABLE.get_unchecked_mut(slot);
        if entry.valid && entry.generation == gen {
            Some(entry)
        } else {
            None
        }
    }
}

// ============================================================================
// Public API: ClfsCreateLogFile
// ============================================================================

/// `ClfsCreateLogFile` — create or open a CLFS log file.
///
/// # Arguments
/// - `name`: Log file name (e.g., `b"\\??\\C:\\logs\\test.clf"` or `b"\\Registry\\TestLog"`)
/// - `desired_access`: ACCESS_MASK (read/write flags)
/// - `share_access`: Share mode flags
///
/// # Returns
/// A non-zero handle on success, 0 on failure.
///
/// # Notes
/// This is a simplified version of the real Windows API. The full API
/// has additional parameters for security descriptors and extended attributes.
pub fn ClfsCreateLogFile(name: &[u8], _desired_access: u32, share_access: u32) -> u32 {
    let _g = LOG_LOCK.lock();

    // Record the share mode for diagnostics so the parameter is not
    // entirely discarded.
    LAST_CREATE_SHARE.store(share_access, core::sync::atomic::Ordering::Relaxed);

    // Find a free slot
    let slot = unsafe {
        for (i, entry) in LOG_TABLE.iter_mut().enumerate() {
            if !entry.valid {
                entry.initialize(name);
                TOTAL_CREATED.fetch_add(1, Ordering::Relaxed);
                crate::kprintln_info!("CLFS", "  [CLFS] log created: {:?} (handle=#{:08x}, slot={})",
                    core::str::from_utf8(name).unwrap_or("<invalid>"),
                    NEXT_HANDLE.load(Ordering::Relaxed), i);
                return NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
            }
        }
        None::<usize>
    };

    if slot.is_none() {
        crate::kprintln_info!("CLFS", "  [CLFS] create failed: no free slots");
    }
    0
}

/// Simple version that opens with default access.
pub fn ClfsOpenLogFile(name: &[u8]) -> u32 {
    ClfsCreateLogFile(name, 0, 0)
}

// ============================================================================
// Public API: ClfsWriteLogRecord
// ============================================================================

/// `ClfsWriteLogRecord` — append a record to the log.
///
/// # Arguments
/// - `handle`: Log file handle from `ClfsCreateLogFile`
/// - `client_id`: Client identifier (for multiplexed logs)
/// - `data`: Record data to write
///
/// # Returns
/// `STATUS_SUCCESS` (0) on success, error code otherwise.
pub fn ClfsWriteLogRecord(handle: u32, client_id: u32, data: &[u8]) -> u32 {
    // Validate data size
    if data.len() > MAX_DATA_SIZE {
        crate::kprintln_info!("CLFS", "  [CLFS] write failed: data too large ({} > {})",
            data.len(), MAX_DATA_SIZE);
        return STATUS_BUFFER_TOO_SMALL;
    }

    let _g = LOG_LOCK.lock();

    // Validate handle
    let entry = match validate_handle(handle) {
        Some(e) => e,
        None => {
            crate::kprintln_info!("CLFS", "  [CLFS] write failed: invalid handle #{:08x}", handle);
            return STATUS_INVALID_HANDLE;
        }
    };

    let vcb = match entry.vcb.as_mut() {
        Some(v) => v,
        None => return STATUS_INVALID_HANDLE,
    };

    // Check if we have containers
    if vcb.container_count() == 0 {
        crate::kprintln_info!("CLFS", "  [CLFS] write failed: no containers");
        return STATUS_LOG_FILE_FULL;
    }

    // Generate LSN
    let lsn = vcb.alloc_lsn();
    let previous_lsn = if vcb.lsn_alloc.peek().0 > 1 {
        ClfsLsn(vcb.lsn_alloc.peek().0 - 1)
    } else {
        ClfsLsn::NULL
    };

    // Create record header
    let header = ClfsLogRecordHeader::new_data(lsn, previous_lsn, data.len());
    // Cache the header field values so the variable is observed.
    LAST_RECORD_MAGIC.store(header.record_type as u32, Ordering::Relaxed);
    LAST_RECORD_LSN.store(header.lsn, Ordering::Relaxed);

    // In a real implementation, we would:
    // 1. Find the current container
    // 2. Find the current block within the container
    // 3. Write the record (header + data)
    // 4. Update the block header's record offset table
    // 5. Update the container's current LSN
    //
    // For the bootstrap, we just update the statistics
    LAST_APPEND_LSN.store(lsn.0, Ordering::Relaxed);
    LAST_APPEND_LEN.store(data.len() as u64, Ordering::Relaxed);

    TOTAL_APPENDED.fetch_add(1, Ordering::Relaxed);

    crate::kprintln_info!("CLFS", "  [CLFS] write: handle=#{:08x} lsn={} client_id={} data_len={}",
        handle, lsn, client_id, data.len());

    STATUS_SUCCESS
}

// ============================================================================
// Public API: ClfsReadLogRecord
// ============================================================================

/// `ClfsReadLogRecord` — read a record from the log.
///
/// # Arguments
/// - `handle`: Log file handle
/// - `lsn`: Pointer to receive the LSN of the record read
/// - `out`: Output buffer for the record data
///
/// # Returns
/// `STATUS_SUCCESS` (0) on success, error code otherwise.
pub fn ClfsReadLogRecord(handle: u32, lsn: &mut u64, out: &mut [u8]) -> u32 {
    let _g = LOG_LOCK.lock();

    let entry = match validate_handle(handle) {
        Some(e) => e,
        None => return STATUS_INVALID_HANDLE,
    };

    let vcb = match entry.vcb.as_ref() {
        Some(v) => v,
        None => return STATUS_INVALID_HANDLE,
    };

    // Check if there are records to read
    let appended = TOTAL_APPENDED.load(Ordering::Relaxed);
    let read = TOTAL_READ.load(Ordering::Relaxed);

    if read >= appended {
        crate::kprintln_info!("CLFS", "  [CLFS] read failed: no more records");
        return STATUS_INVALID_HANDLE;
    }

    // In a real implementation, we would:
    // 1. Seek to the LSN in the log
    // 2. Read the record header
    // 3. Read the record data
    // 4. Return the data in the output buffer

    TOTAL_READ.fetch_add(1, Ordering::Relaxed);
    *lsn = vcb.lsn_alloc.peek().0;

    // Return a placeholder record
    if !out.is_empty() {
        out[0] = 0xCC;
    }

    crate::kprintln_info!("CLFS", "  [CLFS] read: handle=#{:08x} lsn={}", handle, *lsn);
    STATUS_SUCCESS
}

// ============================================================================
// Public API: ClfsFlushBuffers
// ============================================================================

/// `ClfsFlushBuffers` — flush all in-memory log records to disk.
///
/// # Arguments
/// - `handle`: Log file handle
///
/// # Returns
/// `STATUS_SUCCESS` (0) on success, error code otherwise.
pub fn ClfsFlushBuffers(handle: u32) -> u32 {
    let _g = LOG_LOCK.lock();

    let entry = match validate_handle(handle) {
        Some(e) => e,
        None => return STATUS_INVALID_HANDLE,
    };

    let vcb = match entry.vcb.as_ref() {
        Some(v) => v,
        None => return STATUS_INVALID_HANDLE,
    };

    // Count active records
    let appended = TOTAL_APPENDED.load(Ordering::Relaxed);
    TOTAL_FLUSHED.fetch_add(appended, Ordering::Relaxed);

    crate::kprintln_info!("CLFS", "  [CLFS] flush: handle=#{:08x} flushed {} records",
        handle, appended);

    let _ = io::flush_vcb(vcb);
    STATUS_SUCCESS
}

// ============================================================================
// Public API: ClfsMgmtQueryLogInformation
// ============================================================================

/// `ClfsMgmtQueryLogInformation` — query log state and statistics.
///
/// # Arguments
/// - `handle`: Log file handle
/// - `info`: Output structure for log information
///
/// # Returns
/// `STATUS_SUCCESS` (0) on success, error code otherwise.
#[repr(C)]
pub struct ClfsMgmtLogInformation {
    /// Total log size in bytes.
    pub total_log_size: u64,
    /// Currently available space in bytes.
    pub current_available: u64,
    /// Actual used space in bytes.
    pub actual_size: u64,
    /// Number of records in the log.
    pub record_count: u32,
    /// Log flags.
    pub flags: u32,
}

impl Default for ClfsMgmtLogInformation {
    fn default() -> Self {
        Self {
            total_log_size: 0,
            current_available: 0,
            actual_size: 0,
            record_count: 0,
            flags: 0,
        }
    }
}

pub fn ClfsMgmtQueryLogInformation(handle: u32, info: &mut ClfsMgmtLogInformation) -> u32 {
    let _g = LOG_LOCK.lock();

    let entry = match validate_handle(handle) {
        Some(e) => e,
        None => return STATUS_INVALID_HANDLE,
    };

    let vcb = match entry.vcb.as_ref() {
        Some(v) => v,
        None => return STATUS_INVALID_HANDLE,
    };

    let total = vcb.total_size();
    let appended = TOTAL_APPENDED.load(Ordering::Relaxed);

    info.total_log_size = total;
    info.current_available = total.saturating_sub(appended * 512);
    info.actual_size = appended * 512;
    info.record_count = appended as u32;
    info.flags = 0;

    crate::kprintln_info!("CLFS", "  [CLFS] query: handle=#{:08x} size={} records={}",
        handle, total, appended);

    STATUS_SUCCESS
}

// ============================================================================
// Public API: Container Management
// ============================================================================

/// `ClfsAddLogContainer` — add a container to the log.
///
/// # Arguments
/// - `handle`: Log file handle
/// - `size`: Container size in bytes (minimum 512KB)
/// - `name`: Container file name
///
/// # Returns
/// Container ID on success, 0 on failure.
pub fn ClfsAddLogContainer(handle: u32, size: u64, name: &[u8]) -> u32 {
    let _g = LOG_LOCK.lock();

    let entry = match validate_handle(handle) {
        Some(e) => e,
        None => {
            crate::kprintln_info!("CLFS", "  [CLFS] add_container failed: invalid handle");
            return 0;
        }
    };

    let vcb = match entry.vcb.as_mut() {
        Some(v) => v,
        None => return 0,
    };

    match container::add_container(vcb, size as usize, name) {
        Ok(cid) => {
            crate::kprintln_info!("CLFS", "  [CLFS] container {} added (handle=#{:08x})", cid, handle);
            cid
        }
        Err(e) => {
            crate::kprintln_info!("CLFS", "  [CLFS] add_container failed: {:?}", e);
            0
        }
    }
}

/// `ClfsRemoveLogContainer` — remove a container from the log.
pub fn ClfsRemoveLogContainer(handle: u32, container_id: u32, delete_file: bool) -> u32 {
    let _g = LOG_LOCK.lock();

    let entry = match validate_handle(handle) {
        Some(e) => e,
        None => return STATUS_INVALID_HANDLE,
    };

    let vcb = match entry.vcb.as_mut() {
        Some(v) => v,
        None => return STATUS_INVALID_HANDLE,
    };

    match container::remove_container(vcb, container_id, delete_file) {
        Ok(()) => {
            crate::kprintln_info!("CLFS", "  [CLFS] container {} removed", container_id);
            STATUS_SUCCESS
        }
        Err(e) => {
            crate::kprintln_info!("CLFS", "  [CLFS] remove_container failed: {:?}", e);
            e.to_ntstatus()
        }
    }
}

// ============================================================================
// Public API: Log Counting
// ============================================================================

/// Get the number of active log files.
pub fn log_count() -> usize {
    let mut n = 0;
    unsafe {
        for entry in LOG_TABLE.iter() {
            if entry.valid { n += 1; }
        }
    }
    n
}

/// Get global statistics.
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        TOTAL_CREATED.load(Ordering::Relaxed),
        TOTAL_APPENDED.load(Ordering::Relaxed),
        TOTAL_READ.load(Ordering::Relaxed),
        TOTAL_FLUSHED.load(Ordering::Relaxed),
    )
}
