//! CLFS Log Sequence Number (LSN) Management
//
//! Each record in a CLFS log is identified by a Log Sequence Number (LSN).
//! LSNs are monotonically increasing — later records have larger LSNs.
//! The LSN encodes three pieces of information in a single 8-byte value:
//! - Container ID (bits 32-63): which container the record is in
//! - Block offset (bits 9-31): byte offset / 512 within the container
//! - Record index (bits 0-8): record number within the block (0-511)
//
//! LSN Layout (big-endian u64):
//!   bits 63-32: Container ID (32 bits)
//!   bits 31-9:  Block offset in sectors (23 bits, byte offset / 512)
//!   bits 8-0:   Record index within block (9 bits, 0-511)

/// LSN (Log Sequence Number) — an 8-byte identifier for each log record.
///
/// LSNs are the primary way to address records in a CLFS log. They are
/// assigned in monotonically increasing order. Special values:
///
/// - `NULL`: The smallest possible LSN, used as a lower boundary.
/// - `INVALID`: The largest possible LSN, used to mark invalid records.
/// - `FIRST`: The first valid LSN assigned to a new log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct ClfsLsn(pub u64);

impl ClfsLsn {
    /// The null LSN — the lower boundary. No record has an LSN < NULL.
    pub const NULL: ClfsLsn = ClfsLsn(0);

    /// The invalid LSN — the upper boundary. Used to mark deleted/invalid records.
    pub const INVALID: ClfsLsn = ClfsLsn(0xFFFF_FFFF_FFFF_FFFF);

    /// The first valid LSN for a newly created log.
    pub const FIRST: ClfsLsn = ClfsLsn(1);

    /// Create a new LSN from its three components.
    ///
    /// - `container_id`: 32-bit container identifier (0-0xFFFFFFFF)
    /// - `block_offset`: Byte offset within container / 512 (0-0x7FFFFF)
    /// - `record_index`: Record number within block (0-511)
    #[inline]
    pub fn new(container_id: u32, block_offset: u32, record_index: u16) -> Self {
        let lsn = ((container_id as u64) << 32)
                | ((block_offset as u64) << 9)
                | (record_index as u64);
        ClfsLsn(lsn)
    }

    /// Returns true if this is the NULL LSN.
    #[inline]
    pub fn is_null(&self) -> bool {
        self.0 == 0
    }

    /// Returns true if this is the INVALID LSN.
    #[inline]
    pub fn is_invalid(&self) -> bool {
        self.0 == 0xFFFF_FFFF_FFFF_FFFF
    }

    /// Extract the container ID from this LSN.
    #[inline]
    pub fn container_id(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// Extract the block offset (sectors from container start) from this LSN.
    #[inline]
    pub fn block_offset(&self) -> u32 {
        ((self.0 >> 9) & 0x7F_FFFF) as u32
    }

    /// Extract the record index within the block from this LSN.
    #[inline]
    pub fn record_index(&self) -> u16 {
        (self.0 & 0x1FF) as u16
    }

    /// Get the byte offset of this record within its container.
    #[inline]
    pub fn byte_offset(&self) -> usize {
        (self.block_offset() as usize) * 512
    }

    /// Advance to the next record index, staying in the same block.
    /// Returns None if we overflow past 511 records in the block.
    #[inline]
    pub fn next_in_block(&self) -> Option<ClfsLsn> {
        let idx = self.record_index();
        if idx >= 511 {
            None
        } else {
            Some(ClfsLsn(self.0 + 1))
        }
    }

    /// Advance to the next block, resetting record index to 0.
    #[inline]
    pub fn next_block(&self) -> ClfsLsn {
        ClfsLsn((self.0 & !0x3FF_FFFF_E00) // Clear block_offset and record_index
                | (((self.block_offset() as u64) + 1) << 9))
    }

    /// Advance by one LSN (next record in the log).
    #[inline]
    pub fn next(&self) -> ClfsLsn {
        ClfsLsn(self.0 + 1)
    }
}

impl core::fmt::Display for ClfsLsn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "L#{:03}:{:07}:{:03}",
            self.container_id(),
            self.block_offset(),
            self.record_index())
    }
}

// ============================================================================
// Record Types
// ============================================================================

/// CLFS record types stored in the record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClfsRecordType {
    /// No record type specified.
    Null = 0x00,
    /// Client data record — contains application data.
    Data = 0x01,
    /// Restart record — contains client restart information.
    Restart = 0x02,
}

impl ClfsRecordType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => ClfsRecordType::Null,
            0x01 => ClfsRecordType::Data,
            0x02 => ClfsRecordType::Restart,
            _ => ClfsRecordType::Null,
        }
    }
}

/// CLFS record flags.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ClfsRecordFlags(pub u8);

impl ClfsRecordFlags {
    pub const NONE: ClfsRecordFlags = ClfsRecordFlags(0);
    pub const RESET: ClfsRecordFlags = ClfsRecordFlags(0x01);       // First record of a series
    pub const SECOND: ClfsRecordFlags = ClfsRecordFlags(0x02);      // Second record of a series
    pub const CLIENT: ClfsRecordFlags = ClfsRecordFlags(0x04);      // Client-owned record

    pub fn has(&self, flag: ClfsRecordFlags) -> bool {
        (self.0 & flag.0) != 0
    }
}

// ============================================================================
// CLFS_LOG_RECORD_HEADER
// ============================================================================

/// CLFS_LOG_RECORD_HEADER — variable-size header prefixing each log record.
///
/// The minimum header size is 40 bytes (offset 0-39). Additional fields
/// may be present depending on record type. The actual record data
/// immediately follows the header, sector-aligned.
///
/// Layout:
/// ```text
/// offset 0   : u8   record_type     (ClfsRecordType)
/// offset 1   : u8   flags          (ClfsRecordFlags)
/// offset 2   : u16  size           (total record size including header)
/// offset 4   : u16  reserved
/// offset 6   : u32  record_length  (length of actual data)
/// offset 10  : u32  previous_record_length
/// offset 14  : u64  lsn           (this record's LSN)
/// offset 22  : u64  previous_lsn
/// offset 30  : u64  target_lsn
/// offset 38  : u32  client_id
/// offset 42  : ...  record data (sector-aligned, starts at offset 44 or next sector)
/// ```
///
/// The total record is always sector-aligned. If the data ends mid-sector,
/// the record is padded to the next sector boundary.
pub const CLFS_LOG_RECORD_HEADER_SIZE: usize = 40;

#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct ClfsLogRecordHeader {
    /// Record type — data or restart.
    pub record_type: u8,
    /// Record flags.
    pub flags: u8,
    /// Total size of this record in bytes, including the header.
    /// This value is always a multiple of the sector size.
    pub size: u16,
    /// Reserved.
    pub reserved: u16,
    /// Length of the actual record data (excluding this header).
    pub record_length: u32,
    /// Byte offset from the start of this record to the previous record's start.
    /// 0 if this is the first record in a container or after truncation.
    pub previous_record_length: u32,
    /// LSN of this record.
    pub lsn: u64,
    /// LSN of the previous record in the same log.
    pub previous_lsn: u64,
    /// LSN of the next logical record (used for record chain continuation).
    pub target_lsn: u64,
    /// Client ID — the client that owns this record.
    pub client_id: u32,
}

impl ClfsLogRecordHeader {
    /// Create a new record header for a data record.
    pub fn new_data(lsn: ClfsLsn, previous_lsn: ClfsLsn, data_len: usize) -> Self {
        let record_length = data_len as u32;
        // Total size: header + data, sector-aligned
        let header_plus_data = (CLFS_LOG_RECORD_HEADER_SIZE + data_len) as u16;
        // Round up to sector boundary
        let size = ((header_plus_data as usize + 511) & !511) as u16;

        Self {
            record_type: ClfsRecordType::Data as u8,
            flags: ClfsRecordFlags::NONE.0,
            size,
            reserved: 0,
            record_length,
            previous_record_length: if previous_lsn.is_null() { 0 } else { header_plus_data as u32 },
            lsn: lsn.0,
            previous_lsn: previous_lsn.0,
            target_lsn: 0,
            client_id: 0,
        }
    }

    /// Create a new record header for a restart record.
    pub fn new_restart(lsn: ClfsLsn, restart_size: usize) -> Self {
        let header_plus_data = (CLFS_LOG_RECORD_HEADER_SIZE + restart_size) as u16;
        let size = ((header_plus_data as usize + 511) & !511) as u16;

        Self {
            record_type: ClfsRecordType::Restart as u8,
            flags: ClfsRecordFlags::NONE.0,
            size,
            reserved: 0,
            record_length: restart_size as u32,
            previous_record_length: 0,
            lsn: lsn.0,
            previous_lsn: 0,
            target_lsn: 0,
            client_id: 0,
        }
    }

    /// Get the record type.
    #[inline]
    pub fn record_type_enum(&self) -> ClfsRecordType {
        ClfsRecordType::from_u8(self.record_type)
    }

    /// Get the flags.
    #[inline]
    pub fn flags_enum(&self) -> ClfsRecordFlags {
        ClfsRecordFlags(self.flags)
    }

    /// Get the LSN of this record.
    #[inline]
    pub fn lsn_enum(&self) -> ClfsLsn {
        ClfsLsn(self.lsn)
    }

    /// Get the previous LSN.
    #[inline]
    pub fn previous_lsn_enum(&self) -> ClfsLsn {
        ClfsLsn(self.previous_lsn)
    }

    /// Get the total record size in bytes.
    #[inline]
    pub fn total_size(&self) -> usize {
        self.size as usize
    }

    /// Get the data size in bytes.
    #[inline]
    pub fn data_size(&self) -> usize {
        self.record_length as usize
    }

    /// Check if this is a valid data record.
    #[inline]
    pub fn is_data_record(&self) -> bool {
        self.record_type == ClfsRecordType::Data as u8
    }

    /// Check if this is a valid restart record.
    #[inline]
    pub fn is_restart_record(&self) -> bool {
        self.record_type == ClfsRecordType::Restart as u8
    }

    /// Verify the header checksum. In real CLFS this uses a different
    /// algorithm. Here we do a simple sanity check.
    pub fn is_valid(&self) -> bool {
        self.record_type <= 2
            && self.size >= CLFS_LOG_RECORD_HEADER_SIZE as u16
            && self.record_length <= (self.size as usize - CLFS_LOG_RECORD_HEADER_SIZE) as u32
    }

    /// Serialize the header to a byte buffer.
    pub fn write_to(&self, buf: &mut [u8]) {
        if buf.len() < CLFS_LOG_RECORD_HEADER_SIZE {
            return;
        }
        buf[0] = self.record_type;
        buf[1] = self.flags;
        buf[2..4].copy_from_slice(&self.size.to_le_bytes());
        buf[4..6].copy_from_slice(&self.reserved.to_le_bytes());
        buf[6..10].copy_from_slice(&self.record_length.to_le_bytes());
        buf[10..14].copy_from_slice(&self.previous_record_length.to_le_bytes());
        buf[14..22].copy_from_slice(&self.lsn.to_le_bytes());
        buf[22..30].copy_from_slice(&self.previous_lsn.to_le_bytes());
        buf[30..38].copy_from_slice(&self.target_lsn.to_le_bytes());
        buf[38..42].copy_from_slice(&self.client_id.to_le_bytes());
    }

    /// Read a record header from a byte buffer.
    pub fn read_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < CLFS_LOG_RECORD_HEADER_SIZE {
            return None;
        }
        Some(Self {
            record_type: buf[0],
            flags: buf[1],
            size: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
            reserved: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
            record_length: u32::from_le_bytes(buf[6..10].try_into().unwrap()),
            previous_record_length: u32::from_le_bytes(buf[10..14].try_into().unwrap()),
            lsn: u64::from_le_bytes(buf[14..22].try_into().unwrap()),
            previous_lsn: u64::from_le_bytes(buf[22..30].try_into().unwrap()),
            target_lsn: u64::from_le_bytes(buf[30..38].try_into().unwrap()),
            client_id: u32::from_le_bytes(buf[38..42].try_into().unwrap()),
        })
    }
}

// ============================================================================
// LSN Allocation
// ============================================================================

/// Manages LSN generation for a log. Tracks the next LSN to assign.
#[derive(Debug)]
pub struct LsnAllocator {
    /// Next LSN to assign.
    next_lsn: ClfsLsn,
    /// Container ID for the current container.
    container_id: u32,
    /// Block offset within the current container.
    block_offset: u32,
    /// Record index within the current block.
    record_index: u16,
    /// Sectors per block (for container records).
    sectors_per_block: u32,
}

impl LsnAllocator {
    /// Create a new LSN allocator starting at LSN::FIRST.
    pub fn new() -> Self {
        Self {
            next_lsn: ClfsLsn::FIRST,
            container_id: 0,
            block_offset: 0,
            record_index: 0,
            sectors_per_block: 1, // Default: 1 sector per block
        }
    }

    /// Allocate the next LSN. Returns the allocated LSN and advances the state.
    pub fn allocate(&mut self) -> ClfsLsn {
        let lsn = ClfsLsn::new(self.container_id, self.block_offset, self.record_index);
        self.advance();
        lsn
    }

    /// Peek at the next LSN without allocating it.
    pub fn peek(&self) -> ClfsLsn {
        ClfsLsn::new(self.container_id, self.block_offset, self.record_index)
    }

    /// Advance to the next LSN.
    fn advance(&mut self) {
        self.record_index += 1;
        if self.record_index >= 512 {
            self.record_index = 0;
            self.block_offset += self.sectors_per_block;
        }
        self.next_lsn = ClfsLsn::new(self.container_id, self.block_offset, self.record_index);
    }

    /// Set the current container ID (used when writing to a new container).
    pub fn set_container(&mut self, container_id: u32) {
        self.container_id = container_id;
        self.block_offset = 0;
        self.record_index = 0;
    }

    /// Set the sectors-per-block value.
    pub fn set_sectors_per_block(&mut self, sectors: u32) {
        self.sectors_per_block = sectors;
    }

    /// Get the current container ID.
    pub fn container_id(&self) -> u32 {
        self.container_id
    }

    /// Restore from a base LSN (used after a crash, to resume allocation).
    pub fn restore_from(&mut self, lsn: ClfsLsn) {
        self.container_id = lsn.container_id();
        self.block_offset = lsn.block_offset();
        self.record_index = lsn.record_index();
        // Advance past the last used record
        self.advance();
    }
}

impl Default for LsnAllocator {
    fn default() -> Self {
        Self::new()
    }
}
