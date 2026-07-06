//! CLFS Metadata Structures
//
//! Defines the metadata records that live in the BLF (Base Log File).
//! These are the Control Record, Base Record, and Truncate Record,
//! plus their shadow copies.
//
//! Spec source: Microsoft CLFS reference documentation.

use super::format::{CLFS_LOG_BLOCK_HEADER_SIZE, CLFS_SECTOR_SIZE};

// ============================================================================
// CLFS_METADATA_RECORD_HEADER
// ============================================================================

/// CLFS_METADATA_RECORD_HEADER — shared prefix for all metadata records.
/// The `ullDumpCount` field is a version counter used during log recovery
/// to determine which copy of a record is more recent.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ClfsMetadataRecordHeader {
    /// Sequence number for record versioning during recovery.
    /// Higher values indicate more recent records.
    pub dump_count: u64,
}

impl ClfsMetadataRecordHeader {
    pub fn new(dump_count: u64) -> Self {
        Self { dump_count }
    }

    /// Create a metadata record header with dump_count = 1.
    pub fn initial() -> Self {
        Self { dump_count: 1 }
    }

    /// Increment the dump count for a new version.
    pub fn next_version(&self) -> Self {
        Self { dump_count: self.dump_count + 1 }
    }
}

// ============================================================================
// CLFS Control Record
// ============================================================================

/// Extend state — tracks whether a log extension is in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClfsExtendState {
    None = 0,
    Acquiring = 1,
    Acquired = 2,
    Releasing = 3,
}

/// Truncate state — tracks the phase of a truncation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClfsTruncateState {
    None = 0,
    ModifyingStream = 1,
    SavingOwner = 2,
    ModifyingOwner = 3,
    SavingDiscardBlock = 4,
    ModifyingDiscardBlock = 5,
}

/// CLFS_TRUNCATE_CONTEXT — state for truncation operations.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ClfsTruncateContext {
    pub e_state: u8,              // ClfsTruncateState
    pub c_clients: u8,            // Number of clients
    pub i_client: u8,             // Current client index
    pub b_unused: u8,
    pub lsn_owner_page: u64,     // LSN of owner page
    pub lsn_last_owner_page: u64, // LSN of last owner page
    pub c_invalid_sector: u32,   // Count of invalid sectors
}

impl ClfsTruncateContext {
    pub fn new() -> Self {
        Self {
            e_state: ClfsTruncateState::None as u8,
            c_clients: 0,
            i_client: 0,
            b_unused: 0,
            lsn_owner_page: 0,
            lsn_last_owner_page: 0,
            c_invalid_sector: 0,
        }
    }
}

impl Default for ClfsTruncateContext {
    fn default() -> Self {
        Self::new()
    }
}

/// CLFS_CONTROL_RECORD — stores log layout and extend/truncate information.
/// Written to sectors 0 and 1 of the BLF file.
///
/// The Control Record is the most important metadata structure — it tells
/// us where all the other metadata lives and what the log's current state is.
#[derive(Debug, Clone)]
pub struct ClfsControlRecord {
    /// Metadata record header (dump count).
    pub hdr: ClfsMetadataRecordHeader,
    /// Magic value — 0xC1F5C1F500005F1C ("C1F5" in hex).
    pub magic: u64,
    /// Version — always 0x01.
    pub version: u8,
    /// Current extend state.
    pub extend_state: ClfsExtendState,
    /// Index into the extend block array.
    pub i_extend_block: u16,
    /// Index into the flush block array.
    pub i_flush_block: u16,
    /// Number of sectors in a new block.
    pub c_new_block_sectors: u32,
    /// Number of sectors at the start of a log for extend operations.
    pub c_extend_start_sectors: u32,
    /// Number of sectors added during an extend operation.
    pub c_extend_sectors: u32,
    /// Truncation context.
    pub truncate: ClfsTruncateContext,
    /// Number of metadata blocks in the rgBlocks array.
    pub c_blocks: u16,
    /// Reserved.
    pub c_reserved: u32,
    /// Array of metadata block descriptors.
    /// Each entry describes a metadata block's location and type.
    pub rg_blocks: [ClfsMetadataBlock; 6],
}

impl ClfsControlRecord {
    /// The CLFS magic value.
    pub const MAGIC: u64 = 0xC1F5_C1F5_0000_5F1C;

    /// Create a new control record with default values.
    pub fn new() -> Self {
        Self {
            hdr: ClfsMetadataRecordHeader::initial(),
            magic: Self::MAGIC,
            version: 0x01,
            extend_state: ClfsExtendState::None,
            i_extend_block: 0,
            i_flush_block: 0,
            c_new_block_sectors: 0,
            c_extend_start_sectors: 0,
            c_extend_sectors: 0,
            truncate: ClfsTruncateContext::new(),
            c_blocks: 6,
            c_reserved: 0,
            rg_blocks: [
                // Sector 0: Control Record
                ClfsMetadataBlock::new_control(0, 1),
                // Sector 1: Control Shadow
                ClfsMetadataBlock::new_control_shadow(1 * CLFS_SECTOR_SIZE as u32, 1),
                // Sector 2: General (Base) Record
                ClfsMetadataBlock::new_general(2 * CLFS_SECTOR_SIZE as u32, 1),
                // Sector 3: General Shadow
                ClfsMetadataBlock::new_general_shadow(3 * CLFS_SECTOR_SIZE as u32, 1),
                // Sector 4: Truncate Record
                ClfsMetadataBlock::new_truncate(4 * CLFS_SECTOR_SIZE as u32, 1),
                // Sector 5: Truncate Shadow
                ClfsMetadataBlock::new_truncate_shadow(5 * CLFS_SECTOR_SIZE as u32, 1),
            ],
        }
    }

    /// Validate the magic number.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.version == 0x01
    }

    /// Serialize the control record to a byte buffer.
    /// The buffer should be at least CLFS_SECTOR_SIZE (512 bytes).
    pub fn write_to(&self, buf: &mut [u8]) {
        if buf.len() < CLFS_SECTOR_SIZE {
            return;
        }

        // Start at offset CLFS_LOG_BLOCK_HEADER_SIZE (112) to leave room
        // for the log block header
        let mut offset = CLFS_LOG_BLOCK_HEADER_SIZE;

        // dump_count (u64)
        buf[offset..offset+8].copy_from_slice(&self.hdr.dump_count.to_le_bytes());
        offset += 8;

        // magic (u64)
        buf[offset..offset+8].copy_from_slice(&self.magic.to_le_bytes());
        offset += 8;

        // version (u8)
        buf[offset] = self.version;
        offset += 1;

        // extend_state (u8)
        buf[offset] = self.extend_state as u8;
        offset += 1;

        // i_extend_block (u16)
        buf[offset..offset+2].copy_from_slice(&self.i_extend_block.to_le_bytes());
        offset += 2;

        // i_flush_block (u16)
        buf[offset..offset+2].copy_from_slice(&self.i_flush_block.to_le_bytes());
        offset += 2;

        // c_new_block_sectors (u32)
        buf[offset..offset+4].copy_from_slice(&self.c_new_block_sectors.to_le_bytes());
        offset += 4;

        // c_extend_start_sectors (u32)
        buf[offset..offset+4].copy_from_slice(&self.c_extend_start_sectors.to_le_bytes());
        offset += 4;

        // c_extend_sectors (u32)
        buf[offset..offset+4].copy_from_slice(&self.c_extend_sectors.to_le_bytes());
        offset += 4;

        // truncate context
        buf[offset] = self.truncate.e_state;
        offset += 1;
        buf[offset] = self.truncate.c_clients;
        offset += 1;
        buf[offset] = self.truncate.i_client;
        offset += 1;
        buf[offset] = self.truncate.b_unused;
        offset += 1;
        buf[offset..offset+8].copy_from_slice(&self.truncate.lsn_owner_page.to_le_bytes());
        offset += 8;
        buf[offset..offset+8].copy_from_slice(&self.truncate.lsn_last_owner_page.to_le_bytes());
        offset += 8;
        buf[offset..offset+4].copy_from_slice(&self.truncate.c_invalid_sector.to_le_bytes());
        offset += 4;

        // c_blocks (u16)
        buf[offset..offset+2].copy_from_slice(&self.c_blocks.to_le_bytes());
        offset += 2;

        // c_reserved (u32)
        buf[offset..offset+4].copy_from_slice(&self.c_reserved.to_le_bytes());
        offset += 4;

        // rg_blocks array (6 entries)
        for block in &self.rg_blocks {
            block.write_to(&mut buf[offset..offset + 16]);
            offset += 16;
        }
    }
}

impl Default for ClfsControlRecord {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CLFS Metadata Block Descriptor
// ============================================================================

/// Block type constants for metadata blocks.
pub const CLFS_EXTEND_BLOCK:    u16 = 0x0001;
pub const CLFS_NORMAL_BLOCK:    u16 = 0x0002;
pub const CLFS_ZERO_NORMAL_BLOCK: u16 = 0x0003;
pub const CLFS_SHADOW_BLOCK:    u16 = 0x0004;
pub const CLFS_ZERO_SHADOW_BLOCK: u16 = 0x0005;

/// CLFS_METADATA_BLOCK — describes one metadata block in the BLF file.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ClfsMetadataBlock {
    /// Byte offset of the block from the start of the file.
    pub offset: u32,
    /// Number of sectors in this block.
    pub c_sectors: u16,
    /// Block type flags.
    pub flags: u16,
}

impl ClfsMetadataBlock {
    /// Create a new metadata block descriptor.
    pub fn new(offset: u32, sectors: u16, flags: u16) -> Self {
        Self { offset, c_sectors: sectors, flags }
    }

    /// Create a Control Record block descriptor.
    pub fn new_control(offset: u32, sectors: u16) -> Self {
        Self::new(offset, sectors, CLFS_EXTEND_BLOCK | CLFS_SHADOW_BLOCK)
    }

    /// Create a Control Record Shadow block descriptor.
    pub fn new_control_shadow(offset: u32, sectors: u16) -> Self {
        Self::new(offset, sectors, CLFS_SHADOW_BLOCK)
    }

    /// Create a General (Base) Record block descriptor.
    pub fn new_general(offset: u32, sectors: u16) -> Self {
        Self::new(offset, sectors, CLFS_EXTEND_BLOCK | CLFS_SHADOW_BLOCK)
    }

    /// Create a General Shadow block descriptor.
    pub fn new_general_shadow(offset: u32, sectors: u16) -> Self {
        Self::new(offset, sectors, CLFS_SHADOW_BLOCK)
    }

    /// Create a Truncate Record block descriptor.
    pub fn new_truncate(offset: u32, sectors: u16) -> Self {
        Self::new(offset, sectors, CLFS_NORMAL_BLOCK)
    }

    /// Create a Truncate Record Shadow block descriptor.
    pub fn new_truncate_shadow(offset: u32, sectors: u16) -> Self {
        Self::new(offset, sectors, CLFS_SHADOW_BLOCK)
    }

    /// Serialize to 16 bytes.
    pub fn write_to(&self, buf: &mut [u8]) {
        if buf.len() < 16 { return; }
        buf[0..4].copy_from_slice(&self.offset.to_le_bytes());
        buf[4..6].copy_from_slice(&self.c_sectors.to_le_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        buf[8..16].fill(0); // Reserved
    }

    /// Read from 16 bytes.
    pub fn read_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 { return None; }
        Some(Self {
            offset: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            c_sectors: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
            flags: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
        })
    }
}

// ============================================================================
// CLFS Base Record
// ============================================================================

/// Log state values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClfsLogState {
    Uninitialized   = 0x01,
    Initialized     = 0x02,
    Active          = 0x04,
    PendingDelete   = 0x08,
    PendingArchive  = 0x10,
    Shutdown        = 0x20,
    Multiplexed     = 0x40,
    Secure          = 0x80,
}

impl ClfsLogState {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => ClfsLogState::Uninitialized,
            0x02 => ClfsLogState::Initialized,
            0x04 => ClfsLogState::Active,
            0x08 => ClfsLogState::PendingDelete,
            0x10 => ClfsLogState::PendingArchive,
            0x20 => ClfsLogState::Shutdown,
            0x40 => ClfsLogState::Multiplexed,
            0x80 => ClfsLogState::Secure,
            _ => ClfsLogState::Uninitialized,
        }
    }
}

/// CLFS_BASE_RECORD_HEADER — stores client and container state.
/// Written to sectors 2 and 3 of the BLF file.
///
/// This is the "directory" of a CLFS log — it maps client IDs and
/// container IDs to their current state and location.
#[derive(Debug, Clone)]
pub struct ClfsBaseRecordHeader {
    /// Metadata record header.
    pub hdr: ClfsMetadataRecordHeader,
    /// Random log identifier (UUID/GUID).
    pub cid_log: u128,
    /// Hash symbol table for clients — 11 slots.
    /// Each slot is an offset from the base record start to a client symbol entry.
    pub rg_client_sym_tbl: [u64; 11],
    /// Hash symbol table for containers — 11 slots.
    pub rg_container_sym_tbl: [u64; 11],
    /// Hash symbol table for security contexts — 11 slots.
    pub rg_security_sym_tbl: [u64; 11],
    /// Next container ID to assign.
    pub c_next_container: u32,
    /// Next client ID to assign.
    pub c_next_client: u32,
    /// Number of free container slots.
    pub c_free_containers: u32,
    /// Number of active container slots.
    pub c_active_containers: u32,
    /// Byte count of free containers.
    pub cb_free_containers: u32,
    /// Byte count of busy containers.
    pub cb_busy_containers: u32,
    /// Offset to the symbol table zone.
    pub cb_symbol_zone: u32,
    /// Sector size — always 512.
    pub cb_sector: u32,
    /// Unused.
    pub b_unused: u16,
    /// Current log state.
    pub e_log_state: ClfsLogState,
    /// Number of USNs used.
    pub c_usn: u8,
    /// Number of active clients.
    pub c_clients: u8,
    /// Array of client context offsets — 124 entries.
    /// Each entry is an offset from the base record start to a client context.
    pub rg_clients: [u32; 124],
    /// Array of container context offsets — 1024 entries.
    /// Each entry is an offset from the base record start to a container context.
    pub rg_containers: [u32; 1024],
}

impl ClfsBaseRecordHeader {
    /// Create a new base record with default values.
    pub fn new() -> Self {
        Self {
            hdr: ClfsMetadataRecordHeader::initial(),
            cid_log: 0, // Will be set to a random UUID
            rg_client_sym_tbl: [0u64; 11],
            rg_container_sym_tbl: [0u64; 11],
            rg_security_sym_tbl: [0u64; 11],
            c_next_container: 1, // Container 0 is reserved
            c_next_client: 1,
            c_free_containers: 1024,
            c_active_containers: 0,
            cb_free_containers: 0,
            cb_busy_containers: 0,
            cb_symbol_zone: 0,
            cb_sector: CLFS_SECTOR_SIZE as u32,
            b_unused: 0,
            e_log_state: ClfsLogState::Initialized,
            c_usn: 0,
            c_clients: 0,
            rg_clients: [0u32; 124],
            rg_containers: [0u32; 1024],
        }
    }

    /// Serialize to a byte buffer.
    pub fn write_to(&self, buf: &mut [u8]) {
        if buf.len() < 4096 { return; } // Base record can be larger

        let mut offset = CLFS_LOG_BLOCK_HEADER_SIZE;

        // hdr.dump_count
        buf[offset..offset+8].copy_from_slice(&self.hdr.dump_count.to_le_bytes());
        offset += 8;

        // cid_log (128-bit / 16 bytes)
        for i in 0..16 {
            buf[offset + i] = (self.cid_log >> (i * 8)) as u8;
        }
        offset += 16;

        // rg_client_sym_tbl (11 * 8 = 88 bytes)
        for &val in &self.rg_client_sym_tbl {
            buf[offset..offset+8].copy_from_slice(&val.to_le_bytes());
            offset += 8;
        }

        // rg_container_sym_tbl
        for &val in &self.rg_container_sym_tbl {
            buf[offset..offset+8].copy_from_slice(&val.to_le_bytes());
            offset += 8;
        }

        // rg_security_sym_tbl
        for &val in &self.rg_security_sym_tbl {
            buf[offset..offset+8].copy_from_slice(&val.to_le_bytes());
            offset += 8;
        }

        // Scalar fields
        macro_rules! write_u32 { ($val:expr) => {
            buf[offset..offset+4].copy_from_slice(&($val).to_le_bytes());
            offset += 4;
        }; }

        write_u32!(self.c_next_container);
        write_u32!(self.c_next_client);
        write_u32!(self.c_free_containers);
        write_u32!(self.c_active_containers);
        write_u32!(self.cb_free_containers);
        write_u32!(self.cb_busy_containers);
        write_u32!(self.cb_symbol_zone);
        write_u32!(self.cb_sector);

        // b_unused (u16)
        buf[offset..offset+2].copy_from_slice(&self.b_unused.to_le_bytes());
        offset += 2;

        // e_log_state (u8)
        buf[offset] = self.e_log_state as u8;
        offset += 1;

        // c_usn (u8)
        buf[offset] = self.c_usn;
        offset += 1;

        // c_clients (u8)
        buf[offset] = self.c_clients;
        offset += 1;

        // rg_clients (124 * 4 = 496 bytes)
        for &val in &self.rg_clients {
            buf[offset..offset+4].copy_from_slice(&val.to_le_bytes());
            offset += 4;
        }

        // rg_containers (1024 * 4 = 4096 bytes)
        for &val in &self.rg_containers {
            buf[offset..offset+4].copy_from_slice(&val.to_le_bytes());
            offset += 4;
        }
    }
}

impl Default for ClfsBaseRecordHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CLFS Truncate Record
// ============================================================================

/// CLFS_TRUNCATE_RECORD_HEADER — stores truncation information.
/// Written to sectors 4 and 5 of the BLF file.
#[derive(Debug, Clone)]
pub struct ClfsTruncateRecordHeader {
    /// Metadata record header.
    pub hdr: ClfsMetadataRecordHeader,
    /// Offset from record start to the CLFS_TRUNCATE_CLIENT_CHANGE array.
    pub coff_client_change: u32,
    /// Offset from record start to the owner page.
    pub coff_owner_page: u32,
}

impl ClfsTruncateRecordHeader {
    pub fn new() -> Self {
        Self {
            hdr: ClfsMetadataRecordHeader::initial(),
            coff_client_change: 0,
            coff_owner_page: 0,
        }
    }
}

impl Default for ClfsTruncateRecordHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// CLFS_TRUNCATE_CLIENT_CHANGE — describes one client's truncation change.
#[derive(Debug, Clone)]
pub struct ClfsTruncateClientChange {
    /// Client ID.
    pub cid_client: u32,
    /// LSN of this record.
    pub lsn: u64,
    /// LSN of the client's current record.
    pub lsn_client: u64,
    /// LSN of the client's restart area.
    pub lsn_restart: u64,
    /// Length of this change record.
    pub c_length: u16,
    /// Previous length.
    pub c_old_length: u16,
    /// Number of sector change entries.
    pub c_sectors: u32,
}

impl ClfsTruncateClientChange {
    pub fn new() -> Self {
        Self {
            cid_client: 0,
            lsn: 0,
            lsn_client: 0,
            lsn_restart: 0,
            c_length: 0,
            c_old_length: 0,
            c_sectors: 0,
        }
    }
}

impl Default for ClfsTruncateClientChange {
    fn default() -> Self {
        Self::new()
    }
}
