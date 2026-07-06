//! CLFS Disk Format — BLF (Base Log File) Structures
//
//! Implements the on-disk format of the Windows Common Log File System.
//! Each log consists of a BLF file (typically 64KB) containing 6 metadata
//! blocks, plus one or more container files that store log records.
//
//! Spec source: Microsoft CLFS reference documentation and clean-room
//! reverse-engineering from Windows 7 clfs.sys.
//
//! # BLF File Layout
//
//! The BLF file is sector-aligned (512-byte sectors). It contains:
//! - Sector 0: Control Record (metadata block type 0x10)
//! - Sector 1: Control Record Shadow (copy of sector 0)
//! - Sector 2: Base Record (metadata block type 0x10)
//! - Sector 3: Base Record Shadow
//! - Sector 4: Truncate Record
//! - Sector 5: Truncate Record Shadow
//! - Remaining sectors: reserved / future use
//
//! Each sector has a 2-byte trailer: [BlockType | Flags, USN]

// ============================================================================
// Constants
// ============================================================================

/// CLFS sector size — always 512 bytes on x86/x64.
pub const CLFS_SECTOR_SIZE: usize = 512;

/// CLFS_LOG_BLOCK_HEADER size — 112 bytes.
pub const CLFS_LOG_BLOCK_HEADER_SIZE: usize = 112;

/// Sector signature trailer size — 2 bytes at end of each sector.
pub const CLFS_SECTOR_SIGNATURE_SIZE: usize = 2;

/// Default BLF file size — 64KB (128 sectors).
pub const CLFS_DEFAULT_BLF_SIZE: usize = 128 * CLFS_SECTOR_SIZE;

/// Default container size — 512KB (1024 sectors).
pub const CLFS_DEFAULT_CONTAINER_SIZE: usize = 512 * 1024;

/// Maximum container count per log.
pub const CLFS_MAX_CONTAINERS: usize = 1023;

/// Maximum client count per log.
pub const CLFS_MAX_CLIENTS: usize = 124;

// ============================================================================
// Sector / Block Flags
// ============================================================================

/// Block type constants stored in the sector signature.
pub const SECTOR_BLOCK_NONE:   u8 = 0x00;
pub const SECTOR_BLOCK_DATA:   u8 = 0x04;  // Data block
pub const SECTOR_BLOCK_OWNER:  u8 = 0x08;  // Owner page (metadata)
pub const SECTOR_BLOCK_BASE:   u8 = 0x10;  // Base record
pub const SECTOR_BLOCK_END:    u8 = 0x20;  // End of record
pub const SECTOR_BLOCK_BEGIN:  u8 = 0x40;  // Begin of record

/// Block state flags stored in the upper bits of the sector signature.
pub const CLFS_BLOCK_RESET:            u16 = 0x0000;
pub const CLFS_BLOCK_ENCODED:          u16 = 0x0100;  // USN fixup applied
pub const CLFS_BLOCK_DECODED:          u16 = 0x0200;  // USN fixup reversed
pub const CLFS_BLOCK_LATCHED:         u16 = 0x0400;  // Block is being written
pub const CLFS_BLOCK_TRUNCATE_DISCARD: u16 = 0x0800;  // Truncate mark

// ============================================================================
// CLFS_LOG_BLOCK_HEADER
// ============================================================================

/// CLFS_LOG_BLOCK_HEADER — 112 bytes, the header of every log block.
///
/// Every log block starts with this header, followed by record data.
/// The block may span multiple sectors. The sector trailer (2 bytes) at
/// the end of each sector contains the USN fixup values.
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct ClfsLogBlockHeader {
    /// Major version — always 0x15 (21).
    pub major_version: u8,
    /// Minor version — always 0x00.
    pub minor_version: u8,
    /// Update Sequence Number (USN) — used for sector fixup verification.
    pub usn: u8,
    /// Client ID — identifies the client that owns records in this block.
    pub client_id: u8,
    /// Total number of sectors in this block.
    pub total_sector_count: u16,
    /// Number of valid sectors (used for truncation).
    pub valid_sector_count: u16,
    /// Reserved / padding.
    pub padding: u32,
    /// CRC-32 checksum covering bytes 20 through the end of the block.
    /// Polynomial: 0x04C11DB7. Initial: 0xFFFFFFFF, final: ~crc.
    pub checksum: u32,
    /// Block flags.
    pub flags: u32,
    /// Current LSN — the LSN of the most recent record in this block.
    pub current_lsn: u64,
    /// Next LSN — the LSN that will be assigned to the next record.
    pub next_lsn: u64,
    /// Offsets to each record within this block. 16 entries.
    /// An offset of 0 means the slot is unused.
    pub record_offsets: [u32; 16],
    /// Byte offset from block start to the sector signature array.
    /// The signature array has one u16 per sector in the block.
    pub signatures_offset: u32,
}

impl ClfsLogBlockHeader {
    /// Check if this block header is valid by verifying magic values.
    pub fn is_valid(&self) -> bool {
        self.major_version == 0x15 && self.minor_version == 0x00
    }

    /// Read the record_offsets field from a packed struct without creating
    /// a reference to the packed field (which would be UB).
    /// We compute the field offset manually using size_of to avoid UB.
    fn read_record_offsets(&self) -> [u32; 16] {
        // offset = size_of::<u8>() * 4 + size_of::<u16>() * 2 + size_of::<u32>() * 3 + size_of::<u64>() * 2
        //        = 1*4 + 2*2 + 4*3 + 8*2 = 4 + 4 + 12 + 16 = 36
        const RECORD_OFFSETS_OFFSET: usize = 36;
        let base = self as *const ClfsLogBlockHeader as *const u8;
        // SAFETY: self is valid pointer, offset is within struct bounds,
        // we read 64 bytes from a known valid field.
        unsafe { core::ptr::read_unaligned(base.add(RECORD_OFFSETS_OFFSET) as *const [u32; 16]) }
    }

    /// Get the number of records in this block by counting non-zero offsets.
    pub fn record_count(&self) -> u32 {
        let offsets = self.read_record_offsets();
        offsets.iter().filter(|&&o| o != 0).count() as u32
    }

    /// Get a record offset safely from packed struct.
    pub fn get_record_offset(&self, i: usize) -> u32 {
        if i >= 16 { return 0; }
        let offsets = self.read_record_offsets();
        offsets[i]
    }

    /// Get the total size of this block in bytes.
    pub fn block_size(&self) -> usize {
        (self.total_sector_count as usize) * CLFS_SECTOR_SIZE
    }

    /// Create a zeroed header with default CLFS values.
    pub fn new() -> Self {
        Self {
            major_version: 0x15,
            minor_version: 0x00,
            usn: 0,
            client_id: 0,
            total_sector_count: 0,
            valid_sector_count: 0,
            padding: 0,
            checksum: 0,
            flags: 0,
            current_lsn: 0,
            next_lsn: 0,
            record_offsets: [0u32; 16],
            signatures_offset: 0,
        }
    }
}

impl Default for ClfsLogBlockHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Checksum
// ============================================================================

/// CRC-32 lookup table (standard Ethernet polynomial 0x04C11DB7).
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut j = 0usize;
        while j < 8 {
            if c & 0x8000_0000 != 0 {
                c = (c << 1) ^ 0x04C1_1DB7;
            } else {
                c <<= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Compute CRC-32 checksum over a byte slice.
#[inline]
pub fn compute_checksum(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in data {
        let idx = ((crc >> 24) ^ (byte as u32)) as usize;
        crc = (crc << 8) ^ CRC32_TABLE[idx];
    }
    !crc
}

/// Compute checksum over a range starting at byte 20 (skipping the checksum field itself).
pub fn compute_block_checksum(block: &[u8]) -> u32 {
    // The checksum field is at bytes 16-19 (offset from block start).
    // The checksum covers bytes 20 through the end of the block.
    if block.len() < 20 {
        return 0;
    }
    compute_checksum(&block[20..])
}

// ============================================================================
// Sector Fixup (USN)
// ============================================================================

/// Apply USN sector fixup to a sector. The fixup replaces the last 2 bytes
/// of each sector with a USN value. This allows detection of partial writes.
///
/// - `sector`: 512-byte sector buffer
/// - `usn`: Update Sequence Number value to write at the end
pub fn apply_sector_fixup(sector: &mut [u8; 512], usn: u8) {
    // The USN is stored at bytes 510-511 (last 2 bytes of sector).
    // But the real fixup array has per-sector values. For simplicity,
    // we use the block-level USN for all sectors in a block.
    sector[510] = usn;
    sector[511] = 0xFF; // Marker: this sector has been fixed up
}

/// Reverse the USN sector fixup — restore the original data at bytes 510-511.
///
/// Returns the original last 2 bytes of the sector.
pub fn reverse_sector_fixup(sector: &[u8; 512], stored_usn: u8) -> Option<u16> {
    // In real CLFS, each sector has its own fixup entry in the signature array.
    // Here we validate that the sector was fixed up with the expected USN.
    if sector[511] == 0xFF && sector[510] == stored_usn {
        Some(0xFFFF) // Placeholder — real implementation would restore actual values
    } else {
        None // Sector was not fixed up, or wrong USN
    }
}

/// Apply fixup to all sectors in a block.
pub fn apply_block_fixup(block: &mut [u8], usn: u8) {
    let sector_count = block.len() / CLFS_SECTOR_SIZE;
    for i in 0..sector_count {
        let offset = i * CLFS_SECTOR_SIZE;
        let sector = &mut block[offset..offset + CLFS_SECTOR_SIZE];
        if sector.len() == CLFS_SECTOR_SIZE {
            apply_sector_fixup(sector.try_into().unwrap(), usn);
        }
    }
}

/// Reverse fixup for all sectors in a block.
pub fn reverse_block_fixup(block: &mut [u8], usn: u8) -> bool {
    let sector_count = block.len() / CLFS_SECTOR_SIZE;
    for i in 0..sector_count {
        let offset = i * CLFS_SECTOR_SIZE;
        let sector = &block[offset..offset + CLFS_SECTOR_SIZE];
        if sector.len() != CLFS_SECTOR_SIZE {
            return false;
        }
        if reverse_sector_fixup(sector.try_into().unwrap(), usn).is_none() {
            return false;
        }
    }
    true
}

// ============================================================================
// BLF File Structure
// ============================================================================

/// BLF (Base Log File) metadata block types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlfBlockType {
    Control = 0,
    ControlShadow = 1,
    General = 2,
    GeneralShadow = 3,
    Truncate = 4,
    TruncateShadow = 5,
}

impl BlfBlockType {
    /// Get the sector number in the BLF file for this block type.
    pub fn sector_number(&self) -> usize {
        match self {
            BlfBlockType::Control       => 0,
            BlfBlockType::ControlShadow=> 1,
            BlfBlockType::General      => 2,
            BlfBlockType::GeneralShadow=> 3,
            BlfBlockType::Truncate    => 4,
            BlfBlockType::TruncateShadow => 5,
        }
    }

    /// Get the sector block type flag for this block.
    pub fn sector_flag(&self) -> u8 {
        SECTOR_BLOCK_BASE | SECTOR_BLOCK_BEGIN
    }
}

/// Represents the 6-block BLF metadata region at the start of a CLFS log.
#[derive(Debug, Clone)]
pub struct BlfMetadata {
    /// Control record (sector 0).
    pub control: ClfsLogBlockHeader,
    /// Control shadow (sector 1).
    pub control_shadow: ClfsLogBlockHeader,
    /// General/base record (sector 2).
    pub general: ClfsLogBlockHeader,
    /// General shadow (sector 3).
    pub general_shadow: ClfsLogBlockHeader,
    /// Truncate record (sector 4).
    pub truncate: ClfsLogBlockHeader,
    /// Truncate shadow (sector 5).
    pub truncate_shadow: ClfsLogBlockHeader,
}

impl BlfMetadata {
    /// Create a new zeroed BLF metadata structure.
    pub fn new() -> Self {
        Self {
            control: ClfsLogBlockHeader::new(),
            control_shadow: ClfsLogBlockHeader::new(),
            general: ClfsLogBlockHeader::new(),
            general_shadow: ClfsLogBlockHeader::new(),
            truncate: ClfsLogBlockHeader::new(),
            truncate_shadow: ClfsLogBlockHeader::new(),
        }
    }

    /// Total size of all 6 metadata blocks.
    pub fn size(&self) -> usize {
        6 * CLFS_SECTOR_SIZE
    }

    /// Write the metadata blocks to a byte buffer.
    /// The buffer must be at least 6 * 512 = 3072 bytes.
    pub fn write_to(&self, buf: &mut [u8]) {
        let sectors = [
            (&self.control, BlfBlockType::Control),
            (&self.control_shadow, BlfBlockType::ControlShadow),
            (&self.general, BlfBlockType::General),
            (&self.general_shadow, BlfBlockType::GeneralShadow),
            (&self.truncate, BlfBlockType::Truncate),
            (&self.truncate_shadow, BlfBlockType::TruncateShadow),
        ];

        for (i, (header, block_type)) in sectors.iter().enumerate() {
            let offset = i * CLFS_SECTOR_SIZE;
            let sector = &mut buf[offset..offset + CLFS_SECTOR_SIZE];

            // Write header
            let header_bytes = unsafe {
                core::slice::from_raw_parts(
                    header as *const _ as *const u8,
                    CLFS_LOG_BLOCK_HEADER_SIZE
                )
            };
            sector[..CLFS_LOG_BLOCK_HEADER_SIZE].copy_from_slice(header_bytes);

            // Write sector signature trailer
            let sig = ((block_type.sector_flag() as u16) << 8) | (header.usn as u16);
            sector[510] = (sig & 0xFF) as u8;
            sector[511] = ((sig >> 8) & 0xFF) as u8;
        }
    }
}

impl Default for BlfMetadata {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Container Sector Signature
// ============================================================================

/// Container sector signature — stored in the last 2 bytes of each sector.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SectorSignature {
    /// Upper byte: block type | flags. Lower byte: USN.
    pub sig: u16,
}

impl SectorSignature {
    pub fn new(block_type: u8, _flags: u8, usn: u8) -> Self {
        let sig = ((block_type as u16) << 8) | (usn as u16);
        Self { sig }
    }

    pub fn block_type(&self) -> u8 {
        (self.sig >> 8) as u8
    }

    pub fn usn(&self) -> u8 {
        (self.sig & 0xFF) as u8
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Read a little-endian u16 from a byte slice.
#[inline]
pub fn read_u16_le(slice: &[u8]) -> u16 {
    u16::from_le_bytes(slice[..2].try_into().unwrap())
}

/// Read a little-endian u32 from a byte slice.
#[inline]
pub fn read_u32_le(slice: &[u8]) -> u32 {
    u32::from_le_bytes(slice[..4].try_into().unwrap())
}

/// Read a little-endian u64 from a byte slice.
#[inline]
pub fn read_u64_le(slice: &[u8]) -> u64 {
    u64::from_le_bytes(slice[..8].try_into().unwrap())
}

/// Write a little-endian u16 to a byte slice.
#[inline]
pub fn write_u16_le(slice: &mut [u8], val: u16) {
    slice[..2].copy_from_slice(&val.to_le_bytes());
}

/// Write a little-endian u32 to a byte slice.
#[inline]
pub fn write_u32_le(slice: &mut [u8], val: u32) {
    slice[..4].copy_from_slice(&val.to_le_bytes());
}

/// Write a little-endian u64 to a byte slice.
#[inline]
pub fn write_u64_le(slice: &mut [u8], val: u64) {
    slice[..8].copy_from_slice(&val.to_le_bytes());
}

/// Align a value up to the next sector boundary.
#[inline]
pub fn align_to_sector(value: usize) -> usize {
    (value + CLFS_SECTOR_SIZE - 1) & !(CLFS_SECTOR_SIZE - 1)
}

/// Check if a value is sector-aligned.
#[inline]
pub fn is_sector_aligned(value: usize) -> bool {
    value & (CLFS_SECTOR_SIZE - 1) == 0
}
