//! ReFS Integrity Stream Support
//!
//! Implements the ReFS integrity stream layer: per-chunk CRC32C checksums
//! stored separately from data, copy-on-write verification, and integrity
//! metadata headers matching the on-disk ReFS layout.

/// CRC32C initial value.
pub const CRC32C_INIT: u32 = 0xFFFF_FFFF;

/// CRC32C final XOR value.
pub const CRC32C_XOR: u32 = 0xFFFF_FFFF;

/// Castagnoli polynomial (reversed).
const CRC32C_POLY: u32 = 0x82F6_3B78;

/// Bits processed per step of the reflected algorithm.
const CRC32C_BITS_PER_BYTE: u32 = 8;

/// Checksum of the empty string.
const CRC32C_EMPTY_CHECK: u32 = 0;

/// Published CRC32C check value of the ASCII string \`123456789\`.
const CRC32C_CHECK_VALUE: u32 = 0xE306_9283;

/// Default ReFS integrity checksum size in bytes (4-byte CRC32C).
pub const INTEGRITY_CHECKSUM_SIZE: usize = 4;

/// Integrity stream header magic.
pub const INTEGRITY_STREAM_MAGIC: u32 = 0x4954_4143;

/// Compute CRC32C checksum of a byte slice.
///
/// Standard reflected Castagnoli CRC (poly \`0x82F63B78\`, init and
/// final XOR of \`0xFFFFFFFF\`, matching the Intel SSE4.2 \`crc32\`
/// instruction and the ReFS on-disk checksums).
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = CRC32C_INIT;
    for &byte in data {
        crc = crc32c_step(crc, byte);
    }
    crc ^ CRC32C_XOR
}

/// Update an existing CRC32C checksum with additional data.
///
/// The \`crc\` argument is a finalized checksum (as returned by
/// \`crc32c\`); the result is again finalized, so successive calls
/// chain correctly over a byte stream.
pub fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    let mut current = crc ^ CRC32C_XOR;
    for &byte in data {
        current = crc32c_step(current, byte);
    }
    current ^ CRC32C_XOR
}

/// Advance the CRC32C register by one byte (reflected algorithm).
fn crc32c_step(crc: u32, byte: u8) -> u32 {
    let mut register = crc ^ (byte as u32);
    for _ in 0..CRC32C_BITS_PER_BYTE {
        let mask = (register & 1).wrapping_neg();
        register = (register >> 1) ^ (CRC32C_POLY & mask);
    }
    register
}

/// Run self-test on CRC32C implementation.
pub fn crc32c_self_test() -> bool {
    crc32c(b"") == CRC32C_EMPTY_CHECK && crc32c(b"123456789") == CRC32C_CHECK_VALUE
}

/// ReFS integrity stream header (on-disk format).
#[derive(Debug, Clone, Copy)]
pub struct IntegrityStreamHeader {
    pub magic: u32,
    pub version: u32,
    pub checksum_size: u32,
    pub chunk_size: u32,
}

impl IntegrityStreamHeader {
    pub const SIZE: usize = 16;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..8].copy_from_slice(&self.version.to_le_bytes());
        out[8..12].copy_from_slice(&self.checksum_size.to_le_bytes());
        out[12..16].copy_from_slice(&self.chunk_size.to_le_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            magic: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            version: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            checksum_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            chunk_size: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }

    pub fn is_valid(&self) -> bool {
        self.magic == INTEGRITY_STREAM_MAGIC
    }
}

/// Compute the CRC32C checksum for a data chunk.
pub fn compute_chunk_checksum(data: &[u8]) -> u32 {
    crc32c(data)
}

/// Verify a data chunk against its stored checksum.
pub fn verify_chunk_checksum(data: &[u8], stored_checksum: u32) -> bool {
    compute_chunk_checksum(data) == stored_checksum
}
