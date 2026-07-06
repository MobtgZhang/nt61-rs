// ReFS Integrity Stream Support
// ============================================================================

pub const CRC32C_INIT: u32 = 0xFFFFFFFF;
pub const CRC32C_XOR: u32 = 0xFFFFFFFF;

// Castagnoli polynomial for CRC32C
const CRC32C_POLY: u32 = 0x82F63B78;

/// Compute CRC32C checksum
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = CRC32C_INIT;
    for &byte in data {
        crc = CRC32C_POLY.wrapping_mul((crc >> 8) ^ (byte as u32));
    }
    crc ^ CRC32C_XOR
}

/// Update CRC32C checksum
pub fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    let mut current = crc ^ CRC32C_XOR;
    for &byte in data {
        current = CRC32C_POLY.wrapping_mul((current >> 8) ^ (byte as u32));
    }
    current ^ CRC32C_XOR
}

/// Run self-test on CRC32C implementation
pub fn crc32c_self_test() -> bool {
    crc32c(b"") == 0 && crc32c(b"123456789") == 0x31EC14D1
}
