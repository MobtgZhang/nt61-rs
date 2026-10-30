//! ATAPI storage facade shared by every target architecture.
//!
//! Forwards the CD/DVD class I/O surface to the architecture
//! specific ATAPI transport. In Windows NT 6.1 cdrom.sys issues
//! SCSI READ(10) / WRITE(10) CDBs over the ATA transport, so the
//! arch layer routes sector reads and writes through the shared
//! SCSI miniport.

pub fn init() {
    crate::drivers::arch::init_atapi();
}

/// Number of ATAPI devices found on the ATA channels.
pub fn atapi_count() -> u32 {
    crate::drivers::arch::atapi_device_count()
}

/// Read `count` 512-byte sectors from the ATAPI device on
/// `channel` starting at `lba`.
pub fn read_sectors(channel: usize, lba: u32, count: u16, buffer: &mut [u8]) -> bool {
    crate::drivers::arch::atapi_read_sectors(channel, lba, count, buffer)
}

/// Write `count` 512-byte sectors to the ATAPI device on
/// `channel` starting at `lba`.
pub fn write_sectors(channel: usize, lba: u32, count: u16, buffer: &[u8]) -> bool {
    crate::drivers::arch::atapi_write_sectors(channel, lba, count, buffer)
}

pub fn smoke_test() -> bool {
    crate::drivers::arch::atapi_smoke_test()
}
