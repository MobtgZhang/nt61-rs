//! NVMe storage facade shared by every target architecture.
//!
//! Forwards the disk-class I/O surface (read / write sectors and
//! controller enumeration) to the architecture-specific NVMe
//! miniport, mirroring how stornvme.sys sits between disk.sys and
//! the NVMe controller registers in Windows NT 6.1.

pub fn init() {
    crate::drivers::arch::init_nvme();
}

/// Number of NVMe controllers discovered by the miniport.
pub fn controller_count() -> usize {
    crate::drivers::arch::nvme_controller_count()
}

/// Read `buffer.len()` bytes from the NVMe namespace `nsid`
/// starting at `lba`. Delegates to the arch miniport.
pub fn read_sectors(controller: usize, nsid: u32, lba: u64, buffer: &mut [u8]) -> bool {
    crate::drivers::arch::nvme_read_sectors(controller, nsid, lba, buffer)
}

/// Write `buffer.len()` bytes to the NVMe namespace `nsid`
/// starting at `lba`. Delegates to the arch miniport.
pub fn write_sectors(controller: usize, nsid: u32, lba: u64, buffer: &[u8]) -> bool {
    crate::drivers::arch::nvme_write_sectors(controller, nsid, lba, buffer)
}

pub fn smoke_test() -> bool {
    crate::drivers::arch::nvme_smoke_test()
}
