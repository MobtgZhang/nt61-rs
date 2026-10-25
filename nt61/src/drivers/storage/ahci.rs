//! AHCI storage facade shared by every target architecture.

pub fn init() {
    crate::drivers::arch::init_ahci();
}

pub fn smoke_test() -> bool {
    crate::drivers::arch::ahci_smoke_test()
}

pub fn count() -> usize {
    crate::drivers::arch::ahci_count()
}

pub fn first_disk_location() -> Option<(usize, usize)> {
    crate::drivers::arch::ahci_first_disk_location()
}

pub fn read_sector(controller: usize, port: usize, lba: u32, buf: &mut [u8]) -> bool {
    crate::drivers::arch::ahci_read_sector(controller, port, lba, buf)
}

pub fn write_sector(controller: usize, port: usize, lba: u32, buf: &[u8]) -> bool {
    crate::drivers::arch::ahci_write_sector(controller, port, lba, buf)
}
