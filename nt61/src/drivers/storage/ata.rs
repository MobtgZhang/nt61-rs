//! ATA storage facade shared by every target architecture.

pub fn init() {
    crate::drivers::arch::init_ata();
}

pub fn write_sector(idx: usize, lba: u32, buf: &[u16; 256]) -> bool {
    crate::drivers::arch::ata_write_sector(idx, lba, buf)
}
