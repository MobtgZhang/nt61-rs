//! ATA port storage facade shared by every target architecture.

pub fn init() {
    crate::drivers::arch::init_ataport();
}

pub fn ata_port_initialize(channel: u8) -> u32 {
    crate::drivers::arch::ataport_initialize(channel)
}

pub fn read_sector(channel: u8, lba: u32, buf: &mut [u16; 256]) -> bool {
    crate::drivers::arch::ataport_read_sector(channel, lba, buf)
}

pub fn smoke_test() -> bool {
    crate::drivers::arch::ataport_smoke_test()
}
