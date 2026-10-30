//! SCSI storage facade shared by every target architecture.
//!
//! Forwards CDB dispatch and readiness queries to the
//! architecture-specific SCSI miniport layer, which is how the
//! NT 6.1 class drivers (disk.sys / cdrom.sys) talk to miniports
//! through the SCSI Request Block protocol.

pub fn init() {
    crate::drivers::arch::init_scsi();
}

/// Send a SCSI CDB to `target` through the miniport. `direction`
/// is 0 for read, 1 for write. Returns the SRB status code.
pub fn send_cdb(target: u8, cdb: &[u8], direction: u8, buffer: &mut [u8]) -> u8 {
    crate::drivers::arch::scsi_send_cdb(target, cdb, direction, buffer)
}

/// True once the miniport layer has been initialised.
pub fn is_ready() -> bool {
    crate::drivers::arch::scsi_is_ready()
}

pub fn smoke_test() -> bool {
    crate::drivers::arch::scsi_smoke_test()
}
