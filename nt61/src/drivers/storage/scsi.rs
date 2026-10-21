//! SCSI storage facade shared by every target architecture.

pub fn init() {
    crate::drivers::arch::init_scsi();
}
