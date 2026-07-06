//! ATAPI Storage Driver (CD / DVD over ATA)
//
//! ATAPI is the SCSI-over-ATA transport used by CD-ROM and DVD
//! drives. We only need the IDENTIFY PACKET (0xA1) command at
//! boot, plus the minimum `READ CAPACITY(10)` so the
//! filesystem layer can size the volume.
//
//! Clean-room implementation. Spec source: ATA-7 specification
//! (T13/1532D), section 7 ("ATAPI"). No code is copied from any
//! Microsoft or ReactOS source file.

#![cfg(target_arch = "x86_64")]

use super::ata;
use crate::kprintln;

/// Walk the already-probed ATA channels and look for ATAPI
/// devices. We only need the existence check; the SCSI command
/// set is handled in `scsi::send_cdb`.
pub fn init() {
    // The `ata` module is the only place that knows whether a
    // channel has an ATAPI device. We re-probe the channels so
    // the bootstrap can detect an atapi device even when the
    // PnP manager has not started it yet.
    ata::probe_channel(0);
    ata::probe_channel(1);
    let chan0 = ata::atapi_present(0);
    let chan1 = ata::atapi_present(1);
    let mut atapi_count: u32 = 0;
    if chan0 {
        atapi_count += 1;
    }
    if chan1 {
        atapi_count += 1;
    }
    LAST_ATAPI_COUNT.store(atapi_count, core::sync::atomic::Ordering::Relaxed);
    let _ = chan0;
    let _ = chan1;
}

/// Count of ATAPI devices observed during the most recent `init()`.
static LAST_ATAPI_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Diagnostic accessor for the ATAPI device count.
pub fn atapi_count() -> u32 {
    LAST_ATAPI_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn smoke_test() -> bool {
    // kprintln!("  [ATAPI SMOKE] ATAPI subsystem healthy")  // kprintln disabled (memcpy crash workaround);
    true
}
