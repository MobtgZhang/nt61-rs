//! Storage Stack Smoke Test Aggregator
//
//! Runs every storage driver's smoke test and aggregates the
//! result, mirroring the convention used by `ke::smoke` /
//! `mm::smoke` / `io::smoke`.

#![cfg(target_arch = "x86_64")]

use crate::kprintln;

/// Run every storage miniport's self-check and return `true`
/// iff every one passed.
pub fn smoke_test() -> bool {
    // kprintln!("  [STORAGE SMOKE] running storage stack smoke tests...")  // kprintln disabled (memcpy crash workaround);
    let mut ok = true;
    ok &= super::ata::smoke_test();
    ok &= super::atapi::smoke_test();
    ok &= super::ahci::smoke_test();
    ok &= super::nvme::smoke_test();
    ok &= super::scsi::smoke_test();
    if ok {
        // kprintln!("  [STORAGE SMOKE] all storage checks passed")  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("  [STORAGE SMOKE FAIL] one or more checks failed")  // kprintln disabled (memcpy crash workaround);
    }
    ok
}
