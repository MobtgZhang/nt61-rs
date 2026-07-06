//! Driver Subsystem Smoke Test Aggregator
//
//! Runs every driver's smoke test and aggregates the result,
//! mirroring the convention used by `ke::smoke` / `mm::smoke` /
//! `io::smoke`. The boot log shows a single
//! `Driver subsystem smoke test: PASSED` line on success.

#![cfg(target_arch = "x86_64")]

use crate::kprintln;

/// Run every driver's self-check and return `true` iff every
/// one passes.
pub fn smoke_test() -> bool {
    // // kprintln!("  [DRIVER SMOKE] running all driver subsystem smoke tests...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    let mut ok = true;
    ok &= super::bus::smoke_test();
    ok &= super::storage::smoke_test();
    ok &= super::usb::smoke_test();
    ok &= super::net::smoke_test();
    ok &= super::audio::smoke_test();
    ok &= super::input::smoke_test();
    ok &= super::video::smoke_test();
    ok &= super::timer::smoke_test();
    ok &= super::ndis::smoke_test();
    ok &= super::wdf::smoke_test();
    ok &= super::kdcom::smoke_test();
    ok &= super::bootvid::smoke_test();
    ok &= super::clfs::smoke::smoke_test();
    ok &= super::pcw::smoke_test();
    ok &= super::partmgr::smoke_test();
    ok &= super::storage::disk::smoke_test();
    ok &= super::storage::ataport::smoke_test();
    ok &= super::storage::storport::smoke_test();
    ok &= super::volmgr::smoke_test();
    ok &= super::volsnap::smoke_test();
    ok &= super::fltmgr::smoke_test();
    ok &= super::fileinfo::smoke_test();
    ok &= super::spldr::smoke_test();
    if ok {
        // // kprintln!("  [DRIVER SMOKE] all driver checks passed")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    } else {
        // // kprintln!("  [DRIVER SMOKE FAIL] one or more driver checks failed")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
    ok
}
