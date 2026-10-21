//! Driver Subsystem Smoke Test Aggregator
//
//! Runs every driver's smoke test and aggregates the result,
//! mirroring the convention used by `ke::smoke` / `mm::smoke` /
//! `io::smoke`. The boot log shows a single
//! `Driver subsystem smoke test: PASSED` line on success.

/// Run every driver's self-check and return `true` iff every
/// one passes.
pub fn smoke_test() -> bool {
    // // kprintln!("  [DRIVER SMOKE] running all driver subsystem smoke tests...");
    let mut ok = true;
    ok &= crate::drivers::bus::smoke_test();
    ok &= crate::drivers::storage::smoke_test();
    ok &= crate::drivers::usb::smoke_test();
    ok &= crate::drivers::net::smoke_test();
    ok &= crate::drivers::audio::smoke_test();
    ok &= crate::drivers::input::smoke_test();
    ok &= crate::drivers::video::smoke_test();
    ok &= crate::drivers::timer::smoke_test();
    ok &= crate::drivers::ndis::smoke_test();
    ok &= crate::drivers::wdf::smoke_test();
    ok &= super::kdcom::smoke_test();
    ok &= crate::drivers::bootvid::smoke_test();
    ok &= crate::drivers::clfs::smoke::smoke_test();
    ok &= crate::drivers::pcw::smoke_test();
    ok &= crate::drivers::partmgr::smoke_test();
    ok &= crate::drivers::storage::disk::smoke_test();
    ok &= crate::drivers::storage::ataport::smoke_test();
    ok &= crate::drivers::storage::storport::smoke_test();
    ok &= crate::drivers::volmgr::smoke_test();
    ok &= crate::drivers::volsnap::smoke_test();
    ok &= crate::drivers::fltmgr::smoke_test();
    ok &= crate::drivers::fileinfo::smoke_test();
    ok &= crate::drivers::spldr::smoke_test();
    if ok {
        // // kprintln!("  [DRIVER SMOKE] all driver checks passed");
    } else {
        // // kprintln!("  [DRIVER SMOKE FAIL] one or more driver checks failed");
    }
    ok
}
