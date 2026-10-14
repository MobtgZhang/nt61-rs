//! USB Stack Smoke Test Aggregator

use crate::kprintln;

pub fn smoke_test() -> bool {
    // kprintln!("  [USB SMOKE] running USB stack smoke tests...");
    let mut ok = true;
    ok &= super::uhci::smoke_test();
    ok &= super::ehci::smoke_test();
    ok &= super::xhci::smoke_test();
    ok &= super::hub::smoke_test();
    ok &= super::hid::smoke_test();
    if ok {
        // kprintln!("  [USB SMOKE] all USB checks passed");
    } else {
        // kprintln!("  [USB SMOKE FAIL] one or more checks failed");
    }
    ok
}
