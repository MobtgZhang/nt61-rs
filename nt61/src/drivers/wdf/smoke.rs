//! WDF Stack Smoke Test Aggregator

use crate::kprintln;

pub fn smoke_test() -> bool {
    // kprintln!("  [WDF SMOKE] running WDF stack smoke tests...");
    let mut ok = true;
    ok &= super::kmdf::smoke_test();
    if ok {
        // kprintln!("  [WDF SMOKE] all WDF checks passed");
    } else {
        // kprintln!("  [WDF SMOKE FAIL] one or more checks failed");
    }
    ok
}
