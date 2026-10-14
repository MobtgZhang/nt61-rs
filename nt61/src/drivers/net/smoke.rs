//! Network Stack Smoke Test Aggregator

#![cfg(target_arch = "x86_64")]

use crate::kprintln;

pub fn smoke_test() -> bool {
    // kprintln!("  [NET SMOKE] running network stack smoke tests...");
    let mut ok = true;
    ok &= super::e1000::smoke_test();
    ok &= super::rtl8139::smoke_test();
    ok &= super::virtio_net::smoke_test();
    if ok {
        // kprintln!("  [NET SMOKE] all net checks passed");
    } else {
        // kprintln!("  [NET SMOKE FAIL] one or more checks failed");
    }
    ok
}
