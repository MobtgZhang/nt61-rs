//! NDIS Stack Smoke Test Aggregator

use crate::kprintln;

pub fn smoke_test() -> bool {
    // kprintln!("  [NDIS SMOKE] running NDIS stack smoke tests...")  // kprintln disabled (memcpy crash workaround);
    let mut ok = true;
    ok &= super::ndis6::smoke_test();
    ok &= super::miniport::smoke_test();
    if ok {
        // kprintln!("  [NDIS SMOKE] all NDIS checks passed")  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("  [NDIS SMOKE FAIL] one or more checks failed")  // kprintln disabled (memcpy crash workaround);
    }
    ok
}
