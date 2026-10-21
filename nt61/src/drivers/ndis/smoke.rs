//! NDIS Stack Smoke Test Aggregator

pub fn smoke_test() -> bool {
    // kprintln!("  [NDIS SMOKE] running NDIS stack smoke tests...");
    let mut ok = true;
    ok &= super::ndis6::smoke_test();
    ok &= super::miniport::smoke_test();
    if ok {
        // kprintln!("  [NDIS SMOKE] all NDIS checks passed");
    } else {
        // kprintln!("  [NDIS SMOKE FAIL] one or more checks failed");
    }
    ok
}
