//! Audio Stack Smoke Test Aggregator

pub fn smoke_test() -> bool {
    // kprintln!("  [AUDIO SMOKE] running audio stack smoke tests...");
    let mut ok = true;
    ok &= super::intel_hda::smoke_test();
    ok &= super::ac97::smoke_test();
    if ok {
        // kprintln!("  [AUDIO SMOKE] all audio checks passed");
    } else {
        // kprintln!("  [AUDIO SMOKE FAIL] one or more checks failed");
    }
    ok
}
