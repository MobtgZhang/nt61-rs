//! Audio Stack Smoke Test Aggregator

use crate::kprintln;

pub fn smoke_test() -> bool {
    // kprintln!("  [AUDIO SMOKE] running audio stack smoke tests...")  // kprintln disabled (memcpy crash workaround);
    let mut ok = true;
    ok &= super::intel_hda::smoke_test();
    ok &= super::ac97::smoke_test();
    if ok {
        // kprintln!("  [AUDIO SMOKE] all audio checks passed")  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("  [AUDIO SMOKE FAIL] one or more checks failed")  // kprintln disabled (memcpy crash workaround);
    }
    ok
}
