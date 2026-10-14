//! Timer Stack Smoke Test Aggregator

use crate::kprintln;

pub fn smoke_test() -> bool {
    // kprintln!("  [TIMER SMOKE] running timer stack smoke tests...");
    let mut ok = true;
    ok &= super::hpet::smoke_test();
    ok &= super::acpi_pm::smoke_test();
    if ok {
        // kprintln!("  [TIMER SMOKE] all timer checks passed");
    } else {
        // kprintln!("  [TIMER SMOKE FAIL] one or more checks failed");
    }
    ok
}
