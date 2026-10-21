//! Libraries — aggregated smoke test
//
//! Calls each module's `smoke_test()` and reports the
//! conjunction. The boot log shows one PASS/FAIL line per
//! module so a failure is easy to localise.

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn case(_label: &'static str, run: fn() -> bool) -> bool {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    let _ = &n;
    let ok = run();
    // kprintln!("      [libs/{:02}] {} {}", n, if ok { "PASS" } else { "FAIL" }, label);
    ok
}

pub fn smoke_test() -> bool {
    // kprintln!("    [libs] running aggregate smoke tests");
    let mut ok = true;
    ok &= case("ntdll", crate::libs::ntdll::smoke::smoke_test);
    ok &= case("kernel32", crate::libs::kernel32::smoke::smoke_test);
    ok &= case("user32", crate::libs::user32::smoke::smoke_test);
    ok &= case("gdi32", crate::libs::gdi32::smoke::smoke_test);
    ok &= case("wow64", crate::libs::wow64::smoke::smoke_test);
    ok &= case("server::smss", crate::libs::server::smss::smoke_test);
    ok &= case("server::csrss", crate::libs::server::csrss::smoke_test);
    ok &= case("server::wininit", crate::libs::server::wininit::smoke_test);
    ok &= case(
        "server::winlogon",
        crate::libs::server::winlogon::smoke_test,
    );
    ok &= case(
        "server::services",
        crate::libs::server::services::smoke_test,
    );
    ok &= case("server::lsass", crate::libs::server::lsass::smoke_test);
    ok &= case(
        "server::explorer",
        crate::libs::server::explorer::smoke_test,
    );
    ok &= case("server::cmd", crate::libs::server::cmd::smoke_test);
    // kprintln!("    [libs] {}", if ok { "all PASS" } else { "FAIL" });
    ok
}
