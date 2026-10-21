//! server/ — system server EXE stubs
//
//! Each module in this directory represents a system server
//! process. They are stubs: `pub fn main() -> !` is the entry
//! point, and `pub fn smoke_test() -> bool` verifies the
//! internal state is sane after init.
//
//! References:
//!   * MSDN Library "Windows 7" — system processes
//!   * ReactOS 0.3.x `base/system/smss`, `csrss`, `wininit`, etc.

//
//! Modules:
//!   * `smss`     — Session Manager
//!   * `csrss`    — Client/Server Runtime Subsystem
//!   * `wininit`  — Boot-time init helper
//!   * `winlogon` — Logon manager
//!   * `services` — Service control Manager
//!   * `lsass`    — Local Security Authority Subsystem
//!   * `explorer` — User shell
//!   * `cmd`      — Command interpreter

extern crate alloc;

pub mod cmd;
pub mod csrss;
pub mod explorer;
pub mod lsass;
pub mod services;
pub mod smss;
pub mod wininit;
pub mod winlogon;

/// Initialise all server stubs. Each prints a banner and
/// initialises its internal state. The real NT system
/// sequentially starts these processes at boot; the kernel
/// just calls `init()` and then verifies state via
/// `smoke_test()`.
pub fn init() {
    // kprintln!("    [server] init (stubbed: Vec/heap-using code disabled)");
    // The full server stubs use Vec::push and String which
    // hit heap allocs that currently fail (or corrupt the
    // user-mode-library region). For now we just print
    // "ready" and continue to the boot-completion path.
    // kprintln!("    [server] all servers initialised (stubbed)");
}

/// Module-level smoke: walk every server's smoke test and
/// return the conjunction.
pub fn smoke_test() -> bool {
    // kprintln!("    [server] running smoke tests");
    let mut ok = true;
    ok &= smss::smoke_test();
    ok &= csrss::smoke_test();
    ok &= wininit::smoke_test();
    ok &= winlogon::smoke_test();
    ok &= services::smoke_test();
    ok &= lsass::smoke_test();
    ok &= explorer::smoke_test();
    ok &= cmd::smoke_test();
    // kprintln!("    [server] {}", if ok { "all PASS" } else { "FAIL" });
    ok
}
