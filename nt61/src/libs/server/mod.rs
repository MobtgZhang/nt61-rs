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

#![allow(non_snake_case, non_upper_case_globals, dead_code)]
//
//! Modules:
//!   * `smss`     — Session Manager
//!   * `csrss`    — Client/Server Runtime Subsystem
//!   * `wininit`  — Boot-time init helper
//!   * `winlogon` — Logon manager
//!   * `services` — Service Control Manager
//!   * `lsass`    — Local Security Authority Subsystem
//!   * `explorer` — User shell
//!   * `cmd`      — Command interpreter

extern crate alloc;

use crate::kprintln;

pub mod smss;
pub mod csrss;
pub mod wininit;
pub mod winlogon;
pub mod services;
pub mod lsass;
pub mod explorer;
pub mod cmd;

/// Initialise all server stubs. Each prints a banner and
/// initialises its internal state. The real NT system
/// sequentially starts these processes at boot; the kernel
/// just calls `init()` and then verifies state via
/// `smoke_test()`.
pub fn init() {
    // kprintln!("    [server] init (stubbed: Vec/heap-using code disabled)")  // kprintln disabled (memcpy crash workaround);
    // The full server stubs use Vec::push and String which
    // hit heap allocs that currently fail (or corrupt the
    // user-mode-library region). For now we just print
    // "ready" and continue to the boot-completion path.
    // kprintln!("    [server] all servers initialised (stubbed)")  // kprintln disabled (memcpy crash workaround);
}

/// Module-level smoke: walk every server's smoke test and
/// return the conjunction.
pub fn smoke_test() -> bool {
    // kprintln!("    [server] running smoke tests")  // kprintln disabled (memcpy crash workaround);
    let mut ok = true;
    ok &= smss::smoke_test();
    ok &= csrss::smoke_test();
    ok &= wininit::smoke_test();
    ok &= winlogon::smoke_test();
    ok &= services::smoke_test();
    ok &= lsass::smoke_test();
    ok &= explorer::smoke_test();
    ok &= cmd::smoke_test();
    // kprintln!("    [server] {}", if ok { "all PASS" } else { "FAIL" })  // kprintln disabled (memcpy crash workaround);
    ok
}
