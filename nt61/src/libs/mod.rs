//! Libraries — user-mode DLL / server stubs
//
//! Aggregates the user-mode DLLs that would normally be
//! loaded by `winload` after the kernel image:
//!   * `ntdll`    — Native API
//!   * `kernel32` — Win32 base
//!   * `advapi32` — Security and registry
//!   * `msvcrt`   — Microsoft C runtime
//!   * `rpcrt4`   — RPC runtime
//!   * `user32`   — windowing
//!   * `gdi32`    — graphics device interface
//!   * `win32k`   — kernel graphics subsystem
//!   * `wow64`    — 32/64 thunk (stub)
//!   * `sechost`  — Service Host process
//!   * `server`   — system server EXEs (smss/csrss/...)
//
//!     On this kernel the user-mode side is never actually
//!     executed; `winload` simply loads the DLLs to verify the
//!     export tables and call `DllMain` so the boot log shows
//!     the entry points are reachable.

// Stub-only DLLs carry every public symbol the Windows version
// of the DLL exposes, even though the bootstrap never actually
// invokes most of them. The unused-import / dead-code lints
// fire on the stub functions that are exposed for the PE export
// table but not called by the boot log. Suppressing the lints
// at the crate root is the right call — the alternative would
// be hundreds of `#[allow(unused_imports)]` on every stub file.

extern crate alloc;

pub mod advapi32;
pub mod cmd;
pub mod gdi32;
pub mod kernel32;
pub mod msvcrt;
pub mod ntdll;
pub mod rpcrt4;
pub mod sechost;
pub mod server;
pub mod user32;
pub mod win32k;
pub mod wow64;
pub mod wow64win;
pub mod ws2_32;

pub mod smoke;

/// Initialise the library stubs. Each module prints its
/// own banner; this function just reports completion.
pub fn init() {
    // kprintln!("    Library stubs: initialising...");
    ntdll::init();
    kernel32::init();
    advapi32::init();
    msvcrt::init();
    rpcrt4::init();
    user32::init();
    gdi32::init();
    win32k::init();
    wow64::init();
    wow64win::init();
    sechost::init();
    server::init();
    // kprintln!("    Library stubs: initialised");
}

/// Aggregator smoke test. Walks every stub in turn and
/// reports a single boolean result.
pub fn smoke_test() -> bool {
    smoke::smoke_test()
}
