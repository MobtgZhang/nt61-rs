//! System Servers Module
//
//! Implements core Windows system processes: smss, csrss, services, etc.

pub mod smss;
pub mod csrss;
pub mod services;
pub mod wininit;
pub mod winlogon;
pub mod pid1;
pub mod pid2;
pub mod smoke;
// The CMD shell (`kd>` debug prompt + kernel-side `C:\>`
// alternate-shell prompt) is **architecture-independent**. It is
// the SafeBootMode fallback used on every architecture: on
// x86_64 the user-mode `cmd.exe` stub at `C:\Windows\system32\`
// is the primary user-facing shell, and the kernel-side shell
// is only used in `SafeModeDebug`. On aarch64, riscv64 and
// loongarch64 the cmd.exe user-mode binary is not available,
// so the kernel-side shell carries the entire CMD/IDLE UX in
// both `SafeModeCmd` and `SafeModeDebug`. Keeping this module
// non-gated guarantees the same command parser, history, and
// `LOG_RING_LINES`-backed `LOGS` pane works on every target.
pub mod cmd;


/// Initialize all system servers
pub fn init() {
    // kprintln!("  Initializing system servers...")  // kprintln disabled (memcpy crash workaround);

    // Initialize CSRSS (Client Server Runtime Subsystem)
    // kprintln!("    Initializing CSRSS...")  // kprintln disabled (memcpy crash workaround);
    csrss::init();

    // Initialize WinInit (Session 0 init process)
    // kprintln!("    Initializing WinInit...")  // kprintln disabled (memcpy crash workaround);
    wininit::init();

    // Initialize WinLogon (interactive logon)
    // kprintln!("    Initializing WinLogon...")  // kprintln disabled (memcpy crash workaround);
    winlogon::init();

    // User-mode process stubs (kept for backwards compatibility)
    pid1::init();
    pid2::init();

    // kprintln!("  System servers initialized")  // kprintln disabled (memcpy crash workaround);
}

/// Re-export of the system-servers smoke test. The full
/// implementation lives in the `smoke` submodule; this re-export
/// keeps the call site readable as `servers::smoke_test()`.
pub fn smoke_test() -> bool { smoke::smoke_test() }