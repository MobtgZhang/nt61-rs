//! System Servers Module
//
//! Implements core Windows system processes: smss, csrss, services, etc.

pub mod csrss;
pub mod pid1;
pub mod pid2;
pub mod services;
pub mod smoke;
pub mod smss;
pub mod sshd;
pub mod wininit;
pub mod winlogon;
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
pub mod cmd_extensions;

/// Initialize all system servers
pub fn init() {
    // kprintln!("  Initializing system servers...");

    // Initialize CSRSS (Client Server Runtime Subsystem)
    // kprintln!("    Initializing CSRSS...");
    csrss::init();

    // Initialize WinInit (Session 0 init process)
    // kprintln!("    Initializing WinInit...");
    wininit::init();

    // Initialize WinLogon (interactive logon)
    // kprintln!("    Initializing WinLogon...");
    winlogon::init();

    // User-mode process stubs (kept for backwards compatibility)
    pid1::init();
    pid2::init();

    // Service Control Manager — registers default services and marks
    // the SCM running so phase-3 service starts can proceed.
    services::init();

    // kprintln!("  System servers initialized");
}

/// Re-export of the system-servers smoke test. The full
/// implementation lives in the `smoke` submodule; this re-export
/// keeps the call site readable as `servers::smoke_test()`.
pub fn smoke_test() -> bool {
    smoke::smoke_test()
}
pub mod test_csrss_services;
