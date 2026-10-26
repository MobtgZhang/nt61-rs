//! WinInit - Session 0 Initialization Process
//
//! Wininit.exe is the Session 0 initialization process. It is started
//! by SMSS as the first child and runs forever, providing:
//
//!  * the Service control Manager database and RPC endpoint
//!  * the Local Security Authority subsystem process (LSASS)
//!  * the Windows Logon UI infrastructure
//
//! In the bootstrap we model WinInit as a kernel thread that runs the
//! `wininit_main` loop and owns the SCM, the LSA, and the start menu
//! for Session 0.

/// WinInit per-session state.
pub struct WinInitState {
    pub started: bool,
    pub services_started: u32,
    pub lsa_endpoint: *mut (),
}

impl WinInitState {
    pub const fn new() -> Self {
        Self {
            started: false,
            services_started: 0,
            lsa_endpoint: core::ptr::null_mut(),
        }
    }
}

/// Initialize the WinInit subsystem.
pub fn init() {
    // kprintln!("    WinInit: initialized");
}

/// WinInit main loop.
pub fn wininit_main() -> ! {
    // kprintln!("[WinInit] Session 0 initialization started");
    loop {
        crate::arch::halt();
    }
}
