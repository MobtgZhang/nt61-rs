//! WinLogon - Interactive Logon Manager
//
//! WinLogon.exe is the user-mode logon process. It is started by SMSS
//! for each interactive session. Its responsibilities include:
//
//!  * presenting the Secure Attention Sequence (SAS) UI
//!  * handling CTRL+ALT+DELETE
//!  * running the credential provider chain
//!  * managing the user profile once a user logs on
//
//! In the bootstrap we model WinLogon as a kernel thread that runs
//! the `winlogon_main` loop and reports login events via ALPC.


/// WinLogon state.
pub struct WinLogonState {
    pub session_id: u32,
    pub logged_on: bool,
    pub user_sid: u64,
}

impl WinLogonState {
    pub const fn new() -> Self {
        Self {
            session_id: 0,
            logged_on: false,
            user_sid: 0,
        }
    }
}

/// Initialize the WinLogon subsystem.
pub fn init() {
    // kprintln!("    WinLogon: initialized")  // kprintln disabled (memcpy crash workaround);
}

/// WinLogon main loop.
pub fn winlogon_main() -> ! {
    // kprintln!("[WinLogon] Logon manager started")  // kprintln disabled (memcpy crash workaround);
    // In a real implementation, WinLogon would:
    //   1. Wait for SAS (CTRL+ALT+DELETE) via `Win32k.sys`
    //   2. Run the credential provider chain
    //   3. Hand off to LSASS for authentication
    //   4. Profile the user, mount their hives, and create the
    //      initial process (explorer.exe)
    loop {
        crate::arch::halt();
    }
}
