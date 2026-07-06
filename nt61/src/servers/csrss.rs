//! Client/Server Runtime Subsystem (CSRSS)
//
//! Implements the Win32 subsystem server. In real Windows this is a
//! regular user-mode process started by SMSS for each session
//! (Session 0 and Session 1+). The kernel-mode counterpart -
//! win32k.sys - provides the actual window manager, GDI, etc., and is
//! loaded by the I/O manager as a regular driver.
//
//! For the bootstrap we model CSRSS as a kernel thread that runs the
//! `csrss_main` loop and accepts LPC requests from user-mode clients
//! via the ALPC port created in `servers::smss`.


/// CSRSS per-session state.
pub struct CsrsState {
    pub session_id: u32,
    pub in_session: u32,
    pub api_port: *mut (),
}

impl CsrsState {
    pub const fn new() -> Self {
        Self {
            session_id: 0,
            in_session: 0,
            api_port: core::ptr::null_mut(),
        }
    }
}

/// Initialize the CSRSS subsystem.
pub fn init() {
    // kprintln!("    CSRSS subsystem: initialized")  // kprintln disabled (memcpy crash workaround);
}

/// CSRSS main loop - process LPC requests forever. In real Windows
/// the requests are multiplexed over an ALPC port named
/// `\\Sessions\\N\\Windows\\ApiPort`.
pub fn csrss_main() -> ! {
    // kprintln!("[CSRSS] Process started")  // kprintln disabled (memcpy crash workaround);
    loop {
        // Block on the ALPC port. The scheduler will park us until a
        // request arrives.
        crate::arch::halt();
    }
}
