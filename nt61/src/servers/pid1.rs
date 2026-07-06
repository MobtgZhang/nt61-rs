//! pid1
//
//! Placeholder for the first userspace process. In Linux convention
//! this is the system init; in Windows 7 the equivalent role is
//! played by `smss.exe` and the session-manager child
//! `wininit.exe`. We keep the module so the build does not break
//! when the source tree mentions `pid1` in older commits.


/// Stub.
pub fn init() {
    // kprintln!("    pid1 stub: present")  // kprintln disabled (memcpy crash workaround);
}
