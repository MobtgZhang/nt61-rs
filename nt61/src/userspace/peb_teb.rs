//! User-mode PEB and `RTL_USER_PROCESS_PARAMETERS` aliases.
//!
//! The kernel is responsible for creating these structures. Re-exporting the
//! canonical definitions here guarantees that user-mode readers and kernel-side
//! writers use the same Windows 7 x64 layout.

pub use crate::ps::process::peb;
pub use crate::ps::process::CurDir;
pub use crate::ps::process::DriveLetterCurDir;
pub use crate::ps::process::RtlUserProcessParameters;

pub type BOOLEAN = u8;
pub type WCHAR = u16;

pub fn current_peb() -> *mut peb {
    crate::arch::current_teb().map_or(core::ptr::null_mut(), |teb| unsafe {
        let teb = teb as *mut crate::ps::thread::Teb;
        (*teb).process_environment_block as *mut peb
    })
}
