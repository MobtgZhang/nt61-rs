//! Architecture-neutral boot helpers (sub-facade).
//!
//! The original single-file `boot.rs` mixed early-serial bring-up,
//! framebuffer adoption, display-mode switching, debugger transport
//! and the Ring-3 user launch in one file, so every change required a
//! four-ISA sync pass. Each concern now lives in its own submodule;
//! the public API is unchanged because every item is re-exported.

mod dbg_facade;
mod display;
mod early_console;
mod framebuffer;
mod user_launch;

pub use dbg_facade::*;
pub use display::*;
pub use early_console::*;
pub use framebuffer::*;
pub use user_launch::*;

/// Re-export of the kernel's `BootMode` so callers don't need to
/// import the canonical definition from two places.
pub use crate::boot_types::BootMode;

use crate::boot_types::BootInfo;

/// Platform-neutral bare-metal entry handed to `kernel_main`.
///
/// `bi_ptr` is the boot-loader-provided `BootInfo` pointer (0 = use the
/// built-in defaults). The magic is validated before the pointer is
/// trusted, so a garbage register value from a bare loader falls back
/// to the defaults instead of dereferencing random memory.
pub fn kernel_entry(bi_ptr: usize) -> ! {
    if bi_ptr != 0 {
        let candidate = unsafe { &*(bi_ptr as *const BootInfo) };
        if candidate.is_valid() {
            crate::kernel_main::kernel_main(candidate);
        }
    }
    crate::kernel_main::kernel_main(&BootInfo::defaults())
}
