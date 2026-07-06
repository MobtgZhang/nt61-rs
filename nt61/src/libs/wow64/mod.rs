//! wow64 — Windows-on-Windows 64 stub
//
//! WoW64 is the emulation layer that lets 32-bit programs run
//! on a 64-bit kernel. This kernel is x64 only and never
//! hosts 32-bit user-mode code, so the WoW64 DLL is a thin
//! stub whose only purpose is to advertise the WoW64 API
//! surface and verify the loader can find it.
//
//! References:
//!   * MSDN Library "Windows 7" — wow64.dll
//!   * geoffchappell.com — WoW64 architecture
//!   * ReactOS 0.3.x `wow64` thunk layer
//!   * Wine 1.7.x wow64 stub
//
//! Module layout:
//!   * `klog`     — wow64-local lightweight log macro
//!     (avoids the `kprintln!` memcpy path).
//!   * `handle`   — HANDLE32 → kernel object resolvers.
//!   * `types`    — 32↔64 conversion helpers, PEB32/TEB32 structures
//!   * `wow64vas` — 32-bit virtual address space manager
//!   * `thunk`    — Wow64PrepareForException, Wow64ApcRoutine
//!   * `ssd`      — system service dispatch table
//!   * `syscall_thunk` — 32-bit syscall dispatch
//!   * `mem_thunk`    — memory API thunks
//!   * `ps_thunk`     — process/thread info thunks
//!   * `apc_exc_thunk`— APC and exception thunks

#![cfg(target_arch = "x86_64")]
#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

pub mod klog;
pub mod handle;
pub mod thunk;
pub mod types;
pub mod wow64vas;
pub mod ssd;
pub mod syscall_thunk;
pub mod mem_thunk;
pub mod ps_thunk;
pub mod apc_exc_thunk;

/// WoW64 service table. The stub uses this to verify the
/// service dispatch table is reachable.
pub static WOW64_SERVICES: Spinlock<Vec<(&'static str, u64)>> =
    Spinlock::new(Vec::new());

/// Initialise the wow64 stub.
pub fn init() {
    crate::wow64_klog!("init (stubbed)");
    // Defer to the per-subsystem init so that the SSD and
    // thunk layers also get a chance to publish themselves.
    ssd::init_service_table();
    thunk::register_services();
    crate::wow64_klog!("ready ({} services registered)",
        WOW64_SERVICES.lock().len());
}

pub mod smoke;
pub use smoke::smoke_test as run_smoke;
