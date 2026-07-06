//! ntdll.dll — user-mode native API.
//!
//! Phase 2 entry point. Aggregates the syscall primitives, NTSTATUS
//! codes, system call numbers, and RTL helpers used by user-mode
//! code. The actual `Nt*` and `Rtl*` implementations live in
//! `crate::libs::ntdll`; this module wraps them with the
//! syscall-macro surface that user-mode callers actually use.
//!
//! Architecture:
//! - `crate::libs::ntdll` — the authoritative stubs (types, syscall numbers,
//!   Nt* wrappers, Rtl* helpers). These are what gets compiled into the
//!   kernel and exported in the PE DLL stubs.
//! - `crate::userspace::ntdll` — the user-mode-facing shim that
//!   re-exports from `crate::libs::ntdll`. When the full user-mode
//!   switch is turned on, user code will link against this layer.

#![allow(dead_code, non_snake_case, non_upper_case_globals, ambiguous_glob_reexports)]

// These three files contain the authoritative implementations.
pub mod status;   // NTSTATUS constants + NT_SUCCESS etc.
pub mod syscalls;  // syscall numbers (NtCreateProcess, NtWriteFile, ...)
#[cfg(target_arch = "x86_64")]
pub mod syscall;   // inline-asm syscall0..syscall4 macros (x86_64 only)

// RTL helpers: the canonical implementations live in libs::ntdll;
// we pull them in here so that `crate::userspace::ntdll::RtlCopyMemory`
// and `crate::userspace::ntdll::LdrLoadDll` resolve correctly.
pub use crate::libs::ntdll::string::*;
pub use crate::libs::ntdll::rtl_acl::*;
pub use crate::libs::ntdll::rtl_path::*;
pub use crate::libs::ntdll::heap::*;
pub use crate::libs::ntdll::thread::*;
pub use crate::libs::ntdll::process::*;
pub use crate::libs::ntdll::file::*;
pub use crate::libs::ntdll::sync::*;
pub use crate::libs::ntdll::virtual_mem::*;
pub use crate::libs::ntdll::section::*;
pub use crate::libs::ntdll::info::*;
pub use crate::libs::ntdll::ldr::*;
pub use crate::libs::ntdll::peb_teb::*;
pub use crate::libs::ntdll::debug::*;
pub use crate::libs::ntdll::registry::*;
pub use crate::libs::ntdll::ob_integration::*;

#[cfg(target_arch = "x86_64")]
pub use syscall::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall_varargs};
pub use status::*;
pub use syscalls::*;
