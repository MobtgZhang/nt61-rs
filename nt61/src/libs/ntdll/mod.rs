//! ntdll.dll — user-mode native API stub
//
//! The user-mode native API of NT 6.1. The DLL exposes the
//! `Nt*` and `Rtl*` entry points that the Win32 subsystem and
//! every user-mode application ultimately calls. On this
//! kernel, the DLL is loaded by `winload` for logging /
//! smoke-test purposes only — no user-mode code actually
//! runs.
//
//! All entry points follow the Windows naming convention
//! (PascalCase for functions, SCREAMING_CASE for constants),
//! so we silence the Rust naming lints at the crate level.

// The ntdll surface intentionally uses Windows NT naming
// conventions (`Nt*`/`Rtl*` for functions, `STATUS_*` for
// NTSTATUS codes). Those names ARE the API, so we cannot
// rename them to satisfy Rust's style lints.
//
//! Submodules
//!   * `types` — public NT types (UnicodeString, ...)
//!   * `status` — NTSTATUS codes + RtlNtStatusToDosError
//!   * `string` — Rtl*UnicodeString / Rtl*AnsiString
//!   * `heap`   — rtl_allocate_heap / rtl_free_heap / ...
//!   * `file`   — NT_CREATE_FILE / NT_READ_FILE / ...
//!   * `process`, `thread`, `section`, `sync`,
//!     `virtual_mem`, `info` — the rest of the Native API
//!   * `ldr`    — ldr_load_dll / ldr_get_dll_handle / ...
//!   * `peb_teb`— PEB / TEB structures + rtl_get_current_peb
//!   * `debug`  — dbg_print / dbg_print_ex
//!   * `rtl_acl`, `rtl_path` — smaller RTL utilities
//
//!     References (for layout / signatures only):
//!   * Microsoft Windows 7 SDK ntddk.h / ntdef.h
//!   * ReactOS 0.3.x ntdll headers
//!   * Wine 1.7.x ntdll.spec

pub mod debug;
pub mod file;
pub mod heap;
pub mod info;
pub mod ioctl;
pub mod ldr;
pub mod ob_integration;
pub mod peb_teb;
pub mod process;
pub mod registry;
pub mod rtl_acl;
pub mod rtl_genrandom;
pub mod rtl_path;
pub mod section;
pub mod smoke;
pub mod status;
pub mod string;
pub mod sync;
pub mod thread;
pub mod types;
pub mod virtual_mem;

/// Initialise the ntdll stub. Walks every submodule's
/// `init()` (where one is defined) and prints a status line.
pub fn init() {
    // crate::kprintln!("    NTDLL: init");
    // crate::kprintln!("      types:    ready");
    // crate::kprintln!("      status:   ready");
    // crate::kprintln!("      string:   ready (rtl_init_unicode_string etc.)");
    // crate::kprintln!("      heap:     ready (rtl_allocate_heap etc.)");
    // crate::kprintln!("      file:     ready (NT_CREATE_FILE etc.)");
    // crate::kprintln!("      process:  ready (NT_CREATE_PROCESS etc.)");
    // crate::kprintln!("      thread:   ready (NT_CREATE_THREAD etc.)");
    // crate::kprintln!("      section:  ready (NT_CREATE_SECTION etc.)");
    // crate::kprintln!("      sync:     ready (NT_WAIT_FOR_SINGLE_OBJECT etc.)");
    // crate::kprintln!("      vm:       ready (NT_ALLOCATE_VIRTUAL_MEMORY etc.)");
    // crate::kprintln!("      info:     ready (NT_QUERY_SYSTEM_INFORMATION etc.)");
    // crate::kprintln!("      ldr:      ready (ldr_load_dll etc.)");
    // crate::kprintln!("      peb/teb:  ready (rtl_get_current_peb etc.)");
    // crate::kprintln!("      debug:    ready (dbg_print etc.)");
    // crate::kprintln!("      rtl_acl:  ready (rtl_create_acl etc.)");
    // crate::kprintln!("      rtl_path: ready (rtl_get_full_path_name_u etc.)");
    // crate::kprintln!("      registry: ready (NT_CREATE_KEY etc.)");
    // crate::kprintln!("      ob_integration: ready (ob handle bridge)");
    registry::init();
    registry::init_default_keys();
    ob_integration::init();
}

/// Re-export of the ntdll smoke test aggregator.
pub fn smoke_test() -> bool {
    smoke::smoke_test()
}

pub mod apc;
pub mod exception;
pub mod heap_safe;
pub mod nt_extended;
pub mod rtl_bitmap;
pub mod rtl_convert;
pub mod rtl_critical;
pub mod rtl_memory;
pub mod rtl_string_ext;
pub mod security;
pub mod timer;
pub mod tls;
pub mod wait;
