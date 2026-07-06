//! User-mode programs (Ring 3).
//!
//! ## Architecture Overview
//!
//! ```
//! userspace/           ← user-mode shim (re-exports from libs/ and libs/server/)
//!   ntdll/             ← wraps crate::libs::ntdll  (syscall macros, NTSTATUS)
//!   kernel32/          ← wraps crate::libs::kernel32 (Win32 API stubs)
//!   crt.rs            ← CRT startup helpers
//!   smss.rs           ← re-exports crate::libs::server::smss
//!   csrss.rs          ← re-exports crate::libs::server::csrss
//!   services.rs       ← re-exports crate::libs::server::services
//!   lsass.rs          ← re-exports crate::libs::server::lsass
//!   winlogon.rs       ← re-exports crate::libs::server::winlogon
//!   cmd.rs            ← re-exports crate::libs::server::cmd
//!   more.rs           ← paginator stub
//!   find.rs           ← text search stub
//!   minimal_stub/     ← the only thing that actually runs today
//!
//! libs/               ← authoritative stubs (compiled into kernel)
//!   ntdll/            ← types, NTSTATUS, Nt* wrappers, Rtl* helpers
//!   kernel32/         ← Win32 base API stubs
//!   server/           ← thin re-exports of servers/ (the real implementations)
//!
//! servers/            ← real system-process implementations
//!   smss.rs           ← full SMSS boot logic
//!   csrss.rs          ← full CSRSS loop
//!   services.rs       ← SCM implementation
//!   winlogon.rs       ← logon manager
//!   cmd.rs            ← full interactive CMD interpreter
//!   lsass.rs          ← via libs/server/
//! ```
//!
//! ## Design Rules
//!
//! 1. **Every user-mode export lives exactly once** — in either
//!    `libs/` (kernel-side stub) or `servers/` (real implementation).
//! 2. **`userspace/` never duplicates logic** — it only re-exports
//!    from `libs::` or `libs::server::`.
//! 3. **`libs/` is the source of truth for types** — `NTSTATUS`,
//!    `UNICODE_STRING`, syscall numbers, etc. all live in
//!    `crate::libs::ntdll::types`.
//! 4. **`servers/` has the real process logic** — SMSS, CSRSS,
//!    services, winlogon all have complete implementations there.
//! 5. **`libs/server/` is the bridge layer** — thin re-exports that
//!    expose the `servers/` surface through `libs::server::*` paths.
//! 6. **`userspace/` is a shim layer** — it exposes the same
//!    public API surface that real Windows user-mode code would
//!    link against.

#![allow(dead_code, unused_imports)]

pub mod minimal_stub;

// Phase 1: PE loader, PEB/TEB structures, initial stack, params.
// These are kernel-side helpers for building user-mode address spaces.
pub mod loader;
#[cfg(target_arch = "x86_64")]
pub mod peb_teb;
#[cfg(target_arch = "x86_64")]
pub mod stack;
#[cfg(target_arch = "x86_64")]
pub mod user_params;

// Phase 2: ntdll.dll — wraps crate::libs::ntdll with syscall macros.
pub mod ntdll;

// Phase 3: kernel32.dll — wraps crate::libs::kernel32 + CRT helpers.
pub mod kernel32;
pub mod crt;

// Phase 4: system processes.
// These re-export from crate::libs::server/ (the bridge to servers/).
pub mod smss;
pub mod csrss;
pub mod services;
pub mod lsass;
pub mod winlogon;

// Phase 5: user-mode utilities / shell programs.
pub mod cmd;
pub mod more;
pub mod find;
