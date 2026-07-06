//! kernel32.dll — Win32 API stub
//
//! The Win32 user-mode API. Every function in the public
//! `kernel32.dll` surface is here; on this kernel the DLL
//! is loaded by `winload` for logging / smoke-test purposes
//! only — no user-mode code actually runs.

// The Win32 surface intentionally uses Windows naming
// conventions (`CreateFileW`, `GetLastError`, `HANDLE`, etc.).
// Those names ARE the API; renaming them would break the
// Win32 ABI compatibility that this module is meant to model.
#![allow(non_snake_case, non_upper_case_globals, dead_code)]
//
//! Submodules
//!   * `types`   — handle / module / instance newtypes
//!   * `error`   — GetLastError / SetLastError / FormatMessage
//!   * `env`     — environment variables, current directory
//!   * `time`    — GetSystemTime / GetTickCount / Sleep
//!   * `handle`  — CloseHandle / DuplicateHandle
//!   * `file`    — CreateFileW / ReadFile / WriteFile
//!   * `module`  — LoadLibraryW / GetProcAddress / GetModuleHandleW
//!   * `memory`  — VirtualAlloc / HeapAlloc / HeapFree
//!   * `sync`    — CreateEventW / WaitForSingleObject
//!   * `process` — CreateProcessW / ExitProcess / OpenProcess
//!   * `thread`  — CreateThread / Sleep / GetCurrentThreadId
//!   * `console` — WriteConsoleW / AllocConsole
//
//! References (for layout / signatures only):
//!   * Microsoft Windows 7 SDK winbase.h / winuser.h
//!   * ReactOS 0.3.x winbase.h
//!   * Wine 1.7.x kernel32.spec

pub mod types;
pub mod error;
pub mod env;
pub mod time;
pub mod handle;
pub mod file;
pub mod module;
pub mod memory;
pub mod sync;
pub mod process;
pub mod thread;
pub mod console;
pub mod smoke;

/// Initialise the kernel32 stub. Walks every submodule's
/// `init()` (where one is defined) and prints a status
/// line.
pub fn init() {
    // crate::kprintln!("    KERNEL32: init")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      types:   ready")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      error:   ready (GetLastError/SetLastError)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      env:     ready (GetEnvironmentVariableW)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      time:    ready (GetSystemTime/GetTickCount)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      handle:  ready (CloseHandle)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      file:    ready (CreateFileW/ReadFile/WriteFile)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      module:  ready (LoadLibraryW/GetProcAddress)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      memory:  ready (VirtualAlloc/HeapAlloc)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      sync:    ready (CreateEventW/WaitForSingleObject)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      process: ready (CreateProcessW)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      thread:  ready (CreateThread/Sleep)")  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("      console: ready (WriteConsoleW/AllocConsole)")  // kprintln disabled (memcpy crash workaround);
}

/// Re-export of the kernel32 smoke test aggregator.
pub fn smoke_test() -> bool { smoke::smoke_test() }
