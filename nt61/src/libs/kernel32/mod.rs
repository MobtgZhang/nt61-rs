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

pub mod console;
pub mod env;
pub mod error;
pub mod file;
pub mod handle;
pub mod memory;
pub mod module;
pub mod process;
pub mod smoke;
pub mod sync;
pub mod thread;
pub mod time;
pub mod types;

/// Initialise the kernel32 stub. Walks every submodule's
/// `init()` (where one is defined) and prints a status
/// line.
pub fn init() {
    // crate::kprintln!("    KERNEL32: init");
    // crate::kprintln!("      types:   ready");
    // crate::kprintln!("      error:   ready (GetLastError/SetLastError)");
    // crate::kprintln!("      env:     ready (GetEnvironmentVariableW)");
    // crate::kprintln!("      time:    ready (GetSystemTime/GetTickCount)");
    // crate::kprintln!("      handle:  ready (CloseHandle)");
    // crate::kprintln!("      file:    ready (CreateFileW/ReadFile/WriteFile)");
    // crate::kprintln!("      module:  ready (LoadLibraryW/GetProcAddress)");
    // crate::kprintln!("      memory:  ready (VirtualAlloc/HeapAlloc)");
    // crate::kprintln!("      sync:    ready (CreateEventW/WaitForSingleObject)");
    // crate::kprintln!("      process: ready (CreateProcessW)");
    // crate::kprintln!("      thread:  ready (CreateThread/Sleep)");
    // crate::kprintln!("      console: ready (WriteConsoleW/AllocConsole)");
}

/// Re-export of the kernel32 smoke test aggregator.
pub fn smoke_test() -> bool {
    smoke::smoke_test()
}

pub mod console_ext;
pub mod file_async;
pub mod file_ext;
pub mod file_ext_safe;
pub mod process_ext;
pub mod sync_ext;
pub mod sync_srw;
