//! kernel32.dll — process-side stubs around the ntdll exports.
//!
//! Phase 3 task. Each submodule implements one kernel32 export
//! family. The implementations are typed stubs that call the
//! matching ntdll function once Phase 2 has wired the syscall table.

pub mod process;
pub mod file;
pub mod heap;
pub mod console;
pub mod dll;
pub mod env;
pub mod time;
