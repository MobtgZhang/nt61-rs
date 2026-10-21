//! kernel32.dll — Win32 API stub
//
//! The Win32 user-mode API. Every function in the public
//! `kernel32.dll` surface is here; on this kernel the DLL
//! is loaded by `winload` for logging / smoke-test purposes
//! only — no user-mode code actually runs.

// The Win32 surface intentionally uses Windows naming
// conventions (`create_file_w`, `get_last_error`, `HANDLE`, etc.).
// Those names ARE the API; renaming them would break the
// Win32 ABI compatibility that this module is meant to model.
//
//! Submodules
//!   * `types`   — handle / module / instance newtypes
//!   * `error`   — get_last_error / set_last_error / FormatMessage
//!   * `env`     — environment variables, current directory
//!   * `time`    — get_system_time / get_tick_count / sleep
//!   * `handle`  — close_handle / duplicate_handle
//!   * `file`    — create_file_w / read_file / write_file
//!   * `module`  — load_library_w / get_proc_address / get_module_handle_w
//!   * `memory`  — virtual_alloc / heap_alloc / heap_free
//!   * `sync`    — create_event_w / wait_for_single_object
//!   * `process` — create_process_w / exit_process / open_process
//!   * `thread`  — create_thread / sleep / get_current_thread_id
//!   * `console` — write_console_w / alloc_console
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
    // crate::kprintln!("      error:   ready (get_last_error/set_last_error)");
    // crate::kprintln!("      env:     ready (get_environment_variable_w)");
    // crate::kprintln!("      time:    ready (get_system_time/get_tick_count)");
    // crate::kprintln!("      handle:  ready (close_handle)");
    // crate::kprintln!("      file:    ready (create_file_w/read_file/write_file)");
    // crate::kprintln!("      module:  ready (load_library_w/get_proc_address)");
    // crate::kprintln!("      memory:  ready (virtual_alloc/heap_alloc)");
    // crate::kprintln!("      sync:    ready (create_event_w/wait_for_single_object)");
    // crate::kprintln!("      process: ready (create_process_w)");
    // crate::kprintln!("      thread:  ready (create_thread/sleep)");
    // crate::kprintln!("      console: ready (write_console_w/alloc_console)");
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
