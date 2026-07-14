//! Pre-built user-mode subsystem stubs (cmd, lsm, winlogon, userinit).
//!
//! These byte arrays are produced by `nt61/tools/cmd-stub-gen/all_stubs.py`
//! and baked into the build_tool via `include!`. The generator imports
//! the cmd interpreter from `cmd_asm.py` so the cmd body stays in sync
//! with the canonical output, then appends three tiny stubs that call
//! into the kernel via SYS_SPAWN_SUBSYSTEM_PROCESS (0x0210).
//!
//! The cmd interpreter is a 4096-byte table-driven command host: it
//! prints a banner, a help message, then enters a read/dispatch loop
//! accepting `exit`, `ver`, `help`, `autoexec`, `echo <text>`, `cls`,
//! `halt`, `reboot`, and `dir`. Unknown commands print
//! `C:\\> Unknown command.`
//!
//! The lsm stub (256 bytes) prints a banner and idles, polling
//! SYS_POLL_KEY so it can echo characters typed at the keyboard.
//! The winlogon stub (256 bytes) prints a banner, then issues two
//! SYS_SPAWN_SUBSYSTEM_PROCESS calls (csrss.exe + userinit.exe)
//! and idles. The userinit stub (256 bytes) prints a banner, issues
//! a single SYS_SPAWN_SUBSYSTEM_PROCESS call for cmd.exe, and idles.
//!
//! All three stubs use a Microsoft x64-style syscall ABI: the
//! syscall number goes in `rax`, and the single user-pointer
//! argument goes in `rdx` (the kernel dispatcher reads it as arg1).
//!
//! Each stub uses a distinct image base — see build.rs for the table.

include!("boot_stubs.rs");
