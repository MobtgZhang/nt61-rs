//! find.exe — text search (user-mode side)
//!
//! Phase 5 task 5.3. `find.exe` searches for a literal text
//! string in one or more files, printing every line that
//! contains a match (or, with `/V`, every line that does NOT).
//!
//! The kernel-side implementation lives in
//! `crate::libs::kernel32::file` (line-buffer read) and
//! `crate::servers` (search driver). This file is the
//! user-mode wrapper that prints matches with the right
//! `file(line): line` formatting.

#![allow(dead_code, non_snake_case)]

/// User-mode entry point for `find.exe`.
pub fn find_main(_argc: i32, _argv: *const *const u8) -> i32 {
    // TODO: parse /V, /C, /I, /N switches; for each input file
    // open it with kernel32::CreateFileW, read it line by line,
    // and print lines that match.
    0
}
