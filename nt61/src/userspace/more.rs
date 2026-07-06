//! more.com — paginator (user-mode side)
//!
//! Phase 5 task 5.2. `more.com` reads from stdin (or a list of
//! files) and writes to the console a screen at a time, prompting
//! the user to press a key between pages.
//!
//! This is currently a thin wrapper around the kernel-side
//! console paging implementation that lives in
//! `crate::libs::kernel32::console` / `crate::servers`. Phase 5
//! will replace it with a real user-mode paged reader once the
//! console API is fully wired up.

#![allow(dead_code, non_snake_case)]

/// User-mode entry point for `more.com`.
pub fn more_main(_argc: i32, _argv: *const *const u8) -> i32 {
    // TODO: stream stdin (or argv[1..]) to the console a screen
    // at a time, prompting for any-key to continue.
    0
}
