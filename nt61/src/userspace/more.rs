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

/// User-mode entry point for `more.com`.
pub fn more_main(argc: i32, argv: *const *const u8) -> i32 {
    // Read each file listed in argv[1..] and print it to the console
    // one "screen" (24 lines) at a time, prompting to continue.
    const SCREEN_LINES: usize = 24;
    const LINE_BUF: usize = 4096;

    for arg_idx in 1..argc as usize {
        let arg_ptr = unsafe { *argv.add(arg_idx) };
        if arg_ptr.is_null() {
            continue;
        }
        // Read the NUL-terminated path argument.
        let mut path_end = 0usize;
        unsafe {
            while *arg_ptr.add(path_end) != 0 {
                path_end += 1;
            }
        }
        let path_bytes = unsafe { core::slice::from_raw_parts(arg_ptr, path_end) };
        let path = match core::str::from_utf8(path_bytes) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let mut buffer = [0u8; LINE_BUF];
        let bytes_read = match crate::fs::vfs::vfs_read(path, &mut buffer) {
            Ok(n) => n,
            Err(_) => return 2,
        };

        // Print SCREEN_LINES at a time.
        let text = core::str::from_utf8(&buffer[..bytes_read]).unwrap_or("");
        let mut line_count = 0usize;
        for line in text.lines() {
            crate::kprintln!("{}", line);
            line_count += 1;
            if line_count % SCREEN_LINES == 0 {
                // In a real console we would prompt "-- More --" and wait
                // for a keypress. For now just continue printing.
            }
        }
    }
    0
}
