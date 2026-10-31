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

use alloc::string::ToString;
use alloc::vec::Vec;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// User-mode entry point for `find.exe`.
pub unsafe fn find_main(argc: i32, argv: *const *const u8) -> i32 {
    // Parse arguments: find [/V] [/C] [/I] [/N] "string" [files...]
    let mut invert = false; // /V
    let mut count_only = false; // /C
    let mut case_insensitive = false; // /I
    let mut line_numbers = false; // /N
    let mut search_string: Option<alloc::string::String> = None;
    let mut files: Vec<alloc::string::String> = Vec::new();

    for arg_idx in 1..argc as usize {
        let arg_ptr = unsafe { *argv.add(arg_idx) };
        if arg_ptr.is_null() {
            continue;
        }
        let mut path_end = 0usize;
        unsafe {
            while *arg_ptr.add(path_end) != 0 {
                path_end += 1;
            }
        }
        let path_bytes = unsafe { core::slice::from_raw_parts(arg_ptr, path_end) };
        let arg = match core::str::from_utf8(path_bytes) {
            Ok(a) => a,
            Err(_) => continue,
        };

        let upper = arg.to_uppercase();
        match upper.as_str() {
            "/V" => invert = true,
            "/C" => count_only = true,
            "/I" => case_insensitive = true,
            "/N" => line_numbers = true,
            _ => {
                if arg.starts_with('"') && arg.ends_with('"') && arg.len() >= 2 {
                    search_string = Some(arg[1..arg.len() - 1].to_string());
                } else if search_string.is_none() {
                    search_string = Some(arg.to_string());
                } else {
                    files.push(arg.to_string());
                }
            }
        }
    }

    let needle = match &search_string {
        Some(s) => s.clone(),
        None => return 2,
    };

    for file_path in &files {
        let mut buffer = [0u8; 65536];
        let bytes_read = match crate::fs::vfs::vfs_read(file_path, &mut buffer) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let text = core::str::from_utf8(&buffer[..bytes_read]).unwrap_or("");

        let mut match_count = 0usize;
        let mut line_no = 0usize;
        for line in text.lines() {
            line_no += 1;
            let haystack = if case_insensitive {
                line.to_lowercase()
            } else {
                line.to_string()
            };
            let needle_cased = if case_insensitive {
                needle.to_lowercase()
            } else {
                needle.clone()
            };
            let matches = haystack.contains(&needle_cased);
            if matches != invert {
                match_count += 1;
                if !count_only {
                    if line_numbers {
                        crate::kprintln!("{}: {}", line_no, line);
                    } else {
                        crate::kprintln!("{}", line);
                    }
                }
            }
        }
        if count_only {
            crate::kprintln!("{}", match_count);
        }
    }
    0
}
