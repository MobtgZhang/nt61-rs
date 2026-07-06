//! Batch File Runner
//
//! Handles batch file (.bat/.cmd) execution for the CMD shell.
//! This module provides utilities for running batch scripts from FAT32.

#![cfg(target_arch = "x86_64")]

/// Trait for outputting text during batch file execution
pub trait Output {
    fn put_str(&mut self, s: &[u8]);
    fn put_byte(&mut self, b: u8);
}

impl Output for () {
    fn put_str(&mut self, _s: &[u8]) {}
    fn put_byte(&mut self, _b: u8) {}
}

/// Try to dispatch a batch file (.bat / .cmd) by reading it from the
/// FAT32 root and feeding each line back through `dispatch_fn`.
/// Returns `true` if the command looked like a batch filename and
/// was handled (whether successfully or with a parse error).
pub fn run_batch_file<O: Output>(cmd: &[u8], output: &mut O, mut dispatch_fn: impl FnMut(&[u8])) -> bool {
    use crate::fs::fat32;
    
    // Take the first whitespace-delimited token.
    let mut end = 0;
    while end < cmd.len() && cmd[end] != b' ' && cmd[end] != b'\t' {
        end += 1;
    }
    let name = &cmd[..end];
    if name.is_empty() {
        return false;
    }
    
    // Check if it ends with .bat or .cmd
    let lower_end = name
        .iter()
        .position(|&b| b == b'\\' || b == b'/')
        .unwrap_or(name.len());
    let tail = &name[lower_end..];
    let tail_lower: [u8; 4] = [
        tail[tail.len().saturating_sub(4)].to_ascii_lowercase(),
        tail[tail.len().saturating_sub(3)].to_ascii_lowercase(),
        tail[tail.len().saturating_sub(2)].to_ascii_lowercase(),
        tail[tail.len().saturating_sub(1)].to_ascii_lowercase(),
    ];
    let ends_in_bat = tail.len() >= 4 && &tail_lower == b".bat";
    let ends_in_cmd = tail.len() >= 4 && &tail_lower == b".cmd";
    if !ends_in_bat && !ends_in_cmd {
        return false;
    }
    
    if !fat32::is_mounted() {
        output.put_str(b"[BAT] FAT32 not mounted\r\n");
        return true;
    }
    let Some(fs) = fat32::get_mounted_fs() else {
        return true;
    };
    
    // Dispatch order:
    //   1. The full Windows-style path is tried first via
    //      `find_file_at_path`. This makes the canonical
    //      `C:\system\tests\autoexec.bat` location findable
    //      even though `autoexec.bat` lives in a subdirectory.
    //   2. As a last resort the FAT32 root is consulted — this
    //      keeps the legacy `/tests/autoexec.bat` and bare
    //      `autoexec.bat` roots visible to operators who don't
    //      want to type a full path.
    let mut entry = None;
    let name_str = core::str::from_utf8(name).unwrap_or("");
    let upper = name_str.to_ascii_uppercase();
    if upper.contains('\\') || upper.contains('/') {
        entry = fat32::find_file_at_path(fs, name_str);
    }
    if entry.is_none() {
        let short_name = fat32::name_to_83(name_str);
        entry = fat32::find_file_in_root(fs, &short_name);
    }
    let entry = match entry {
        Some(e) => e,
        None => {
            output.put_str(b"File not found: ");
            output.put_str(name);
            output.put_str(b"\r\n");
            return true;
        }
    };
    
    let cluster = entry.first_cluster();
    let size = entry.file_size() as usize;
    if size == 0 {
        return true;
    }
    
    let mut buf = [0u8; 8192];
    let read_size = core::cmp::min(size, buf.len());
    let n = fat32::read_file(fs, cluster, read_size as u32, &mut buf).unwrap_or(0);
    
    // Process the batch file line by line
    let mut line = [0u8; 128];
    let mut line_len = 0usize;
    let mut i = 0usize;
    while i < n {
        let b = buf[i];
        if b == b'\n' || b == b'\r' {
            if line_len > 0 {
                // Strip a leading '@' (silent echo)
                let exec_cmd = if line[0] == b'@' {
                    &line[1..line_len]
                } else {
                    &line[..line_len]
                };
                dispatch_fn(exec_cmd);
                line_len = 0;
            }
        } else if line_len < line.len() {
            line[line_len] = b;
            line_len += 1;
        }
        i += 1;
    }
    if line_len > 0 {
        dispatch_fn(&line[..line_len]);
    }
    true
}

/// Simple batch file executor that runs commands via a callback.
pub struct BatchExecutor<F> {
    dispatch_fn: F,
}

impl<F> BatchExecutor<F> 
where
    F: FnMut(&[u8]),
{
    pub fn new(dispatch_fn: F) -> Self {
        Self { dispatch_fn }
    }
    
    pub fn run<O: Output>(&mut self, _output: &mut O, filename: &[u8]) -> bool {
        run_batch_file(filename, _output, |cmd| (self.dispatch_fn)(cmd))
    }
}
