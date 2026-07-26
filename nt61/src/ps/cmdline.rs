//! Command-line parsing for NT 6.1 CreateProcessW.
//!
//! Windows command-lines are not a simple split-on-space: the
//! first argument (the application name) is taken verbatim if
//! the caller passes it via `lpApplicationName`, but the rest
//! must obey these rules:
//!
//!   - A double-quoted run keeps its trailing spaces (NT6.1
//!     breaks here from POSIX).
//!   - `\\\"` is an escaped double-quote inside a quoted run;
//!     the backslashes before the quote collapse to half their
//!     count, and the quote itself becomes a literal.
//!   - Backslashes preceding a quote are special: 2n backslashes
//!     followed by a quote collapse to n backslashes and toggle
//!     the quoted run, while 2n+1 backslashes collapse to n
//!     backslashes and the quote is literal.
//!   - Outside any quoted run, whitespace separates arguments.
//!   - argv[0] is the executable name; argv[1..] are the parsed
//!     arguments.
//!
//! This is a self-contained, no-`alloc` tokenizer so the kernel
//! can call it from any context without pulling in the global
//! allocator.

/// Tokenize one argument starting at `i` and ending at (but not
/// including) `end`. Writes the de-quoted, de-escaped bytes into
/// `out[out_offset..]`. Returns the new `i` and writes the bytes
/// count. Returns `0` as the bytes-written count if the argument
/// is empty.
fn tokenize_one(cmdline: &[u8], mut i: usize, end: usize, out: &mut [u8], out_offset: usize) -> (usize, usize) {
    let mut pos = out_offset;
    while i < end {
        let c = cmdline[i];
        if c == b'\\' {
            let mut n = 0usize;
            while i < end && cmdline[i] == b'\\' {
                n += 1;
                i += 1;
            }
            if i < end && cmdline[i] == b'"' {
                let keep = n / 2;
                for _ in 0..keep {
                    if pos < out.len() { out[pos] = b'\\'; pos += 1; }
                }
                if (n % 2) == 1 {
                    if pos < out.len() { out[pos] = b'"'; pos += 1; }
                    i += 1;
                }
                continue;
            }
            for _ in 0..n {
                if pos < out.len() { out[pos] = b'\\'; pos += 1; }
            }
            continue;
        }
        if c == b'"' {
            i += 1;
            continue;
        }
        if pos < out.len() { out[pos] = c; pos += 1; }
        i += 1;
    }
    (i, pos - out_offset)
}

/// Parse `cmdline` into at most `max` arguments. Each output
/// element is `(offset, length)` into `out_buffer`. The caller
/// must provide a scratch buffer large enough to hold the
/// longest argument; 1 KiB is more than enough for a normal
/// command line.
pub fn parse_command_line(cmdline: &[u8], out: &mut [(usize, usize)], out_buffer: &mut [u8], max: usize) -> usize {
    let mut count = 0usize;
    let mut buf_cursor = 0usize;
    let mut i = 0usize;
    let n = cmdline.len();
    while i < n && (cmdline[i] == b' ' || cmdline[i] == b'\t') {
        i += 1;
    }
    while i < n && count < max {
        while i < n && (cmdline[i] == b' ' || cmdline[i] == b'\t') {
            i += 1;
        }
        if i >= n { break; }
        let start = i;
        let mut in_quotes = false;
        let mut end = i;
        while end < n {
            let c = cmdline[end];
            if c == b'"' {
                in_quotes = !in_quotes;
                end += 1;
                continue;
            }
            if !in_quotes && (c == b' ' || c == b'\t') {
                break;
            }
            end += 1;
        }
        let (new_i, written) = tokenize_one(cmdline, start, end, out_buffer, buf_cursor);
        let _ = new_i;
        if count < max {
            out[count] = (buf_cursor, written);
            buf_cursor += written;
            count += 1;
        }
        i = end;
    }
    count
}

/// Build a `CreateProcessW`-style command line from a program
/// name and argv. Quotes the program name and each argument if it
/// contains whitespace, then joins with spaces.
pub fn build_command_line(program: &[u8], argv: &[&[u8]], out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    let mut wrote_any = false;
    let mut pieces: [&[u8]; 64] = [&[]; 64];
    let piece_count = if argv.is_empty() {
        pieces[0] = program;
        1
    } else {
        pieces[0] = program;
        for (i, a) in argv.iter().enumerate().take(63) {
            pieces[i + 1] = a;
        }
        argv.len() + 1
    };
    for p in 0..piece_count {
        let arg = pieces[p];
        let needs_quote = arg.iter().any(|c| *c == b' ' || *c == b'\t' || *c == b'"');
        if wrote_any {
            if pos < out.len() { out[pos] = b' '; pos += 1; }
        }
        if needs_quote {
            if pos < out.len() { out[pos] = b'"'; pos += 1; }
            for c in arg {
                if *c == b'"' {
                    if pos < out.len() { out[pos] = b'\\'; pos += 1; }
                }
                if pos < out.len() { out[pos] = *c; pos += 1; }
            }
            if pos < out.len() { out[pos] = b'"'; pos += 1; }
        } else {
            for c in arg {
                if pos < out.len() { out[pos] = *c; pos += 1; }
            }
        }
        wrote_any = true;
    }
    pos
}
