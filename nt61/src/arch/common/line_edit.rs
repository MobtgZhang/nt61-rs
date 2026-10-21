//! Shared Ring-3 line editor for the `cmd.exe` host ABI.
//!
//! Every architecture's `SYS_READ_LINE` handler funnels through
//! `read_line()` here so the user-mode shell behaves identically
//! on x86_64, aarch64, riscv64 and loongarch64:
//!
//! - printable ASCII is echoed and stored, backspace erases;
//! - `\r` / `\n` terminates the line (echoed as `\r\n`);
//! - arrow keys (`ESC [ A` / `ESC [ B`) recall command history;
//! - `ESC [ C` / `ESC [ D` are swallowed (no mid-line cursor);
//! - TAB completes the current word via `servers::cmd`;
//! - Ctrl+C abandons the current line.
//!
//! The editor is POLLED — it never registers an interrupt handler
//! and works with interrupts masked or unmasked.

use crate::hal::text_console;
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

const LINE_CAP: usize = 256;
const HISTORY_MAX: usize = 16;

static HISTORY: Spinlock<Vec<[u8; LINE_CAP]>> = Spinlock::new(Vec::new());

/// Push one completed line into the shared history. Lines that
/// duplicate the most recent entry are ignored.
pub fn push_history(line: &[u8]) {
    if line.is_empty() {
        return;
    }
    let mut entry = [0u8; LINE_CAP];
    let len = line.len().min(LINE_CAP - 1);
    entry[..len].copy_from_slice(&line[..len]);

    let mut history = HISTORY.lock();
    if let Some(last) = history.last() {
        if *last == entry {
            return;
        }
    }
    history.push(entry);
    while history.len() > HISTORY_MAX {
        history.remove(0);
    }
}

/// Current history length (used by tests).
#[cfg(test)]
pub fn history_len() -> usize {
    HISTORY.lock().len()
}

/// Erase `count` characters from the console (backspace sequence).
fn erase_chars(count: usize) {
    for _ in 0..count {
        text_console::put_byte(0x08);
        text_console::put_byte(b' ');
        text_console::put_byte(0x08);
    }
}

/// Replace the on-screen line with `entry` after erasing `pos`
/// characters. Returns the new length.
fn redraw_line(buf: &mut [u8], pos: usize, entry: &[u8]) -> usize {
    erase_chars(pos);
    let len = entry.iter().position(|&b| b == 0).unwrap_or(entry.len());
    let len = len.min(buf.len() - 1);
    buf[..len].copy_from_slice(&entry[..len]);
    for &byte in &buf[..len] {
        text_console::put_byte(byte);
    }
    len
}

/// Read one editable line from the unified keyboard backend.
///
/// Returns the number of bytes stored in `buffer` (excluding the
/// NUL terminator that is always written), or `None` on a bad
/// caller buffer.
pub fn read_line(buffer: &mut [u8], length: usize) -> usize {
    if buffer.is_empty() || length < 2 {
        return 0;
    }
    let cap = length.min(buffer.len()).min(LINE_CAP);
    let mut buf = [0u8; LINE_CAP];
    let mut pos: usize = 0;
    let mut escape: u8 = 0;
    let mut history_index: usize = 0;
    let history_len = HISTORY.lock().len();

    loop {
        crate::hal::keyboard_input::poll();
        let Some(byte) = crate::hal::keyboard_input::try_read_byte() else {
            core::hint::spin_loop();
            continue;
        };

        match byte {
            // Ctrl+C — abandon the line.
            0x03 => {
                text_console::put_byte(b'^');
                text_console::put_byte(b'C');
                text_console::put_byte(b'\r');
                text_console::put_byte(b'\n');
                buffer[0] = 0;
                return 0;
            }
            // Enter.
            b'\r' | b'\n' => {
                text_console::put_byte(b'\r');
                text_console::put_byte(b'\n');
                push_history(&buf[..pos]);
                buf[pos] = 0;
                buffer[..pos].copy_from_slice(&buf[..pos]);
                buffer[pos] = 0;
                return pos;
            }
            // Backspace / Delete.
            0x08 | 0x7F => {
                if pos > 0 {
                    pos -= 1;
                    buf[pos] = 0;
                    erase_chars(1);
                }
            }
            // TAB — command completion for the trailing word.
            b'\t' => {
                let input = core::str::from_utf8(&buf[..pos]).unwrap_or("");
                if let Some(completion) = crate::servers::cmd::find_completion(input) {
                    let word_start = buf[..pos]
                        .iter()
                        .rposition(|&byte| byte == b' ')
                        .map_or(0, |index| index + 1);
                    let word_len = pos - word_start;
                    let completion_bytes = completion.as_bytes();
                    let new_len = word_start + completion_bytes.len();
                    if new_len < cap {
                        erase_chars(word_len);
                        buf[word_start..new_len].copy_from_slice(completion_bytes);
                        pos = new_len;
                        for &byte in &buf[word_start..pos] {
                            text_console::put_byte(byte);
                        }
                    }
                }
            }
            // ESC [ A — history up.
            b'A' if escape == 2 => {
                escape = 0;
                if history_len > 0 {
                    let next = if history_index == 0 {
                        history_len
                    } else {
                        history_index - 1
                    };
                    if next >= 1 {
                        history_index = next;
                        let entry = *HISTORY
                            .lock()
                            .get(history_index - 1)
                            .unwrap_or(&[0u8; LINE_CAP]);
                        pos = redraw_line(&mut buf, pos, &entry);
                    }
                }
            }
            // ESC [ B — history down.
            b'B' if escape == 2 => {
                escape = 0;
                if history_len > 0 && history_index > 0 {
                    history_index -= 1;
                    if history_index == 0 {
                        erase_chars(pos);
                        buf[..pos].fill(0);
                        pos = 0;
                    } else {
                        let entry = *HISTORY
                            .lock()
                            .get(history_index - 1)
                            .unwrap_or(&[0u8; LINE_CAP]);
                        pos = redraw_line(&mut buf, pos, &entry);
                    }
                }
            }
            // ESC [ C / ESC [ D — left / right: ignored.
            b'C' | b'D' if escape == 2 => {
                escape = 0;
            }
            // Second byte of a three-byte escape sequence.
            b'[' if escape == 1 => {
                escape = 2;
            }
            // Lone ESC — swallow.
            0x1B => {
                escape = 1;
            }
            // Printable ASCII.
            byte if (0x20..=0x7E).contains(&byte) => {
                escape = 0;
                if pos < cap - 1 {
                    buf[pos] = byte;
                    pos += 1;
                    text_console::put_byte(byte);
                }
            }
            _ => {
                escape = 0;
            }
        }
    }
}
