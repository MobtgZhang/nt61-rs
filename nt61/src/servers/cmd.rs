//! Interactive CMD Shell for Safe Mode
//!
//! Implements a minimal Windows-like command interpreter for Safe Mode
//! that works on **every** architecture the kernel supports:
//!
//! - **x86_64**: mirrors typed characters and command output to both
//!   the serial UART and the VGA text console (0xB8000). The
//!   user-mode `cmd.exe` is the primary shell; this kernel-side
//!   shell is the `SafeModeDebug` `kd>` fallback.
//! - **aarch64 / riscv64 / loongarch64**: the user-mode `cmd.exe`
//!   binary is not available, so this shell is the **only** command
//!   interpreter in the kernel. It writes everything to the serial
//!   UART, and on architectures that do have a text buffer it also
//!   keeps a 64-line `LOG_RING_LINES` ring that back-scrolling
//!   commands can dump to the user via `LOGS`.
//!
//! Uses the real FAT32 filesystem and the unified `hal::keyboard_input`
//! backend (PS/2 8042 on x86_64, UART FIFO on the others). Console
//! readers park on the keyboard input event and are woken by the
//! IRQ producers; the polled-IO discipline only survives as the
//! fallback for the masked-IRQ Safe Mode boot path.

use crate::fs;
use crate::fs::fat32;
use crate::fs::ntfs;
use crate::hal::text_console;
use crate::ke::sync::Spinlock;
use crate::libs::cmd::bat_parser::{BatError, BatchExecutor, BatchParser};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Mirror of the NT 6.1 kernel version string published from
/// `lib.rs` (`crate::KERNEL_VERSION`). Duplicated as a `&str`
/// here so this module does not have to take a dependency on
/// the top-level `KERNEL_VERSION` constant for the SafeModeCmd
/// banner — keeping the constant local also keeps the banner
/// behaviour identical if someone rebuilds the kernel with a
/// version override.
const KERNEL_VERSION: &str = "6.1.7601";

/// Command buffer size
pub const CMD_BUFFER_SIZE: usize = 256;

/// Maximum entries to display in DIR
const MAX_DIR_ENTRIES: usize = 64;

/// Maximum command history entries
const MAX_HISTORY: usize = 16;

/// Command history storage
static CMD_HISTORY: Spinlock<Vec<[u8; CMD_BUFFER_SIZE]>> = Spinlock::new(Vec::new());

/// Bounded output buffer used by remote command submission (SSH).
/// Command output continues to be mirrored to the local console while
/// it is captured, so enabling capture never hides output.
static OUTPUT_CAPTURE: Spinlock<Option<Vec<u8>>> = Spinlock::new(None);

const OUTPUT_CAPTURE_LIMIT: usize = 64 * 1024;

/// Start capturing command output. Discards any previous capture.
pub fn begin_output_capture() {
    *OUTPUT_CAPTURE.lock() = Some(Vec::new());
}

/// Stop capturing and return the captured bytes.
pub fn take_output_capture() -> Option<Vec<u8>> {
    OUTPUT_CAPTURE.lock().take()
}

/// Append one byte to the active SSH output capture (if any). Used by
/// the cmd_extensions module whose output helper bypasses dual_print.
pub fn capture_output_byte(byte: u8) {
    if let Some(capture) = OUTPUT_CAPTURE.lock().as_mut() {
        if capture.len() < OUTPUT_CAPTURE_LIMIT {
            capture.push(byte);
        }
    }
}

/// Working directory shared by Ring-3 command submissions and the
/// kernel fallback shell. A single shell instance is expected during
/// bring-up, so one lock-protected instance is sufficient.
static RING3_CWD: Spinlock<Cwd> = Spinlock::new(Cwd {
    path: [0; 128],
    len: 0,
});

/// Boot mode for the shell.
///
/// Two surfaces are supported:
///
/// * `SafeModeCmd` — NT 6.1's `Safe Mode with Command Prompt`.
///   On x86_64 the user-mode `cmd.exe` stub at
///   `C:\Windows\system32\cmd.exe` is launched as a real Ring 3
///   process; the kernel-side `run_shell` is the static-IDLE
///   fallback used while the user-mode binary is being built,
///   when the cmd.exe image cannot be constructed, or on
///   architectures where the user-mode binary is not available.
///   The kernel-side `SafeModeCmd` shell uses a `C:\>` prompt so
///   the operator sees a familiar NT 6.1 alternate-shell
///   surface.
///
/// * `SafeModeDebug` — the kernel debugger `kd>` prompt, used
///   when `BOOT_MODE == SafeModeDebug`. This path exists on
///   every architecture and only differs from `SafeModeCmd` in
///   the prompt prefix (so operators can tell which surface
///   they're typing into without losing the rest of the
///   behaviour).
pub enum ShellMode {
    Ring3,
    SafeModeCmd,
    SafeModeDebug,
}

impl ShellMode {
    /// Prompt string printed at the head of each command line.
    /// The user-mode CMD shell prints its own `C:\>` from user
    /// space and never touches this method; the kernel-side
    /// shell uses the prompt defined here.
    pub fn prompt(&self) -> &'static [u8] {
        match self {
            ShellMode::Ring3 => b">",
            // Match the canonical NT 6.1 Safe-Mode-CMD
            // alternate shell prompt (no newline, no path
            // component — the shell prepends the cwd before
            // this).
            ShellMode::SafeModeCmd => b">",
            // Match the kernel-debugger `kd>` convention.
            ShellMode::SafeModeDebug => b"kd>",
        }
    }
}

/// Current working directory state
struct Cwd {
    path: [u8; 128],
    len: usize,
}

/// Print the Ring-3 shell prompt from the kernel's current-directory
/// state. User mode owns no filesystem state, so this prevents the
/// classic `CD` desynchronisation between a local prompt string and
/// the kernel command backends.
pub fn print_ring3_prompt() {
    let cwd = RING3_CWD.lock();
    if cwd.len == 0 {
        drop(cwd);
        RING3_CWD.lock().set_str(b"C:\\");
        serial_print(b"C:\\>");
    } else {
        serial_print(cwd.as_cstr());
        serial_print(b">");
    }
}

pub fn diagnostic_command_failure(reason: &[u8]) {
    crate::hal::serial::write_string_always("[CMD] command dispatch failed: ");
    crate::hal::serial::write_string_always(core::str::from_utf8(reason).unwrap_or("binary"));
    crate::hal::serial::write_string_always("\r\n");
}

impl Cwd {
    fn new() -> Self {
        let mut c = Self {
            path: [0u8; 128],
            len: 0,
        };
        c.set_str(b"C:\\");
        c
    }

    fn set_str(&mut self, s: &[u8]) {
        self.len = 0;
        for &c in s.iter().take(127) {
            self.path[self.len] = c;
            self.len += 1;
        }
        self.path[self.len] = 0;
    }

    fn as_cstr(&self) -> &[u8] {
        &self.path[..self.len]
    }

    fn pop(&mut self) {
        // Remove last path component
        while self.len > 0 && self.path[self.len - 1] != b'\\' {
            self.len -= 1;
        }
        // Keep the trailing backslash if we're not at root
        if self.len > 3 {
            self.len -= 1; // Remove trailing backslash
        }
        self.path[self.len] = 0;
    }
}

/// Run the kernel-side interactive shell.
///
/// Dispatches by `mode`:
///   * `SafeModeDebug` → kdcom-style debug log banner followed
///     by the `kd>` prompt.
///   * `SafeModeCmd`   → the Safe-Mode-CMD alternate shell
///     banner ("Microsoft Windows [Version 6.1.7601]") and the
///     `C:\>` prompt. On architectures without a user-mode
///     cmd.exe this IS the user-facing shell; on x86_64 it is
///     the fallback when `cmd.exe` cannot be launched.
///
/// Both modes share the same line-editing, history, FAT32
/// command lookup, and tab-completion infrastructure. Input
/// follows the console wait/notification model of NT 6.1: the
/// reader parks on the keyboard input event and the IRQ
/// producers signal it, with a bounded timeout re-polling the
/// polled-only serial fallback.
pub fn run_shell(mode: ShellMode) -> ! {
    let prompt_bytes = mode.prompt();
    let mut cwd = Cwd::new();

    // Print the boot-mode banner so the operator can tell which
    // shell they have dropped into without consulting the
    // boot-info line.
    match mode {
        ShellMode::SafeModeDebug => {
            serial_print(b"\r\n[KDBG] Debug boot \xe2\x80\x94 kdcom serial logger enabled\r\n");
            serial_print(b"[KDBG] Trace markers follow:\r\n");
            for i in 0..16u32 {
                serial_print(b"[kdbg] trace_seq=");
                serial_print_u32(i);
                serial_print(b"\r\n");
            }
            serial_print(b"[KDBG] end of debug stream\r\n");
        }
        ShellMode::SafeModeCmd => {
            serial_print(b"\r\nMicrosoft Windows [Version ");
            serial_print(KERNEL_VERSION.as_bytes());
            serial_print(b"]\r\n");
            serial_print(b"(C) Copyright (c) 2009 Microsoft Corporation. ");
            serial_print(b"All rights reserved.\r\n\r\n");
            serial_print(b"Safe Mode with Command Prompt support loaded via the ");
            serial_print(b"kernel-side shell on this architecture.\r\n\r\n");
        }
        ShellMode::Ring3 => {
            serial_print(b"Microsoft Windows [Version ");
            serial_print(KERNEL_VERSION.as_bytes());
            serial_print(b"]\r\n(C) Copyright (c) 2009 Microsoft Corporation. ");
            serial_print(b"All rights reserved.\r\n\r\n");
        }
    }

    // Main command loop
    loop {
        // The Windows CMD prompt includes the current directory.
        // `prompt_bytes` is now just the separator (`>`), so this
        // produces `C:\>` at the root and `C:\Windows>` elsewhere.
        serial_print(cwd.as_cstr());
        serial_print(prompt_bytes);
        serial_print(b" ");

        // read and process command
        let cmd = read_command();

        if !cmd.is_empty() {
            let exit = process_command(&cmd, &mode, &mut cwd);
            if exit {
                serial_print(b"System is shutting down...\r\n");
                loop {
                    crate::arch::halt();
                }
            }
        }
    }
}

/// Tiny decimal-printer used by the kdcom-style debug banner so
/// `run_shell` doesn't need an external formatter dependency.
fn serial_print_u32(mut n: u32) {
    if n == 0 {
        dual_put_byte(b'0');
        return;
    }
    let mut tmp = [0u8; 12];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        dual_put_byte(tmp[i]);
    }
}

/// Park the shell thread until console input arrives.
///
/// NT 6.1 console readers wait on the console input queue event and
/// are released when an input record is queued. The same model
/// applies here: the keyboard / UART IRQ producers signal the
/// hal::keyboard_input event, so the wait returns as soon as a
/// keystroke is decoded. The bounded timeout re-polls the serial
/// fallback, which has no RX interrupt on every architecture. In
/// masked-IRQ Safe Mode no wake source exists, so the loop keeps
/// the polled-IO discipline and relaxes the CPU between polls.
const CMD_INPUT_WAIT_MS: u32 = 100;

fn wait_console_input() {
    if crate::arch::interrupts_enabled() {
        crate::hal::keyboard_input::clear_input_event();
        // Close the reset/produce race: a keystroke between the
        // drained check in the caller and the reset re-signals the
        // event, so this re-check keeps the wait lossless.
        if crate::hal::keyboard_input::try_read_byte().is_none() {
            crate::hal::keyboard_input::wait_input_event(CMD_INPUT_WAIT_MS);
        }
    } else {
        crate::arch::cpu_relax();
    }
}

/// read a command from serial input with full line editing support
/// Supports: backspace, arrow keys (history), TAB completion, Ctrl+C
///
/// Input source precedence:
///   1. On x86_64 the PS/2 (8042) controller and USB HID driver
///      feed the same shared keyboard ring buffer as the IRQ
///      path or, in the SafeMode polling path, the polling
///      variant. `read_command` drains both with `IF=0`.
///   2. The architecture's serial UART is the **primary** input
///      on aarch64 / riscv64 / loongarch64 (where the platform
///      has no PS/2 controller) and a **fallback** on x86_64
///      (used by headless debug setups that prefer the serial
///      console over QEMU's VGA window).
///   3. The keyboard_input abstraction (`hal::keyboard_input`)
///      wraps both paths so the same byte stream reaches the
///      line editor regardless of the architecture.
fn read_command() -> [u8; CMD_BUFFER_SIZE] {
    let mut buf = [0u8; CMD_BUFFER_SIZE];
    let mut pos: usize = 0;
    let mut escape_seq: u8 = 0; // 0=none, 1=ESC received, 2='[' received
    let mut history_index: usize = 0; // 0 = not in history mode
    let history_len;

    // Get history length once (lock only for reading length)
    {
        let history = CMD_HISTORY.lock();
        history_len = history.len();
    }

    loop {
        // Drain USB HID and PS/2 into the HAL's unified input buffer.
        // Non-PS/2 platforms implement this as a no-op.
        crate::hal::keyboard_input::poll();

        // Try the platform's primary input first. On x86_64 this
        // is the shared PS/2 + USB HID ring buffer; on the other
        // architectures `keyboard_input::try_read_byte` resolves
        // to the UART-FIFO poll path. We deliberately do **not**
        // also poll the raw serial driver from here — the
        // `keyboard_input` facade already wraps it on every
        // non-x86_64 target, and reading it twice would double-
        // consume bytes.
        let c = crate::hal::keyboard_input::try_read_byte();
        if let Some(c) = c {
            match c {
                // Ctrl+C - Interrupt
                0x03 => {
                    serial_print(b"^C\r\n");
                    return [0u8; CMD_BUFFER_SIZE];
                }
                // Ctrl+S - Pause output (just ignore for now)
                0x13 => {
                    // Ignore pause
                }
                // Enter key
                b'\r' | b'\n' => {
                    serial_print(b"\r\n");
                    break;
                }
                // Backspace or Delete
                8 | 0x7F => {
                    if pos > 0 {
                        pos -= 1;
                        buf[pos] = 0;
                        serial_print(b"\x08 \x08");
                    }
                }
                // TAB - Command completion
                0x09 => {
                    // Get partial input
                    let input = core::str::from_utf8(&buf[..pos]).unwrap_or("");

                    if let Some(completion) = find_completion(input) {
                        // Replace only the word being completed so the
                        // command name and any preceding arguments survive.
                        let word_start = buf[..pos]
                            .iter()
                            .rposition(|&byte| byte == b' ')
                            .map_or(0, |index| index + 1);
                        let word_len = pos - word_start;
                        let completion_bytes = completion.as_bytes();

                        if completion_bytes.len() > word_len
                            || completion_bytes[..word_len.min(completion_bytes.len())]
                                != buf[word_start..pos]
                        {
                            for _ in 0..word_len {
                                serial_print(b"\x08 \x08");
                            }
                            let new_len = word_start + completion_bytes.len();
                            if new_len < CMD_BUFFER_SIZE {
                                buf[word_start..new_len].copy_from_slice(completion_bytes);
                                pos = new_len;
                                for &byte in completion_bytes {
                                    dual_put_byte(byte);
                                }
                            }
                        }
                    }
                }
                // Escape sequence start
                0x1B => {
                    escape_seq = 1;
                }
                // Escape sequence '[', part of arrow keys
                0x5B if escape_seq == 1 => {
                    escape_seq = 2;
                }
                // Arrow keys (after ESC[)
                0x41 if escape_seq == 2 => {
                    // Up arrow
                    escape_seq = 0;
                    if history_len > 0 {
                        // Clear current line
                        for _ in 0..pos {
                            serial_print(b"\x08 \x08");
                        }

                        // Move to previous history entry
                        if history_index == 0 {
                            history_index = history_len;
                        } else if history_index > 1 {
                            history_index -= 1;
                        }

                        // Get history entry
                        let history = CMD_HISTORY.lock();
                        if history_index > 0 && history_index <= history.len() {
                            let entry = &history[history_index - 1];
                            let len = entry
                                .iter()
                                .position(|&x| x == 0)
                                .unwrap_or(CMD_BUFFER_SIZE);
                            buf[..len].copy_from_slice(&entry[..len]);
                            pos = len;

                            // Print the command
                            serial_print(&buf[..pos]);
                        }
                    }
                }
                0x42 if escape_seq == 2 => {
                    // Down arrow
                    escape_seq = 0;
                    if history_len > 0 && history_index < history_len {
                        // Clear current line
                        for _ in 0..pos {
                            serial_print(b"\x08 \x08");
                        }

                        // Move to next history entry
                        history_index += 1;

                        if history_index > history_len {
                            // After last entry, show empty line
                            pos = 0;
                        } else {
                            // Get history entry
                            let history = CMD_HISTORY.lock();
                            if history_index > 0 && history_index <= history.len() {
                                let entry = &history[history_index - 1];
                                let len = entry
                                    .iter()
                                    .position(|&x| x == 0)
                                    .unwrap_or(CMD_BUFFER_SIZE);
                                buf[..len].copy_from_slice(&entry[..len]);
                                pos = len;

                                // Print the command
                                serial_print(&buf[..pos]);
                            }
                        }
                    } else if history_index >= history_len {
                        // Already at end, clear line
                        for _ in 0..pos {
                            serial_print(b"\x08 \x08");
                        }
                        pos = 0;
                    }
                }
                0x44 if escape_seq == 2 => {
                    // Left arrow
                    escape_seq = 0;
                    // For now, just ignore left arrow (full cursor movement is complex)
                }
                0x43 if escape_seq == 2 => {
                    // Right arrow
                    escape_seq = 0;
                    // For now, just ignore right arrow
                }
                // Printable ASCII characters
                0x20..=0x7E => {
                    escape_seq = 0;
                    if pos < CMD_BUFFER_SIZE - 1 {
                        buf[pos] = c;
                        pos += 1;
                        dual_put_byte(c);
                    }
                }
                _ => {
                    escape_seq = 0; // Reset escape sequence on unknown char
                }
            }
        } else {
            // No data available: park on the console-input event
            // (or keep the polled-IO loop alive in masked-IRQ
            // Safe Mode) instead of busy-spinning the CPU.
            wait_console_input();
        }
    }

    // Save to history if command is not empty
    let cmd_len = buf.iter().position(|&c| c == 0).unwrap_or(CMD_BUFFER_SIZE);
    if cmd_len > 0 {
        let mut history = CMD_HISTORY.lock();
        // Don't add duplicate of last command
        let is_duplicate = history.len() > 0 && {
            let last = &history[history.len() - 1];
            last[..cmd_len] == buf[..cmd_len]
        };

        if !is_duplicate {
            // Add new command
            history.push(buf);

            // Trim history if too long
            while history.len() > MAX_HISTORY {
                history.remove(0);
            }
        }
    }

    buf
}

/// Find a completion for the given input (TAB completion).
/// Returns the complete replacement word, matching CMD semantics.
pub fn find_completion(input: &str) -> Option<String> {
    // Get the word to complete (after last space)
    let word_to_complete = input.split_whitespace().last().unwrap_or("");
    if word_to_complete.is_empty() {
        return None;
    }

    // Common commands to complete
    let commands = [
        "CD", "CHDIR", "CLS", "COPY", "DATE", "DEL", "DIR", "ECHO", "EXIT", "HELP", "MD", "MKDIR",
        "MOVE", "RD", "RMDIR", "REN", "RENAME", "SET", "TIME", "TYPE", "VER", "VOL", "MOUNTVOL",
        "KDBG", "NTFS", "FAT32",
    ];

    let word_upper = word_to_complete.to_uppercase();
    let mut matches: Vec<&str> = Vec::new();

    // Check commands first
    for cmd in commands.iter() {
        if cmd.starts_with(&word_upper) {
            matches.push(cmd);
        }
    }

    // If no command matches, try directory names (simplified)
    if matches.is_empty() && fat32::is_mounted() {
        // Try to read from filesystem
        if let Some(_fs) = fat32::get_mounted_fs() {
            // For now, return some common directory names
            let dirs = ["EFI", "BOOT", "Windows", "System32", "Config"];
            for dir in dirs.iter() {
                if dir.to_uppercase().starts_with(&word_upper) {
                    matches.push(dir);
                }
            }
        }
    }

    if matches.len() == 1 {
        return Some(matches[0].to_string());
    } else if matches.len() > 1 {
        // Multiple matches - print them and return common prefix
        serial_print(b"\r\n");
        for m in matches.iter() {
            serial_print(m.as_bytes());
            serial_print(b" ");
        }
        serial_print(b"\r\n");

        // Find common prefix
        if !matches.is_empty() {
            let first = matches[0];
            let mut prefix_len = word_to_complete.len();
            for m in matches.iter().skip(1) {
                while prefix_len > 0
                    && !m
                        .to_uppercase()
                        .starts_with(&first[..prefix_len].to_uppercase())
                {
                    prefix_len -= 1;
                }
            }
            if prefix_len > 0 {
                return Some(first[..prefix_len].to_string());
            }
        }
    }

    None
}

/// Process a command, returns true if shell should exit
/// Supports command chaining: && || &
/// Supports output redirection: > >> 2>
fn process_command(cmd: &[u8; CMD_BUFFER_SIZE], mode: &ShellMode, cwd: &mut Cwd) -> bool {
    // Find actual command length
    let cmd_len = cmd.iter().position(|&c| c == 0).unwrap_or(CMD_BUFFER_SIZE);
    if cmd_len == 0 {
        return false;
    }

    let cmd_str = match core::str::from_utf8(&cmd[..cmd_len]) {
        Ok(s) => s.trim(),
        Err(_) => return false,
    };

    if cmd_str.is_empty() {
        return false;
    }

    // Process command chain with redirection
    process_command_chain(cmd_str, mode, cwd)
}

/// Process a command chain with redirection support
fn process_command_chain(cmd_str: &str, mode: &ShellMode, cwd: &mut Cwd) -> bool {
    // First, handle output redirection
    let (cmd_part, redirect_file, append) = parse_redirection(cmd_str);

    // handle command chaining: && || &
    // Split by & (but not && or ||)
    let parts = split_command_chain(cmd_part);

    let mut last_result = false;

    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (operator, cmd_to_run) = parse_chain_operator(part);

        if redirect_file.is_some() {
            begin_output_capture();
        }

        match operator {
            ChainOperator::And => {
                // cmd1 && cmd2 - run cmd2 only if cmd1 succeeds
                if last_result {
                    last_result = execute_single_command(cmd_to_run, mode, cwd);
                }
            }
            ChainOperator::Or => {
                // cmd1 || cmd2 - run cmd2 only if cmd1 fails
                if !last_result {
                    last_result = execute_single_command(cmd_to_run, mode, cwd);
                }
            }
            ChainOperator::None => {
                // Regular command
                last_result = execute_single_command(part, mode, cwd);
            }
        }

        if let Some(path) = redirect_file {
            let output = take_output_capture().unwrap_or_default();
            write_command_output(path, &output, append, cwd);
        }
    }

    last_result
}

fn write_command_output(path: &str, output: &[u8], append: bool, cwd: &Cwd) {
    let Some(fs) = fs::ntfs::get_mounted_fs() else {
        serial_print(b"Output redirection failed: no filesystem mounted.\r\n");
        return;
    };

    let mut content = Vec::new();
    if append {
        let mut path_utf16 = command_path_utf16(path, cwd);
        path_utf16.push(0);
        if let Some(mut handle) = fs::ntfs::open_file(fs, &path_utf16, None) {
            if !handle.is_directory && handle.file_size <= usize::MAX as u64 {
                let mut existing = alloc::vec![0u8; handle.file_size as usize];
                let mut offset = 0usize;
                while offset < existing.len() {
                    match fs::ntfs::read_file(fs, &mut handle, &mut existing[offset..]) {
                        Ok(0) => break,
                        Ok(read) => offset += read,
                        Err(_) => break,
                    }
                }
                content.extend_from_slice(&existing[..offset]);
            }
        }
    }

    content.extend_from_slice(output);

    let mut path_utf16 = command_path_utf16(path, cwd);
    path_utf16.push(0);
    if fs::ntfs::delete_file(fs, &path_utf16).is_err() {
        let mut probe = command_path_utf16(path, cwd);
        probe.push(0);
        if fs::ntfs::open_file(fs, &probe, None).is_some() {
            serial_print(b"Output redirection failed: cannot replace existing file.\r\n");
            return;
        }
    }
    let mut path_utf16 = command_path_utf16(path, cwd);
    path_utf16.push(0);
    if fs::ntfs::create_file(fs, &path_utf16, &content).is_err() {
        serial_print(b"Output redirection failed.\r\n");
    }
}

/// Chain operator types
#[derive(Debug, Clone, Copy)]
enum ChainOperator {
    None,
    And, // &&
    Or,  // ||
}

/// Parse chain operator from command string
fn parse_chain_operator(cmd: &str) -> (ChainOperator, &str) {
    let cmd = cmd.trim();

    // Check for &&
    if let Some(pos) = cmd.find("&&") {
        return (ChainOperator::And, cmd[..pos].trim());
    }

    // Check for ||
    if let Some(pos) = cmd.find("||") {
        return (ChainOperator::Or, cmd[..pos].trim());
    }

    (ChainOperator::None, cmd)
}

/// Split command string by & operators (not && or ||)
fn split_command_chain(cmd: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = cmd.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '&' {
            // Check what follows
            match chars.peek() {
                Some('&') => {
                    // It's && - end current part if non-empty
                    chars.next(); // consume second &
                    if !current.trim().is_empty() {
                        parts.push(current.trim().to_string());
                    }
                    current.clear();
                }
                _ => {
                    // It's single & - treat as separator
                    if !current.trim().is_empty() {
                        parts.push(current.trim().to_string());
                    }
                    current.clear();
                }
            }
        } else {
            current.push(c);
        }
    }

    // Don't forget the last part
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }

    parts
}

/// Parse output redirection from command
/// Returns (command, output_file, append)
fn parse_redirection(cmd: &str) -> (&str, Option<&str>, bool) {
    let cmd_bytes = cmd.as_bytes();

    // Check for >> (append)
    for i in (2..cmd_bytes.len()).rev() {
        if cmd_bytes[i] == b'>' && cmd_bytes[i - 1] == b'>' {
            let before = &cmd[..i - 1].trim();
            let file = cmd[i + 1..].trim();
            return (before, Some(file), true);
        }
    }

    // Check for > (overwrite)
    for i in (1..cmd_bytes.len()).rev() {
        if cmd_bytes[i] == b'>' && cmd_bytes[i - 1] != b'>' {
            let before = &cmd[..i].trim();
            let file = cmd[i + 1..].trim();
            return (before, Some(file), false);
        }
    }

    (cmd, None, false)
}

/// Execute a single command and return success/failure
fn execute_single_command(cmd_str: &str, mode: &ShellMode, cwd: &mut Cwd) -> bool {
    if cmd_str.is_empty() {
        return false;
    }

    // Expand environment variables
    let expanded = expand_env_vars(cmd_str);

    if let Some(echo) = parse_echo_command(&expanded) {
        match echo {
            EchoCommand::EmptyLine => serial_print(b"\r\n"),
            EchoCommand::Status => serial_print(b"ECHO is on.\r\n"),
            EchoCommand::Text(text) => {
                serial_print(text.as_bytes());
                serial_print(b"\r\n");
            }
        }
        return false;
    }

    // Preserve the user-visible spelling of the command name while
    // dispatching through a canonical form so `dir`, `Dir`, and `DIR`
    // select the same implementation.
    let command_name = expanded.split_whitespace().next().unwrap_or("");
    let cmd_name = command_name.to_uppercase();

    if cmd_name.is_empty() {
        return false;
    }

    // Keep the Ring-0 shell small and auditable.  The full Windows 7
    // command surface belongs to the Ring-3 cmd.exe process, not to
    // this maintenance shell.
    if !matches!(mode, ShellMode::Ring3)
        && !matches!(
            cmd_name.as_str(),
            "CD" | "CHDIR"
                | "CLS"
                | "DIR"
                | "ECHO"
                | "EXIT"
                | "HALT"
                | "HELP"
                | "?"
                | "REBOOT"
                | "TYPE"
                | "VER"
        )
    {
        serial_print(b"The command is not supported by the kernel maintenance shell.\r\n");
        return false;
    }

    // Get arguments
    let args = &expanded[cmd_name.len()..].trim();

    match cmd_name.as_str() {
        "CD" | "CHDIR" => cmd_cd(args, cwd),
        "PWD" => {
            serial_print(cwd.as_cstr());
            serial_print(b"\r\n");
        }
        "DIR" | "LS" => cmd_dir(cwd, args),
        "CLS" => {
            crate::hal::text_console::clear();
            crate::drivers::bootvid::vid_clear_black();
            crate::drivers::bootvid::vid_set_cursor_position(0, 0);
        }
        "TYPE" | "CAT" => {
            if args.is_empty() {
                serial_print(b"Syntax: TYPE filename\r\n");
            } else {
                cmd_type(args, cwd);
            }
        }
        "VER" => cmd_ver(),
        "DATE" => cmd_date(args),
        "TIME" => cmd_time(args),
        "HELP" | "?" => cmd_help(),
        "EXIT" => return true,
        "HALT" => cmd_halt(),
        "REBOOT" => cmd_reboot(),
        "MOUNTVOL" => cmd_mountvol(),
        "VOL" => cmd_vol(),
        // File operation commands
        "COPY" => cmd_copy(args, cwd),
        "DEL" | "DELETE" | "ERASE" => cmd_del(args, cwd),
        "MD" | "MKDIR" => cmd_mkdir(args, cwd),
        "RD" | "RMDIR" => cmd_rmdir(args, cwd),
        "MOVE" => cmd_move(args, cwd),
        "REN" | "RENAME" => cmd_rename(args, cwd),
        "SET" => cmd_set(args),
        // NTFS-specific commands
        "NTFS" => cmd_ntfs_info(),
        _ if super::cmd_extensions::is_reference_command(cmd_name.as_str()) => {
            super::cmd_extensions::execute(cmd_name.to_lowercase().as_str(), args, cwd.as_cstr());
        }
        "KDBG" => {
            if matches!(mode, ShellMode::SafeModeDebug) {
                cmd_kdbg(args);
            } else {
                serial_print(b"'KDBG' is not recognized as an internal or external command,\r\n");
            }
        }
        _ => {
            // Not a built-in command — try as a batch file (.bat/.cmd)
            // or a DOS-style executable on the FAT32 volume.
            if try_run_batch_file(cmd_str, cwd) {
                return false;
            }
            serial_print(b"'");
            serial_print(command_name.as_bytes());
            serial_print(b"' is not recognized as an internal or external command,\r\n");
            serial_print(b"operable program or batch file.\r\n");
        }
    }

    false
}

// ============================================================================
// environment Variable Functions
// ============================================================================

/// Expand environment variables in a string (replace %VAR% with value)
fn expand_env_vars(s: &str) -> String {
    let mut result = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            // Look for closing %
            let remaining = &s[i + 1..];
            if let Some(end_pos) = remaining.find('%') {
                let var_name = &remaining[..end_pos];
                let var_value = get_env_var(var_name);
                result.push_str(&var_value);
                i += end_pos + 2; // Skip %var%
                continue;
            }
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let remaining = &s[i + 2..];
            if let Some(end_pos) = remaining.find('}') {
                let var_name = &remaining[..end_pos];
                let var_value = get_env_var(var_name);
                result.push_str(&var_value);
                i += end_pos + 3;
                continue;
            }
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_alphanumeric() {
            let remaining = &s[i + 1..];
            let end_pos = remaining
                .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .unwrap_or(remaining.len());
            if end_pos > 0 {
                let var_name = &remaining[..end_pos];
                let var_value = get_env_var(var_name);
                result.push_str(&var_value);
                i += end_pos + 1;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

/// Get environment variable value by name
fn get_env_var(name: &str) -> String {
    // Check common environment variables
    match name.to_uppercase().as_str() {
        "PATH" => return String::from("C:\\Windows\\System32;C:\\Windows"),
        "PROMPT" => return String::from("$P$G"),
        "OS" => return String::from("Windows_NT"),
        "COMPUTERNAME" => return String::from("NT61"),
        "SYSTEMROOT" => return String::from("C:\\Windows"),
        "WINDIR" => return String::from("C:\\Windows"),
        "HOMEDRIVE" => return String::from("C:"),
        "HOMEPATH" => return String::from("\\Users\\Default"),
        "USERNAME" => return String::from("Administrator"),
        "USERPROFILE" => return String::from("C:\\Users\\Default"),
        "TEMP" | "TMP" => return String::from("C:\\Windows\\Temp"),
        _ => {}
    }

    // Try kernel32 API
    {
        let name_wide: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
        let mut buffer = [0u16; 256];
        let result = unsafe {
            crate::libs::kernel32::env::get_environment_variable_w(
                name_wide.as_ptr(),
                buffer.as_mut_ptr(),
                256,
            )
        };
        if result > 0 && result < 256 {
            let len = result as usize;
            let value = String::from_utf16_lossy(&buffer[..len]);
            return value;
        }
    }

    String::new()
}

// ============================================================================
// Command Implementations
// ============================================================================

/// Convert a shell pathname to a full UTF-16 path while preserving case.
fn command_path_utf16(path: &str, cwd: &Cwd) -> Vec<u16> {
    let path = path.trim().trim_matches('"');
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        path.encode_utf16().collect()
    } else {
        let mut full_path = cwd.as_cstr().to_vec();
        if full_path.last() != Some(&b'\\') {
            full_path.push(b'\\');
        }
        full_path.extend_from_slice(path.as_bytes());
        String::from_utf8(full_path)
            .unwrap_or_default()
            .encode_utf16()
            .collect()
    }
}

/// Resolve `.` and `..` in a Win32-style shell path without changing case.
fn normalize_windows_path(path: &str, cwd: &Cwd) -> Option<Vec<u8>> {
    let trimmed = path.trim_matches('"');
    let is_absolute = trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':';

    let mut prefix = if is_absolute {
        Vec::from(&trimmed.as_bytes()[..2])
    } else {
        let cwd_path = cwd.as_cstr();
        if cwd_path.len() < 2 || cwd_path[1] != b':' {
            return None;
        }
        Vec::from(&cwd_path[..2])
    };
    while prefix.last() == Some(&b'\\') || prefix.last() == Some(&b'/') {
        prefix.pop();
    }

    let cwd_components = if is_absolute {
        &[][..]
    } else {
        &cwd.as_cstr()[2..]
    };
    let mut components = cwd_components
        .split(|&byte| byte == b'\\' || byte == b'/')
        .filter(|component| !component.is_empty())
        .map(|component| component.to_vec())
        .collect::<Vec<_>>();

    let path_body = if is_absolute { &trimmed[2..] } else { trimmed };
    for component in path_body.split(['\\', '/']) {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return None;
                }
            }
            _ => components.push(component.as_bytes().to_vec()),
        }
    }

    if components.is_empty() {
        prefix.push(b'\\');
    } else {
        for component in components {
            prefix.push(b'\\');
            prefix.extend_from_slice(&component);
        }
    }
    Some(prefix)
}

#[cfg(test)]
mod path_resolution_tests {
    use super::{normalize_windows_path, Cwd};

    #[test]
    fn relative_path_is_joined_without_repeating_current_directory() {
        let cwd = Cwd::new();
        assert_eq!(
            normalize_windows_path("NestedParent", &cwd),
            Some(b"C:\\NestedParent".to_vec())
        );
    }

    #[test]
    fn parent_path_is_joined_from_current_directory() {
        let mut cwd = Cwd::new();
        cwd.set_str(b"C:\\NestedParent");
        assert_eq!(
            normalize_windows_path("NestedChild", &cwd),
            Some(b"C:\\NestedParent\\NestedChild".to_vec())
        );
    }

    #[test]
    fn absolute_path_replaces_current_directory() {
        let mut cwd = Cwd::new();
        cwd.set_str(b"C:\\NestedParent");
        assert_eq!(
            normalize_windows_path("C:\\NT61_Test", &cwd),
            Some(b"C:\\NT61_Test".to_vec())
        );
    }

    #[test]
    fn multiple_parent_paths_can_return_to_root() {
        let mut cwd = Cwd::new();
        cwd.set_str(b"C:\\NestedParent\\NestedChild");
        assert_eq!(
            normalize_windows_path("..\\..", &cwd),
            Some(b"C:\\".to_vec())
        );
    }
}

fn cmd_cd(args: &str, cwd: &mut Cwd) {
    if args.is_empty() {
        // Show current directory
        serial_print(cwd.as_cstr());
        serial_print(b"\r\n");
        return;
    }

    let target = args.trim().trim_matches('"');
    if target.is_empty() {
        return;
    }

    // handle special cases
    if target == "." {
        // Stay in current directory
        return;
    }
    if target == ".." {
        // Go up one level
        if cwd.len > 3 {
            // Don't go above C:\
            cwd.pop();
        }
        return;
    }

    if !ntfs::is_mounted() {
        serial_print(b"The system cannot find the path specified.\r\n");
        return;
    }

    let Some(full_path) = normalize_windows_path(target, cwd) else {
        serial_print(b"The system cannot find the path specified.\r\n");
        return;
    };
    if full_path == b"C:\\" {
        cwd.set_str(&full_path);
        return;
    }
    let path_utf16: Vec<u16> = full_path
        .iter()
        .map(|&byte| byte as u16)
        .chain(core::iter::once(0))
        .collect();
    let directory = ntfs::open_file(ntfs::get_mounted_fs().unwrap(), &path_utf16, None);
    if !directory.is_some_and(|handle| handle.is_directory) {
        serial_print(b"The system cannot find the path specified.\r\n");
        return;
    }

    cwd.set_str(&full_path);

    // Remove trailing backslash except for root
    while cwd.len > 3 && cwd.path[cwd.len - 1] == b'\\' {
        cwd.len -= 1;
        cwd.path[cwd.len] = 0;
    }
}

enum EchoCommand<'a> {
    EmptyLine,
    Status,
    Text(&'a str),
}

fn parse_echo_command(command: &str) -> Option<EchoCommand<'_>> {
    let command = command.trim();
    if command.eq_ignore_ascii_case("ECHO.") {
        return Some(EchoCommand::EmptyLine);
    }

    let name = command.split_whitespace().next()?;
    if name.eq_ignore_ascii_case("ECHO") {
        let args = command[name.len()..].trim();
        if args.is_empty() {
            Some(EchoCommand::Status)
        } else {
            Some(EchoCommand::Text(args))
        }
    } else {
        None
    }
}

#[cfg(test)]
mod echo_command_tests {
    use super::{parse_echo_command, EchoCommand};

    #[test]
    fn echo_dot_emits_an_empty_line() {
        assert!(matches!(
            parse_echo_command("echo."),
            Some(EchoCommand::EmptyLine)
        ));
    }

    #[test]
    fn echo_text_is_preserved() {
        assert!(matches!(
            parse_echo_command("echo hello world"),
            Some(EchoCommand::Text("hello world"))
        ));
    }

    #[test]
    fn echo_without_arguments_reports_status() {
        assert!(matches!(
            parse_echo_command("echo"),
            Some(EchoCommand::Status)
        ));
    }
}

/// DIR options structure
pub struct DirOptions {
    recursive: bool,          // /S - include subdirectories
    brief: bool,              // /B - bare format (no header/summary)
    wide: bool,               // /W - wide format
    attr_filter: u32,         // /A - attribute filter
    sort_order: u8,           // /O - sort order
    pub display_hidden: bool, // Show hidden files
}

impl DirOptions {
    fn new() -> Self {
        Self {
            recursive: false,
            brief: false,
            wide: false,
            attr_filter: 0xFF, // All attributes by default
            sort_order: 0,     // name sort
            display_hidden: true,
        }
    }
}

/// Parse DIR command options
fn parse_dir_options(args: &str) -> (DirOptions, &str) {
    let mut options = DirOptions::new();
    let mut path = "";

    for part in args.split_whitespace() {
        let upper = part.to_uppercase();

        if upper.starts_with("/S") {
            options.recursive = true;
        } else if upper == "/B" {
            options.brief = true;
        } else if upper == "/W" {
            options.wide = true;
        } else if upper.starts_with("/A:") {
            // Parse attribute filter
            let attr_str = &upper[3..];
            options.attr_filter = parse_attr_filter(attr_str);
        } else if upper.starts_with("/O:") {
            // Parse sort order
            let sort_str = &upper[3..];
            options.sort_order = parse_sort_order(sort_str);
        } else if upper.starts_with("/") {
            // Unknown option, skip
        } else {
            // This is the path
            if path.is_empty() {
                path = part;
            }
        }
    }

    (options, path)
}

/// Parse attribute filter string (e.g., "D", "R", "H", "A")
fn parse_attr_filter(attr_str: &str) -> u32 {
    let mut filter = 0u32;
    let mut negated = false;
    // Bit 0: read-only, Bit 1: Hidden, Bit 2: System, Bit 3: Directory
    // Bit 4: Archive, Bit 5: Device, Bit 6: Normal, Bit 7: Temporary

    for c in attr_str.chars() {
        if c == '-' {
            negated = true;
            continue;
        }

        let bit = match c {
            'D' | 'd' => 0x10,
            'R' | 'r' => 0x01,
            'H' | 'h' => 0x02,
            'S' | 's' => 0x04,
            'A' | 'a' => 0x20,
            _ => 0,
        };

        if negated {
            filter &= !bit;
        } else {
            filter |= bit;
        }
    }

    if filter == 0 {
        filter = 0xFF; // All attributes
    }

    filter
}

#[cfg(test)]
mod attr_filter_tests {
    use super::parse_attr_filter;

    #[test]
    fn attribute_negation_clears_the_requested_bit() {
        assert_eq!(parse_attr_filter("D-H"), 0x10);
        assert_eq!(parse_attr_filter("H-D"), 0x02);
    }
}

/// Parse sort order string (e.g., "N", "S", "E", "D")
fn parse_sort_order(sort_str: &str) -> u8 {
    // 0: name, 1: Extension, 2: Size, 3: Date
    // Bit 7: Descending order

    let mut order = 0u8;

    for c in sort_str.chars() {
        match c {
            'N' | 'n' => order = 0, // name
            'E' | 'e' => order = 1, // Extension
            'S' | 's' => order = 2, // Size
            'D' | 'd' => order = 3, // Date
            '-' => order |= 0x80,   // Descending
            _ => {}
        }
    }

    order
}

fn cmd_dir(cwd: &Cwd, args: &str) {
    // Parse options
    let (options, _path) = parse_dir_options(args);

    // Brief format (/B) suppresses headers and summary
    if !options.brief {
        // Print header with volume info
        serial_print(b" Volume in drive C is NT6.1\r\n");
        if let Some(volume) = ntfs::get_mounted_fs() {
            serial_print(
                format!(
                    " Volume Serial Number is {:04X}-{:04X}\r\n\r\n",
                    ((volume.ntfs_data.volume_serial >> 32) & 0xFFFF) as u16,
                    (volume.ntfs_data.volume_serial & 0xFFFF) as u16
                )
                .as_bytes(),
            );
        } else {
            serial_print(b" Volume Serial Number is 0000-0000\r\n\r\n");
        }

        serial_print(b" Directory of ");
        serial_print(cwd.as_cstr());
        serial_print(b"\r\n\r\n");
    }

    // Print . and ..
    if !options.brief && !options.wide {
        serial_print(b"01/01/1601  12:00 AM    <DIR>          .\r\n");
        serial_print(b"01/01/1601  12:00 AM    <DIR>          ..\r\n");
    } else if options.wide {
        serial_print(b".\r\n");
        serial_print(b"..\r\n");
    }

    // Initialize counters
    let mut file_count: u32 = 0;
    let mut dir_count: u32 = 2; // . and ..
    let mut total_size: u64 = 0;

    // Check filesystem and list entries
    if ntfs::is_mounted() {
        if let Some(ntfs_fs) = ntfs::get_mounted_fs() {
            let cwd_bytes = cwd.as_cstr();
            let cwd_utf16: Vec<u16> = cwd_bytes.iter().map(|byte| *byte as u16).collect();
            let directory_handle = ntfs::open_file(ntfs_fs, &cwd_utf16, None);
            let directory_record = directory_handle
                .map(|handle| handle.mft_record)
                .unwrap_or(5);

            for entry in ntfs::list_directory(ntfs_fs, directory_record) {
                let name = String::from_utf16_lossy(&entry.name);
                if entry.is_directory {
                    dir_count += 1;
                    if !options.brief && !options.wide {
                        serial_print(format_dir_timestamp(entry.modification_time).as_bytes());
                        serial_print(b"    <DIR>          ");
                        serial_print(name.as_bytes());
                        serial_print(b"\r\n");
                    } else if options.wide {
                        serial_print(b"<DIR>  ");
                        serial_print(name.as_bytes());
                        serial_print(b"  ");
                    } else {
                        serial_print(name.as_bytes());
                        serial_print(b"\r\n");
                    }
                } else {
                    file_count += 1;
                    total_size += entry.file_size;
                    if !options.brief && !options.wide {
                        serial_print(format_dir_timestamp(entry.modification_time).as_bytes());
                        serial_print(b"         ");
                        serial_print_str(&format_size(entry.file_size as u32));
                        serial_print(b" ");
                        serial_print(name.as_bytes());
                        serial_print(b"\r\n");
                    } else if options.wide {
                        serial_print(name.as_bytes());
                        serial_print(b"  ");
                    } else {
                        serial_print(name.as_bytes());
                        serial_print(b"\r\n");
                    }
                }
            }
        }
    } else if fat32::is_mounted() {
        // Try to read directory entries from FAT32
        if let Some(fs) = fat32::get_mounted_fs() {
            let mut entries = [fat32::FatDirEntry::new(); MAX_DIR_ENTRIES];
            let count = fat32::list_root_directory(fs, &mut entries);

            // Show real entries
            for i in 0..count {
                let entry = &entries[i];
                let name_len = entry.name.iter().position(|&c| c == 0).unwrap_or(13);

                if entry.is_dir {
                    if !options.brief && !options.wide {
                        serial_print(b"06/20/2026  12:00 PM    <DIR>          ");
                        serial_print(&entry.name[..name_len]);
                        serial_print(b"\r\n");
                    } else if options.wide {
                        serial_print(b"<DIR>  ");
                        serial_print(&entry.name[..name_len]);
                        serial_print(b"  ");
                    } else {
                        serial_print(&entry.name[..name_len]);
                        serial_print(b"\r\n");
                    }
                    dir_count += 1;
                } else {
                    if !options.brief && !options.wide {
                        serial_print(b"06/20/2026  12:00 PM         ");
                        serial_print_str(&format_size(entry.size));
                        serial_print(b" ");
                        serial_print(&entry.name[..name_len]);
                        serial_print(b"\r\n");
                    } else if options.wide {
                        serial_print(&entry.name[..name_len]);
                        serial_print(b"  ");
                    } else {
                        serial_print(&entry.name[..name_len]);
                        serial_print(b"\r\n");
                    }
                    file_count += 1;
                    total_size += entry.size as u64;
                }
            }
        }
    } else {
        // Use built-in directory listing
        print_builtin_dir(cwd, &options);
    }

    // Print summary (unless /B)
    if !options.brief {
        if options.wide {
            serial_print(b"\r\n");
        }
        serial_print(b"\r\n");
        serial_print(b"               ");
        serial_print_str(&format_number(file_count));
        serial_print(b" File(s)      ");
        serial_print_str(&format_size(total_size as u32));
        serial_print(b" bytes\r\n");
        serial_print(b"                ");
        serial_print_str(&format_number(dir_count));
        serial_print(b" Dir(s)       64,000,000 bytes free\r\n");
    }
}

/// Convert an NTFS FILETIME value to the compact date/time form used by
/// Windows CMD `DIR`. FILETIME is 100-nanosecond ticks since 1601-01-01.
fn format_dir_timestamp(filetime: u64) -> String {
    let mut system_time = crate::userspace::kernel32::time::SystemTime::default();
    let file_time = crate::libs::ntdll::types::LargeInteger {
        quad_part: filetime as i64,
    };
    if crate::userspace::kernel32::time::file_time_to_system_time(&file_time, &mut system_time)
        .is_err()
    {
        return String::from("01/01/1601  12:00 AM");
    }

    let hour = system_time.w_hour;
    let hour12 = if hour == 0 {
        12
    } else if hour > 12 {
        hour - 12
    } else {
        hour
    };
    let meridiem = if hour < 12 { "AM" } else { "PM" };
    format!(
        "{:02}/{:02}/{:04}  {:02}:{:02} {}",
        system_time.w_month,
        system_time.w_day,
        system_time.w_year,
        hour12,
        system_time.w_minute,
        meridiem
    )
}

/// Print built-in directory listing for Safe Mode
fn print_builtin_dir(cwd: &Cwd, options: &DirOptions) {
    // Get built-in entries based on current path
    let path_str = core::str::from_utf8(cwd.as_cstr()).unwrap_or("");

    // Helper to print directory entry
    let print_entry = |is_dir: bool, name: &[u8], size: u32| {
        if !options.brief && !options.wide {
            // Full format
            serial_print(b"06/20/2026  12:00 AM    ");
            if is_dir {
                serial_print(b"<DIR>          ");
            } else {
                serial_print(b"         ");
                serial_print_str(&format_size(size));
                serial_print(b" ");
            }
            serial_print(name);
            serial_print(b"\r\n");
        } else if options.wide {
            // Wide format
            if is_dir {
                serial_print(b"<DIR>  ");
            }
            serial_print(name);
            serial_print(b"  ");
        } else {
            // Brief format
            serial_print(name);
            serial_print(b"\r\n");
        }
    };

    if path_str == "C:\\"
        || path_str == "C:"
        || path_str.contains("Windows") && !path_str.contains("System32")
    {
        // Windows directory
        print_entry(true, b"System32", 0);
        print_entry(true, b"Boot", 0);
        print_entry(true, b"Resources", 0);
        print_entry(true, b"WinSxS", 0);
    } else if path_str.contains("System32") || path_str.contains("SYSTEM32") {
        // System32 directory
        print_entry(true, b"drivers", 0);
        print_entry(true, b"config", 0);
        print_entry(false, b"ntoskrnl.exe", 10240);
        print_entry(false, b"hal.dll", 5120);
        print_entry(false, b"ntdll.dll", 2048);
        print_entry(false, b"kernel32.dll", 8192);
        print_entry(false, b"kernelbase.dll", 4096);
        print_entry(false, b"cmd.exe", 3072);
        print_entry(false, b"winlogon.exe", 4096);
        print_entry(false, b"services.exe", 4096);
        print_entry(false, b"lsass.exe", 3072);
        print_entry(false, b"csrss.exe", 4096);
        print_entry(false, b"smss.exe", 2048);
        print_entry(false, b"wininit.exe", 2048);
        print_entry(false, b"explorer.exe", 5120);
        print_entry(false, b"user32.dll", 8192);
        print_entry(false, b"gdi32.dll", 4096);
        print_entry(false, b"advapi32.dll", 3072);
        print_entry(false, b"rpcrt4.dll", 4096);
        print_entry(false, b"msvcrt110.dll", 8192);
    } else if path_str.contains("Boot")
        || path_str.contains("Config")
        || path_str.contains("drivers")
    {
        print_entry(false, b"BCD", 8192);
        print_entry(false, b"bootmgr.exe", 1024);
        print_entry(false, b"bootsect.sys", 512);
    } else {
        // Root directory
        print_entry(true, b"Windows", 0);
        print_entry(true, b"Program Files", 0);
        print_entry(true, b"Config", 0);
        print_entry(true, b"Boot", 0);
        print_entry(true, b"Recovery", 0);
        print_entry(false, b"autoexec.bat", 128);
        print_entry(false, b"config.sys", 256);
        print_entry(false, b"pagefile.sys", 12288);
    }

    if options.wide {
        serial_print(b"\r\n");
    }
}

fn cmd_type(path: &str, _cwd: &Cwd) {
    let filename = path.trim().trim_matches('"').as_bytes();
    if fs::ntfs::is_mounted() && try_read_ntfs_file(path, _cwd) {
        return;
    }

    let fs_mounted = fat32::is_mounted();
    if !fs_mounted {
        serial_print(b"No filesystem mounted.\r\n");
        serial_print(b"Cannot read file: ");
        serial_print(filename);
        serial_print(b"\r\n");
        return;
    }

    if fat32::is_mounted() {
        if let Some(fs) = fat32::get_mounted_fs() {
            let mut buffer = [0u8; 512];

            // Look for file in root directory
            if let Some(entry) = find_file_in_root(fs, filename) {
                let cluster = entry.first_cluster();
                let size = entry.file_size();

                if size > 0 {
                    // read file content
                    let read_size = core::cmp::min(size as usize, buffer.len());
                    if let Ok(n) = fat32::read_file(fs, cluster, read_size as u32, &mut buffer) {
                        // Print content as text (limit to readable ASCII)
                        for &b in &buffer[..n] {
                            if b >= 0x20 && b < 0x7F {
                                dual_put_byte(b);
                            } else if b == b'\n' {
                                dual_put_byte(b);
                            } else if b == b'\r' {
                                // Skip (already handled \n)
                            } else if b == 0 {
                                break;
                            } else {
                                // Print hex for non-printable
                                dual_put_byte(b'.');
                            }
                        }
                        serial_print(b"\r\n");
                        return;
                    }
                }
            }

            serial_print(b"File not found: ");
            serial_print(filename);
            serial_print(b"\r\n");
            return;
        }

        serial_print(b"Failed to access filesystem.\r\n");
    } else {
        serial_print(b"No filesystem available.\r\n");
    }
}

fn try_read_ntfs_file(path: &str, cwd: &Cwd) -> bool {
    let Some(fs) = fs::ntfs::get_mounted_fs() else {
        return false;
    };
    let mut path_utf16 = command_path_utf16(path, cwd);
    path_utf16.push(0);
    let Some(mut handle) = fs::ntfs::open_file(fs, &path_utf16, None) else {
        return false;
    };
    if handle.is_directory {
        return false;
    }

    let mut content = alloc::vec![0u8; handle.file_size as usize];
    let mut total = 0usize;
    let mut iterations = 0usize;
    while total < content.len() && iterations < 16 {
        let read = match fs::ntfs::read_file(fs, &mut handle, &mut content[total..]) {
            Ok(read) => read,
            Err(_) => break,
        };
        if read == 0 {
            break;
        }
        total += read;
        iterations += 1;
    }
    if total == 0 {
        return false;
    }

    for &byte in &content[..total] {
        if byte >= 0x20 || byte == b'\n' || byte == b'\r' || byte == b'\t' {
            dual_put_byte(byte);
        } else if byte == 0 {
            break;
        } else {
            dual_put_byte(b'.');
        }
    }
    serial_print(b"\r\n");
    true
}

fn find_file_in_root<'a>(
    fs: &'a fat32::Fat32FileSystem,
    filename: &[u8],
) -> Option<fat32::FatDirectoryEntry> {
    // Convert filename to 8.3 format
    let mut short_name = [0x20u8; 11];

    // Find extension separator
    let mut ext_start = 0;
    let mut base_end = filename.len();
    for i in 0..filename.len() {
        if filename[i] == b'.' {
            ext_start = i + 1;
            base_end = i;
        }
    }

    // Base name (up to 8 chars)
    let base_len = core::cmp::min(base_end, 8);
    for i in 0..base_len {
        short_name[i] = filename[i].to_ascii_uppercase();
    }

    // Extension (up to 3 chars after dot)
    if ext_start > 0 && ext_start < filename.len() {
        let ext_len = core::cmp::min(filename.len() - ext_start, 3);
        for i in 0..ext_len {
            short_name[8 + i] = filename[ext_start + i].to_ascii_uppercase();
        }
    }

    // Use the existing find_file_in_root function
    fat32::find_file_in_root(fs, &short_name)
}

fn cmd_ver() {
    serial_print(b"Microsoft Windows [Version 6.1.7601]\r\n");
    serial_print(b"Copyright (c) 2009 Microsoft Corporation. All rights reserved.\r\n");
}

fn cmd_halt() {
    crate::hal::common::power::return_to_firmware(
        crate::hal::common::power::FirmwareAction::Shutdown,
    );
}

fn cmd_reboot() {
    crate::hal::common::power::return_to_firmware(
        crate::hal::common::power::FirmwareAction::Reboot,
    );
}

fn cmd_date(args: &str) {
    // Check for /T option (time only, no prompt)
    let time_only = args.trim().to_uppercase() == "/T";

    // Get real date from the platform RTC. The legacy
    // x86_64 CMOS driver lives in `hal::cmos`; on the other
    // architectures there is no CMOS, so the command prints
    // a stub date string. The shell still works — only the
    // date/time content differs.
    if let Some(time) = crate::hal::common::cmos::query_real_time_clock() {
        if time_only {
            serial_print(b"date /t: ");
            print_two_digits(time.month);
            serial_print(b"/");
            print_two_digits(time.day);
            serial_print(b"/");
            print_four_digits(time.year);
            serial_print(b"\r\n");
        } else {
            serial_print(b"Current date: ");
            print_two_digits(time.month);
            serial_print(b"/");
            print_two_digits(time.day);
            serial_print(b"/");
            print_four_digits(time.year);
            serial_print(b"\r\n");
            serial_print(b"Type date /t to display without prompt.\r\n");
        }
    } else {
        serial_print(b"Could not read RTC.\r\n");
    }
}

fn cmd_time(args: &str) {
    let time_only = args.trim().to_uppercase() == "/T";

    if let Some(time) = crate::hal::common::cmos::query_real_time_clock() {
        if time_only {
            print_two_digits(time.hour);
            serial_print(b":");
            print_two_digits(time.minute);
            serial_print(b":");
            print_two_digits(time.second());
            serial_print(b"\r\n");
        } else {
            serial_print(b"Current time: ");
            print_two_digits(time.hour);
            serial_print(b":");
            print_two_digits(time.minute);
            serial_print(b":");
            print_two_digits(time.second());
            serial_print(b".00\r\n");
            serial_print(b"Type time /t to display without prompt.\r\n");
        }
    } else {
        serial_print(b"Could not read RTC.\r\n");
    }
}

fn print_two_digits(n: u8) {
    dual_put_byte(b'0' + (n / 10) % 10);
    dual_put_byte(b'0' + n % 10);
}

fn print_four_digits(n: u16) {
    dual_put_byte(b'0' + ((n / 1000) % 10) as u8);
    dual_put_byte(b'0' + ((n / 100) % 10) as u8);
    dual_put_byte(b'0' + ((n / 10) % 10) as u8);
    dual_put_byte(b'0' + (n % 10) as u8);
}

/// Print a 32-bit value as eight ASCII hex digits (cross-architecture
/// equivalent of the legacy x86_64 `hal::x86_64::serial::write_u32_hex`
/// helper used by `run_batch_from_user_ptr`).
fn write_hex_byte(n: u32) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut started = false;
    for i in (0..8u32).rev() {
        let nibble = ((n >> (i * 4)) & 0xF) as u8;
        if nibble != 0 || started || i == 0 {
            dual_put_byte(HEX[nibble as usize]);
            started = true;
        }
    }
    // Always end with at least one '0' so the caller sees a stable
    // width (matches the legacy serial hex printer for n=0).
    if !started {
        dual_put_byte(b'0');
    }
}

fn cmd_help() {
    serial_print(b"\r\nCD or CHDIR     Change directory\r\n");
    serial_print(b"CLS             Clear screen\r\n");
    serial_print(b"DATE            Display or set date (real RTC)\r\n");
    serial_print(b"DIR             List directory contents\r\n");
    serial_print(b"ECHO            Display messages\r\n");
    serial_print(b"EXIT            Exit command interpreter\r\n");
    serial_print(b"HELP            Show help for commands\r\n");
    serial_print(b"TIME            Display or set system time (real RTC)\r\n");
    serial_print(b"TYPE            Display file contents\r\n");
    serial_print(b"VER             Display version information\r\n");
    serial_print(b"\r\nSpecial keys:\r\n");
    serial_print(b"  UP/DOWN        Command history\r\n");
    serial_print(b"  TAB            Auto-complete command\r\n");
    serial_print(b"  Ctrl+C         Cancel current command\r\n");
    serial_print(b"\r\nFor more information on a specific command, type HELP command-name\r\n");
}

fn cmd_mountvol() {
    serial_print(b"\r\n  Mount Points:\r\n");
    serial_print(b"    C: -> \\Device\\HardDisk0\\Partition1 (FAT32)\r\n");
    serial_print(b"\r\n");
}

fn cmd_vol() {
    serial_print(b" Volume in drive C is NT6.1\r\n");
    if let Some(volume) = ntfs::get_mounted_fs() {
        serial_print(
            format!(
                " Volume Serial Number is {:04X}-{:04X}\r\n",
                ((volume.ntfs_data.volume_serial >> 32) & 0xFFFF) as u16,
                (volume.ntfs_data.volume_serial & 0xFFFF) as u16
            )
            .as_bytes(),
        );
    } else {
        serial_print(b" Volume Serial Number is 0000-0000\r\n");
    }

    // Show filesystem status
    if ntfs::is_mounted() {
        serial_print(b" Filesystem: NTFS (mounted)\r\n");
    } else {
        serial_print(b" Filesystem: Unknown (not mounted)\r\n");
    }
}

fn cmd_kdbg(args: &str) {
    let first = args.split_whitespace().next().unwrap_or("");

    match first.to_uppercase().as_str() {
        "" => {
            serial_print(b"KD> Commands available: g, p, t, r, u, d, lm\r\n");
            serial_print(b"Type 'g' to continue execution.\r\n");
        }
        "G" | "GO" => {
            serial_print(b"Continuing execution...\r\n");
            serial_print(b"(Use Ctrl+C to break into debugger)\r\n");
        }
        "P" | "STEP" => {
            serial_print(b"Stepping to next instruction...\r\n");
        }
        "T" | "TRACE" => {
            serial_print(b"Call stack:\r\n");
            serial_print(b" #0  nt!KiSystemStartup\r\n");
            serial_print(b" #1  nt!KeInitializeProcess\r\n");
            serial_print(b" #2  nt!Phase1Initialization\r\n");
            serial_print(b" #3  nt!NtStartup\r\n");
        }
        "R" | "REGISTERS" => {
            serial_print(b"rax=0000000000000000 rbx=0000000000000000 rcx=0000000000000000\r\n");
            serial_print(b"rdx=0000000000000000 rsi=0000000000000000 rdi=0000000000000000\r\n");
            serial_print(b"rip=fffff80002601000 rsp=fffff880009d8000 rbp=0000000000000000\r\n");
        }
        "U" | "UNASSEMBLE" => {
            serial_print(b"fffff80002601000: 48895c2408      mov     [rsp+8], rbx\r\n");
            serial_print(b"fffff80002601005: 57                push    rdi\r\n");
            serial_print(b"fffff80002601006: 4883ec40        sub     rsp, 40h\r\n");
        }
        "D" | "DUMP" => {
            serial_print(b"fffff80002601000: 48 89 5C 24 08 57 48 83 EC 40 48 8B F9 ...\r\n");
        }
        "LM" | "MODULES" => {
            serial_print(b"start             end                 module name\r\n");
            serial_print(b"fffff80002600000 fffff80004000000 nt\r\n");
            serial_print(b"fffff80000000000 fffff80001000000 hal\r\n");
            serial_print(b"fffff80004000000 fffff80005000000 win32k\r\n");
        }
        _ => {
            serial_print(b"Unknown command: ");
            serial_print(first.as_bytes());
            serial_print(b"\r\n");
        }
    }
}

// ============================================================================
// File Operation Commands
// ============================================================================

/// COPY command - Copy files
/// Syntax: COPY source [+source2...] dest
fn cmd_copy(args: &str, _cwd: &Cwd) {
    if args.is_empty() {
        serial_print(b"Syntax: COPY source [+source2...] dest\r\n");
        return;
    }

    // Find the last space-separated token (destination)
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        serial_print(b"Invalid number of arguments.\r\n");
        serial_print(b"Syntax: COPY source dest\r\n");
        return;
    }

    let dest = parts[parts.len() - 1];
    let sources: Vec<&str> = parts[..parts.len() - 1].to_vec();

    // Check if filesystem is available
    if !fat32::is_mounted() {
        serial_print(b"No filesystem mounted. Cannot copy.\r\n");
        return;
    }

    let fs = match fat32::get_mounted_fs() {
        Some(f) => f,
        None => {
            serial_print(b"No FAT32 filesystem available.\r\n");
            return;
        }
    };

    // Convert destination to 8.3 format
    let dest_83 = fat32::name_to_83(dest);

    // Check if destination already exists
    if fat32::file_exists_in_root(fs, &dest_83) {
        serial_print(b"Destination file already exists: ");
        serial_print(dest.as_bytes());
        serial_print(b"\r\n");
        return;
    }

    let mut copied_count: u32 = 0;

    for source in sources {
        let source = source.trim_matches('"');

        serial_print(b"        ");
        serial_print(source.as_bytes());
        serial_print(b"\r\n");

        // Convert source to 8.3 format
        let source_83 = fat32::name_to_83(source);

        // Find source file
        if let Some(source_entry) = fat32::find_file_in_root(fs, &source_83) {
            let source_cluster = source_entry.first_cluster();
            let source_size = source_entry.file_size();

            if source_cluster == 0 || source_cluster >= fat32::FAT32_EOC {
                serial_print(b"        Invalid source file cluster.\r\n");
                continue;
            }

            // Allocate new cluster for destination
            let dest_cluster = match fat32::allocate_cluster(fs, 0) {
                Ok(c) => c,
                Err(_) => {
                    serial_print(b"        Failed to allocate cluster for destination.\r\n");
                    continue;
                }
            };

            // Copy file data cluster by cluster
            let cluster_size = fs.base.cluster_size as usize;
            let mut remaining = source_size as usize;
            let mut current_source_cluster = source_cluster;
            let mut current_dest_cluster = dest_cluster;

            while remaining > 0
                && current_source_cluster >= 2
                && current_source_cluster < fat32::FAT32_EOC
            {
                let to_copy = core::cmp::min(remaining, cluster_size);

                // read from source
                if to_copy > 0 {
                    let mut read_buf = alloc::vec![0u8; to_copy];
                    if fat32::read_file(fs, current_source_cluster, to_copy as u32, &mut read_buf)
                        .is_ok()
                    {
                        // write to destination
                        if fat32::write_cluster(fs, current_dest_cluster, &read_buf).is_err() {
                            serial_print(b"        Error writing to destination.\r\n");
                            break;
                        }
                    }
                }

                remaining = remaining.saturating_sub(to_copy);

                // Move to next source cluster
                let next_source = fat32::read_fat_entry(fs, current_source_cluster);
                if next_source >= fat32::FAT32_EOC || remaining == 0 {
                    break;
                }
                current_source_cluster = next_source;

                // Allocate next destination cluster if needed
                if remaining > 0 {
                    match fat32::allocate_cluster(fs, current_dest_cluster) {
                        Ok(c) => current_dest_cluster = c,
                        Err(_) => {
                            serial_print(b"        Failed to allocate destination cluster.\r\n");
                            break;
                        }
                    }
                }
            }

            // create destination file entry
            if fat32::create_file_in_root(fs, &dest_83, dest_cluster, source_size).is_ok() {
                serial_print(b"        1 file(s) copied.\r\n");
                copied_count += 1;
            } else {
                serial_print(b"        Failed to create destination entry.\r\n");
                // Free allocated cluster
                let _ = fat32::free_cluster_chain(fs, dest_cluster);
            }
        } else {
            serial_print(b"        Source file not found: ");
            serial_print(source.as_bytes());
            serial_print(b"\r\n");
        }
    }

    serial_print(b"       ");
    serial_print_str(&format_number(copied_count));
    serial_print(b" file(s) copied.\r\n");
}

/// DEL/DELETE command - Delete files
/// Syntax: DEL [/F] [/Q] pathname
fn cmd_del(args: &str, _cwd: &Cwd) {
    if args.is_empty() {
        serial_print(b"Syntax: DEL [/F] [/Q] pathname\r\n");
        return;
    }

    // Parse options
    let mut force = false;
    let mut quiet = false;
    let mut prompt = false;
    let mut pathname = String::new();

    for part in args.split_whitespace() {
        match part.to_uppercase().as_str() {
            "/F" => force = true,
            "/Q" => quiet = true,
            "/P" => prompt = true,
            _ => {
                if pathname.is_empty() {
                    pathname = part.to_string();
                }
            }
        }
    }

    if pathname.is_empty() {
        serial_print(b"Syntax: DEL pathname\r\n");
        return;
    }

    // Check if filesystem is available
    if !fat32::is_mounted() {
        serial_print(b"No filesystem mounted. Cannot delete.\r\n");
        return;
    }

    let fs = match fat32::get_mounted_fs() {
        Some(f) => f,
        None => {
            serial_print(b"No FAT32 filesystem available.\r\n");
            return;
        }
    };

    // Convert filename to 8.3 format
    let name_83 = fat32::name_to_83(&pathname);

    // Find the file
    if let Some((_cluster, byte_offset)) = fat32::find_file_in_root_ex(fs, &name_83) {
        // read entry to get cluster and size
        let sector_size = fs.base.sector_size as usize;
        let sector_index = byte_offset / sector_size;
        let offset_in_sector = byte_offset % sector_size;

        let mut buffer = [0u8; 512];
        if fat32::read_cluster_sector(fs, _cluster, sector_index as u32, &mut buffer).is_err() {
            serial_print(b"Error reading directory entry.\r\n");
            return;
        }

        // Get cluster from entry (offset 20-21 for high word, 26-27 for low word)
        let high =
            u16::from_le_bytes([buffer[offset_in_sector + 20], buffer[offset_in_sector + 21]]);
        let low =
            u16::from_le_bytes([buffer[offset_in_sector + 26], buffer[offset_in_sector + 27]]);
        let file_cluster = ((high as u32) << 16) | (low as u32);

        if prompt && !quiet && !confirm_delete(pathname.as_str()) {
            serial_print(b"Skipped.\r\n");
            return;
        }

        serial_print(b"Deleting: ");
        serial_print(pathname.as_bytes());
        serial_print(b"\r\n");

        // Free the cluster chain
        if file_cluster >= 2 {
            if fat32::free_cluster_chain(fs, file_cluster).is_err() {
                serial_print(b"Warning: Error freeing file clusters.\r\n");
            }
        }

        // Mark directory entry as deleted
        if fat32::delete_file_entry(fs, _cluster, byte_offset).is_ok() {
            serial_print(b"File deleted successfully.\r\n");
        } else {
            serial_print(b"Error marking file as deleted.\r\n");
        }

        let _ = (force, quiet);
    } else {
        serial_print(b"File not found: ");
        serial_print(pathname.as_bytes());
        serial_print(b"\r\n");
    }
}

fn confirm_delete(pathname: &str) -> bool {
    serial_print(b"Delete ");
    serial_print(pathname.as_bytes());
    serial_print(b"? [Y/N] ");

    loop {
        crate::hal::keyboard_input::poll();
        if let Some(byte) = crate::hal::keyboard_input::try_read_byte() {
            let byte = byte.to_ascii_uppercase();
            dual_put_byte(byte);
            serial_print(b"\r\n");
            return byte == b'Y';
        }
        wait_console_input();
    }
}

/// MD/MKDIR command - create directory
/// Syntax: MD pathname or MKDIR pathname
fn cmd_mkdir(args: &str, cwd: &Cwd) {
    let path = args.trim();
    if path.is_empty() {
        serial_print(b"Syntax: MD pathname\r\n");
        return;
    }

    // Remove quotes if present
    let path = path.trim_matches('"');

    if !ntfs::is_mounted() {
        serial_print(b"No filesystem mounted. Cannot create directory.\r\n");
        return;
    }

    let path_utf16 = command_path_utf16(path, cwd);
    if ntfs::create_directory(ntfs::get_mounted_fs().unwrap(), &path_utf16).is_ok() {
        serial_print(b"        1 dir(s) created.\r\n");
    } else {
        serial_print(b"Directory already exists or the filesystem rejected the request.\r\n");
    }
}

/// RD/RMDIR command - Remove directory
/// Syntax: RD [/S] [/Q] pathname
fn cmd_rmdir(args: &str, cwd: &Cwd) {
    if args.is_empty() {
        serial_print(b"Syntax: RD [/S] [/Q] pathname\r\n");
        return;
    }

    // Parse options
    let mut recursive = false;
    let mut quiet = false;
    let mut pathname = String::new();

    for part in args.split_whitespace() {
        match part.to_uppercase().as_str() {
            "/S" => recursive = true,
            "/Q" => quiet = true,
            _ => {
                if pathname.is_empty() {
                    pathname = part.to_string();
                }
            }
        }
    }

    if pathname.is_empty() {
        serial_print(b"Syntax: RD pathname\r\n");
        return;
    }

    if !ntfs::is_mounted() {
        serial_print(b"No filesystem mounted. Cannot remove directory.\r\n");
        return;
    }

    if recursive {
        serial_print(b"Removing directory tree: ");
    } else {
        serial_print(b"Removing directory: ");
    }
    serial_print(pathname.as_bytes());
    serial_print(b"\r\n");

    if recursive && !quiet {
        serial_print(b"Are you sure (Y/N)? ");
        serial_print(b"Y\r\n");
    }

    let path_utf16 = command_path_utf16(pathname.as_str(), cwd);
    if ntfs::delete_directory(ntfs::get_mounted_fs().unwrap(), &path_utf16).is_ok() {
        serial_print(b"        1 dir(s) removed.\r\n");
    } else {
        serial_print(b"Directory not found or not empty.\r\n");
    }
}

/// MOVE command - Move or rename files
/// Syntax: MOVE source dest
fn cmd_move(args: &str, _cwd: &Cwd) {
    if args.is_empty() {
        serial_print(b"Syntax: MOVE source dest\r\n");
        return;
    }

    // Find the destination (last token)
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        serial_print(b"Invalid number of arguments.\r\n");
        serial_print(b"Syntax: MOVE source dest\r\n");
        return;
    }

    let source = parts[0].trim_matches('"');
    let dest = parts[parts.len() - 1].trim_matches('"');

    // Check if filesystem is available
    if !fat32::is_mounted() {
        serial_print(b"No filesystem mounted. Cannot move.\r\n");
        return;
    }

    let fs = match fat32::get_mounted_fs() {
        Some(f) => f,
        None => {
            serial_print(b"No FAT32 filesystem available.\r\n");
            return;
        }
    };

    // Convert to 8.3 format
    let source_83 = fat32::name_to_83(source);
    let dest_83 = fat32::name_to_83(dest);

    // Check if destination already exists
    if fat32::file_exists_in_root(fs, &dest_83) {
        serial_print(b"Destination file already exists: ");
        serial_print(dest.as_bytes());
        serial_print(b"\r\n");
        return;
    }

    // Find source file
    if let Some((_cluster, _byte_offset)) = fat32::find_file_in_root_ex(fs, &source_83) {
        serial_print(b"Moving: ");
        serial_print(source.as_bytes());
        serial_print(b"\r\n       To: ");
        serial_print(dest.as_bytes());
        serial_print(b"\r\n");

        // Simply rename the file (in same directory)
        if fat32::rename_file_in_root(fs, &source_83, &dest_83).is_ok() {
            serial_print(b"        1 file(s) moved.\r\n");
        } else {
            serial_print(b"Failed to rename file.\r\n");
        }
    } else {
        serial_print(b"Source file not found: ");
        serial_print(source.as_bytes());
        serial_print(b"\r\n");
    }
}

/// REN/RENAME command - Rename files
/// Syntax: REN source dest or RENAME source dest
fn cmd_rename(args: &str, _cwd: &Cwd) {
    if args.is_empty() {
        serial_print(b"Syntax: REN source dest\r\n");
        return;
    }

    // Find the new name (last token)
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        serial_print(b"Invalid number of arguments.\r\n");
        serial_print(b"Syntax: REN source dest\r\n");
        return;
    }

    let source = parts[0].trim_matches('"');
    let dest = parts[parts.len() - 1].trim_matches('"');

    // Check if filesystem is available
    if !fat32::is_mounted() {
        serial_print(b"No filesystem mounted. Cannot rename.\r\n");
        return;
    }

    let fs = match fat32::get_mounted_fs() {
        Some(f) => f,
        None => {
            serial_print(b"No FAT32 filesystem available.\r\n");
            return;
        }
    };

    // Convert to 8.3 format
    let source_83 = fat32::name_to_83(source);
    let dest_83 = fat32::name_to_83(dest);

    // Check if destination already exists
    if fat32::file_exists_in_root(fs, &dest_83) {
        serial_print(b"A file with that name already exists: ");
        serial_print(dest.as_bytes());
        serial_print(b"\r\n");
        return;
    }

    // Find source file
    if fat32::find_file_in_root(fs, &source_83).is_some() {
        serial_print(b"Renaming: ");
        serial_print(source.as_bytes());
        serial_print(b"\r\n        To: ");
        serial_print(dest.as_bytes());
        serial_print(b"\r\n");

        // Rename the file
        if fat32::rename_file_in_root(fs, &source_83, &dest_83).is_ok() {
            serial_print(b"        1 file(s) renamed.\r\n");
        } else {
            serial_print(b"Failed to rename file.\r\n");
        }
    } else {
        serial_print(b"File not found: ");
        serial_print(source.as_bytes());
        serial_print(b"\r\n");
    }
}

/// SET command - Display or set environment variables
/// Syntax: SET [variable=value] or SET [variable]
fn cmd_set(args: &str) {
    let args = args.trim();

    if args.is_empty() {
        // Display all environment variables
        serial_print(b"COMPUTERNAME=NT61\r\n");
        serial_print(b"HOMEDRIVE=C:\r\n");
        serial_print(b"HOMEPATH=\\Users\\Default\r\n");
        serial_print(b"OS=Windows_NT\r\n");
        serial_print(b"PATH=C:\\Windows\\System32;C:\\Windows\r\n");
        serial_print(b"PROMPT=$P$G\r\n");
        serial_print(b"SYSTEMROOT=C:\\Windows\r\n");
        serial_print(b"TEMP=C:\\Windows\\Temp\r\n");
        serial_print(b"TMP=C:\\Windows\\Temp\r\n");
        serial_print(b"USERNAME=Administrator\r\n");
        serial_print(b"USERPROFILE=C:\\Users\\Default\r\n");
        serial_print(b"WINDIR=C:\\Windows\r\n");
        return;
    }

    if args.contains('=') {
        // Set a variable
        let parts: Vec<&str> = args.splitn(2, '=').collect();
        let name = parts[0].trim();
        let value = if parts.len() > 1 { parts[1].trim() } else { "" };

        // Use kernel32 API to set the variable
        let name_wide: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
        let value_wide: Vec<u16> = value.encode_utf16().chain(core::iter::once(0)).collect();

        let result = unsafe {
            crate::libs::kernel32::env::set_environment_variable_w(
                name_wide.as_ptr(),
                value_wide.as_ptr(),
            )
        };

        if result != 0 {
            serial_print(name.as_bytes());
            serial_print(b"=");
            serial_print(value.as_bytes());
            serial_print(b"\r\n");
        } else {
            serial_print(b"Failed to set environment variable.\r\n");
        }
    } else {
        // Display specific variable
        let value = get_env_var(args);
        if value.is_empty() {
            serial_print(b"Environment variable not found: ");
            serial_print(args.as_bytes());
            serial_print(b"\r\n");
        } else {
            serial_print(args.as_bytes());
            serial_print(b"=");
            serial_print(value.as_bytes());
            serial_print(b"\r\n");
        }
    }
}

/// NTFS command - Display NTFS filesystem information
fn cmd_ntfs_info() {
    serial_print(b"\r\n");
    serial_print(b"NTFS File System Information:\r\n");
    serial_print(b"-----------------------------\r\n");

    // Check both FAT32 and NTFS
    if fs::ntfs::is_mounted() {
        serial_print(b"  Status:        Mounted\r\n");
        serial_print(b"  Type:          NTFS\r\n");
        serial_print(b"\r\nNOTE: NTFS driver is available and mounted.\r\n");
        serial_print(b"Run DIR/TYPE to access NTFS files.\r\n");
    } else if fat32::is_mounted() {
        serial_print(b"  Status:        Not mounted\r\n");
        serial_print(b"  FAT32 Status:  Mounted (active)\r\n");
    } else {
        serial_print(b"  Status:        No filesystem mounted\r\n");
    }

    serial_print(b"\r\n");
}

// ============================================================================
// Helper Functions
// ============================================================================
//
// The interactive CMD shell in Safe Mode needs to be visible to a
// human sitting at the QEMU/VM display, not only to a serial
// console attached on COM1. Every helper here writes to BOTH the
// serial UART (so `tail -f serial.log` still works) AND the
// platform text console (so the on-screen CMD window shows
// prompts, command echo, and command output).
//
// On x86_64 the platform text console is the canonical 0xB8000
// VGA text buffer via `hal::text_console::put_byte_vga_only`. On
// the other architectures the same facade resolves to a thin
// log-ring sink that is also surfaced via `text_console::LOGS`,
// so the visible behaviour is consistent across targets while
// the on-screen representation differs by what the underlying
// framebuffer backend (or lack thereof) supports.
//
// The conditional guard in `dual_print` skips two bytes that
// confuse the VGA font without contributing to the visible
// output:
//   * `\x1b` (ESC) — leaves the cursor mid escape sequence.
//   * `\x00` (NUL) — would overstrike with a space character.
//
// Everything else (CR/LF/printable ASCII, TAB, BS) flows through
// to both sinks so users see prompts and command echo on screen.

/// write a UTF-8 byte string to both the serial UART and the
/// platform text console. Stops at the first NUL byte.
fn serial_print(s: &[u8]) {
    dual_print(s);
}

fn dual_print(s: &[u8]) {
    let len = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    let mut i = 0;
    while i < len {
        let c = s[i];
        if c == b'\x1b' {
            // Skip the ANSI CSI sequence: ESC [ params final-byte.
            i += 1;
            if i < len && s[i] == b'[' {
                i += 1;
                while i < len && !(0x40..=0x7E).contains(&s[i]) {
                    i += 1;
                }
                if i < len {
                    i += 1; // skip the final byte
                }
            }
            continue;
        }
        if c != b'\x00' {
            crate::hal::serial::with_serial_unmasked(|| {
                text_console::put_serial_and_console(c);
            });
            if let Some(capture) = OUTPUT_CAPTURE.lock().as_mut() {
                if capture.len() < OUTPUT_CAPTURE_LIMIT {
                    capture.push(c);
                }
            }
        }
        i += 1;
    }
}

/// write one byte to both serial and the platform text console.
/// Used by the line-editing path where each key press is
/// mirrored immediately.
fn dual_put_byte(c: u8) {
    if c != b'\x1b' && c != b'\x00' {
        crate::hal::serial::with_serial_unmasked(|| {
            text_console::put_serial_and_console(c);
        });
    }
}

/// Print a fixed 16-byte string (for FAT32 8.3 names and similar)
/// to both sinks. Stops at the first space — matches the previous
/// behaviour and prevents trailing spaces from being echoed.
fn serial_print_str(s: &[u8; 16]) {
    let end = s.iter().rposition(|&c| c != b' ').map_or(0, |pos| pos + 1);
    for &c in s[..end].iter() {
        dual_put_byte(c);
    }
}

fn format_size(size: u32) -> [u8; 16] {
    // Format size with comma separators (e.g., "123,456")
    let mut buf = [b' '; 16];
    let mut pos = 15;
    let mut digits = 0;
    let mut n = size;

    if n == 0 {
        buf[pos] = b'0';
    } else {
        while n > 0 && pos > 0 {
            if digits > 0 && digits % 3 == 0 {
                buf[pos] = b',';
                pos -= 1;
            }
            buf[pos] = b'0' + (n % 10) as u8;
            n /= 10;
            digits += 1;
            pos -= 1;
        }
    }

    buf
}

fn format_number(n: u32) -> [u8; 16] {
    // Format number with comma separators
    format_size(n)
}

// ============================================================================
// Batch File (.bat / .cmd) Execution
// ============================================================================
//
// When the user types `script.bat` at the CMD prompt (or invokes a
// command whose name has no built-in handler), the shell looks the
// file up in the current directory on the FAT32 volume, reads its
// contents, and feeds the lines to the `BatchParser` defined in
// `libs::cmd::bat_parser`. The parser walks the line stream, expands
// variables, classifies each line (label / GOTO / IF / FOR / CALL /
// SETLOCAL / EXIT / etc.), and dispatches built-in commands to
// `CmdBatchExecutor`, which re-uses the same `execute_single_command`
// infrastructure the interactive shell uses.
//
// The executor is a thin wrapper around the existing CWD and
// environment state. It owns its own copy of the CWD because the
// interactive shell's CWD is a local in `run_shell` and we cannot
// borrow it across an `&mut dyn BatchExecutor` interface.

/// internal state shared with the batch parser.
struct CmdBatchExecutor {
    cwd: Cwd,
    error_level: u32,
}

impl CmdBatchExecutor {
    fn new(initial_cwd: &Cwd) -> Self {
        let mut cwd = Cwd::new();
        cwd.set_str(initial_cwd.as_cstr());
        Self {
            cwd,
            error_level: 0,
        }
    }

    /// read `filename` through the FAT32 driver. This is the
    /// canonical path used when the system partition is FAT32
    /// (also used as the legacy fallback for the ESP). The
    /// directory walk uses the 8.3 short-name directory chain
    /// produced by `tools/src/fs/build.rs::build_disk`.
    fn read_file_fat32(&self, filename: &str) -> Result<String, BatError> {
        if !fat32::is_mounted() {
            return Err(BatError::IoError);
        }
        let fs = fat32::get_mounted_fs().ok_or(BatError::IoError)?;
        let entry = if let Some(e) = fat32::find_file_at_path(fs, filename) {
            e
        } else if let Some(e) = find_file_in_root(fs, filename.as_bytes()) {
            e
        } else {
            return Err(BatError::FileNotFound(alloc::string::String::from(
                filename,
            )));
        };
        let cluster = entry.first_cluster();
        let size = entry.file_size() as usize;
        if size == 0 {
            return Ok(alloc::string::String::new());
        }
        let mut buf = alloc::vec![0u8; size];
        let n = fat32::read_file(fs, cluster, size as u32, &mut buf).unwrap_or(0);
        Ok(normalise_batch_text(&buf[..n]))
    }

    /// read `filename` through the NTFS driver. The Windows
    /// path is converted to UTF-16 on the way down because NTFS
    /// stores file names as UTF-16LE and the
    /// `ntfs::open_file` walker expects a UTF-16 slice.
    fn read_file_ntfs(&self, filename: &str) -> Result<String, BatError> {
        if !crate::fs::ntfs::is_mounted() {
            return Err(BatError::IoError);
        }
        // Switch the active mirror to the system partition so
        // every `read_sector` call inside the NTFS driver hits
        // the C: image, not the ESP.
        let prev_active = crate::fs::active_partition_ramdisk();
        if let Some(sys_base) = crate::fs::sys_mirror_address() {
            crate::fs::set_active_partition_ramdisk(Some(sys_base));
        }

        let fs = match crate::fs::ntfs::get_mounted_fs() {
            Some(f) => f,
            None => {
                crate::fs::set_active_partition_ramdisk(prev_active);
                return Err(BatError::IoError);
            }
        };

        // ASCII -> UTF-16LE conversion. The autoexec.bat path
        // uses ASCII characters only (it lives on a build-system
        // host that writes UTF-8); UTF-8 -> UTF-16 would be the
        // next step if we ever embed non-ASCII content in the
        // batch file.
        let mut path_utf16 = [0u16; 256];
        let bytes = filename.as_bytes();
        let len = core::cmp::min(bytes.len(), path_utf16.len() - 1);
        for i in 0..len {
            path_utf16[i] = bytes[i] as u16;
        }
        path_utf16[len] = 0;

        let mut handle = match crate::fs::ntfs::open_file(fs, &path_utf16[..len + 1], None) {
            Some(h) => h,
            None => {
                crate::fs::set_active_partition_ramdisk(prev_active);
                return Err(BatError::FileNotFound(alloc::string::String::from(
                    filename,
                )));
            }
        };

        let total = (handle.file_size as usize).min(64 * 1024);
        if total == 0 {
            crate::fs::set_active_partition_ramdisk(prev_active);
            return Ok(alloc::string::String::new());
        }
        let mut buf = alloc::vec![0u8; total];
        let mut read_total = 0usize;
        let mut iter = 0usize;
        while read_total < total && iter < 16 {
            let n = match crate::fs::ntfs::read_file(fs, &mut handle, &mut buf[read_total..]) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            read_total += n;
            iter += 1;
        }
        crate::fs::set_active_partition_ramdisk(prev_active);
        if read_total == 0 {
            return Err(BatError::IoError);
        }
        Ok(normalise_batch_text(&buf[..read_total]))
    }

    /// read `filename` through the ext2/3/4 driver. The
    /// Windows-style path is converted to the POSIX-style
    /// path that `ext2::read_whole_file` expects.
    fn read_file_ext2(&self, filename: &str) -> Result<String, BatError> {
        if !crate::fs::ext2::is_mounted() {
            return Err(BatError::IoError);
        }
        let fs = match crate::fs::ext2::get_mounted_fs() {
            Some(f) => f,
            None => return Err(BatError::IoError),
        };
        let data = match crate::fs::ext2::read_whole_file(fs, filename) {
            Ok(v) => v,
            Err(_) => {
                return Err(BatError::FileNotFound(alloc::string::String::from(
                    filename,
                )));
            }
        };
        Ok(normalise_batch_text(&data))
    }
}

/// Normalise a buffer full of batch-file text into a Rust
/// `String` so the BAT parser can iterate it line by line.
/// Strips the trailing `\r` that DOS-inserted into every line
/// so the parser can split on `\n` without seeing CRLF.
fn normalise_batch_text(buf: &[u8]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(buf.len());
    for &b in buf {
        if b == b'\r' {
            continue;
        }
        s.push(b as char);
    }
    s
}

impl BatchExecutor for CmdBatchExecutor {
    fn read_file(&self, filename: &str) -> Result<String, BatError> {
        // Resolution order:
        //   1. Try the literal path (Windows-style with drive
        //      letter and `\` separators). This is the canonical
        //      location for NT 6.1 batch files —
        //      `C:\system\tests\autoexec.bat`. The FAT32 helper
        //      `find_file_at_path` walks subdirectories using the
        //      8.3 short-name directory chain.
        //   2. Fall back to the FAT32 root for callers that pass
        //      a bare filename like `autoexec.bat`. The legacy
        //      /tests/autoexec.bat and /autoexec.bat locations
        //      registered by `tools/src/fs/build.rs` are still
        //      visible here.
        //   3. If the system partition is NTFS or EXT2/3/4
        //      instead of FAT32, route the read to the matching
        //      driver. The path is converted from the Windows
        //      form ("C:\Windows\System32\foo.bat") to the FS's
        //      preferred encoding (UTF-16 for NTFS, POSIX-style
        //      for ext) on the way down, so the kernel-side
        //      `cmd.exe` host can run the same `autoexec.bat`
        //      regardless of which FS the boot image used.
        //
        // The FAT32 read path (`CmdBatchExecutor::read_file`)
        // detects the active filesystem at call time and only
        // touches the driver that owns the system partition.

        // Detect the system-partition FS once so the resolution
        // matches the boot — without this, an NTFS boot image
        // would still try to read through the FAT32 driver.
        let fs_type = crate::fs::detect_system_partition_type();
        match fs_type {
            crate::fs::FsType::Fat32 => self.read_file_fat32(filename),
            crate::fs::FsType::Ntfs => self.read_file_ntfs(filename),
            crate::fs::FsType::Ext2 | crate::fs::FsType::Ext3 | crate::fs::FsType::Ext4 => {
                self.read_file_ext2(filename)
            }
            crate::fs::FsType::Unknown => {
                // Last-ditch attempt: try FAT32 anyway since the
                // ESP still uses it on every supported boot.
                self.read_file_fat32(filename)
            }
        }
    }

    fn execute_command(&mut self, command: &str) -> Result<u32, BatError> {
        // Re-route to the interactive shell's command dispatcher.
        // The kernel-side debug shell uses `ShellMode::SafeModeDebug`;
        // the user-mode `cmd.exe` host does not invoke this path
        // (it runs each batch line through its own dispatcher and
        // never touches the kernel shell loop). SafeModeDebug is
        // therefore the right transient mode — it carries the same
        // prompt semantics as the kernel-side shell.
        let mode = ShellMode::SafeModeCmd;
        // Drop the error level into a sentinel before dispatch —
        // the inner command may overwrite it via SET ERRORLEVEL, but
        // we propagate the legacy behaviour by clearing on success.
        let saved = self.error_level;
        let _ = execute_single_command(command, &mode, &mut self.cwd);
        // Naive error level: 0 unless the command name starts with
        // a known-failing token. A full implementation would have
        // execute_single_command return the error level.
        let _ = saved;
        self.error_level = 0;
        Ok(0)
    }

    fn echo_line(&self, line: &str) {
        serial_print(line.as_bytes());
        serial_print(b"\r\n");
    }
}

/// Detect whether a command line refers to a batch file (.bat or
/// .cmd) and, if so, dispatch it through the batch parser.
/// Returns `true` if the command was handled as a batch file.
fn try_run_batch_file(cmd_str: &str, cwd: &Cwd) -> bool {
    let trimmed = cmd_str.trim();
    // Extract the first token (the command name) — strip a leading
    // call site path like ".\script" or "subdir\script".
    let first = trimmed.split_whitespace().next().unwrap_or("");
    if first.is_empty() {
        return false;
    }
    // Skip if it has a directory separator and the file doesn't end
    // in .bat/.cmd. Skip if it contains characters that are
    // unambiguously an internal command.
    let lower = first.to_ascii_lowercase();
    if !lower.ends_with(".bat") && !lower.ends_with(".cmd") {
        return false;
    }
    // Strip a leading ".\" or "./" so the file lookup stays at the
    // current directory.
    let cleaned = if let Some(stripped) = lower.strip_prefix(".\\") {
        stripped
    } else if let Some(stripped) = lower.strip_prefix("./") {
        stripped
    } else {
        lower.as_str()
    };
    let mut parser = BatchParser::new();
    let mut executor = CmdBatchExecutor::new(cwd);
    match parser.execute(cleaned, &mut executor) {
        Ok(()) => true,
        Err(BatError::FileNotFound(name)) => {
            serial_print(b"'");
            serial_print(cleaned.as_bytes());
            serial_print(b"' is not recognized as an internal or external command,\r\n");
            serial_print(b"operable program or batch file.\r\n");
            let _ = name;
            false
        }
        Err(BatError::Exit(_)) => {
            // EXIT /B — leave the CMD prompt alive.
            true
        }
        Err(e) => {
            serial_print(b"BAT execution error: ");
            let mut s = alloc::string::String::new();
            let _ = core::fmt::write(&mut s, format_args!("{:?}", e));
            serial_print(s.as_bytes());
            serial_print(b"\r\n");
            false
        }
    }
}

/// Public entry point: run the batch file at `path`.
///
/// Used both by the interactive shell (when the user types
/// `autoexec.bat` at the prompt) and by the user-mode `cmd.exe`
/// stub via the `SYS_RUN_AUTOEXEC` syscall. `path` is interpreted
/// as a Windows-style absolute path (e.g.
/// `C:\system\tests\autoexec.bat`); the BAT parser emits the
/// canonical form. The FAT32 read path (`CmdBatchExecutor::read_file`)
/// resolves the path against the system partition — see the
/// resolution order in that function for the fallback chain that
/// keeps the legacy `/autoexec.bat` and `/tests/autoexec.bat`
/// copies working.
///
/// `BatError::Exit` is intentionally **not** swallowed here: if
/// the batch script ends with `EXIT /B n`, the kernel must let
/// the cmd.exe stub exit the process instead of falling back to
/// the interactive prompt. The caller (the syscall handler or
/// `try_run_batch_file`) decides whether to propagate the exit.
pub fn run_batch_file(path: &str) -> Result<(), BatError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(BatError::FileNotFound(String::from("<empty path>")));
    }
    // Strip a leading ".\" or "./" so the file lookup stays at the
    // current directory. Mirror `try_run_batch_file` semantics.
    let lower = trimmed.to_ascii_lowercase();
    let cleaned = if let Some(stripped) = lower.strip_prefix(".\\") {
        stripped
    } else if let Some(stripped) = lower.strip_prefix("./") {
        stripped
    } else {
        lower.as_str()
    };
    // Use a fresh CWD anchored at the system root so the user-mode
    // `cmd.exe` stub — which has no notion of "current directory"
    // beyond what we feed it — gets a sensible default. The shell
    // already maintains its own `Cwd` instance; we are running on
    // behalf of the user-mode stub and must avoid touching it.
    let cwd = Cwd::new();
    let mut parser = BatchParser::new();
    let mut executor = CmdBatchExecutor::new(&cwd);
    parser.execute(cleaned, &mut executor)
}

/// Run a batch file referenced by a user-mode pointer.
///
/// Used by the `SYS_RUN_AUTOEXEC` syscall. The user-mode stub
/// passes the absolute path as a NUL-terminated C string living
/// in the user address space; we copy it byte-by-byte (the user
/// pointer is not safe to dereference beyond the NUL terminator
/// from kernel space) and dispatch to `run_batch_file`.
///
/// Returns `Some(())` when the batch file was located and the
/// interpreter ran it to completion (or it issued `EXIT /B`).
/// Returns `None` when the path is malformed or the file could
/// not be read.
pub fn run_batch_from_user_ptr(user_ptr: *const u8) -> Option<()> {
    serial_print(b"[CMD-A] run_batch_from_user_ptr entered\r\n");
    if user_ptr.is_null() {
        serial_print(b"[CMD-A] user_ptr=null\r\n");
        return None;
    }
    // Copy at most 256 bytes (matches the cmd.exe stub's buffer)
    // and stop at the first NUL. We do not trust the user to
    // provide a properly sized path — clamp aggressively.
    let mut buf = [0u8; 256];
    let mut len = 0usize;
    serial_print(b"[CMD-A] copying user path byte-by-byte\r\n");
    if crate::mm::user_copy::copy_from_user(&mut buf, user_ptr as u64).is_err() {
        serial_print(b"[CMD-A] copy_from_user failed\r\n");
        return None;
    }
    while len < buf.len() {
        if buf[len] == 0 {
            break;
        }
        len += 1;
    }
    serial_print(b"[CMD-A] copied len=");
    write_hex_byte(len as u32);
    serial_print(b"\r\n");
    if len == 0 {
        serial_print(b"[CMD-A] len=0, returning None\r\n");
        return None;
    }
    let path = match core::str::from_utf8(&buf[..len]) {
        Ok(s) => {
            serial_print(b"[CMD-A] path utf8 ok: ");
            serial_print(s.as_bytes());
            serial_print(b"\r\n");
            s
        }
        Err(e) => {
            serial_print(b"[CMD-A] path utf8 err=");
            write_hex_byte(e.valid_up_to() as u32);
            serial_print(b"\r\n");
            return None;
        }
    };
    serial_print(b"[CMD-A] calling run_batch_file('");
    serial_print(path.as_bytes());
    serial_print(b"')\r\n");
    match run_batch_file(path) {
        Ok(()) => {
            serial_print(b"[CMD-A] run_batch_file OK\r\n");
            Some(())
        }
        Err(BatError::Exit(_)) => {
            serial_print(b"[CMD-A] run_batch_file Exit\r\n");
            Some(())
        }
        Err(BatError::FileNotFound(name)) => {
            serial_print(b"CMD: batch file not found: ");
            serial_print(name.as_bytes());
            serial_print(b"\r\n");
            None
        }
        Err(e) => {
            serial_print(b"CMD: batch execution error: ");
            let mut s = alloc::string::String::new();
            let _ = core::fmt::write(&mut s, format_args!("{:?}", e));
            serial_print(s.as_bytes());
            serial_print(b"\r\n");
            None
        }
    }
}

/// Execute one command line submitted by Ring 3.
///
/// The complete line is passed unchanged so diagnostics and paths keep
/// their original case. Command matching remains case-insensitive in
/// `execute_single_command`.
pub fn execute_command_line(command_line: &str) -> bool {
    let mut cwd = RING3_CWD.lock();
    if cwd.len == 0 {
        *cwd = Cwd::new();
    }
    process_command_chain(command_line.trim(), &ShellMode::Ring3, &mut cwd)
}

/// Copy a NUL-terminated UTF-8 command line from user memory and run it.
pub fn execute_command_from_user_ptr(
    user_ptr: *const u8,
    user_length: usize,
) -> Result<bool, &'static str> {
    let diagnostic = alloc::format!(
        "[CMD-PTR] ptr={:#x} len={:#x} range={} root={:#x} trans={:#x?}\r\n",
        user_ptr as usize,
        user_length,
        crate::mm::user_copy::is_user_range(user_ptr as u64, user_length),
        crate::arch::read_current_page_root(),
        crate::arch::translate_virt(user_ptr as u64)
    );
    crate::hal::serial::write_string_always(&diagnostic);
    if user_ptr.is_null() {
        return Err("null command pointer");
    }
    let capacity = user_length.min(CMD_BUFFER_SIZE - 1);
    let mut bytes = alloc::vec![0u8; capacity];
    if crate::mm::user_copy::copy_from_user(&mut bytes, user_ptr as u64).is_err() {
        return Err("command buffer is not readable user memory");
    }
    execute_command_bytes(&bytes)
}

pub fn execute_command_bytes(bytes: &[u8]) -> Result<bool, &'static str> {
    let line = core::str::from_utf8(bytes).map_err(|_| "command is not valid UTF-8")?;
    let line = line.trim_matches(|character: char| character == '\0' || character.is_whitespace());
    Ok(execute_command_line(line))
}
