//! Strings + constants shared between the cmd.exe interpreter and the
//! three subsystem stubs. Sourced verbatim from the Python originals so
//! the Rust output is byte-for-byte identical.

// ===== Syscall numbers ===========================================

/// Single-character output: arg in `r10`, returns nothing.
pub const SYS_PUTCHAR: u32 = 0x0202;
/// Non-blocking PS/2 / serial poll, returns scancode or 0.
pub const SYS_POLL_KEY: u32 = 0x0203;
/// Exit the calling Ring-3 process.
pub const SYS_EXIT: u32 = 0x0201;

/// Run the autoexec batch (kernel side). The user-mode stub invokes
/// this at start-up with `r10 = NULL` to use the default
/// `C:\tests\autoexec.bat` path that the build tool installs on
/// the on-disk NTFS image.
pub const SYS_RUN_AUTOEXEC: u32 = 0x0200;

/// Spawn a new subsystem process by name (used by winlogon/userinit).
pub const SYS_SPAWN_SUBSYSTEM_PROC: u32 = 0x0210;

/// Execute one complete command line from the Ring-3 command host.
pub const SYS_CMD_EXECUTE: u32 = 0x0215;
pub const SYS_CLEARSCREEN: u32 = 0x0205;

// ===== cmd.exe strings ============================================

pub const BANNER: &[u8] = b"\r\nMicrosoft Windows [Version 6.1.7601]\r\n\
Copyright (c) 2009 Microsoft Corporation. All rights reserved.\r\n\r\n";

pub const HELP: &[u8] =
    b"Built-ins: exit ver help autoexec echo <text> cls halt reboot time date ipconfig\r\n";
pub const UNKNOWN: &[u8] = b"Unknown command.\r\n";
pub const VER_TXT: &[u8] = b"Microsoft Windows [Version 6.1.7601]\r\n";
pub const HALTTXT: &[u8] = b"Windows is halting.\r\n";
pub const PROMPT: &[u8] = b"C:\\> ";
pub const EXIT_TXT: &[u8] = b"The command completed successfully.\r\n";

// ===== PS/2 scancode set-1 -> ASCII =================================

/// Indexed by PS/2 Set-1 make code, value is ASCII (0 = no mapping).
pub const SCAN_TO_ASCII: [u8; 128] = [
    0, 0x1b, b'1', b'2', b'3', b'4', b'5', b'6', // 0x00-0x07
    b'7', b'8', b'9', b'0', b'-', b'=', 0x08, 0x09, // 0x08-0x0F
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', // 0x10-0x17
    b'o', b'p', b'[', b']', b'\n', 0, b'a', b's', // 0x18-0x1F
    b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', // 0x20-0x27
    b'\'', b'`', 0, b'\\', b'z', b'x', b'c', b'v', // 0x28-0x2F
    b'b', b'n', b'm', b',', b'.', b'/', 0, b'*', // 0x30-0x37
    0, b' ', 0, 0, 0, 0, 0, 0, // 0x38-0x3F
    0, 0, 0, 0, 0, 0, 0, 0, // 0x40-0x47
    0, 0, 0, b'-', 0, 0, 0, b'+', // 0x48-0x4F
    0, 0, 0, 0, 0, 0, 0, 0, // 0x50-0x57
    0, 0, 0, 0, 0, 0, 0, 0, // 0x58-0x5F
    0, 0, 0, 0, 0, 0, 0, 0, // 0x60-0x67
    0, 0, 0, 0, 0, 0, 0, 0, // 0x68-0x6F
    0, 0, 0, 0, 0, 0, 0, 0, // 0x70-0x77
    0, 0, 0, 0, 0, 0, 0, 0, // 0x78-0x7F
];

// ===== Sizes of the four stub images (matches the constants in
//      the original Python script) ===================================

// Bumped from 4096 to 5632 to make room for the built-in command
// branches (`time`, `date`, `ipconfig`) plus the reboot branch and
// the firmware-return syscalls wired into `halt` / `reboot`. The
// do_exit block was shifted from 0x640 to 0x800 to give
// dispatch_command additional room, and the trailing padding was
// extended to match.
pub const CMD_STUB_SIZE: usize = 5632;
pub const LSM_STUB_SIZE: usize = 256;
pub const WINLOGON_STUB_SIZE: usize = 256;
pub const USERINIT_STUB_SIZE: usize = 256;
