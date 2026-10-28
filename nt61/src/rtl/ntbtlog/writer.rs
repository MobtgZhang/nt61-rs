//! NTBTLOG.TXT Writer
//
//! Implements the boot log file writer for Windows 7 boot logging.
//!
//! # Behavior
//!
//! - Log is written to an internal buffer during boot
//! - buffer is cleared at the start of each boot
//! - Log can be retrieved as raw bytes for writing to disk

use core::sync::atomic::{AtomicUsize, Ordering};

/// Maximum boot log size (1 MB)
const MAX_LOG_SIZE: usize = 1024 * 1024;

/// Boot log buffer (static allocation)
static mut BOOT_LOG_BUFFER: [u8; MAX_LOG_SIZE] = [0u8; MAX_LOG_SIZE];

/// Current write position in the log buffer
static BOOT_LOG_POS: AtomicUsize = AtomicUsize::new(0);

/// Serializes buffer writes (audit hal_rtl P0-2: two CPUs writing
/// boot entries concurrently could interleave and corrupt the log).
/// Reentrant on the owning CPU so nested log calls cannot self-spin.
static BOOT_LOG_LOCK: crate::hal::common::relock::ReentrantLock =
    crate::hal::common::relock::ReentrantLock::new();

/// write a line to the boot log
pub fn write_line(line: &[u8]) {
    let _guard = BOOT_LOG_LOCK.lock();
    let pos = BOOT_LOG_POS.load(Ordering::Acquire);

    if pos + line.len() >= MAX_LOG_SIZE {
        return; // Log buffer full
    }

    unsafe {
        BOOT_LOG_BUFFER[pos..pos + line.len()].copy_from_slice(line);
    }

    BOOT_LOG_POS.store(pos + line.len(), Ordering::Relaxed);
}

/// Clear the boot log buffer
pub fn clear_log() {
    let _guard = BOOT_LOG_LOCK.lock();
    // Read the live position first, then clear those bytes; storing
    // 0 before reading (the old order) made the zeroing loop a no-op.
    let pos = BOOT_LOG_POS.load(Ordering::Acquire);
    unsafe {
        for i in 0..pos {
            BOOT_LOG_BUFFER[i] = 0;
        }
    }
    BOOT_LOG_POS.store(0, Ordering::Relaxed);
}

/// Get the current log as a byte slice
pub fn get_log() -> Option<&'static [u8]> {
    let pos = BOOT_LOG_POS.load(Ordering::Relaxed);
    if pos == 0 {
        return None;
    }

    Some(unsafe { &BOOT_LOG_BUFFER[..pos] })
}

/// Get the current log position
pub fn get_log_len() -> usize {
    BOOT_LOG_POS.load(Ordering::Relaxed)
}

/// write formatted boot log entry
///
/// Format: `YYYY MM DD HH:MM:SS.mmm BOOTLOG_LOADED \SystemRoot\...`
pub fn write_boot_entry(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    millisecond: u16,
    loaded: bool,
    path: &[u8],
) {
    let mut line = [b' '; 512];
    let mut pos = 0;

    // YYYY
    line[pos..pos + 4].copy_from_slice(&[
        b'0' + ((year / 1000) % 10) as u8,
        b'0' + ((year / 100) % 10) as u8,
        b'0' + ((year / 10) % 10) as u8,
        b'0' + (year % 10) as u8,
    ]);
    pos += 4;
    line[pos] = b' ';
    pos += 1;

    // MM
    line[pos] = b'0' + (month / 10);
    line[pos + 1] = b'0' + (month % 10);
    pos += 2;
    line[pos] = b' ';
    pos += 1;

    // DD
    line[pos] = b'0' + (day / 10);
    line[pos + 1] = b'0' + (day % 10);
    pos += 2;
    line[pos] = b' ';
    pos += 1;

    // HH:MM:SS.mmm
    line[pos] = b'0' + (hour / 10);
    line[pos + 1] = b'0' + (hour % 10);
    pos += 2;
    line[pos] = b':';
    pos += 1;
    line[pos] = b'0' + (minute / 10);
    line[pos + 1] = b'0' + (minute % 10);
    pos += 2;
    line[pos] = b':';
    pos += 1;
    line[pos] = b'0' + (second / 10);
    line[pos + 1] = b'0' + (second % 10);
    pos += 2;
    line[pos] = b'.';
    pos += 1;
    line[pos] = b'0' + ((millisecond / 100) % 10) as u8;
    line[pos + 1] = b'0' + ((millisecond / 10) % 10) as u8;
    line[pos + 2] = b'0' + (millisecond % 10) as u8;
    pos += 3;
    line[pos] = b' ';
    pos += 1;

    // BOOTLOG_LOADED or BOOTLOG_NOT_LOADED
    if loaded {
        let s = b"BOOTLOG_LOADED";
        line[pos..pos + s.len()].copy_from_slice(s);
        pos += s.len();
    } else {
        let s = b"BOOTLOG_NOT_LOADED";
        line[pos..pos + s.len()].copy_from_slice(s);
        pos += s.len();
    }
    line[pos] = b' ';
    pos += 1;

    // Path
    for &b in path {
        if b == 0 {
            break;
        }
        if pos < 480 {
            line[pos] = b;
            pos += 1;
        }
    }

    // CRLF
    if pos < 510 {
        line[pos] = b'\r';
        line[pos + 1] = b'\n';
        pos += 2;
    }

    write_line(&line[..pos]);
}

/// write standard Windows 7 boot log header
pub fn write_header() {
    write_line(b"\r\n");
    write_line(b"Microsoft (R) Windows (R) Boot Log Utility\r\n");
    write_line(b"Copyright (C) Microsoft Corporation. All rights reserved.\r\n");
    write_line(b"\r\n");
    write_line(b"Boot Operation Started.\r\n");
    write_line(b"\r\n");
}

/// write standard Windows 7 boot log footer
pub fn write_footer() {
    write_line(b"\r\n");
    write_line(b"Boot Operation Completed.\r\n");
    write_line(b"\r\n");
    write_line(b"End of Boot Log\r\n");
}

/// write driver loading entry with timestamp
pub fn write_driver_entry(loaded: bool, path: &[u8]) {
    // Read the wall clock from the RTC so boot entries carry the real
    // boot time. When the CMOS is inaccessible (probe failure) fall back
    // to zeroes rather than inventing a date.
    if let Some(t) = crate::hal::common::cmos::query_real_time_clock() {
        write_boot_entry(
            t.year,
            t.month,
            t.day,
            t.hour,
            t.minute,
            t.second(),
            0,
            loaded,
            path,
        );
    } else {
        write_boot_entry(0, 0, 0, 0, 0, 0, 0, loaded, path);
    }
}
