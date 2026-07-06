//! NTBTLOG.TXT - Windows Boot Log
//
//! Implements Windows 7 boot log file format compatible with NT 6.1.7601.
//
//! # Format
//
//! ```text
//! YYYY MM DD HH:MM:SS.mmm BOOTLOG_LOADED   \SystemRoot\system32\ntoskrnl.exe
//! YYYY MM DD HH:MM:SS.mmm BOOTLOG_NOT_LOADED \SystemRoot\System32\drivers\bad.sys
//! ```

#![allow(dead_code)]

pub mod writer;

use core::sync::atomic::{AtomicBool, Ordering};

/// Whether boot logging is enabled
static BOOT_LOG_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether we are currently in the boot process
static IN_BOOT_SEQUENCE: AtomicBool = AtomicBool::new(false);

/// Boot log entry type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootEntryType {
    Loaded,
    NotLoaded,
}

impl BootEntryType {
    /// Get the string representation
    pub fn as_str(&self) -> &'static [u8] {
        match self {
            BootEntryType::Loaded => b"BOOTLOG_LOADED   ",
            BootEntryType::NotLoaded => b"BOOTLOG_NOT_LOADED",
        }
    }
}

/// Boot log entry
#[derive(Debug, Clone)]
pub struct BootLogEntry {
    /// Entry type
    pub entry_type: BootEntryType,
    /// Driver/Module path (NT path format)
    pub path: [u8; 256],
    /// Timestamp components
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub millisecond: u16,
}

impl BootLogEntry {
    /// Create a new boot log entry
    pub fn new(entry_type: BootEntryType, path: &[u8]) -> Self {
        let mut path_buf = [0u8; 256];
        for (i, &b) in path.iter().take(255).enumerate() {
            path_buf[i] = b;
        }
        
        Self {
            entry_type,
            path: path_buf,
            year: 2026,
            month: 6,
            day: 30,
            hour: 9,
            minute: 0,
            second: 0,
            millisecond: 0,
        }
    }
    
    /// Format the entry as a line for ntbtlog.txt
    pub fn format_line(&self) -> [u8; 512] {
        let mut line = [b' '; 512];
        let mut pos = 0;
        
        // YYYY
        line[pos..pos+4].copy_from_slice(&itoa4(self.year));
        pos += 4;
        line[pos] = b' ';
        pos += 1;
        
        // MM
        line[pos..pos+2].copy_from_slice(&itoa2(self.month));
        pos += 2;
        line[pos] = b' ';
        pos += 1;
        
        // DD
        line[pos..pos+2].copy_from_slice(&itoa2(self.day));
        pos += 2;
        line[pos] = b' ';
        pos += 1;
        
        // HH:MM:SS.mmm
        line[pos..pos+2].copy_from_slice(&itoa2(self.hour));
        pos += 2;
        line[pos] = b':';
        pos += 1;
        line[pos..pos+2].copy_from_slice(&itoa2(self.minute));
        pos += 2;
        line[pos] = b':';
        pos += 1;
        line[pos..pos+2].copy_from_slice(&itoa2(self.second));
        pos += 2;
        line[pos] = b'.';
        pos += 1;
        line[pos..pos+3].copy_from_slice(&itoa3(self.millisecond));
        pos += 3;
        line[pos] = b' ';
        pos += 1;
        
        // BOOTLOG_LOADED or BOOTLOG_NOT_LOADED
        line[pos..pos+17].copy_from_slice(self.entry_type.as_str());
        pos += 17;
        line[pos] = b' ';
        pos += 1;
        
        // Path
        for &b in &self.path {
            if b == 0 {
                break;
            }
            line[pos] = b;
            pos += 1;
        }
        
        // CRLF
        line[pos] = b'\r';
        line[pos+1] = b'\n';
        
        line
    }
}

/// Convert u16 to 4-digit ASCII
fn itoa4(n: u16) -> [u8; 4] {
    [
        b'0' + ((n / 1000) % 10) as u8,
        b'0' + ((n / 100) % 10) as u8,
        b'0' + ((n / 10) % 10) as u8,
        b'0' + (n % 10) as u8,
    ]
}

/// Convert u8 to 2-digit ASCII
fn itoa2(n: u8) -> [u8; 2] {
    [
        b'0' + (n / 10) % 10,
        b'0' + n % 10,
    ]
}

/// Convert u16 to 3-digit ASCII
fn itoa3(n: u16) -> [u8; 3] {
    [
        b'0' + ((n / 100) % 10) as u8,
        b'0' + ((n / 10) % 10) as u8,
        b'0' + (n % 10) as u8,
    ]
}

/// Enable boot logging
pub fn enable_boot_log() {
    BOOT_LOG_ENABLED.store(true, Ordering::Release);
    writer::clear_log();
}

/// Disable boot logging
pub fn disable_boot_log() {
    BOOT_LOG_ENABLED.store(false, Ordering::Release);
}

/// Check if boot logging is enabled
pub fn is_enabled() -> bool {
    BOOT_LOG_ENABLED.load(Ordering::Acquire)
}

/// Mark the beginning of the boot sequence
pub fn begin_boot_sequence() {
    IN_BOOT_SEQUENCE.store(true, Ordering::Release);
    
    // Log header
    writer::write_line(b"\r\n");
    writer::write_line(b"Microsoft (R) Windows (R) Boot Log\r\n");
    writer::write_line(b"Version 6.1.7601\r\n");
    writer::write_line(b"\r\n");
    writer::write_line(b"Default = Start Registry\r\n");
    writer::write_line(b"\r\n");
}

/// Mark the end of the boot sequence
pub fn end_boot_sequence() {
    IN_BOOT_SEQUENCE.store(false, Ordering::Release);
    
    writer::write_line(b"\r\n");
    writer::write_line(b"End of Boot Log\r\n");
}

/// Log a driver loading event
pub fn log_driver_load(path: &[u8]) {
    if !is_enabled() {
        return;
    }
    
    let entry = BootLogEntry::new(BootEntryType::Loaded, path);
    let line = entry.format_line();
    writer::write_line(&line);
}

/// Log a driver that was not loaded
pub fn log_driver_not_load(path: &[u8]) {
    if !is_enabled() {
        return;
    }
    
    let entry = BootLogEntry::new(BootEntryType::NotLoaded, path);
    let line = entry.format_line();
    writer::write_line(&line);
}

/// Log ntoskrnl.exe loading
pub fn log_ntoskrnl() {
    log_driver_load(b"\\SystemRoot\\system32\\ntoskrnl.exe");
}

/// Log hal.dll loading
pub fn log_hal() {
    log_driver_load(b"\\SystemRoot\\system32\\hal.dll");
}

/// Log kdcom.dll loading
pub fn log_kdcom() {
    log_driver_load(b"\\SystemRoot\\System32\\drivers\\kdcom.dll");
}

/// Log a disk driver
pub fn log_disk_driver(name: &str) {
    // Path is always 64 bytes; copy what we can
    let mut path_buf = [0u8; 64];
    path_buf[..15].copy_from_slice(b"\\SystemRoot\\Sys");
    path_buf[15..27].copy_from_slice(b"tem32\\drivers");
    path_buf[27] = b'\\';
    let rest = name.as_bytes();
    let n = core::cmp::min(rest.len(), 64 - 28);
    path_buf[28..28 + n].copy_from_slice(&rest[..n]);
    log_driver_load(&path_buf);
}

/// Check if in boot sequence
pub fn is_in_boot_sequence() -> bool {
    IN_BOOT_SEQUENCE.load(Ordering::Acquire)
}

/// Get the ntbtlog.txt file path
pub fn get_log_path() -> &'static str {
    "C:\\Windows\\ntbtlog.txt"
}

/// Get the log contents
pub fn get_log_contents() -> Option<&'static [u8]> {
    writer::get_log()
}
