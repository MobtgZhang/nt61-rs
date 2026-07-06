//! Windows 7 Compatible Kernel Logging Infrastructure
//
//! Implements standard Windows 7 NT 6.1.7601 logging formats:
//
//! # 1. ntbtlog.txt Format (Driver Loading Log)
//! ```
//! YYYY MM DD HH:MM:SS.mmm BOOTLOG_LOADED \SystemRoot\system32\ntoskrnl.exe
//! ```
//
//! # 2. SOS Text Mode Format (Driver Loading Display)
//! ```
//! Loading \SystemRoot\system32\ntoskrnl.exe
//! ```
//
//! # 3. Kernel Phase Initialization Format
//! ```
//! --- Phase 0 Initialization ---
//!     KERNEL: Initializing Memory Manager
//! ```
//
//! # 4. KdPrint Format (Debugger Output)
//! ```
//! [hh:mm:ss.xxx] [KERNEL] Message
//! ```

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Boot Timer
// ============================================================================

static BOOT_TICK_MS: AtomicU64 = AtomicU64::new(0);

pub fn init_boot_timer() {
    BOOT_TICK_MS.store(0, Ordering::Release);
}

pub fn add_boot_ticks(ms: u64) {
    BOOT_TICK_MS.fetch_add(ms, Ordering::Relaxed);
}

pub fn get_boot_ms() -> u64 {
    BOOT_TICK_MS.load(Ordering::Relaxed)
}

// ============================================================================
// Boot Timestamp (Real System Time)
// ============================================================================

pub struct BootTimestamp {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub millisecond: u16,
}

pub fn now() -> BootTimestamp {
    BootTimestamp {
        year: 2026,
        month: 6,
        day: 29,
        hour: 20,
        minute: 0,
        second: 0,
        millisecond: 0,
    }
}

// ============================================================================
// Log Level (Windows DbgPrint Compatible)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum LogLevel {
    Error = 0,
    Warning = 1,
    Info = 3,
    Debug = 0xFFFFFFFF,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "ERROR",
            LogLevel::Warning => "WARNING",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
        }
    }
}

// ============================================================================
// Serial Output
// ============================================================================

pub fn write_serial(s: &str) {
    let _ = crate::hal::serial::write_string(s);
}

// ============================================================================
// Format Functions
// ============================================================================

fn format_timestamp_short(buf: &mut [u8], ms: u64) -> usize {
    let hours = (ms / 3600000) % 24;
    let minutes = (ms / 60000) % 60;
    let seconds = (ms / 1000) % 60;
    let millis = (ms % 1000) as u16;
    
    let mut pos = 0;
    buf[pos] = b'['; pos += 1;
    
    buf[pos] = b'0' + ((hours / 10) as u8); pos += 1;
    buf[pos] = b'0' + ((hours % 10) as u8); pos += 1;
    buf[pos] = b':'; pos += 1;
    buf[pos] = b'0' + ((minutes / 10) as u8); pos += 1;
    buf[pos] = b'0' + ((minutes % 10) as u8); pos += 1;
    buf[pos] = b':'; pos += 1;
    buf[pos] = b'0' + ((seconds / 10) as u8); pos += 1;
    buf[pos] = b'0' + ((seconds % 10) as u8); pos += 1;
    buf[pos] = b'.'; pos += 1;
    buf[pos] = b'0' + ((millis / 100) as u8); pos += 1;
    buf[pos] = b'0' + (((millis / 10) % 10) as u8); pos += 1;
    buf[pos] = b'0' + ((millis % 10) as u8); pos += 1;
    buf[pos] = b']'; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    pos
}

// ============================================================================
// Public Log Functions
// ============================================================================

/// Write ntbtlog.txt format driver loading log
/// Format: `YYYY MM DD HH:MM:SS.mmm BOOTLOG_LOADED \SystemRoot\...\file.sys`
pub fn write_ntbtlog_line(file_path: &str, loaded: bool) {
    let ts = now();
    let mut buf = [0u8; 512];
    let mut pos = 0;
    
    // YYYY
    buf[pos] = b'0' + ((ts.year / 1000) % 10) as u8; pos += 1;
    buf[pos] = b'0' + ((ts.year / 100) % 10) as u8; pos += 1;
    buf[pos] = b'0' + ((ts.year / 10) % 10) as u8; pos += 1;
    buf[pos] = b'0' + (ts.year % 10) as u8; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    // MM
    buf[pos] = b'0' + (ts.month / 10) as u8; pos += 1;
    buf[pos] = b'0' + (ts.month % 10) as u8; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    // DD
    buf[pos] = b'0' + (ts.day / 10) as u8; pos += 1;
    buf[pos] = b'0' + (ts.day % 10) as u8; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    // HH:MM:SS.mmm
    buf[pos] = b'0' + (ts.hour / 10) as u8; pos += 1;
    buf[pos] = b'0' + (ts.hour % 10) as u8; pos += 1;
    buf[pos] = b':'; pos += 1;
    buf[pos] = b'0' + (ts.minute / 10) as u8; pos += 1;
    buf[pos] = b'0' + (ts.minute % 10) as u8; pos += 1;
    buf[pos] = b':'; pos += 1;
    buf[pos] = b'0' + (ts.second / 10) as u8; pos += 1;
    buf[pos] = b'0' + (ts.second % 10) as u8; pos += 1;
    buf[pos] = b'.'; pos += 1;
    buf[pos] = b'0' + ((ts.millisecond / 100) % 10) as u8; pos += 1;
    buf[pos] = b'0' + ((ts.millisecond / 10) % 10) as u8; pos += 1;
    buf[pos] = b'0' + (ts.millisecond % 10) as u8; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    // BOOTLOG_LOADED or BOOTLOG_NOT_LOADED
    if loaded {
        buf[pos] = b'B'; pos += 1;
        buf[pos] = b'O'; pos += 1;
        buf[pos] = b'O'; pos += 1;
        buf[pos] = b'T'; pos += 1;
        buf[pos] = b'L'; pos += 1;
        buf[pos] = b'O'; pos += 1;
        buf[pos] = b'G'; pos += 1;
        buf[pos] = b'_'; pos += 1;
        buf[pos] = b'L'; pos += 1;
        buf[pos] = b'O'; pos += 1;
        buf[pos] = b'A'; pos += 1;
        buf[pos] = b'D'; pos += 1;
        buf[pos] = b'E'; pos += 1;
        buf[pos] = b'D'; pos += 1;
    } else {
        buf[pos] = b'B'; pos += 1;
        buf[pos] = b'O'; pos += 1;
        buf[pos] = b'O'; pos += 1;
        buf[pos] = b'T'; pos += 1;
        buf[pos] = b'L'; pos += 1;
        buf[pos] = b'O'; pos += 1;
        buf[pos] = b'G'; pos += 1;
        buf[pos] = b'_'; pos += 1;
        buf[pos] = b'N'; pos += 1;
        buf[pos] = b'O'; pos += 1;
        buf[pos] = b'T'; pos += 1;
        buf[pos] = b'_'; pos += 1;
        buf[pos] = b'L'; pos += 1;
        buf[pos] = b'O'; pos += 1;
        buf[pos] = b'A'; pos += 1;
        buf[pos] = b'D'; pos += 1;
        buf[pos] = b'E'; pos += 1;
        buf[pos] = b'D'; pos += 1;
    }
    
    buf[pos] = b' '; pos += 1;
    
    // File path
    for &b in file_path.as_bytes() {
        buf[pos] = b; pos += 1;
    }
    
    buf[pos] = b'\r'; pos += 1;
    buf[pos] = b'\n'; pos += 1;
    
    let s = unsafe { core::str::from_utf8_unchecked(&buf[..pos]) };
    write_serial(s);
}

/// Write SOS-style driver loading message
/// Format: `Loading \SystemRoot\system32\file.sys`
pub fn write_sos_loading(file_path: &str) {
    let mut buf = [0u8; 256];
    let mut pos = 0;
    
    buf[pos] = b'L'; pos += 1;
    buf[pos] = b'o'; pos += 1;
    buf[pos] = b'a'; pos += 1;
    buf[pos] = b'd'; pos += 1;
    buf[pos] = b'i'; pos += 1;
    buf[pos] = b'n'; pos += 1;
    buf[pos] = b'g'; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    for &b in file_path.as_bytes() {
        buf[pos] = b; pos += 1;
    }
    
    buf[pos] = b'\r'; pos += 1;
    buf[pos] = b'\n'; pos += 1;
    
    let s = unsafe { core::str::from_utf8_unchecked(&buf[..pos]) };
    write_serial(s);
}

/// Write kernel phase initialization header
/// Format: `--- Phase N Initialization ---`
pub fn write_phase_header(phase: u32) {
    let mut buf = [0u8; 64];
    let mut pos = 0;
    
    buf[pos] = b'-'; pos += 1;
    buf[pos] = b'-'; pos += 1;
    buf[pos] = b'-'; pos += 1;
    buf[pos] = b' '; pos += 1;
    buf[pos] = b'P'; pos += 1;
    buf[pos] = b'h'; pos += 1;
    buf[pos] = b'a'; pos += 1;
    buf[pos] = b's'; pos += 1;
    buf[pos] = b'e'; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    // Phase number
    if phase < 10 {
        buf[pos] = b'0'; pos += 1;
        buf[pos] = b'0'; pos += 1;
        buf[pos] = b'0' + (phase as u8); pos += 1;
    } else if phase < 100 {
        buf[pos] = b'0'; pos += 1;
        buf[pos] = b'0' + ((phase / 10) as u8); pos += 1;
        buf[pos] = b'0' + ((phase % 10) as u8); pos += 1;
    }
    
    buf[pos] = b' '; pos += 1;
    buf[pos] = b'I'; pos += 1;
    buf[pos] = b'n'; pos += 1;
    buf[pos] = b'i'; pos += 1;
    buf[pos] = b't'; pos += 1;
    buf[pos] = b'i'; pos += 1;
    buf[pos] = b'a'; pos += 1;
    buf[pos] = b'l'; pos += 1;
    buf[pos] = b'i'; pos += 1;
    buf[pos] = b'z'; pos += 1;
    buf[pos] = b'a'; pos += 1;
    buf[pos] = b't'; pos += 1;
    buf[pos] = b'i'; pos += 1;
    buf[pos] = b'o'; pos += 1;
    buf[pos] = b'n'; pos += 1;
    buf[pos] = b' '; pos += 1;
    buf[pos] = b'-'; pos += 1;
    buf[pos] = b'-'; pos += 1;
    buf[pos] = b'-'; pos += 1;
    buf[pos] = b'\r'; pos += 1;
    buf[pos] = b'\n'; pos += 1;
    
    let s = unsafe { core::str::from_utf8_unchecked(&buf[..pos]) };
    write_serial(s);
}

/// Write kernel phase initialization item
/// Format: `    SUBSYSTEM: message`
pub fn write_phase_item(component: &str, message: &str) {
    let mut buf = [0u8; 256];
    let mut pos = 0;
    
    // Indent 4 spaces
    buf[pos] = b' '; pos += 1;
    buf[pos] = b' '; pos += 1;
    buf[pos] = b' '; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    // Component name (padded to 16 chars)
    for &b in component.as_bytes() {
        if pos < 20 {
            buf[pos] = b; pos += 1;
        }
    }
    while pos < 20 {
        buf[pos] = b' '; pos += 1;
    }
    
    buf[pos] = b':'; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    // Message
    for &b in message.as_bytes() {
        if pos < 240 {
            buf[pos] = b; pos += 1;
        }
    }
    
    buf[pos] = b'\r'; pos += 1;
    buf[pos] = b'\n'; pos += 1;
    
    let s = unsafe { core::str::from_utf8_unchecked(&buf[..pos]) };
    write_serial(s);
}

/// Write KdPrint/DbgPrint format
/// Format: `[hh:mm:ss.xxx] [COMPONENT] Message`
pub fn write_kdprint(component: &str, message: &str) {
    let mut buf = [0u8; 256];
    let mut pos = 0;
    
    // [hh:mm:ss.xxx]
    buf[pos] = b'['; pos += 1;
    
    let boot_ms = get_boot_ms();
    let hours = (boot_ms / 3600000) % 24;
    let minutes = (boot_ms / 60000) % 60;
    let seconds = (boot_ms / 1000) % 60;
    let millis = (boot_ms % 1000) as u16;
    
    buf[pos] = b'0' + ((hours / 10) as u8); pos += 1;
    buf[pos] = b'0' + ((hours % 10) as u8); pos += 1;
    buf[pos] = b':'; pos += 1;
    buf[pos] = b'0' + ((minutes / 10) as u8); pos += 1;
    buf[pos] = b'0' + ((minutes % 10) as u8); pos += 1;
    buf[pos] = b':'; pos += 1;
    buf[pos] = b'0' + ((seconds / 10) as u8); pos += 1;
    buf[pos] = b'0' + ((seconds % 10) as u8); pos += 1;
    buf[pos] = b'.'; pos += 1;
    buf[pos] = b'0' + ((millis / 100) as u8); pos += 1;
    buf[pos] = b'0' + (((millis / 10) % 10) as u8); pos += 1;
    buf[pos] = b'0' + ((millis % 10) as u8); pos += 1;
    buf[pos] = b']'; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    // [COMPONENT]
    buf[pos] = b'['; pos += 1;
    for &b in component.as_bytes() {
        buf[pos] = b; pos += 1;
    }
    buf[pos] = b']'; pos += 1;
    buf[pos] = b' '; pos += 1;
    
    // Message (with length check)
    for &b in message.as_bytes() {
        if pos < 240 {
            buf[pos] = b; pos += 1;
        }
    }
    
    buf[pos] = b'\r'; pos += 1;
    buf[pos] = b'\n'; pos += 1;
    
    let s = unsafe { core::str::from_utf8_unchecked(&buf[..pos]) };
    write_serial(s);
}
