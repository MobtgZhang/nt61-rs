//! Kernel Logging Infrastructure
//
//! Provides Windows-compatible multi-level logging system with subsystem-based
//! filtering and KdCom debugger integration.
//
//! # Unified Log Format
//
//! All kernel log entries follow this format:
//
//! ```text
//! [TIMESTAMP ] [LEVEL] [SUBSYSTEM] [CPU] Message
//! ```
//
//! - `TIMESTAMP`: `[SSSSSS.mmm]` - Seconds since boot with millisecond precision
//! - `LEVEL`: 6-char padded level (`Error `, `Warn  `, `Info  `, `Debug `)
//! - `SUBSYSTEM`: Subsystem identifier (e.g., `KERNEL`, `MEMORY`, `IO`)
//! - `CPU`: Processor number (0-99)
//! - `Message`: Log message content
//
//! # Usage
//
//! For new code, prefer using `kprintln_info!`, `kprintln_warn!`, etc.
//! from `crate::rtl::klog` (via the module re-export).
//
//! # Compile-time Configuration
//
//! The default log level is INFO. Use Cargo features to change:
//! - `log_level_debug` — enables DEBUG and all higher levels
//! - `log_level_info`  — enables INFO and all higher levels (default)
//! - `log_level_warn`  — enables WARN and all higher levels
//! - `log_level_error` — enables ERROR only

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Log Level
// ---------------------------------------------------------------------------

/// Kernel log severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    Error = 0,
    Warn  = 1,
    Info  = 2,
    Debug = 3,
}

impl LogLevel {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "Error ",
            LogLevel::Warn  => "Warn  ",
            LogLevel::Info  => "Info  ",
            LogLevel::Debug => "Debug ",
        }
    }

    #[inline]
    pub fn as_prefix(self) -> &'static str {
        match self {
            LogLevel::Error => "ERROR",
            LogLevel::Warn  => "WARN ",
            LogLevel::Info  => "INFO ",
            LogLevel::Debug => "DEBUG",
        }
    }
}

// ---------------------------------------------------------------------------
// Subsystem Flags
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    pub struct SubsystemFlags: u32 {
        const KERNEL     = 1 << 0;
        const MEMORY     = 1 << 1;
        const PROCESS    = 1 << 2;
        const IO         = 1 << 3;
        const FILESYSTEM = 1 << 4;
        const DRIVER    = 1 << 5;
        const NET       = 1 << 6;
        const CLFS      = 1 << 7;
        const REGISTRY   = 1 << 8;
        const DPC       = 1 << 9;
        const IRQL      = 1 << 10;
        const SYNC      = 1 << 11;
        const HAL       = 1 << 12;
        const ARCH      = 1 << 13;
        const VFS       = 1 << 14;
        const FAT32     = 1 << 15;
        const NTFS      = 1 << 16;
        const USB       = 1 << 17;
        const STORAGE   = 1 << 18;
        const AUDIO     = 1 << 19;
        const VIDEO     = 1 << 20;
        const INPUT     = 1 << 21;
        const WIN32K    = 1 << 22;
        const NDIS      = 1 << 23;
        const KDCOM     = 1 << 24;
        const DBG        = 1 << 25;
        const SMOKE      = 1 << 26;
        const PS        = 1 << 27;
        const THREAD    = 1 << 28;
        const SCHED     = 1 << 29;
        const OB        = 1 << 30;
        const FS        = 1 << 31;
    }
}

pub mod subsystem {
    use super::SubsystemFlags;
    pub const KERNEL:     u32 = SubsystemFlags::KERNEL.bits();
    pub const MEMORY:     u32 = SubsystemFlags::MEMORY.bits();
    pub const PROCESS:    u32 = SubsystemFlags::PROCESS.bits();
    pub const IO:        u32 = SubsystemFlags::IO.bits();
    pub const FILESYSTEM:u32 = SubsystemFlags::FILESYSTEM.bits();
    pub const DRIVER:    u32 = SubsystemFlags::DRIVER.bits();
    pub const NET:       u32 = SubsystemFlags::NET.bits();
    pub const CLFS:      u32 = SubsystemFlags::CLFS.bits();
    pub const REGISTRY:   u32 = SubsystemFlags::REGISTRY.bits();
    pub const DPC:       u32 = SubsystemFlags::DPC.bits();
    pub const IRQL:      u32 = SubsystemFlags::IRQL.bits();
    pub const SYNC:      u32 = SubsystemFlags::SYNC.bits();
    pub const HAL:       u32 = SubsystemFlags::HAL.bits();
    pub const ARCH:      u32 = SubsystemFlags::ARCH.bits();
    pub const VFS:       u32 = SubsystemFlags::VFS.bits();
    pub const FAT32:     u32 = SubsystemFlags::FAT32.bits();
    pub const NTFS:      u32 = SubsystemFlags::NTFS.bits();
    pub const USB:       u32 = SubsystemFlags::USB.bits();
    pub const STORAGE:   u32 = SubsystemFlags::STORAGE.bits();
    pub const AUDIO:     u32 = SubsystemFlags::AUDIO.bits();
    pub const VIDEO:     u32 = SubsystemFlags::VIDEO.bits();
    pub const INPUT:     u32 = SubsystemFlags::INPUT.bits();
    pub const WIN32K:    u32 = SubsystemFlags::WIN32K.bits();
    pub const NDIS:      u32 = SubsystemFlags::NDIS.bits();
    pub const KDCOM:    u32 = SubsystemFlags::KDCOM.bits();
    pub const DBG:      u32 = SubsystemFlags::DBG.bits();
    pub const SMOKE:    u32 = SubsystemFlags::SMOKE.bits();
    pub const PS:       u32 = SubsystemFlags::PS.bits();
    pub const THREAD:   u32 = SubsystemFlags::THREAD.bits();
    pub const SCHED:    u32 = SubsystemFlags::SCHED.bits();
    pub const OB:       u32 = SubsystemFlags::OB.bits();
    pub const FS:       u32 = SubsystemFlags::FS.bits();
}

/// Per-subsystem log level overrides.
static SUBSYSTEM_LEVELS: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);

/// Set the log level for a specific subsystem.
pub fn set_subsystem_level(subsystem: SubsystemFlags, level: LogLevel) {
    let bits = subsystem.bits();
    let override_val = (level as u32) << 16;
    let new_val = (SUBSYSTEM_LEVELS.load(Ordering::Relaxed) & !bits) | (bits & override_val);
    SUBSYSTEM_LEVELS.store(new_val, Ordering::Relaxed);
}

#[inline]
fn get_effective_level(subsystem_bits: u32) -> LogLevel {
    let stored = SUBSYSTEM_LEVELS.load(Ordering::Relaxed);
    if subsystem_bits & stored != 0 {
        let override_level = (stored >> 16) as u8;
        if override_level <= LogLevel::Debug as u8 {
            return unsafe { core::mem::transmute(override_level) };
        }
    }
    GLOBAL_LOG_LEVEL
}

// ---------------------------------------------------------------------------
// Global Log Level
// ---------------------------------------------------------------------------

#[cfg(feature = "log_level_debug")]
pub const GLOBAL_LOG_LEVEL: LogLevel = LogLevel::Debug;
#[cfg(feature = "log_level_info")]
pub const GLOBAL_LOG_LEVEL: LogLevel = LogLevel::Info;
#[cfg(feature = "log_level_warn")]
pub const GLOBAL_LOG_LEVEL: LogLevel = LogLevel::Warn;
#[cfg(feature = "log_level_error")]
pub const GLOBAL_LOG_LEVEL: LogLevel = LogLevel::Error;
#[cfg(all(
    not(feature = "log_level_error"),
    not(feature = "log_level_warn"),
    not(feature = "log_level_debug")
))]
pub const GLOBAL_LOG_LEVEL: LogLevel = LogLevel::Info;

// ---------------------------------------------------------------------------
// CRC32
// ---------------------------------------------------------------------------

const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut j = 0usize;
        while j < 8 {
            if c & 0x8000_0000 != 0 {
                c = (c << 1) ^ 0x04C1_1DB7;
            } else {
                c <<= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

#[inline]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in data {
        let idx = ((crc >> 24) ^ (byte as u32)) as usize;
        crc = (crc << 8) ^ CRC32_TABLE[idx];
    }
    !crc
}

// ---------------------------------------------------------------------------
// Architecture: CPU number
// ---------------------------------------------------------------------------

pub fn current_cpu() -> u32 {
    0
}

// ---------------------------------------------------------------------------
// Boot Timestamp (monotonic, starts at 0 at kernel entry)
// ---------------------------------------------------------------------------

/// Boot time counter - increments every millisecond
static BOOT_TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Initialize the boot timer. Called once at kernel entry.
pub fn init_boot_timer() {
    BOOT_TICK_COUNTER.store(0, Ordering::Release);
}

/// Add milliseconds to the boot timer. Called by the scheduler timer interrupt.
pub fn add_boot_ticks(ms: u64) {
    BOOT_TICK_COUNTER.fetch_add(ms, Ordering::Relaxed);
}

/// Get current boot time in milliseconds.
pub fn get_boot_ms() -> u64 {
    BOOT_TICK_COUNTER.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Timestamp formatting
// ---------------------------------------------------------------------------

/// Format: `[SSSSSS.mmm]` - seconds since boot with millisecond precision
/// Fixed width: 12 characters
#[inline]
pub fn format_timestamp_fixed(buf: &mut [u8; 13], boot_ms: u64) -> usize {
    let seconds = boot_ms / 1000;
    let ms = (boot_ms % 1000) as u32;

    let s0 = ((seconds / 100000) % 10) as u8;
    let s1 = ((seconds / 10000) % 10) as u8;
    let s2 = ((seconds / 1000) % 10) as u8;
    let s3 = ((seconds / 100) % 10) as u8;
    let s4 = ((seconds / 10) % 10) as u8;
    let s5 = (seconds % 10) as u8;

    let m0 = ((ms / 100) % 10) as u8;
    let m1 = ((ms / 10) % 10) as u8;
    let m2 = (ms % 10) as u8;

    // Format: [SSSSSS.mmm]
    buf[0] = b'[';
    buf[1] = s0 + b'0';
    buf[2] = s1 + b'0';
    buf[3] = s2 + b'0';
    buf[4] = s3 + b'0';
    buf[5] = s4 + b'0';
    buf[6] = s5 + b'0';
    buf[7] = b'.';
    buf[8] = m0 + b'0';
    buf[9] = m1 + b'0';
    buf[10] = m2 + b'0';
    buf[11] = b']';
    buf[12] = b' ';
    13
}

/// Format subsystem name to fixed 10-char width
#[inline]
pub fn format_subsystem_fixed(buf: &mut [u8; 11], name: &str) -> usize {
    let bytes = name.as_bytes();
    let len = bytes.len().min(10);

    for i in 0..len {
        buf[i] = bytes[i];
    }
    // Pad with spaces
    for i in len..10 {
        buf[i] = b' ';
    }
    buf[10] = b' ';
    11
}

// ---------------------------------------------------------------------------
// Core log output (called by the wrapper macros)
// ---------------------------------------------------------------------------

/// Map a subsystem name (string) to its `SubsystemFlags` bit value.
///
/// Used by the leveled `kprintln!` macro and `log_write_atomic` to
/// apply the per-subsystem level filter. Unknown subsystem names
/// fall back to `KERNEL` so new subsystems don't accidentally get
/// bypassed.
pub fn subsystem_to_bits(name: &str) -> u32 {
    use self::subsystem::*;
    match name {
        "KERNEL"     => KERNEL,
        "MEMORY"     => MEMORY,
        "PROCESS"    => PROCESS,
        "IO"         => IO,
        "FILESYSTEM" => FILESYSTEM,
        "FS"         => FILESYSTEM,
        "DRIVER"     => DRIVER,
        "NET"        => NET,
        "CLFS"       => CLFS,
        "REGISTRY"   => REGISTRY,
        "DPC"        => DPC,
        "IRQL"       => IRQL,
        "SYNC"       => SYNC,
        "HAL"        => HAL,
        "ARCH"       => ARCH,
        "VFS"        => VFS,
        "FAT32"      => FAT32,
        "NTFS"       => NTFS,
        "USB"        => USB,
        "STORAGE"    => STORAGE,
        "AUDIO"      => AUDIO,
        "VIDEO"      => VIDEO,
        "INPUT"      => INPUT,
        "WIN32K"     => WIN32K,
        "NDIS"       => NDIS,
        "KDCOM"      => KDCOM,
        "DBG"        => DBG,
        "SMOKE"      => SMOKE,
        "PS"         => PS,
        "THREAD"     => THREAD,
        "SCHED"      => SCHED,
        "OB"         => OB,
        "APC"        => SYNC,
        "TIMER"      => DPC,
        "PAGER"      => MEMORY,
        _            => KERNEL,
    }
}

/// Filtered serial-output entry point used by the leveled `kprintln!`
/// macro. Performs the level/subsystem gate before delegating to
/// `log_write_impl` (which does the actual prefix-formatted serial
/// write).
///
/// # When this is silent
///
/// The call is dropped without further work when
/// `should_log(level, subsystem_to_bits(subsystem))` is false. This
/// is the hot path for muted subsystems (e.g. `Debug`-level calls
/// when `GLOBAL_LOG_LEVEL == Info`).
#[inline]
pub fn log_write_atomic(level: LogLevel, subsystem: &str, cpu: u32, message: &str) {
    let subsystem_bits = subsystem_to_bits(subsystem);
    if !should_log(level, subsystem_bits) {
        return;
    }
    log_write_impl(level, subsystem, cpu, message);
}

/// Core log output implementation - formats and writes to serial port.
/// Format: `[SSSSSS.mmm] [LEVEL] [SUBSYSTEM] [CPU] Message\r\n`
pub fn log_write_impl(level: LogLevel, subsystem: &str, cpu: u32, message: &str) {
    let mut line_buf = [0u8; 320];
    let mut pos = 0;

    // 1. Timestamp: [SSSSSS.mmm]
    let ts = get_boot_ms();
    let ts_secs = ts / 1000;
    let ts_ms = (ts % 1000) as u32;

    line_buf[pos] = b'['; pos += 1;
    // Write 6-digit seconds
    let s0 = ((ts_secs / 100000) % 10) as u8;
    let s1 = ((ts_secs / 10000) % 10) as u8;
    let s2 = ((ts_secs / 1000) % 10) as u8;
    let s3 = ((ts_secs / 100) % 10) as u8;
    let s4 = ((ts_secs / 10) % 10) as u8;
    let s5 = (ts_secs % 10) as u8;
    line_buf[pos] = s0 + b'0'; pos += 1;
    line_buf[pos] = s1 + b'0'; pos += 1;
    line_buf[pos] = s2 + b'0'; pos += 1;
    line_buf[pos] = s3 + b'0'; pos += 1;
    line_buf[pos] = s4 + b'0'; pos += 1;
    line_buf[pos] = s5 + b'0'; pos += 1;
    line_buf[pos] = b'.'; pos += 1;
    // Write 3-digit milliseconds
    let m0 = ((ts_ms / 100) % 10) as u8;
    let m1 = ((ts_ms / 10) % 10) as u8;
    let m2 = (ts_ms % 10) as u8;
    line_buf[pos] = m0 + b'0'; pos += 1;
    line_buf[pos] = m1 + b'0'; pos += 1;
    line_buf[pos] = m2 + b'0'; pos += 1;
    line_buf[pos] = b']'; pos += 1;
    line_buf[pos] = b' '; pos += 1;

    // 2. Level: [LEVEL]
    let level_str = level.as_str();
    line_buf[pos] = b'['; pos += 1;
    for &b in level_str.as_bytes() {
        line_buf[pos] = b; pos += 1;
    }
    line_buf[pos] = b']'; pos += 1;
    line_buf[pos] = b' '; pos += 1;

    // 3. Subsystem: [SUBSYSTEM] (padded to 10 chars)
    line_buf[pos] = b'['; pos += 1;
    for (i, &b) in subsystem.as_bytes().iter().enumerate() {
        if i < 10 { line_buf[pos] = b; pos += 1; }
    }
    // Pad with spaces
    let sub_len = subsystem.len().min(10);
    while pos < 11 + sub_len {
        line_buf[pos] = b' '; pos += 1;
    }
    line_buf[pos] = b']'; pos += 1;
    line_buf[pos] = b' '; pos += 1;

    // 4. CPU: [CPU]
    line_buf[pos] = b'['; pos += 1;
    if cpu >= 10 {
        line_buf[pos] = b'0' + (cpu / 10) as u8; pos += 1;
    }
    line_buf[pos] = b'0' + (cpu % 10) as u8; pos += 1;
    line_buf[pos] = b']'; pos += 1;
    line_buf[pos] = b' '; pos += 1;

    // 5. Message
    for &b in message.as_bytes() {
        line_buf[pos] = b; pos += 1;
    }

    // 6. Line ending
    line_buf[pos] = b'\r'; pos += 1;
    line_buf[pos] = b'\n'; pos += 1;

    let line_slice = &line_buf[..pos];
    crate::rtl::klog::write_serial(core::str::from_utf8(line_slice).unwrap_or("<bad log utf8>"));
}

#[inline]
pub fn should_log(level: LogLevel, subsystem_bits: u32) -> bool {
    level <= get_effective_level(subsystem_bits)
}
