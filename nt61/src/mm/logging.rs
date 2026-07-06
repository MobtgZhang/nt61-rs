//! Memory Manager Logging System
//
//! Provides a log level system for memory manager debug output.
//! Allows filtering of messages based on verbosity level.

use core::sync::atomic::{AtomicU8, Ordering};

/// Log levels for memory manager output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    /// Fatal errors - system cannot continue
    Fatal = 0,
    /// Error conditions - operation failed
    Error = 1,
    /// Warning conditions -需要注意的情况
    Warn = 2,
    /// Informational messages - 正常操作信息
    Info = 3,
    /// Debug messages - 调试信息
    Debug = 4,
    /// Trace messages - 详细跟踪信息
    Trace = 5,
}

impl LogLevel {
    /// Get the name of this log level as a string
    pub fn name(&self) -> &'static str {
        match self {
            LogLevel::Fatal => "FATAL",
            LogLevel::Error => "ERROR",
            LogLevel::Warn => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
            LogLevel::Trace => "TRACE",
        }
    }

    /// Get the ANSI color code for this log level (for terminal output)
    pub fn color(&self) -> &'static str {
        match self {
            LogLevel::Fatal => "\x1b[1;31m",   // Bold red
            LogLevel::Error => "\x1b[31m",     // Red
            LogLevel::Warn => "\x1b[33m",      // Yellow
            LogLevel::Info => "\x1b[32m",      // Green
            LogLevel::Debug => "\x1b[36m",     // Cyan
            LogLevel::Trace => "\x1b[90m",     // Bright black/gray
        }
    }

    /// Reset ANSI color
    pub const RESET: &'static str = "\x1b[0m";
}

/// Current log level for the memory manager.
/// Default is Info level. Set to Debug or Trace for more verbose output.
static MM_LOG_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

/// Get the current log level
pub fn get_log_level() -> LogLevel {
    let level = MM_LOG_LEVEL.load(Ordering::Relaxed);
    match level {
        0 => LogLevel::Fatal,
        1 => LogLevel::Error,
        2 => LogLevel::Warn,
        3 => LogLevel::Info,
        4 => LogLevel::Debug,
        5 => LogLevel::Trace,
        _ => LogLevel::Info,
    }
}

/// Set the log level at runtime
pub fn set_log_level(level: LogLevel) {
    MM_LOG_LEVEL.store(level as u8, Ordering::SeqCst);
}

/// Check if a message at the given level should be printed
#[inline]
pub fn should_log(level: LogLevel) -> bool {
    level as u8 <= MM_LOG_LEVEL.load(Ordering::Relaxed)
}

/// Conditional logging macro for memory manager.
/// Usage: kprintln_mm!(LogLevel::Debug, "value = {}", x);
#[macro_export]
macro_rules! kprintln_mm {
    ($level:expr, $($arg:tt)*) => {
        if $level as u8 <= crate::mm::logging::MM_LOG_LEVEL.load(core::sync::atomic::Ordering::Relaxed) {
            // kprintln disabled (memcpy crash workaround)
        }
    };
}

/// Conditional logging macro with color support.
/// Only works when MM_LOG_WITH_COLOR is enabled.
#[macro_export]
macro_rules! kprintln_mm_color {
    ($level:expr, $($arg:tt)*) => {
        if $level as u8 <= crate::mm::logging::MM_LOG_LEVEL.load(core::sync::atomic::Ordering::Relaxed) {
            // kprintln disabled (memcpy crash workaround)
        }
    };
}

/// Log a message at the specified level with subsystem tag.
/// Usage: mm_log!(Error, "PFN", "Allocation failed");
#[macro_export]
macro_rules! mm_log {
    ($level:expr, $subsystem:expr, $($arg:tt)*) => {
        if $level as u8 <= crate::mm::logging::MM_LOG_LEVEL.load(core::sync::atomic::Ordering::Relaxed) {
            // // crate::kprintln!(concat!("[", $subsystem, "] ", $($arg)*))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        }
    };
}

/// Get a mutable reference to the log level for initialization
pub fn init_log_level() {
    // Default log level is Info
    MM_LOG_LEVEL.store(LogLevel::Info as u8, Ordering::SeqCst);
}

/// Initialize the logging system
pub fn init() {
    init_log_level();
    // // kprintln!("[MM LOG] Memory manager logging initialized at {} level", get_log_level().name())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Print current log level settings
pub fn print_settings() {
    let _level = get_log_level();
    // _level is intentionally unused - reserved for future logging
    // // kprintln!("=== Memory Manager Log Settings ===")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  Current level: {} ({})", _level.name(), _level as u8)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  Level values: Fatal=0, Error=1, Warn=2, Info=3, Debug=4, Trace=5")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("================================")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

// =============================================================================
// Convenience functions for common logging patterns
// =============================================================================

/// Log PFN-related operations
pub fn log_pfn_alloc(_pfn: u64, _from_list: &str) {
    // _pfn and _from_list are intentionally unused - reserved for future logging
    if should_log(LogLevel::Debug) {
        // // kprintln!("[PFN] Allocate: pfn={} from={}", _pfn, _from_list)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Log PFN free operations
pub fn log_pfn_free(_pfn: u64) {
    // _pfn is intentionally unused - reserved for future logging
    if should_log(LogLevel::Debug) {
        // // kprintln!("[PFN] Free: pfn={}", _pfn)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Log page fault information
pub fn log_page_fault(_addr: u64, _fault_type: &str) {
    // _addr and _fault_type are intentionally unused - reserved for future logging
    if should_log(LogLevel::Trace) {
        // // kprintln!("[PF] Fault @ 0x{:016x}: {}", _addr, _fault_type)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Log VAS operations
pub fn log_vas_operation(_op: &str, _va: u64) {
    // _op and _va are intentionally unused - reserved for future logging
    if should_log(LogLevel::Debug) {
        // // kprintln!("[VAS] {}: va=0x{:016x}", _op, _va)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Log self-map operations
pub fn log_selfmap(_status: &str, _detail: u64) {
    // _status and _detail are intentionally unused - reserved for future logging
    if should_log(LogLevel::Debug) {
        // // kprintln!("[SELF-MAP] {}: 0x{:016x}", _status, _detail)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Log memory pressure events
pub fn log_memory_pressure(_pressure: f32, _action: &str) {
    // _pressure and _action are intentionally unused - reserved for future logging
    if should_log(LogLevel::Info) {
        // // kprintln!("[MEM] Pressure {:.2}%: {}", _pressure, _action)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Fatal < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Trace);
    }

    #[test]
    fn test_log_level_names() {
        assert_eq!(LogLevel::Fatal.name(), "FATAL");
        assert_eq!(LogLevel::Error.name(), "ERROR");
        assert_eq!(LogLevel::Warn.name(), "WARN");
        assert_eq!(LogLevel::Info.name(), "INFO");
        assert_eq!(LogLevel::Debug.name(), "DEBUG");
        assert_eq!(LogLevel::Trace.name(), "TRACE");
    }

    #[test]
    fn test_should_log() {
        // Set to Info level
        set_log_level(LogLevel::Info);
        assert!(should_log(LogLevel::Info));
        assert!(should_log(LogLevel::Warn));
        assert!(should_log(LogLevel::Error));
        assert!(should_log(LogLevel::Fatal));
        assert!(!should_log(LogLevel::Debug));
        assert!(!should_log(LogLevel::Trace));

        // Set to Debug level
        set_log_level(LogLevel::Debug);
        assert!(should_log(LogLevel::Debug));
        assert!(should_log(LogLevel::Trace));
    }
}
