//! Video Driver Logging Utilities
//
//! Provides unified serial logging for all video driver modules.
//! Replaces the commented-out `kprintln!` calls that were disabled
//! due to the memcpy crash workaround.
//!
//! Uses the existing `crate::hal::x86_64::serial::write_string`
//! infrastructure, formatting messages as `[VID] module: message\r\n`.

#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::serial;

/// write a video driver log message via the serial port.
///
/// Format: `[VID] module: message\r\n`
///
/// All video driver modules should use this instead of the disabled
/// `kprintln!` macro.
#[cfg(target_arch = "x86_64")]
pub fn video_log(module: &str, msg: &str) {
    if log_level_debug() {
        serial::write_string("[VID] ");
        serial::write_string(module);
        serial::write_string(": ");
        serial::write_string(msg);
        serial::write_string("\r\n");
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn video_log(_module: &str, _msg: &str) {}

/// write a video driver log message with a u32 hex value.
/// Format: `[VID] module: msg_prefix 0xHEXVAL\r\n`
#[cfg(target_arch = "x86_64")]
pub fn video_log_hex(module: &str, prefix: &str, value: u32) {
    if log_level_debug() {
        serial::write_string("[VID] ");
        serial::write_string(module);
        serial::write_string(": ");
        serial::write_string(prefix);
        serial::write_string(" 0x");
        serial::write_u32_hex(value);
        serial::write_string("\r\n");
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn video_log_hex(_module: &str, _prefix: &str, _value: u32) {}

/// write a video driver log message with a u64 hex value.
/// Format: `[VID] module: msg_prefix 0xHEXVAL\r\n`
#[cfg(target_arch = "x86_64")]
pub fn video_log_hex64(module: &str, prefix: &str, value: u64) {
    if log_level_debug() {
        serial::write_string("[VID] ");
        serial::write_string(module);
        serial::write_string(": ");
        serial::write_string(prefix);
        serial::write_string(" 0x");
        serial::write_u64_hex(value);
        serial::write_string("\r\n");
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn video_log_hex64(_module: &str, _prefix: &str, _value: u64) {}

/// write a video driver error message.
/// Format: `[VID] module: ERROR: message\r\n`
#[cfg(target_arch = "x86_64")]
pub fn video_error(module: &str, msg: &str) {
    serial::write_string_always("[VID] ");
    serial::write_string_always(module);
    serial::write_string_always(": ERROR: ");
    serial::write_string_always(msg);
    serial::write_string_always("\r\n");
}

#[cfg(not(target_arch = "x86_64"))]
pub fn video_error(_module: &str, _msg: &str) {}

/// write a video driver warn message.
/// Format: `[VID] module: WARN: message\r\n`
#[cfg(target_arch = "x86_64")]
pub fn video_warn(module: &str, msg: &str) {
    serial::write_string_always("[VID] ");
    serial::write_string_always(module);
    serial::write_string_always(": WARN: ");
    serial::write_string_always(msg);
    serial::write_string_always("\r\n");
}

#[cfg(not(target_arch = "x86_64"))]
pub fn video_warn(_module: &str, _msg: &str) {}

/// write a video driver success/OK message.
/// Format: `[VID] module: OK: message\r\n`
#[cfg(target_arch = "x86_64")]
pub fn video_ok(module: &str, msg: &str) {
    if log_level_debug() {
        serial::write_string("[VID] ");
        serial::write_string(module);
        serial::write_string(": OK: ");
        serial::write_string(msg);
        serial::write_string("\r\n");
    }
}

#[cfg(target_arch = "x86_64")]
fn log_level_debug() -> bool {
    cfg!(feature = "log_level_debug")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn video_ok(_module: &str, _msg: &str) {}
