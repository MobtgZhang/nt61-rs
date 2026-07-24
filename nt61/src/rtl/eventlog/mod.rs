//! Windows Event Log System
//
//! Implements Windows Event Log (.evtx) semantics compatible with NT 6.1.7601.
//
//! # Channels
//
//! - `System.evtx`, `Application.evtx`, `Security.evtx`, `Setup.evtx`,
//!   `ForwardedEvents.evtx` are the standard 5 channels.

#![allow(dead_code)]

extern crate alloc;

pub mod evtx;
pub mod channels;
pub mod xml_export;

use alloc::vec::Vec;

/// Event log level (matches Windows Event Viewer)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventLevel {
    LogAlways = 0,
    Critical = 1,
    Error = 2,
    Warning = 3,
    Information = 4,
    Verbose = 5,
}

impl EventLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventLevel::LogAlways => "LogAlways",
            EventLevel::Critical => "Critical",
            EventLevel::Error => "Error",
            EventLevel::Warning => "Warning",
            EventLevel::Information => "Information",
            EventLevel::Verbose => "Verbose",
        }
    }
}

/// Event keyword flags (Windows 7 standard values)
#[derive(Debug, Clone, Copy, Default)]
pub struct EventKeywords(pub u64);

impl EventKeywords {
    pub const CLASSIFICATION_OK: EventKeywords = EventKeywords(0x0000_0000_0000_0000);
    pub const CLASSIFICATION_RPC: EventKeywords = EventKeywords(0x0000_0000_0000_1000);
    pub const CLASSIFICATION_LOCAL_QM: EventKeywords = EventKeywords(0x0000_0000_0000_4000);
    pub const CLASSIFICATION_CALLCAP: EventKeywords = EventKeywords(0x0000_0000_0000_8000);
    pub const CLASSIFICATION_SECURITY: EventKeywords = EventKeywords(0x1000_0000_0000_0000);
    pub const CLASSIFICATION_WDI: EventKeywords = EventKeywords(0x0800_0000_0000_0000);
    pub const CLASSIFICATION_SQM: EventKeywords = EventKeywords(0x0400_0000_0000_0000);
    pub const CLASSIFICATION_AUDIT: EventKeywords = EventKeywords(0x0200_0000_0000_0000);
    pub const CLASSIFICATION_DIAG: EventKeywords = EventKeywords(0x0100_0000_0000_0000);
    pub const CLASSIFICATION_EVENTLOG: EventKeywords = EventKeywords(0x0080_0000_0000_0000);
    pub const CLASSIFICATION_RT: EventKeywords = EventKeywords(0x0040_0000_0000_0000);
}

/// Event record structure (fixed-size, no heap allocation)
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub record_id: u64,
    pub timestamp: u64,
    pub source: [u8; 64],
    pub source_len: u8,
    pub event_id: u16,
    pub version: u8,
    pub level: EventLevel,
    pub task: u16,
    pub keywords: EventKeywords,
    pub user: [u8; 128],
    pub user_len: u8,
    pub computer: [u8; 64],
    pub computer_len: u8,
    pub channel: EventChannel,
    pub activity_id: u64,
    pub related_activity_id: u64,
    /// Event data stored as a fixed-size UTF-16LE buffer (no Vec)
    pub event_data: [u16; 256],
    pub event_data_len: u16,
}

impl EventRecord {
    /// Create a new event record with the given source, event ID, and level
    pub fn new(source: &[u8], event_id: u16, level: EventLevel) -> Self {
        let mut src = [0u8; 64];
        let mut src_len: u8 = 0;
        for (i, &b) in source.iter().take(63).enumerate() {
            src[i] = b;
            src_len = (i + 1) as u8;
        }

        let mut computer = [0u8; 64];
        let computer_bytes = b"NT6.1.7601";
        let mut computer_len: u8 = 0;
        for (i, &b) in computer_bytes.iter().take(63).enumerate() {
            computer[i] = b;
            computer_len = (i + 1) as u8;
        }

        Self {
            record_id: 0,
            timestamp: 0,
            source: src,
            source_len: src_len,
            event_id,
            version: 0,
            level,
            task: 0,
            keywords: EventKeywords::default(),
            user: [0u8; 128],
            user_len: 0,
            computer,
            computer_len,
            channel: EventChannel::System,
            activity_id: 0,
            related_activity_id: 0,
            event_data: [0u16; 256],
            event_data_len: 0,
        }
    }

    /// Set the event description (truncated to fit in 256 UTF-16 code units)
    pub fn set_description(&mut self, desc: &str) {
        self.event_data_len = 0;
        for (i, c) in desc.encode_utf16().enumerate() {
            if i >= 255 {
                break;
            }
            self.event_data[i] = c;
            self.event_data_len = (i + 1) as u16;
        }
    }
}

/// Current timestamp in Windows FILETIME format (100-nanosecond intervals since 1601-01-01)
pub fn current_filetime() -> u64 {
    const WINDOWS_TICK: u64 = 10_000_000;
    const SECS_1601_TO_1970: u64 = 11_644_473_600;
    SECS_1601_TO_1970 * WINDOWS_TICK
}

/// Event channel (log name)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventChannel {
    System = 0,
    Application = 1,
    Security = 2,
    Setup = 3,
    ForwardedEvents = 4,
}

impl EventChannel {
    pub fn name(&self) -> &'static [u8] {
        match self {
            EventChannel::System => b"System\0",
            EventChannel::Application => b"Application\0",
            EventChannel::Security => b"Security\0",
            EventChannel::Setup => b"Setup\0",
            EventChannel::ForwardedEvents => b"ForwardedEvents\0",
        }
    }

    pub fn evtx_file(&self) -> &'static str {
        match self {
            EventChannel::System => "System.evtx",
            EventChannel::Application => "Application.evtx",
            EventChannel::Security => "Security.evtx",
            EventChannel::Setup => "Setup.evtx",
            EventChannel::ForwardedEvents => "ForwardedEvents.evtx",
        }
    }
}

/// Event log manager (fixed capacity)
pub const MAX_RECORDS: usize = 64;

pub struct EventLog {
    pub records: [Option<EventRecord>; MAX_RECORDS],
    pub count: usize,
    pub next_record_id: u64,
    pub channel: EventChannel,
}

impl EventLog {
    pub const fn new(channel: EventChannel) -> Self {
        Self {
            records: [const { None }; MAX_RECORDS],
            count: 0,
            next_record_id: 1,
            channel,
        }
    }

    pub fn write(&mut self, mut record: EventRecord) {
        if self.count >= MAX_RECORDS {
            return;
        }
        record.record_id = self.next_record_id;
        if record.timestamp == 0 {
            record.timestamp = current_filetime();
        }
        self.next_record_id += 1;
        self.records[self.count] = Some(record);
        self.count += 1;
    }

    pub fn export_evtx(&self) -> Vec<u8> {
        let mut tmp = alloc::vec::Vec::new();
        for slot in &self.records[..self.count] {
            if let Some(rec) = slot { tmp.push(rec.clone()); }
        }
        evtx::write_evtx_file(&tmp, self.channel)
    }

    pub fn export_xml(&self) -> Vec<u8> {
        let mut tmp = alloc::vec::Vec::new();
        for slot in &self.records[..self.count] {
            if let Some(rec) = slot { tmp.push(rec.clone()); }
        }
        xml_export::records_to_xml(&tmp, self.channel)
    }
}

// ============================================================================
// Global Event Logs (Windows 7 default channels)
// ============================================================================

use core::sync::atomic::{AtomicBool, Ordering};

static mut SYSTEM_LOG: [u8; core::mem::size_of::<EventLog>()] = [0; core::mem::size_of::<EventLog>()];
static mut APPLICATION_LOG: [u8; core::mem::size_of::<EventLog>()] = [0; core::mem::size_of::<EventLog>()];
static mut SECURITY_LOG: [u8; core::mem::size_of::<EventLog>()] = [0; core::mem::size_of::<EventLog>()];
static mut SETUP_LOG: [u8; core::mem::size_of::<EventLog>()] = [0; core::mem::size_of::<EventLog>()];

static SYSTEM_LOG_INIT: AtomicBool = AtomicBool::new(false);
static APPLICATION_LOG_INIT: AtomicBool = AtomicBool::new(false);
static SECURITY_LOG_INIT: AtomicBool = AtomicBool::new(false);
static SETUP_LOG_INIT: AtomicBool = AtomicBool::new(false);

fn cast_log_init<'a>(storage: &'a mut [u8], init_flag: &AtomicBool) -> Option<&'a mut EventLog> {
    if !init_flag.load(Ordering::Acquire) {
        return None;
    }
    let ptr = storage.as_mut_ptr() as *mut EventLog;
    unsafe { Some(&mut *ptr) }
}

fn system_log_mut() -> Option<&'static mut EventLog> {
    // SAFETY: SYSTEM_LOG is a `static mut` of zero-initialised storage
    // that `init()` re-writes with a valid `EventLog` value before the
    // `SYSTEM_LOG_INIT` flag is published; reading through `cast_log_init`
    // only happens after the flag has been set, so the cast is sound.
    unsafe { cast_log_init(&mut SYSTEM_LOG, &SYSTEM_LOG_INIT) }
}

fn application_log_mut() -> Option<&'static mut EventLog> {
    unsafe { cast_log_init(&mut APPLICATION_LOG, &APPLICATION_LOG_INIT) }
}

fn security_log_mut() -> Option<&'static mut EventLog> {
    unsafe { cast_log_init(&mut SECURITY_LOG, &SECURITY_LOG_INIT) }
}

fn setup_log_mut() -> Option<&'static mut EventLog> {
    unsafe { cast_log_init(&mut SETUP_LOG, &SETUP_LOG_INIT) }
}

/// Initialize all event logs
pub fn init() {
    // SAFETY: each log is initialized exactly once at boot
    unsafe {
        let ptr = core::ptr::addr_of!(SYSTEM_LOG) as *mut EventLog;
        core::ptr::write(ptr, EventLog::new(EventChannel::System));
        SYSTEM_LOG_INIT.store(true, Ordering::Release);

        let ptr = core::ptr::addr_of!(APPLICATION_LOG) as *mut EventLog;
        core::ptr::write(ptr, EventLog::new(EventChannel::Application));
        APPLICATION_LOG_INIT.store(true, Ordering::Release);

        let ptr = core::ptr::addr_of!(SECURITY_LOG) as *mut EventLog;
        core::ptr::write(ptr, EventLog::new(EventChannel::Security));
        SECURITY_LOG_INIT.store(true, Ordering::Release);

        let ptr = core::ptr::addr_of!(SETUP_LOG) as *mut EventLog;
        core::ptr::write(ptr, EventLog::new(EventChannel::Setup));
        SETUP_LOG_INIT.store(true, Ordering::Release);
    }

    let mut record = EventRecord::new(b"Microsoft-Windows-Kernel-General", 1, EventLevel::Information);
    record.set_description("The system boot has begun.");
    if let Some(log) = system_log_mut() {
        log.write(record);
    }
}

/// Write an event to the System log
pub fn write_system_event(event_id: u16, level: EventLevel, source: &[u8], description: &str) {
    let mut record = EventRecord::new(source, event_id, level);
    record.set_description(description);
    record.channel = EventChannel::System;
    if let Some(log) = system_log_mut() {
        log.write(record);
    }
}

/// Write an event to the Application log
pub fn write_application_event(event_id: u16, level: EventLevel, source: &[u8], description: &str) {
    let mut record = EventRecord::new(source, event_id, level);
    record.set_description(description);
    record.channel = EventChannel::Application;
    if let Some(log) = application_log_mut() {
        log.write(record);
    }
}

/// Write an event to the Setup log
pub fn write_setup_event(event_id: u16, level: EventLevel, source: &[u8], description: &str) {
    let mut record = EventRecord::new(source, event_id, level);
    record.set_description(description);
    record.channel = EventChannel::Setup;
    if let Some(log) = setup_log_mut() {
        log.write(record);
    }
}

/// Write an event to the Security log
pub fn write_security_event(event_id: u16, level: EventLevel, source: &[u8], description: &str) {
    let mut record = EventRecord::new(source, event_id, level);
    record.set_description(description);
    record.channel = EventChannel::Security;
    if let Some(log) = security_log_mut() {
        log.write(record);
    }
}

/// Snapshot read of system log records (returns count found)
pub fn system_log_count() -> usize {
    if let Some(log) = system_log_mut() {
        log.count
    } else {
        0
    }
}

pub fn application_log_count() -> usize {
    if let Some(log) = application_log_mut() {
        log.count
    } else {
        0
    }
}

pub fn security_log_count() -> usize {
    if let Some(log) = security_log_mut() {
        log.count
    } else {
        0
    }
}

pub fn setup_log_count() -> usize {
    if let Some(log) = setup_log_mut() {
        log.count
    } else {
        0
    }
}

// ============================================================================
// Common Windows Event IDs
// ============================================================================

/// Microsoft-Windows-Kernel-General events
pub mod kernel_events {
    use super::*;

    pub const EVENT_BOOT_START: u16 = 10;
    pub const EVENT_SHUTDOWN_REQUEST: u16 = 11;
    pub const EVENT_SHUTDOWN_COMPLETE: u16 = 12;

    pub fn log_boot_start() {
        write_system_event(
            EVENT_BOOT_START,
            EventLevel::Information,
            b"Microsoft-Windows-Kernel-General",
            "The system boot has begun.",
        );
    }

    pub fn log_boot_complete() {
        write_system_event(
            EVENT_BOOT_START,
            EventLevel::Information,
            b"Microsoft-Windows-Kernel-General",
            "The system boot has completed.",
        );
    }
}

/// Microsoft-Windows-Kernel-Boot events
pub mod boot_events {
    use super::*;

    pub const EVENT_DRIVERS_LOAD: u16 = 23;

    pub fn log_ntoskrnl_load() {
        write_setup_event(
            22,
            EventLevel::Information,
            b"Microsoft-Windows-Kernel-Boot",
            "\\SystemRoot\\system32\\ntoskrnl.exe",
        );
    }

    pub fn log_driver_load(driver_path: &str) {
        let mut record = EventRecord::new(
            b"Microsoft-Windows-Kernel-Boot",
            EVENT_DRIVERS_LOAD,
            EventLevel::Information,
        );
        record.set_description(driver_path);
        record.channel = EventChannel::Setup;
        if let Some(log) = setup_log_mut() {
            log.write(record);
        }
    }
}

/// Microsoft-Windows-Security-Auditing events
pub mod security_events {
    use super::*;

    pub const EVENT_LOGON: u16 = 4624;
    pub const EVENT_LOGOFF: u16 = 4634;
    pub const EVENT_PRIVILEGE_USE: u16 = 4672;

    pub fn log_logon(username: &str) {
        let desc_static = "An account was successfully logged on.";
        let mut record = EventRecord::new(
            b"Microsoft-Windows-Security-Auditing",
            EVENT_LOGON,
            EventLevel::Information,
        );
        record.set_description(desc_static);
        record.channel = EventChannel::Security;
        // username is stored separately in user field
        let user_bytes = username.as_bytes();
        let n = if user_bytes.len() > 127 { 127 } else { user_bytes.len() };
        record.user[..n].copy_from_slice(&user_bytes[..n]);
        record.user_len = n as u8;
        if let Some(log) = security_log_mut() {
            log.write(record);
        }
    }
}

/// Microsoft-Windows-WindowsUpdateClient events
pub mod update_events {
    use super::*;

    pub const EVENT_UPDATE_START: u16 = 18;

    pub fn log_update_install(update_id: &str) {
        let mut record = EventRecord::new(
            b"Microsoft-Windows-WindowsUpdateClient",
            EVENT_UPDATE_START,
            EventLevel::Information,
        );
        record.set_description(update_id);
        record.channel = EventChannel::Application;
        if let Some(log) = application_log_mut() {
            log.write(record);
        }
    }
}
