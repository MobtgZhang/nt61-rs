//! Windows Event Log Channels

use super::{EventChannel, EventLevel};

/// Channel metadata
#[derive(Debug, Clone, Copy)]
pub struct ChannelInfo {
    pub name: &'static str,
    pub display_name: &'static str,
    pub file_name: &'static str,
    pub enabled: bool,
    pub default_level: EventLevel,
    pub isolation: ChannelIsolation,
    pub is_security: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum ChannelIsolation {
    Application,
    System,
    Custom,
}

/// Get channel information
pub fn get_channel_info(channel: EventChannel) -> ChannelInfo {
    match channel {
        EventChannel::System => ChannelInfo {
            name: "System",
            display_name: "System",
            file_name: "System.evtx",
            enabled: true,
            default_level: EventLevel::Information,
            isolation: ChannelIsolation::System,
            is_security: false,
        },
        EventChannel::Application => ChannelInfo {
            name: "Application",
            display_name: "Application",
            file_name: "Application.evtx",
            enabled: true,
            default_level: EventLevel::Information,
            isolation: ChannelIsolation::Application,
            is_security: false,
        },
        EventChannel::Security => ChannelInfo {
            name: "Security",
            display_name: "Security",
            file_name: "Security.evtx",
            enabled: true,
            default_level: EventLevel::Information,
            isolation: ChannelIsolation::System,
            is_security: true,
        },
        EventChannel::Setup => ChannelInfo {
            name: "Setup",
            display_name: "Setup",
            file_name: "Setup.evtx",
            enabled: true,
            default_level: EventLevel::Information,
            isolation: ChannelIsolation::System,
            is_security: false,
        },
        EventChannel::ForwardedEvents => ChannelInfo {
            name: "ForwardedEvents",
            display_name: "Forwarded Events",
            file_name: "ForwardedEvents.evtx",
            enabled: false,
            default_level: EventLevel::Verbose,
            isolation: ChannelIsolation::Custom,
            is_security: false,
        },
    }
}

/// Windows Event Log file paths (canonical form)
pub mod paths {
    pub const WINEVT_LOGS_DIR: &str = "C:\\Windows\\System32\\winevt\\Logs";
    pub const SYSTEM_EVTX: &str = "C:\\Windows\\System32\\winevt\\Logs\\System.evtx";
    pub const APPLICATION_EVTX: &str = "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx";
    pub const SECURITY_EVTX: &str = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";
    pub const SETUP_EVTX: &str = "C:\\Windows\\System32\\winevt\\Logs\\Setup.evtx";
    pub const FORWARDED_EVENTS_EVTX: &str = "C:\\Windows\\System32\\winevt\\Logs\\ForwardedEvents.evtx";
}

/// Channel access rights
pub mod access {
    pub const READ_EVENTS: u32 = 0x0001;
    pub const WRITE_EVENTS: u32 = 0x0002;
    pub const CLEAR_LOG: u32 = 0x0004;
    pub const MANAGE_SUBSCRIPTIONS: u32 = 0x0008;
    pub const ALL_ACCESS: u32 = 0x00FF;
}

/// Channel configuration
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    pub name: [u8; 64],
    pub file_name: [u8; 128],
    pub max_size: u64,
    pub retention_days: u32,
    pub enabled: bool,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            name: [0u8; 64],
            file_name: [0u8; 128],
            max_size: 20 * 1024 * 1024,
            retention_days: 0,
            enabled: true,
        }
    }
}

impl ChannelConfig {
    pub fn system() -> Self {
        let mut config = Self::default();
        config.name[..6].copy_from_slice(b"System");
        config.file_name[..11].copy_from_slice(b"System.evtx");
        config
    }
    pub fn application() -> Self {
        let mut config = Self::default();
        config.name[..11].copy_from_slice(b"Application");
        config.file_name[..15].copy_from_slice(b"Application.evtx");
        config
    }
    pub fn security() -> Self {
        let mut config = Self::default();
        config.name[..8].copy_from_slice(b"Security");
        config.file_name[..13].copy_from_slice(b"Security.evtx");
        config
    }
    pub fn setup() -> Self {
        let mut config = Self::default();
        config.name[..5].copy_from_slice(b"Setup");
        config.file_name[..10].copy_from_slice(b"Setup.evtx");
        config
    }
}
