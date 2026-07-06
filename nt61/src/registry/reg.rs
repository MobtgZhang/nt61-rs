//! Windows Registry
//
//! These are the low-level wrapper types that the rest of the
//! kernel uses. The real binary-format parser lives in
//! `registry::hive`, and the high-level configuration manager
//! lives in `registry::cm`. This file remains so that the
//! historical `RegistryHive` and `RegValueType` enums continue
//! to resolve for any caller that still uses them.

/// Registry hives. The values match the Windows 7 hive IDs so
/// callers can use a single enum throughout the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryHive {
    Unknown = 0,
    System,
    Software,
    SAM,
    Security,
    Default,
    BCD,
}

impl RegistryHive {
    pub fn as_str(&self) -> &'static str {
        match self {
            RegistryHive::System => "System",
            RegistryHive::Software => "Software",
            RegistryHive::SAM => "SAM",
            RegistryHive::Security => "Security",
            RegistryHive::Default => "Default",
            RegistryHive::BCD => "BCD",
            RegistryHive::Unknown => "Unknown",
        }
    }
}

/// Registry key handle (kept for callers that still use the
/// raw handle type). Real keys are reached through
/// `registry::cm::query_value` / `enumerate_subkeys`.
pub type RegKeyHandle = *mut RegistryKey;

/// Registry key — kept as a thin compatibility wrapper. New
/// code should use `registry::hive::KeyNode` or
/// `registry::cm::query_value`.
pub struct RegistryKey {
    pub hive: RegistryHive,
    pub name: [u16; 256],
    pub subkeys: [*mut RegistryKey; 16],
    pub subkey_count: usize,
}

impl RegistryKey {
    pub fn new(hive: RegistryHive) -> Self {
        Self {
            hive,
            name: [0; 256],
            subkeys: [core::ptr::null_mut(); 16],
            subkey_count: 0,
        }
    }
}

/// Registry value types — re-exported from `hive::ValueType`.
pub use crate::registry::hive::ValueType as RegValueType;

/// Registry value — kept as a thin compatibility wrapper.
pub struct RegValue {
    pub value_type: RegValueType,
    pub data: [u8; 256],
    pub data_len: usize,
}

impl RegValue {
    pub fn new(value_type: RegValueType) -> Self {
        Self {
            value_type,
            data: [0; 256],
            data_len: 0,
        }
    }
}
