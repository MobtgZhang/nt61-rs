//! BCD (Boot Configuration Data) Type Definitions
//
//! This module defines the types used in BCD binary parsing.
//! BCD is a binary registry hive format used by Windows 7 Boot Manager.

#![allow(dead_code)]

use core::fmt;

/// BCD-specific GUID type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BcdGuid(pub [u8; 16]);

impl BcdGuid {
    /// Create a new BCD GUID from bytes
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the first 4 bytes for quick matching
    pub fn first_four(&self) -> [u8; 4] {
        [self.0[0], self.0[1], self.0[2], self.0[3]]
    }

    /// Get reference to raw bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Check if GUID matches expected bytes (first 4 bytes)
    pub fn matches_prefix(&self, prefix: &[u8; 4]) -> bool {
        self.first_four() == *prefix
    }
}

impl fmt::Display for BcdGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.0[3], self.0[2], self.0[1], self.0[0],
            self.0[5], self.0[4],
            self.0[7], self.0[6],
            self.0[8], self.0[9],
            self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15])
    }
}

/// Well-known BCD GUIDs
pub mod wellknown {
    use super::BcdGuid;

    /// Current boot entry GUID
    pub const CURRENT_BOOT_ENTRY: BcdGuid = BcdGuid([
        0x9D, 0xA3, 0x12, 0x8B, 0xC1, 0x9A, 0x11, 0xD0,
        0x80, 0x5E, 0x00, 0xC0, 0x4F, 0xD9, 0x38, 0x9C,
    ]);

    /// Boot manager GUID
    pub const BOOT_MANAGER: BcdGuid = BcdGuid([
        0x9D, 0xA3, 0x12, 0x8B, 0xC1, 0x9A, 0x11, 0xD0,
        0x80, 0x5E, 0x00, 0xC0, 0x4F, 0xD9, 0x38, 0x9D,
    ]);

    /// Windows boot loader GUID
    pub const WINDOWS_BOOT_LOADER: BcdGuid = BcdGuid([
        0xA5, 0xDC, 0x26, 0x9A, 0xE6, 0xB7, 0x11, 0xD0,
        0x93, 0xF7, 0x00, 0xA0, 0xC9, 0x69, 0xD4, 0x69,
    ]);

    /// Windows 7 normal boot entry (first 4 bytes: 0x9DEA862C)
    pub const ENTRY_WINDOWS_7: BcdGuid = BcdGuid([
        0x9D, 0xEA, 0x86, 0x2C, 0x5C, 0xDD, 0x4E, 0x70,
        0xAC, 0xC1, 0xF3, 0x2B, 0x34, 0x4D, 0x47, 0x95,
    ]);

    /// Windows 7 Safe Mode CMD (first 4 bytes: 0xB2721D66)
    pub const ENTRY_SAFE_MODE_CMD: BcdGuid = BcdGuid([
        0xB2, 0x72, 0x1D, 0x66, 0x7D, 0xBF, 0x4E, 0x50,
        0xAE, 0x7C, 0xD2, 0x7F, 0x2D, 0x90, 0xCE, 0x20,
    ]);

    /// Windows 7 Safe Mode Debug (first 4 bytes: 0x5189B25C)
    pub const ENTRY_SAFE_MODE_DEBUG: BcdGuid = BcdGuid([
        0x51, 0x89, 0xB2, 0x5C, 0x55, 0x58, 0x4B, 0xF2,
        0xBB, 0x0F, 0xCD, 0x5A, 0x4F, 0x8C, 0x7E, 0x20,
    ]);
}

/// BCD element types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BcdElementType {
    // Object elements (0x11000001-0x11XXXXXX)
    Device = 0x11000001,
    Object = 0x11000002,
    
    // Description elements (0x12000001-0x15XXXXXX)
    Description = 0x12000001,
    BootSequence = 0x14000001,
    DisplayOrder = 0x14000002,
    Sequence = 0x14000003,
    DefaultSequence = 0x14000004,
    Timeout = 0x15000001,
    
    // Tools elements (0x16000001-0x16XXXXXX)
    ToolsDisplayOrder = 0x16000001,
    BootLoadOptions = 0x16000002,
    DebuggerSettings = 0x16000003,
    DebuggerType = 0x16000004,
    SerialPort = 0x16000005,
    SerialBaudRate = 0x16000006,
    
    // OS Loader elements (0x21000001-0x23XXXXXX)
    OsDevice = 0x21000001,
    FilePath = 0x21000002,
    OsLoadOptions = 0x22000001,
    LoadOptions = 0x23000001,
    
    // Unknown element type
    Unknown = 0xFFFFFFFF,
}

impl BcdElementType {
    /// Parse element type from raw u32 value
    pub fn from_u32(val: u32) -> Self {
        match val {
            0x11000001 => Self::Device,
            0x11000002 => Self::Object,
            0x12000001 => Self::Description,
            0x14000001 => Self::BootSequence,
            0x14000002 => Self::DisplayOrder,
            0x14000003 => Self::Sequence,
            0x14000004 => Self::DefaultSequence,
            0x15000001 => Self::Timeout,
            0x16000001 => Self::ToolsDisplayOrder,
            0x16000002 => Self::BootLoadOptions,
            0x16000003 => Self::DebuggerSettings,
            0x16000004 => Self::DebuggerType,
            0x16000005 => Self::SerialPort,
            0x16000006 => Self::SerialBaudRate,
            0x21000001 => Self::OsDevice,
            0x21000002 => Self::FilePath,
            0x22000001 => Self::OsLoadOptions,
            0x23000001 => Self::LoadOptions,
            _ => Self::Unknown,
        }
    }
}

/// BCD element value types
#[derive(Debug, Clone)]
pub enum BcdValue {
    /// Integer value (u64)
    Integer(u64),
    /// Boolean value
    Boolean(bool),
    /// String value (UTF-16LE)
    String(alloc::vec::Vec<u16>),
    /// GUID reference
    Guid(BcdGuid),
    /// Device path (binary)
    DevicePath(alloc::vec::Vec<u8>),
    /// Multiple GUIDs (for lists)
    GuidList(alloc::vec::Vec<BcdGuid>),
}

impl BcdValue {
    /// Get integer value if this is an integer type
    pub fn as_integer(&self) -> Option<u64> {
        match self {
            BcdValue::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// Get string value if this is a string type
    pub fn as_string(&self) -> Option<&[u16]> {
        match self {
            BcdValue::String(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Get GUID value if this is a GUID type
    pub fn as_guid(&self) -> Option<BcdGuid> {
        match self {
            BcdValue::Guid(g) => Some(*g),
            _ => None,
        }
    }
}

/// A single BCD element
#[derive(Debug, Clone)]
pub struct BcdElement {
    /// Element type
    pub element_type: BcdElementType,
    /// Element value
    pub value: BcdValue,
}

/// A BCD object (represents a boot entry)
#[derive(Debug, Clone)]
pub struct BcdObject {
    /// Object GUID
    pub guid: BcdGuid,
    /// Object flags
    pub flags: u32,
    /// Elements belonging to this object
    pub elements: alloc::vec::Vec<BcdElement>,
}

impl BcdObject {
    /// Get an element by type
    pub fn get_element(&self, etype: BcdElementType) -> Option<&BcdElement> {
        self.elements.iter().find(|e| e.element_type == etype)
    }
}

/// BCD file header
#[derive(Debug, Clone)]
pub struct BcdHeader {
    /// BCD signature ("BBCD")
    pub signature: [u8; 4],
    /// BCD version
    pub version: u32,
    /// Reserved
    pub reserved: u32,
    /// Object list offset
    pub object_list_offset: u32,
    /// Object list size
    pub object_list_size: u32,
    /// Element list offset
    pub element_list_offset: u32,
    /// Element list size
    pub element_list_size: u32,
    /// String store offset
    pub string_store_offset: u32,
    /// String store size
    pub string_store_size: u32,
}

impl BcdHeader {
    /// BCD file signature
    pub const SIGNATURE: [u8; 4] = [0x42, 0x42, 0x43, 0x44]; // "BBCD"
    
    /// BCD version for Windows 7
    pub const VERSION_WIN7: u32 = 0x00000003;
    
    /// Check if header is valid
    pub fn is_valid(&self) -> bool {
        self.signature == Self::SIGNATURE
    }
}

/// BCD mailbox structure (for boot manager -> winload handoff)
/// 
/// This is the shared memory structure at physical address 0x10_100
/// used to pass boot parameters from boot manager to winload.
#[repr(C)]
pub struct BcdMailbox {
    /// Signature "BCDE"
    pub signature: [u8; 4],
    /// Version (0x00000003 for Windows 7)
    pub version: u32,
    /// Total length of mailbox structure
    pub length: u32,
    /// Entry GUID (16 bytes)
    pub entry_guid: [u8; 16],
    /// Boot options (variable length, up to 224 bytes)
    pub boot_options: [u8; 224],
}

impl BcdMailbox {
    /// Mailbox signature
    pub const SIGNATURE: [u8; 4] = [b'B', b'C', b'D', b'E'];
    
    /// Mailbox version for Windows 7
    pub const VERSION: u32 = 0x00000003;
    
    /// Physical address where mailbox is located
    pub const PHYS_ADDRESS: u64 = 0x10_100;
    
    /// Check if mailbox is valid
    pub fn is_valid(&self) -> bool {
        self.signature == Self::SIGNATURE && self.version == Self::VERSION
    }
    
    /// Get entry GUID as BcdGuid
    pub fn entry_guid(&self) -> BcdGuid {
        BcdGuid::new(self.entry_guid)
    }
}
