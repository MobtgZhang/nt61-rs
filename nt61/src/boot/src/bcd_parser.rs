//! BCD hive parser (REGF format) - Compatible with Windows 7 SP2 Standard BCD
//
//! Parses the BCD file as a Windows-style registry hive (REGF format).
//! Standard Windows 7 BCD structure:
//!   - Root key: "NewStoreRoot" or "System"
//!   - Objects: "NewStoreRoot/Objects/{guid}"
//!   - Elements: "NewStoreRoot/Objects/{guid}/Elements/{type-id}/Element"
//
//! Common BCD element types (stored as node names under Elements/):
//!   - 11000001: Device (device path binary)
//!   - 12000002: FilePath (string) - Application path
//!   - 12000004: Description (string)
//!   - 12000005: Locale (string)
//!   - 14000006: DisplayOrder (string list)
//!   - 15000011: Timeout (DWORD)
//!   - 15000013: BootMenuPolicy (DWORD)
//!   - 15000014: BootStatusPolicy (QWORD)
//!   - 21000001: OsDevice (device path binary)
//!   - 22000001: OsLoadOptions (string)
//!   - 22000002: SystemRoot (string)
//!   - 23000003: AssociatedLocator (string)
//!   - 24000001: BcdDeviceLocator (string list)
//!   - 25000004: DebuggerType (DWORD)
//!   - 26000010: EmulatorAlwaysStartPolicy (binary)
//!   - 26000022: DebuggerSettingsBlock (binary)
//
//! Object types:
//!   - 0x10100002: Boot Manager
//!   - 0x10200003: Windows Boot Loader
//!   - 0x10200004: Resume from Hibernate
//!   - 0x10100010: Firmware Boot Manager
//!   - 0x1020000A: BootApp (EFI application)
//

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::bcd_registry::{Hive, HiveError, REG_DWORD};

/// BCD parsing errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BcdError {
    TooSmall,
    InvalidSignature,
    InvalidVersion,
    Truncated,
    MissingObject,
}

impl From<HiveError> for BcdError {
    fn from(e: HiveError) -> Self {
        match e {
            HiveError::TooSmall => BcdError::TooSmall,
            HiveError::BadMagic => BcdError::InvalidSignature,
            HiveError::Truncated => BcdError::Truncated,
            HiveError::OutOfBounds => BcdError::MissingObject,
            HiveError::BadVersion => BcdError::InvalidVersion,
        }
    }
}

/// BCD parser result type
pub type BcdResult<T> = core::result::Result<T, BcdError>;

/// A single boot entry extracted from the BCD hive.
#[derive(Debug, Clone)]
pub struct BcdEntry {
    /// Object GUID (16 bytes, raw).
    pub guid: [u8; 16],
    /// Friendly description from the `12000004` element.
    pub description: String,
    /// Application device path / file path from `12000002` (FilePath).
    pub application_path: String,
}

// ============================================================================
// Friendly name alias table for BCD element types
// ============================================================================

/// Get friendly-name aliases for a given BCD element type ID.
/// Some BCD implementations use friendly names instead of numeric type IDs.
fn aliases_for(type_id: &str) -> &'static [&'static str] {
    match type_id {
        "12000002" => &["ApplicationPath", "FilePath", "path"],
        "12000004" => &["Description", "description"],
        "12000005" => &["Locale", "locale"],
        "21000001" => &["OsDevice", "osdevice"],
        "22000001" => &["OsLoadOptions", "loadoptions"],
        "22000002" => &["SystemRoot", "systemroot"],
        "23000003" => &["AssociatedLocator", "associatedlocator"],
        "14000006" => &["DisplayOrder", "displayorder"],
        "15000011" => &["Timeout", "timeout"],
        "15000013" => &["BootMenuPolicy"],
        "15000014" => &["BootStatusPolicy"],
        _ => &[],
    }
}

// ============================================================================
// Object type constants
// ============================================================================

/// Object type: Windows Boot Loader
pub const OBJECT_TYPE_WINDOWS_BOOT_LOADER: u32 = 0x1020_0003;
/// Object type: BootApp (EFI application)

/// Top-level BCD hive wrapper.
pub struct BcdHive<'a> {
    hive: Hive<'a>,
}

impl<'a> BcdHive<'a> {
    /// Parse a BCD hive from a byte slice.
    pub fn parse(data: &'a [u8]) -> BcdResult<Self> {
        let hive = Hive::parse(data).map_err(BcdError::from)?;
        Ok(Self { hive })
    }

    /// Try to open the Boot Manager object, supporting both "NewStoreRoot" and "System" root keys.
    fn try_open_boot_manager(&self) -> Option<crate::bcd_registry::KeyNode> {
        // Try NewStoreRoot (Windows 8+ style)
        if let Ok(bm) = self
            .hive
            .open("NewStoreRoot/Objects/{9dea862c-5cdd-4e70-acc1-f32b344d4795}")
        {
            return Some(bm);
        }
        if let Ok(bm) = self
            .hive
            .open("Objects/{9dea862c-5cdd-4e70-acc1-f32b344d4795}")
        {
            return Some(bm);
        }
        // Try System (Windows 7 style)
        if let Ok(bm) = self
            .hive
            .open("System/Objects/{9dea862c-5cdd-4e70-acc1-f32b344d4795}")
        {
            return Some(bm);
        }
        None
    }

    /// Try to open the Objects key, supporting both "NewStoreRoot" and "System" root keys.
    fn try_open_objects(&self) -> Option<crate::bcd_registry::KeyNode> {
        // Try NewStoreRoot (Windows 8+ style)
        if let Ok(objs) = self.hive.open("NewStoreRoot/Objects") {
            return Some(objs);
        }
        // Try direct Objects (some layouts have it directly under root)
        if let Ok(objs) = self.hive.open("Objects") {
            return Some(objs);
        }
        // Try System (Windows 7 style)
        if let Ok(objs) = self.hive.open("System/Objects") {
            return Some(objs);
        }
        None
    }

    /// Open `\Objects` and enumerate every immediate subkey as a boot entry.
    pub fn boot_entries(&self) -> BcdResult<Vec<BcdEntry>> {
        // BCD structure: NewStoreRoot\Objects\{guid} or System\Objects\{guid}
        let objects = match self.try_open_objects() {
            Some(o) => o,
            None => {
                uefi::println!("[BCD] ERROR: Could not find Objects key");
                return Ok(Vec::new());
            }
        };

        let children = self.hive.subkeys(&objects)?;
        crate::debug_println!("[BCD] Found {} subkeys under Objects", children.len());

        let mut out = Vec::new();

        for node in &children {
            // BCD object names are `{xxxxxxxx-xxxx-...}` (38 chars).
            if !node.name.starts_with('{') || !node.name.ends_with('}') {
                continue;
            }

            // Parse GUID
            let mut guid = [0u8; 16];
            if parse_guid_braced(&node.name, &mut guid).is_none() {
                continue;
            }

            let object_type = self.get_object_type(&node);

            // Filter by object type: only include entries the Windows 7 boot
            // manager offers in its normal OS menu. Resume objects are BCD
            // metadata for winresume.efi, not user-selectable boot loaders.
            // Skip: Boot Manager (0x10100002), Firmware Boot Manager (0x10100010)
            if object_type != OBJECT_TYPE_WINDOWS_BOOT_LOADER {
                crate::debug_println!("[BCD]   Skipping non-OS-loader entry: {}", node.name);
                continue;
            }

            // Get description from 12000004 element (with friendly alias fallback)
            let description = self
                .get_element_string(&node, "12000004")
                .unwrap_or_else(|| "Unknown".to_string());

            // Skip entries with no description
            if description.is_empty() || description == "Unknown" {
                continue;
            }

            // Get application path from 12000002 element
            let application_path = self
                .get_element_string(&node, "12000002")
                .unwrap_or_default();

            if application_path.is_empty() {
                crate::debug_println!("[BCD]   Skipping invalid entry: {}", node.name);
                continue;
            }

            crate::debug_println!("[BCD]   Entry: {} ({})", description, node.name);

            out.push(BcdEntry {
                guid,
                description,
                application_path,
            });
        }

        Ok(out)
    }

    /// Get object type from the Description/r#type subkey value.
    fn get_object_type(&self, node: &crate::bcd_registry::KeyNode) -> u32 {
        // Look for Description subkey using relative path
        if let Ok(desc_node) = self.hive.open_at(node, "Description") {
            if let Ok(Some(v)) = self.hive.get_value(&desc_node, "Type") {
                if let Some(t) = v.as_u32() {
                    return t;
                }
            }
        }
        0
    }

    /// Get a string element value by type ID (e.g., "12000004").
    /// Tries multiple layouts in order:
    /// 1. Standard: Elements\{type}\Element
    /// 2. Flat: Elements\{type}=value
    /// 3. Direct: {type}=value on object node
    /// 4. Friendly aliases on object node
    fn get_element_string(
        &self,
        node: &crate::bcd_registry::KeyNode,
        element_type: &str,
    ) -> Option<String> {
        // 1. Standard layout: Elements\{type}\Element
        if let Ok(elements_node) = self.hive.open_at(node, "Elements") {
            if let Ok(element_node) = self.hive.open_at(&elements_node, element_type) {
                if let Ok(Some(v)) = self.hive.get_value(&element_node, "Element") {
                    if let Some(s) = v.as_string() {
                        return Some(s);
                    }
                }
            }
            // 2. Flat layout: Elements\{type}=value
            if let Ok(Some(v)) = self.hive.get_value(&elements_node, element_type) {
                if let Some(s) = v.as_string() {
                    return Some(s);
                }
            }
        }

        // 3. Direct value on object node
        if let Ok(Some(v)) = self.hive.get_value(node, element_type) {
            if let Some(s) = v.as_string() {
                return Some(s);
            }
        }

        // 4. Try friendly aliases
        for alias in aliases_for(element_type) {
            if let Ok(Some(v)) = self.hive.get_value(node, alias) {
                if let Some(s) = v.as_string() {
                    return Some(s);
                }
            }
        }

        None
    }

    /// Get a DWORD element value by type ID (e.g., "15000011").
    /// The DWORD may be stored as:
    /// 1. Standard: Elements\{type}\Element (REG_DWORD)
    /// 2. Binary: Elements\{type}\Element with 4-byte binary data
    /// 3. Direct: {type}=value on object node
    /// 4. Friendly aliases
    fn get_element_dword(
        &self,
        node: &crate::bcd_registry::KeyNode,
        element_type: &str,
    ) -> Option<u32> {
        // 1. Standard layout: Elements\{type}\Element
        if let Ok(elements_node) = self.hive.open_at(node, "Elements") {
            if let Ok(element_node) = self.hive.open_at(&elements_node, element_type) {
                if let Ok(Some(v)) = self.hive.get_value(&element_node, "Element") {
                    // Try as REG_DWORD first
                    if v.value_type == REG_DWORD {
                        if let Some(n) = v.as_u32() {
                            return Some(n);
                        }
                    }
                    // Try as binary (4 bytes)
                    if v.data.len() >= 4 {
                        return Some(u32::from_le_bytes([
                            v.data[0], v.data[1], v.data[2], v.data[3],
                        ]));
                    }
                }
            }
            // 2. Flat layout: Elements\{type}=value
            if let Ok(Some(v)) = self.hive.get_value(&elements_node, element_type) {
                if v.value_type == REG_DWORD {
                    if let Some(n) = v.as_u32() {
                        return Some(n);
                    }
                }
                if v.data.len() >= 4 {
                    return Some(u32::from_le_bytes([
                        v.data[0], v.data[1], v.data[2], v.data[3],
                    ]));
                }
            }
        }

        // 3. Direct value on object node
        if let Ok(Some(v)) = self.hive.get_value(node, element_type) {
            if v.value_type == REG_DWORD {
                if let Some(n) = v.as_u32() {
                    return Some(n);
                }
            }
            if v.data.len() >= 4 {
                return Some(u32::from_le_bytes([
                    v.data[0], v.data[1], v.data[2], v.data[3],
                ]));
            }
        }

        // 4. Try friendly aliases
        for alias in aliases_for(element_type) {
            if let Ok(Some(v)) = self.hive.get_value(node, alias) {
                if v.value_type == REG_DWORD {
                    if let Some(n) = v.as_u32() {
                        return Some(n);
                    }
                }
                if v.data.len() >= 4 {
                    return Some(u32::from_le_bytes([
                        v.data[0], v.data[1], v.data[2], v.data[3],
                    ]));
                }
            }
        }

        None
    }

    /// Look up the boot manager's Timeout value, defaulting to 30s.
    pub fn timeout_seconds(&self) -> u32 {
        if let Some(bm) = self.try_open_boot_manager() {
            if let Some(timeout) = self.get_element_dword(&bm, "15000011") {
                return timeout;
            }
        }
        30
    }

    /// Convert the parsed hive into a `BcdStore`.
    pub fn into_store(self) -> crate::bcd::BcdStore {
        use crate::bcd::{BcdStore, BootEntry};
        let mut store = BcdStore::new();

        let entries = match self.boot_entries() {
            Ok(e) => e,
            Err(_) => return store,
        };

        let timeout = self.timeout_seconds();
        store.timeout = timeout;

        for (i, e) in entries.iter().enumerate() {
            if i >= crate::bcd::MAX_ENTRIES {
                break;
            }

            let guid = crate::bcd::Guid(e.guid);
            let entry = BootEntry {
                guid,
                description: crate::bcd::StaticStr::from_str(&e.description),
                application: crate::bcd::StaticStr::from_str(&e.application_path),
            };
            store.entries[i] = Some(entry);
            store.display_order[i] = Some(guid);
            store.entry_count += 1;
            store.display_count += 1;
        }

        store
    }
}

// ============================================================================
// GUID parsing
// ============================================================================

/// Parse a canonical Windows GUID string (`{xxxxxxxx-xxxx-...}`) into raw 16 bytes.
/// Windows GUIDs are stored in mixed-endian form on disk: the first three fields
/// are little-endian, the last two are big-endian.
fn parse_guid_braced(s: &str, out: &mut [u8; 16]) -> Option<()> {
    if s.len() != 38 || !s.starts_with('{') || !s.ends_with('}') {
        return None;
    }
    let inner = &s[1..37];
    let p1_bytes = hex_to_bytes_4(&inner[0..8])?;
    let p2_bytes = hex_to_bytes_2(&inner[9..13])?;
    let p3_bytes = hex_to_bytes_2(&inner[14..18])?;
    let p4 = hex_to_bytes_1(&inner[19..21])?;
    let p5 = hex_to_bytes_1(&inner[21..23])?;
    let p6 = hex_to_bytes_6(&inner[24..36])?;
    out[0] = p1_bytes[0];
    out[1] = p1_bytes[1];
    out[2] = p1_bytes[2];
    out[3] = p1_bytes[3];
    out[4] = p2_bytes[0];
    out[5] = p2_bytes[1];
    out[6] = p3_bytes[0];
    out[7] = p3_bytes[1];
    out[8] = p4[0];
    out[9] = p5[0];
    out[10] = p6[0];
    out[11] = p6[1];
    out[12] = p6[2];
    out[13] = p6[3];
    out[14] = p6[4];
    out[15] = p6[5];
    Some(())
}

fn hex_to_bytes_4(s: &str) -> Option<[u8; 4]> {
    if s.len() != 8 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 4];
    for i in 0..4 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_to_bytes_2(s: &str) -> Option<[u8; 2]> {
    if s.len() != 4 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 2];
    for i in 0..2 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_to_bytes_1(s: &str) -> Option<[u8; 1]> {
    if s.len() != 2 {
        return None;
    }
    let bytes = s.as_bytes();
    let hi = hex_nibble(bytes[0])?;
    let lo = hex_nibble(bytes[1])?;
    Some([(hi << 4) | lo])
}

fn hex_to_bytes_6(s: &str) -> Option<[u8; 6]> {
    if s.len() != 12 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 6];
    for i in 0..6 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
