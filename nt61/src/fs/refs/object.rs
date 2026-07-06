//! ReFS Object ID Management
//
//! Implements object ID to file record mapping for ReFS.
//! Every file/directory in ReFS has a unique 64-bit object ID.
//
//! ## Object ID Structure
//! Object IDs are managed through an Object ID B+ tree that maps:
//!   Object ID -> File Record Location
//
//! ## Object ID Table
//! The Object ID table is stored as a B+ tree and contains:
//! - Object ID
//! - Sub-sequence number (for versions)
//! - Location information

use alloc::vec::Vec;

// ============================================================================
// Object ID Constants
// ============================================================================

/// Special object IDs (reserved by ReFS)
pub const REFS_OBJECT_ID_ROOT: u64 = 0x0000000000000001;
pub const REFS_OBJECT_ID_SECURITY: u64 = 0x0000000000000002;
pub const REFS_OBJECT_ID_UPDATER: u64 = 0x0000000000000003;
pub const REFS_OBJECT_ID_DEFECT: u64 = 0x0000000000000004;
pub const REFS_OBJECT_ID_QUOTA: u64 = 0x0000000000000005;
pub const REFS_OBJECT_ID_REPARSE: u64 = 0x0000000000000006;
pub const REFS_OBJECT_ID_MOUNT_POINT: u64 = 0x0000000000000007;
pub const REFS_OBJECT_ID_SVN_QUOTA: u64 = 0x0000000000000008;
pub const REFS_OBJECT_ID_VIEW_TABLE: u64 = 0x0000000000000009;
pub const REFS_OBJECT_ID_CORRUPT_LOG: u64 = 0x000000000000000A;

/// First user object ID
pub const REFS_FIRST_USER_OBJECT_ID: u64 = 0x0000000000010000;

/// Object ID B+ tree key structure
pub struct ObjectIdKey {
    /// Object ID (64-bit)
    pub object_id: u64,
    /// Sub-sequence number
    pub sub_sequence: u64,
}

impl ObjectIdKey {
    /// Create a new object ID key
    pub fn new(object_id: u64, sub_sequence: u64) -> Self {
        Self {
            object_id,
            sub_sequence,
        }
    }

    /// Get the root key
    pub fn root() -> Self {
        Self::new(REFS_OBJECT_ID_ROOT, 0)
    }

    /// Check if this is a special object ID
    pub fn is_special(&self) -> bool {
        self.object_id <= REFS_OBJECT_ID_CORRUPT_LOG
    }

    /// Check if this is a user object ID
    pub fn is_user_object(&self) -> bool {
        self.object_id >= REFS_FIRST_USER_OBJECT_ID
    }
}

/// Object ID value (location information)
pub struct ObjectIdValue {
    /// LBA of the object record
    pub record_lba: u64,
    /// Record size
    pub record_size: u32,
    /// Flags
    pub flags: u32,
}

impl ObjectIdValue {
    /// Create a new object ID value
    pub fn new(record_lba: u64, record_size: u32) -> Self {
        Self {
            record_lba,
            record_size,
            flags: 0,
        }
    }
}

// ============================================================================
// Object ID Table
// ============================================================================

/// Object ID table (in-memory cache)
pub struct ObjectIdTable {
    /// Root LBA of the Object ID B+ tree
    pub root_lba: u64,
    /// Cached object ID entries
    pub entries: Vec<ObjectIdEntry>,
    /// Is the table loaded?
    pub loaded: bool,
}

impl ObjectIdTable {
    /// Create a new empty object ID table
    pub fn new() -> Self {
        Self {
            root_lba: 0,
            entries: Vec::new(),
            loaded: false,
        }
    }

    /// Create from a B+ tree
    pub fn from_btree(root_lba: u64) -> Self {
        let mut table = Self::new();
        table.root_lba = root_lba;
        table.loaded = false; // Will be loaded on demand
        table
    }

    /// Mark as loaded
    pub fn set_loaded(&mut self) {
        self.loaded = true;
    }

    /// Check if loaded
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add an entry
    pub fn add_entry(&mut self, entry: ObjectIdEntry) {
        self.entries.push(entry);
    }

    /// Find an entry by object ID
    pub fn find_by_id(&self, object_id: u64) -> Option<&ObjectIdEntry> {
        self.entries.iter().find(|e| e.key.object_id == object_id)
    }
}

/// An object ID entry
pub struct ObjectIdEntry {
    /// Object ID key
    pub key: ObjectIdKey,
    /// Object ID value (location)
    pub value: ObjectIdValue,
}

impl ObjectIdEntry {
    /// Create a new entry
    pub fn new(key: ObjectIdKey, value: ObjectIdValue) -> Self {
        Self { key, value }
    }

    /// Get the object ID
    pub fn object_id(&self) -> u64 {
        self.key.object_id
    }

    /// Get the record LBA
    pub fn record_lba(&self) -> u64 {
        self.value.record_lba
    }
}

// ============================================================================
// Object ID Operations
// ============================================================================

/// Create a new object ID
pub fn create_object_id(table: &mut ObjectIdTable, record_lba: u64, record_size: u32) -> u64 {
    // Find the highest existing object ID
    let mut max_id = REFS_FIRST_USER_OBJECT_ID;
    
    for entry in &table.entries {
        if entry.key.object_id > max_id && entry.key.object_id < u64::MAX - 1 {
            max_id = entry.key.object_id;
        }
    }
    
    let new_id = max_id + 1;
    
    // Add the entry
    table.add_entry(ObjectIdEntry::new(
        ObjectIdKey::new(new_id, 0),
        ObjectIdValue::new(record_lba, record_size),
    ));
    
    new_id
}

/// Delete an object ID
pub fn delete_object_id(table: &mut ObjectIdTable, object_id: u64) -> Option<ObjectIdEntry> {
    let index = table.entries.iter().position(|e| e.key.object_id == object_id)?;
    Some(table.entries.remove(index))
}

/// Find object by ID
pub fn find_by_object_id(table: &ObjectIdTable, object_id: u64) -> Option<&ObjectIdEntry> {
    table.find_by_id(object_id)
}

/// Check if object ID exists
pub fn object_id_exists(table: &ObjectIdTable, object_id: u64) -> bool {
    table.find_by_id(object_id).is_some()
}

/// Get the root object
pub fn get_root_object(table: &ObjectIdTable) -> Option<&ObjectIdEntry> {
    table.find_by_id(REFS_OBJECT_ID_ROOT)
}

// ============================================================================
// Object ID B+ Tree Key Operations
// ============================================================================

/// Convert object ID key to bytes for B+ tree
pub fn key_to_bytes(key: &ObjectIdKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&key.object_id.to_le_bytes());
    bytes.extend_from_slice(&key.sub_sequence.to_le_bytes());
    bytes
}

/// Parse object ID key from bytes
pub fn key_from_bytes(bytes: &[u8]) -> Option<ObjectIdKey> {
    if bytes.len() < 16 {
        return None;
    }
    
    let object_id = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let sub_sequence = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    
    Some(ObjectIdKey::new(object_id, sub_sequence))
}

// ============================================================================
// Special Object IDs
// ============================================================================

/// Check if an object ID is reserved
pub fn is_reserved_object_id(object_id: u64) -> bool {
    matches!(
        object_id,
        REFS_OBJECT_ID_ROOT
            | REFS_OBJECT_ID_SECURITY
            | REFS_OBJECT_ID_UPDATER
            | REFS_OBJECT_ID_DEFECT
            | REFS_OBJECT_ID_QUOTA
            | REFS_OBJECT_ID_REPARSE
            | REFS_OBJECT_ID_MOUNT_POINT
            | REFS_OBJECT_ID_SVN_QUOTA
            | REFS_OBJECT_ID_VIEW_TABLE
            | REFS_OBJECT_ID_CORRUPT_LOG
    )
}

/// Get the name of a special object ID
pub fn get_special_object_name(object_id: u64) -> Option<&'static str> {
    match object_id {
        REFS_OBJECT_ID_ROOT => Some("Root"),
        REFS_OBJECT_ID_SECURITY => Some("Security"),
        REFS_OBJECT_ID_UPDATER => Some("Updater"),
        REFS_OBJECT_ID_DEFECT => Some("Defect"),
        REFS_OBJECT_ID_QUOTA => Some("Quota"),
        REFS_OBJECT_ID_REPARSE => Some("Reparse"),
        REFS_OBJECT_ID_MOUNT_POINT => Some("Mount Point"),
        REFS_OBJECT_ID_SVN_QUOTA => Some("SVN Quota"),
        REFS_OBJECT_ID_VIEW_TABLE => Some("View Table"),
        REFS_OBJECT_ID_CORRUPT_LOG => Some("Corrupt Log"),
        _ => None,
    }
}

// ============================================================================
// Object ID Lookup
// ============================================================================

/// Object lookup result
pub struct ObjectLookupResult {
    /// Object ID
    pub object_id: u64,
    /// Sub-sequence
    pub sub_sequence: u64,
    /// Record LBA
    pub record_lba: u64,
    /// Record size
    pub record_size: u32,
}

impl ObjectLookupResult {
    /// Create a new result
    pub fn new(object_id: u64, sub_sequence: u64, record_lba: u64, record_size: u32) -> Self {
        Self {
            object_id,
            sub_sequence,
            record_lba,
            record_size,
        }
    }
}

/// Look up an object by ID from the B+ tree
pub fn lookup_object(
    _table: &ObjectIdTable,
    object_id: u64,
    sub_sequence: u64,
) -> Option<ObjectLookupResult> {
    // In a real implementation, we would search the Object ID B+ tree
    // For now, return None as we don't have the B+ tree loaded
    
    // Check if it's in our cached entries
    if let Some(entry) = _table.find_by_id(object_id) {
        if entry.key.sub_sequence == sub_sequence {
            return Some(ObjectLookupResult::new(
                object_id,
                sub_sequence,
                entry.value.record_lba,
                entry.value.record_size,
            ));
        }
    }
    
    None
}

// ============================================================================
// Object Enumeration
// ============================================================================

/// Iterator over object IDs
pub struct ObjectIdIterator<'a> {
    table: &'a ObjectIdTable,
    index: usize,
}

impl<'a> ObjectIdIterator<'a> {
    /// Create a new iterator
    pub fn new(table: &'a ObjectIdTable) -> Self {
        Self { table, index: 0 }
    }
}

impl<'a> Iterator for ObjectIdIterator<'a> {
    type Item = &'a ObjectIdEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.table.entries.len() {
            let entry = &self.table.entries[self.index];
            self.index += 1;
            Some(entry)
        } else {
            None
        }
    }
}

impl ObjectIdTable {
    /// Get an iterator over all entries
    pub fn iter(&self) -> ObjectIdIterator<'_> {
        ObjectIdIterator::new(self)
    }

    /// Get user object count
    pub fn user_object_count(&self) -> usize {
        self.entries.iter()
            .filter(|e| e.key.is_user_object())
            .count()
    }
}

// ============================================================================
// Debug Output
// ============================================================================

/// Print object ID information
pub fn debug_print_object_id(object_id: u64) {
    if let Some(name) = get_special_object_name(object_id) {
        // Reference fields to retain the API contract
        let _ = (object_id, name);
    } else if is_reserved_object_id(object_id) {
        // Reference object_id to retain the API contract
        let _ = object_id;
    } else {
        // Reference object_id to retain the API contract
        let _ = object_id;
    }
}

/// Print object ID table
pub fn debug_print_table(table: &ObjectIdTable) {
    // kprintln!("[REFS] Object ID Table:")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Loaded: {}", table.loaded)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Entries: {}", table.len())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Root LBA: {}", table.root_lba)  // kprintln disabled (memcpy crash workaround);
    
    for entry in table.iter() {
        let name = get_special_object_name(entry.key.object_id)
            .unwrap_or("User Object");
        // Reference the entry fields to preserve the API contract
        let _ = (entry.key.object_id, name, entry.value.record_lba, entry.value.record_size);
    }
}
