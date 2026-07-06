//! ReFS B+ Tree Implementation
//
//! Implements B+ tree data structures used by ReFS for managing
//! metadata and directory entries.
//
//! ## B+ Tree Structure
//! ReFS uses B+ trees for:
//! - Object ID table (mapping object IDs to file records)
//! - Directory indexes (fast directory lookup)
//! - Chunk address tables (file data allocation)
//! - Security descriptors
//
//! ## B+ Tree Page Format
//! Each B+ tree page contains:
//! - Page header (magic, flags, key/value counts)
//! - Key entries
//! - Value entries (optional)
//! - Free space

use alloc::vec::Vec;

// ============================================================================
// B+ Tree Constants
// ============================================================================

/// B+ tree data page magic ("RBDt" = 0x52626474)
pub const REFS_BCBT_MAGIC: u32 = 0x52626474;

/// B+ tree index page magic ("RBIt" = 0x52626974)
pub const REFS_BCBT_INDEX_MAGIC: u32 = 0x52626974;

/// B+ tree overflow page magic
pub const REFS_BCBT_OVERFLOW_MAGIC: u32 = 0x52624F76;

/// Page flags
pub const REFS_BCBT_FLAG_LEAF: u8 = 0x01;
pub const REFS_BCBT_FLAG_INDEX: u8 = 0x02;
pub const REFS_BCBT_FLAG_ROOT: u8 = 0x04;
pub const REFS_BCBT_FLAG_KEEPSIZE: u8 = 0x08;
pub const REFS_BCBT_FLAG_COMPRESSED: u8 = 0x10;
pub const REFS_BCBT_FLAG_CHKSUM: u8 = 0x20;

/// Maximum key size
pub const REFS_BCBT_MAX_KEY_SIZE: usize = 256;

/// Maximum value size
pub const REFS_BCBT_MAX_VALUE_SIZE: usize = 4080;

// ============================================================================
// B+ Tree Structures
// ============================================================================

/// B+ tree page header (16 bytes)
#[repr(C)]
pub struct RefsBtreePageHeader {
    /// Magic number (RBDt or RBIt)
    pub magic: u32,
    /// Page flags
    pub flags: u8,
    /// Page height (0 = leaf)
    pub height: u8,
    /// Number of pages in this allocation
    pub page_count: u16,
    /// Number of keys in this page
    pub key_count: u16,
    /// Length of each value (0 if variable)
    pub value_length: u16,
    /// Reserved
    pub reserved: [u8; 4],
}

impl RefsBtreePageHeader {
    /// Check if this is a valid page header
    pub fn is_valid(&self) -> bool {
        self.magic == REFS_BCBT_MAGIC || self.magic == REFS_BCBT_INDEX_MAGIC
    }

    /// Check if this is a leaf page
    pub fn is_leaf(&self) -> bool {
        (self.flags & REFS_BCBT_FLAG_LEAF) != 0 || self.magic == REFS_BCBT_MAGIC
    }

    /// Check if this is an index page
    pub fn is_index(&self) -> bool {
        (self.flags & REFS_BCBT_FLAG_INDEX) != 0 || self.magic == REFS_BCBT_INDEX_MAGIC
    }

    /// Check if this is a root page
    pub fn is_root(&self) -> bool {
        (self.flags & REFS_BCBT_FLAG_ROOT) != 0
    }

    /// Check if checksum is present
    pub fn has_checksum(&self) -> bool {
        (self.flags & REFS_BCBT_FLAG_CHKSUM) != 0
    }

    /// Get the page height
    pub fn get_height(&self) -> u8 {
        self.height
    }

    /// Get the number of keys
    pub fn get_key_count(&self) -> u16 {
        self.key_count
    }
}

/// B+ tree key prefix
#[repr(C)]
pub struct RefsBtreeKeyPrefix {
    /// Key length
    pub key_len: u16,
    /// Number of shared bytes with next key
    pub shared_len: u16,
}

/// B+ tree key entry
#[repr(C)]
pub struct RefsBtreeKeyEntry {
    /// Key data offset (from start of key area)
    pub key_offset: u16,
    /// Key data length
    pub key_len: u16,
    /// Value data offset (from start of value area)
    pub value_offset: u16,
    /// Value data length
    pub value_len: u16,
}

/// B+ tree key (variable size)
pub struct RefsBtreeKey {
    /// Object ID (64-bit)
    pub object_id: u64,
    /// Sub-sequence number (for file versions)
    pub sub_sequence: u64,
    /// Key code (for indexing)
    pub code: u64,
    /// Additional key data
    pub data: Vec<u8>,
}

impl RefsBtreeKey {
    /// Create a new key
    pub fn new(object_id: u64, sub_sequence: u64, code: u64) -> Self {
        Self {
            object_id,
            sub_sequence,
            code,
            data: Vec::new(),
        }
    }

    /// Get the total key size
    pub fn total_size(&self) -> usize {
        24 + self.data.len()  // 3 x u64 + data
    }
}

/// B+ tree value (variable size)
pub struct RefsBtreeValue {
    /// Value data
    pub data: Vec<u8>,
}

impl RefsBtreeValue {
    /// Create a new value
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the value size
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

// ============================================================================
// B+ Tree Page
// ============================================================================

/// Represents a B+ tree page loaded from disk
pub struct RefsBtreePage {
    /// Page header
    pub header: RefsBtreePageHeader,
    /// Key entries
    pub keys: Vec<RefsBtreeKeyEntry>,
    /// Key data area
    pub key_data: Vec<u8>,
    /// Value data area
    pub value_data: Vec<u8>,
    /// Checksum (if present)
    pub checksum: u32,
    /// LBA of this page
    pub lba: u64,
}

impl RefsBtreePage {
    /// Create a new empty page
    pub fn new() -> Self {
        Self {
            header: RefsBtreePageHeader {
                magic: REFS_BCBT_MAGIC,
                flags: 0,
                height: 0,
                page_count: 1,
                key_count: 0,
                value_length: 0,
                reserved: [0; 4],
            },
            keys: Vec::new(),
            key_data: Vec::new(),
            value_data: Vec::new(),
            checksum: 0,
            lba: 0,
        }
    }

    /// Check if this is a valid page
    pub fn is_valid(&self) -> bool {
        self.header.is_valid()
    }

    /// Get the number of entries
    pub fn entry_count(&self) -> u16 {
        self.header.get_key_count()
    }
}

// ============================================================================
// B+ Tree Operations
// ============================================================================

/// A loaded B+ tree
pub struct RefsBtree {
    /// Root page
    pub root: RefsBtreePage,
    /// Tree height
    pub height: u8,
    /// Page size (typically 4096 or 65536)
    pub page_size: usize,
    /// Is this a variable-length tree?
    pub is_variable: bool,
}

impl RefsBtree {
    /// Create a new B+ tree
    pub fn new(page_size: usize) -> Self {
        Self {
            root: RefsBtreePage::new(),
            height: 0,
            page_size,
            is_variable: true,
        }
    }

    /// Get the root page
    pub fn get_root(&self) -> &RefsBtreePage {
        &self.root
    }

    /// Get the tree height
    pub fn get_height(&self) -> u8 {
        self.height
    }
}

/// Search result from B+ tree lookup
pub struct BtreeSearchResult {
    /// Found key entry
    pub entry: RefsBtreeKeyEntry,
    /// Key data
    pub key: RefsBtreeKey,
    /// Value data
    pub value: RefsBtreeValue,
}

// ============================================================================
// B+ Tree Page Operations
// ============================================================================

/// Parse a B+ tree page from a buffer
pub fn parse_page(buffer: &[u8], lba: u64) -> Option<RefsBtreePage> {
    if buffer.len() < 16 {
        return None;
    }

    // Read header
    let magic = u32::from_le_bytes(buffer[0..4].try_into().ok()?);
    let flags = buffer[4];
    let height = buffer[5];
    let page_count = u16::from_le_bytes(buffer[6..8].try_into().ok()?);
    let key_count = u16::from_le_bytes(buffer[8..10].try_into().ok()?);
    let value_length = u16::from_le_bytes(buffer[10..12].try_into().ok()?);
    let reserved = buffer[12..16].try_into().ok()?;

    let header = RefsBtreePageHeader {
        magic,
        flags,
        height,
        page_count,
        key_count,
        value_length,
        reserved,
    };

    if !header.is_valid() {
        // kprintln!("[REFS] Invalid B+ tree page magic: 0x{:08x}", magic)  // kprintln disabled (memcpy crash workaround);
        return None;
    }

    // Skip header to get to key/value areas
    let header_size = 16usize;
    let key_entry_size = 8usize; // 4 x u16

    // Calculate areas
    let keys_area_offset = header_size;
    let keys_area_size = (key_count as usize) * key_entry_size;
    let data_area_offset = keys_area_offset + keys_area_size;
    let data_area_size = buffer.len() - data_area_offset;

    // Verify sizes
    if data_area_size == 0 {
        return Some(RefsBtreePage {
            header,
            keys: Vec::new(),
            key_data: Vec::new(),
            value_data: buffer[data_area_offset..].to_vec(),
            checksum: 0,
            lba,
        });
    }

    // Parse key entries
    let mut keys = Vec::with_capacity(key_count as usize);
    for i in 0..key_count as usize {
        let offset = keys_area_offset + i * key_entry_size;
        if offset + key_entry_size > buffer.len() {
            break;
        }

        let key_offset = u16::from_le_bytes(buffer[offset..offset + 2].try_into().ok()?);
        let key_len = u16::from_le_bytes(buffer[offset + 2..offset + 4].try_into().ok()?);
        let value_offset = u16::from_le_bytes(buffer[offset + 4..offset + 6].try_into().ok()?);
        let value_len = u16::from_le_bytes(buffer[offset + 6..offset + 8].try_into().ok()?);

        keys.push(RefsBtreeKeyEntry {
            key_offset,
            key_len,
            value_offset,
            value_len,
        });
    }

    // The key and value data are interleaved after the key entries
    // For simplicity, we store them separately
    let key_data_size = if key_count > 0 {
        keys.iter().map(|k| k.key_offset as usize + k.key_len as usize).max().unwrap_or(0)
    } else {
        0
    };

    let key_data = buffer[data_area_offset..data_area_offset + key_data_size].to_vec();
    let value_data = buffer[data_area_offset + key_data_size..].to_vec();

    Some(RefsBtreePage {
        header,
        keys,
        key_data,
        value_data,
        checksum: 0,
        lba,
    })
}

/// Verify page checksum
pub fn verify_page_checksum(page: &RefsBtreePage, _buffer: &[u8]) -> bool {
    if !page.header.has_checksum() {
        return true;
    }

    // ReFS stores checksum at the end of the page
    // For now, we skip checksum verification
    true
}

// ============================================================================
// B+ Tree Search
// ============================================================================

/// Compare two B+ tree keys. The comparison uses the standard
/// ordering for ReFS keys: primary by object_id, secondary by
/// sub_sequence, tertiary by code.
pub fn compare_keys(a: &RefsBtreeKey, b: &RefsBtreeKey) -> core::cmp::Ordering {
    match a.object_id.cmp(&b.object_id) {
        core::cmp::Ordering::Equal => match a.sub_sequence.cmp(&b.sub_sequence) {
            core::cmp::Ordering::Equal => a.code.cmp(&b.code),
            other => other,
        },
        other => other,
    }
}

/// Find a key in a page using binary search
pub fn find_key_in_page(page: &RefsBtreePage, key: &RefsBtreeKey) -> Option<usize> {
    let key_count = page.header.get_key_count() as usize;
    
    if key_count == 0 {
        return None;
    }

    // Binary search for the key
    let mut left = 0;
    let mut right = key_count;

    while left < right {
        let mid = (left + right) / 2;
        
        // Get the key at mid position
        let entry = &page.keys[mid];
        
        // Extract key data from page
        let key_data_start = entry.key_offset as usize;
        let key_data_len = entry.key_len as usize;
        
        if key_data_start + key_data_len > page.key_data.len() {
            break;
        }
        
        let key_data = &page.key_data[key_data_start..key_data_start + key_data_len];
        
        // Compare with target key (simplified - just compare first 24 bytes)
        let compare_len = core::cmp::min(key_data_len, 24);
        let target_bytes = key.as_bytes();
        
        match key_data[..compare_len].cmp(&target_bytes[..compare_len]) {
            core::cmp::Ordering::Equal => {
                if key_data_len > 24 && target_bytes.len() > 24 {
                    match key_data[24..].cmp(&target_bytes[24..]) {
                        core::cmp::Ordering::Equal => return Some(mid),
                        other => return Some(mid + (other == core::cmp::Ordering::Less) as usize),
                    }
                } else {
                    return Some(mid);
                }
            }
            other => {
                if other == core::cmp::Ordering::Less {
                    left = mid + 1;
                } else {
                    right = mid;
                }
            }
        }
    }

    None
}

impl RefsBtreeKey {
    /// Convert key to bytes for comparison
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24 + self.data.len());
        bytes.extend_from_slice(&self.object_id.to_le_bytes());
        bytes.extend_from_slice(&self.sub_sequence.to_le_bytes());
        bytes.extend_from_slice(&self.code.to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Create key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 {
            return None;
        }

        let object_id = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let sub_sequence = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let code = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let data = bytes[24..].to_vec();

        Some(Self {
            object_id,
            sub_sequence,
            code,
            data,
        })
    }
}

// ============================================================================
// B+ Tree Traversal
// ============================================================================

/// Find the leaf page containing a key
pub fn find_leaf_page(
    _tree: &RefsBtree,
    _root: &RefsBtreePage,
    _key: &RefsBtreeKey,
) -> Option<&'static RefsBtreePage> {
    // In a real implementation, we would:
    // 1. Start at the root page
    // 2. Navigate down the tree based on key comparisons
    // 3. Return the leaf page containing the key
    
    // This is a simplified placeholder
    None
}

/// Insert a key-value pair into the tree
pub fn insert_key(
    _page: &mut RefsBtreePage,
    _key: &RefsBtreeKey,
    _value: &RefsBtreeValue,
) -> Result<(), ()> {
    // In a real implementation, we would:
    // 1. Find the correct position
    // 2. Insert the key and value
    // 3. Handle page splitting if needed
    
    Err(())
}

/// Delete a key from the tree
pub fn delete_key(
    _page: &mut RefsBtreePage,
    _key: &RefsBtreeKey,
) -> Result<(), ()> {
    // In a real implementation, we would:
    // 1. Find the key
    // 2. Remove it from the page
    // 3. Handle page merging if needed
    
    Err(())
}

// ============================================================================
// B+ Tree Iterator
// ============================================================================

/// Iterator over B+ tree entries
pub struct BtreeIterator<'a> {
    /// Current page
    page: Option<&'a RefsBtreePage>,
    /// Current index within page
    index: usize,
}

impl<'a> BtreeIterator<'a> {
    /// Create a new iterator
    pub fn new(page: &'a RefsBtreePage) -> Self {
        Self {
            page: Some(page),
            index: 0,
        }
    }
}

impl<'a> Iterator for BtreeIterator<'a> {
    type Item = (RefsBtreeKey, RefsBtreeValue);

    fn next(&mut self) -> Option<Self::Item> {
        let page = self.page?;
        let index = self.index;
        
        if index >= page.header.get_key_count() as usize {
            return None;
        }
        
        let entry = &page.keys[index];
        self.index += 1;
        
        // Extract key and value from page data
        let key_start = entry.key_offset as usize;
        let key_len = entry.key_len as usize;
        let value_start = entry.value_offset as usize;
        let value_len = entry.value_len as usize;
        
        if key_start + key_len > page.key_data.len() || 
           value_start + value_len > page.value_data.len() {
            return None;
        }
        
        let key = RefsBtreeKey::from_bytes(&page.key_data[key_start..key_start + key_len])?;
        let value = RefsBtreeValue::new(page.value_data[value_start..value_start + value_len].to_vec());
        
        Some((key, value))
    }
}

// ============================================================================
// Debug Output
// ============================================================================

/// Print page information for debugging
pub fn debug_print_page(page: &RefsBtreePage) {
    // kprintln!("[REFS] B+ Tree Page:")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Magic:     0x{:08x}", page.header.magic)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Flags:     0x{:02x}", page.header.flags)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Height:    {}", page.header.height)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Key count: {}", page.header.key_count)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  LBA:       {}", page.lba)  // kprintln disabled (memcpy crash workaround);
    
    if page.header.is_leaf() {
        // kprintln!("  Type:      LEAF")  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("  Type:      INDEX")  // kprintln disabled (memcpy crash workaround);
    }
}
