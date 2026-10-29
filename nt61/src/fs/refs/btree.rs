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

use alloc::vec;
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
    /// length of each value (0 if variable)
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
#[derive(Clone)]
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
    /// create a new key
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
        24 + self.data.len() // 3 x u64 + data
    }
}

/// B+ tree value (variable size)
pub struct RefsBtreeValue {
    /// Value data
    pub data: Vec<u8>,
}

impl RefsBtreeValue {
    /// create a new value
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
    /// create a new empty page
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
    /// create a new B+ tree
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

    // read header
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
        // kprintln!("[REFS] Invalid B+ tree page magic: 0x{:08x}", magic);
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
        keys.iter()
            .map(|k| k.key_offset as usize + k.key_len as usize)
            .max()
            .unwrap_or(0)
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

pub fn serialize_page(page: &RefsBtreePage, page_size: usize) -> Result<Vec<u8>, ()> {
    let mut buffer = vec![0u8; page_size];
    let mut cursor = 0usize;
    buffer[cursor..cursor + 4].copy_from_slice(&page.header.magic.to_le_bytes());
    cursor += 4;
    buffer[cursor] = page.header.flags;
    buffer[cursor + 1] = page.header.height;
    cursor += 2;
    buffer[cursor..cursor + 2].copy_from_slice(&page.header.page_count.to_le_bytes());
    cursor += 2;
    buffer[cursor..cursor + 2]
        .copy_from_slice(&(page.keys.len() as u16).to_le_bytes());
    cursor += 2;
    buffer[cursor..cursor + 2].copy_from_slice(&page.header.value_length.to_le_bytes());
    cursor += 2;
    buffer[cursor..cursor + 4].copy_from_slice(&page.header.reserved);
    cursor += 4;

    for entry in &page.keys {
        buffer[cursor..cursor + 2].copy_from_slice(&entry.key_offset.to_le_bytes());
        buffer[cursor + 2..cursor + 4].copy_from_slice(&entry.key_len.to_le_bytes());
        buffer[cursor + 4..cursor + 6].copy_from_slice(&entry.value_offset.to_le_bytes());
        buffer[cursor + 6..cursor + 8].copy_from_slice(&entry.value_len.to_le_bytes());
        cursor += 8;
    }

    let data_base = cursor;
    if cursor + page.key_data.len() + page.value_data.len() > page_size {
        return Err(());
    }
    buffer[cursor..cursor + page.key_data.len()].copy_from_slice(&page.key_data);
    cursor += page.key_data.len();
    buffer[cursor..cursor + page.value_data.len()].copy_from_slice(&page.value_data);
    let _ = data_base;

    Ok(buffer)
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

/// Return the key stored at the given position within a page.
pub fn key_at(page: &RefsBtreePage, index: usize) -> Option<RefsBtreeKey> {
    let entry = page.keys.get(index)?;
    let start = entry.key_offset as usize;
    let len = entry.key_len as usize;
    let bytes = page.key_data.get(start..start.checked_add(len)?)?;
    RefsBtreeKey::from_bytes(bytes)
}

/// Find a key in a page using binary search
pub fn find_key_in_page(page: &RefsBtreePage, key: &RefsBtreeKey) -> Option<usize> {
    let mut left = 0usize;
    let mut right = page.keys.len();

    while left < right {
        let mid = left + (right - left) / 2;
        let current = key_at(page, mid)?;
        match compare_keys(&current, key) {
            core::cmp::Ordering::Equal => return Some(mid),
            core::cmp::Ordering::Less => left = mid + 1,
            core::cmp::Ordering::Greater => right = mid,
        }
    }

    let current = key_at(page, left)?;
    if compare_keys(&current, key) == core::cmp::Ordering::Equal {
        Some(left)
    } else {
        None
    }
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

    /// create key from bytes
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

/// Maximum entries retained per page when `insert_key` must split it.
///
/// ReFS keys and values are variable sized. This conservative bound keeps a
/// split well below the smallest supported page while leaving room for the
/// entry array and page header.
const REFS_BTREE_DEFAULT_PAGE_CAPACITY: usize = 64;

/// Result of splitting a full B+ tree page.
pub struct RefsBtreePageSplit {
    /// Copy of the first key of the right page, for insertion in the parent.
    pub separator: RefsBtreeKey,
    /// Newly allocated right-hand page.
    pub right: RefsBtreePage,
}

fn append_entry(
    page: &mut RefsBtreePage,
    key: &RefsBtreeKey,
    value: &RefsBtreeValue,
) -> Result<(), ()> {
    if key.total_size() > REFS_BCBT_MAX_KEY_SIZE
        || value.data.len() > u16::MAX as usize
        || page.keys.len() >= u16::MAX as usize
    {
        return Err(());
    }

    let key_offset = page.key_data.len().min(u16::MAX as usize);
    let value_offset = page.value_data.len().min(u16::MAX as usize);
    if key_offset + key.total_size() > u16::MAX as usize {
        return Err(());
    }

    page.key_data.extend_from_slice(&key.as_bytes());
    page.value_data.extend_from_slice(&value.data);
    page.keys.push(RefsBtreeKeyEntry {
        key_offset: key_offset as u16,
        key_len: key.total_size() as u16,
        value_offset: value_offset as u16,
        value_len: value.data.len() as u16,
    });
    page.header.key_count = page.keys.len() as u16;
    Ok(())
}

fn insert_entry_at(
    page: &mut RefsBtreePage,
    position: usize,
    key: &RefsBtreeKey,
    value: &RefsBtreeValue,
) -> Result<(), ()> {
    if position > page.keys.len()
        || key.total_size() > REFS_BCBT_MAX_KEY_SIZE
        || value.data.len() > u16::MAX as usize
        || page.keys.len() >= u16::MAX as usize
    {
        return Err(());
    }

    let key_offset = page.key_data.len().min(u16::MAX as usize);
    let value_offset = page.value_data.len().min(u16::MAX as usize);
    if key_offset + key.total_size() > u16::MAX as usize {
        return Err(());
    }

    page.key_data.extend_from_slice(&key.as_bytes());
    page.value_data.extend_from_slice(&value.data);
    page.keys.insert(
        position,
        RefsBtreeKeyEntry {
            key_offset: key_offset as u16,
            key_len: key.total_size() as u16,
            value_offset: value_offset as u16,
            value_len: value.data.len() as u16,
        },
    );
    page.header.key_count = page.keys.len() as u16;
    Ok(())
}

fn build_split_page(keys: &[RefsBtreeKeyEntry], page: &RefsBtreePage) -> RefsBtreePage {
    let mut right = RefsBtreePage::new();
    right.header.flags = page.header.flags & !REFS_BCBT_FLAG_ROOT;
    right.header.height = page.header.height;
    right.header.page_count = page.header.page_count;
    right.lba = page.lba;

    for entry in keys {
        let key_bytes = page
            .key_data
            .get(entry.key_offset as usize..(entry.key_offset as usize + entry.key_len as usize));
        let value_bytes = page.value_data.get(
            entry.value_offset as usize..(entry.value_offset as usize + entry.value_len as usize),
        );
        if let (Some(key_bytes), Some(value_bytes)) = (key_bytes, value_bytes) {
            let key_offset = right.key_data.len().min(u16::MAX as usize);
            let value_offset = right.value_data.len().min(u16::MAX as usize);
            right.key_data.extend_from_slice(key_bytes);
            right.value_data.extend_from_slice(value_bytes);
            right.keys.push(RefsBtreeKeyEntry {
                key_offset: key_offset as u16,
                key_len: entry.key_len,
                value_offset: value_offset as u16,
                value_len: entry.value_len,
            });
        }
    }
    right.header.key_count = right.keys.len() as u16;
    right
}

/// Split a full leaf page at its midpoint.
///
/// The left half remains in `page`; the right half is returned together with
/// the separator that the caller must insert into (or store in) the parent.
pub fn split_page(page: &mut RefsBtreePage) -> Result<RefsBtreePageSplit, ()> {
    if page.keys.len() < 2 {
        return Err(());
    }

    let split_at = page.keys.len() / 2;
    let separator = key_at(page, split_at).ok_or(())?;
    let right_entries = page.keys.split_off(split_at);

    let mut right = build_split_page(&right_entries, page);
    page.header.key_count = page.keys.len() as u16;
    right.lba = page.lba;
    Ok(RefsBtreePageSplit { separator, right })
}

/// Insert a key-value pair into a sorted page.
///
/// If the page is full, it is split first and the pair is inserted into the
/// correct half. The caller writes the returned right-hand page and inserts
/// its separator into the parent page. If the tree only has one page, the
/// returned right page is also the new sibling.
pub fn insert_key(
    page: &mut RefsBtreePage,
    key: &RefsBtreeKey,
    value: &RefsBtreeValue,
) -> Result<Option<RefsBtreePage>, ()> {
    let mut position = 0usize;
    while position < page.keys.len() {
        let current = key_at(page, position).ok_or(())?;
        match compare_keys(&current, key) {
            core::cmp::Ordering::Equal => return Err(()),
            core::cmp::Ordering::Greater => break,
            core::cmp::Ordering::Less => position += 1,
        }
    }

    let needs_split = page.keys.len() >= REFS_BTREE_DEFAULT_PAGE_CAPACITY;
    if needs_split {
        let split = split_page(page)?;
        let first_right = key_at(&split.right, 0).ok_or(())?;
        let target_is_right = compare_keys(&first_right, key) != core::cmp::Ordering::Greater;
        let mut right = split.right;
        if target_is_right {
            let right_position = right.keys.len();
            insert_entry_at(&mut right, right_position, key, value)?;
        } else {
            insert_entry_at(page, position, key, value)?;
        }
        return Ok(Some(right));
    }

    insert_entry_at(page, position, key, value)?;
    Ok(None)
}

/// Merge a right page into a left page.
///
/// The caller is responsible for removing the separator and the right-child
/// pointer from their common parent. Pages are only merged when the combined
/// entry count is representable.
pub fn merge_pages(left: &mut RefsBtreePage, right: &mut RefsBtreePage) -> Result<(), ()> {
    if left.keys.len() + right.keys.len() > u16::MAX as usize {
        return Err(());
    }

    let right_keys = right.keys.clone();
    for entry in &right_keys {
        let key_bytes = right
            .key_data
            .get(entry.key_offset as usize..(entry.key_offset as usize + entry.key_len as usize));
        let value_bytes = right.value_data.get(
            entry.value_offset as usize..(entry.value_offset as usize + entry.value_len as usize),
        );
        let (Some(key_bytes), Some(value_bytes)) = (key_bytes, value_bytes) else {
            return Err(());
        };
        let key = RefsBtreeKey::from_bytes(key_bytes).ok_or(())?;
        append_entry(left, &key, &RefsBtreeValue::new(value_bytes.to_vec()))?;
    }

    right.key_data.clear();
    right.value_data.clear();
    right.keys.clear();
    right.header.key_count = 0;
    Ok(())
}

/// Delete a key from a sorted page.
///
/// The entry array and backing data are compacted. B+ tree underflow is
/// handled by the caller with [`merge_pages`] once it has located the sibling.
pub fn delete_key(page: &mut RefsBtreePage, key: &RefsBtreeKey) -> Result<(), ()> {
    let position = find_key_in_page(page, key).ok_or(())?;
    page.keys.remove(position);
    page.header.key_count = page.keys.len() as u16;

    let old_key_data = core::mem::take(&mut page.key_data);
    let old_value_data = core::mem::take(&mut page.value_data);

    for entry in page.keys.iter_mut() {
        let key_bytes = old_key_data
            .get(entry.key_offset as usize..(entry.key_offset as usize + entry.key_len as usize));
        let value_bytes = old_value_data.get(
            entry.value_offset as usize..(entry.value_offset as usize + entry.value_len as usize),
        );
        let (Some(key_bytes), Some(value_bytes)) = (key_bytes, value_bytes) else {
            return Err(());
        };

        entry.key_offset = page.key_data.len() as u16;
        entry.value_offset = page.value_data.len() as u16;
        page.key_data.extend_from_slice(key_bytes);
        page.value_data.extend_from_slice(value_bytes);
    }

    Ok(())
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
    /// create a new iterator
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

        if key_start + key_len > page.key_data.len()
            || value_start + value_len > page.value_data.len()
        {
            return None;
        }

        let key = RefsBtreeKey::from_bytes(&page.key_data[key_start..key_start + key_len])?;
        let value =
            RefsBtreeValue::new(page.value_data[value_start..value_start + value_len].to_vec());

        Some((key, value))
    }
}

// ============================================================================
// Debug Output
// ============================================================================

/// Print page information for debugging
pub fn debug_print_page(page: &RefsBtreePage) {
    // kprintln!("[REFS] B+ Tree Page:");
    // kprintln!("  Magic:     0x{:08x}", page.header.magic);
    // kprintln!("  flags:     0x{:02x}", page.header.flags);
    // kprintln!("  Height:    {}", page.header.height);
    // kprintln!("  Key count: {}", page.header.key_count);
    // kprintln!("  LBA:       {}", page.lba);

    if page.header.is_leaf() {
        // kprintln!("  r#type:      LEAF");
    } else {
        // kprintln!("  r#type:      INDEX");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn key(id: u64) -> RefsBtreeKey {
        RefsBtreeKey::new(id, 0, 0)
    }

    #[test]
    fn insert_maintains_sorted_order_and_rejects_duplicates() {
        let mut page = RefsBtreePage::new();
        for id in [30u64, 10, 20] {
            insert_key(&mut page, &key(id), &RefsBtreeValue::new(vec![id as u8]))
                .unwrap();
        }

        let ids: alloc::vec::Vec<u64> = (0..page.keys.len())
            .map(|index| key_at(&page, index).unwrap().object_id)
            .collect();
        assert_eq!(ids, alloc::vec![10, 20, 30]);
        assert!(insert_key(&mut page, &key(20), &RefsBtreeValue::new(vec![])).is_err());
    }

    #[test]
    fn insert_splits_full_page_into_two_sorted_pages() {
        let mut page = RefsBtreePage::new();
        let mut right_page = None;
        for id in 0..(REFS_BTREE_DEFAULT_PAGE_CAPACITY as u64 + 1) {
            right_page = insert_key(&mut page, &key(id), &RefsBtreeValue::new(vec![])).unwrap();
        }

        let left_count = page.keys.len();
        assert!(left_count > 0 && left_count < REFS_BTREE_DEFAULT_PAGE_CAPACITY);
        let left_last = key_at(&page, left_count - 1).unwrap().object_id;
        let right = right_page.as_ref().unwrap();
        let right_first = key_at(right, 0).unwrap().object_id;
        assert!(left_last < right_first);
    }

    #[test]
    fn delete_removes_entry_and_compacts_backing_data() {
        let mut page = RefsBtreePage::new();
        for id in [10u64, 20, 30] {
            insert_key(&mut page, &key(id), &RefsBtreeValue::new(vec![id as u8; 7]))
                .unwrap();
        }

        delete_key(&mut page, &key(20)).unwrap();
        assert!(find_key_in_page(&page, &key(20)).is_none());
        assert_eq!(page.keys.len(), 2);
        assert_eq!(page.key_data.len(), 2 * key(20).total_size());
        assert_eq!(page.value_data.len(), 14);
    }

    #[test]
    fn merge_pages_appends_right_entries_to_left() {
        let mut left = RefsBtreePage::new();
        let mut right = RefsBtreePage::new();
        for id in [10u64, 20] {
            insert_key(&mut left, &key(id), &RefsBtreeValue::new(vec![]))
                .unwrap();
        }
        for id in [30u64, 40] {
            insert_key(&mut right, &key(id), &RefsBtreeValue::new(vec![]))
                .unwrap();
        }

        merge_pages(&mut left, &mut right).unwrap();
        assert_eq!(left.keys.len(), 4);
        assert_eq!(right.keys.len(), 0);
        for (index, expected) in [10u64, 20, 30, 40].iter().enumerate() {
            assert_eq!(key_at(&left, index).unwrap().object_id, *expected);
        }
    }

    #[test]
    fn serialize_page_round_trips_entries() {
        let mut page = RefsBtreePage::new();
        for id in [10u64, 20, 30] {
            insert_key(&mut page, &key(id), &RefsBtreeValue::new(vec![id as u8]))
                .unwrap();
        }
        page.lba = 31;

        let serialized = serialize_page(&page, 4096).unwrap();
        let parsed = parse_page(&serialized, page.lba).unwrap();
        assert_eq!(parsed.keys.len(), 3);
        assert_eq!(parsed.lba, 31);
        for index in 0..3 {
            let expected = key_at(&page, index).unwrap();
            let actual = key_at(&parsed, index).unwrap();
            assert_eq!(expected.object_id, actual.object_id);
        }
    }
}
