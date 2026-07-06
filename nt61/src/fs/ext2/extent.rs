//! ext4 Extent Tree Support
//
//! Implements extent-based file storage for ext4 filesystems.
//! Extents provide more efficient storage for large files compared
//! to the traditional block pointer approach.
//
//! ## Extent Tree Structure
//! An extent tree is stored in the inode (or in an external tree).
//! The root of the tree is stored in the inode's block array at index 0
//! (replacing the first direct block pointer).
//
//! ## Extent Format
//! Each extent covers a contiguous range of logical blocks:
//!   - Logical block number (where this extent starts)
//!   - Physical block number (where the data is stored)
//!   - Length (number of blocks in this extent)

extern crate alloc;

use alloc::vec;

use super::inode::Ext2Inode;
use super::superblock::Ext2SuperBlock;

// ============================================================================
// Extent Constants
// ============================================================================

/// Extent magic number (stored in extent header)
pub const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

/// Extent header flags
pub const EXT4_EXT_FLAGS_LEAF: u16 = 0x0001;       // Leaf node
pub const EXT4_EXT_FLAGS_INDEX: u16 = 0x0002;      // Index node
pub const EXT4_EXT_FLAGS_UNINIT: u16 = 0x0004;     // Uninitialized
pub const EXT4_EXT_FLAGS_LEAF_NEW: u16 = 0x0001;   // New format leaf

/// Maximum number of entries in an extent header
pub const EXT4_EXTENT_COUNT: usize = 5;
pub const EXT4_EXTENT_MAX_COUNT: usize = 5;

/// Maximum number of entries in an extent index
pub const EXT4_EXTENT_INDEX_COUNT: usize = 4;

// ============================================================================
// Extent Structures
// ============================================================================

/// Extent header (stored at the beginning of an extent block)
/// The header is followed by extent entries.
#[repr(C)]
pub struct Ext4ExtentHeader {
    /// Magic number (0xF30A)
    pub magic: u16,
    /// Number of valid entries
    pub entries: u16,
    /// Maximum number of entries
    pub max_entries: u16,
    /// Depth of this extent tree
    pub depth: u16,
    /// Generation of the extent tree
    pub generation: u32,
}

impl Ext4ExtentHeader {
    /// Create a new extent header
    pub fn new(depth: u16, max_entries: u16) -> Self {
        Self {
            magic: EXT4_EXTENT_MAGIC,
            entries: 0,
            max_entries,
            depth,
            generation: 0,
        }
    }

    /// Check if this is a valid extent header
    pub fn is_valid(&self) -> bool {
        self.magic == EXT4_EXTENT_MAGIC
    }

    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        self.depth == 0
    }

    /// Check if this is an index node
    pub fn is_index(&self) -> bool {
        self.depth > 0
    }

    /// Check if this is a new format header
    pub fn is_new_format(&self) -> bool {
        self.max_entries <= EXT4_EXTENT_MAX_COUNT as u16
    }
}

/// Extent entry (for leaf nodes)
/// Represents a contiguous range of blocks.
#[repr(C)]
pub struct Ext4Extent {
    /// First logical block number this extent covers
    pub ee_block: u32,
    /// Number of blocks in this extent (upper 16 bits of length)
    pub ee_len_hi: u16,
    /// Starting physical block number (upper 16 bits)
    pub ee_start_hi: u16,
    /// Starting physical block number (lower 32 bits)
    pub ee_start_lo: u32,
}

impl Ext4Extent {
    /// Create a new extent
    pub fn new(logical: u32, physical: u64, len: u32) -> Self {
        Self {
            ee_block: logical,
            ee_len_hi: (len >> 16) as u16,
            ee_start_hi: (physical >> 32) as u16,
            ee_start_lo: physical as u32,
        }
    }

    /// Get the length of this extent in blocks
    pub fn get_len(&self) -> u32 {
        // For ext4, ee_len is a 16-bit field (ee_len_hi contains upper 16 bits of a 32-bit value)
        // But in practice, ext4 uses 16-bit lengths, so we combine with ee_len_hi properly
        let len_lo = (self.ee_len_hi & 0x8000) as u32;  // Check if upper bit set (indicates 32-bit)
        if len_lo != 0 {
            // 32-bit length mode
            ((self.ee_len_hi as u32) << 16) | 0xFFFF
        } else {
            // Standard 16-bit length mode
            self.ee_len_hi as u32
        }
    }

    /// Get the physical block number
    pub fn get_physical(&self) -> u64 {
        ((self.ee_start_hi as u64) << 32) | (self.ee_start_lo as u64)
    }

    /// Check if this extent covers a given logical block
    pub fn covers(&self, logical: u32) -> bool {
        logical >= self.ee_block && logical < self.ee_block + (self.get_len() as u32)
    }

    /// Get the physical block for a given logical block within this extent
    pub fn logical_to_physical(&self, logical: u32) -> Option<u64> {
        if !self.covers(logical) {
            return None;
        }
        let offset = (logical - self.ee_block) as u64;
        Some(self.get_physical() + offset)
    }
}

/// Extent index entry (for internal nodes)
/// Points to a child extent block.
#[repr(C)]
pub struct Ext4ExtentIdx {
    /// First logical block number this index covers
    pub ei_block: u32,
    /// Pointer to the child extent block (lower 32 bits)
    pub ei_leaf_lo: u32,
    /// Reserved
    pub ei_unused: u16,
    /// Pointer to the child extent block (upper 16 bits)
    pub ei_leaf_hi: u16,
}

impl Ext4ExtentIdx {
    /// Create a new extent index
    pub fn new(logical: u32, child_block: u64) -> Self {
        Self {
            ei_block: logical,
            ei_leaf_lo: child_block as u32,
            ei_unused: 0,
            ei_leaf_hi: (child_block >> 32) as u16,
        }
    }

    /// Get the child extent block number
    pub fn get_child_block(&self) -> u64 {
        ((self.ei_leaf_hi as u64) << 32) | (self.ei_leaf_lo as u64)
    }

    /// Check if this index covers a given logical block
    pub fn covers(&self, logical: u32) -> bool {
        logical >= self.ei_block
    }
}

// ============================================================================
// Extent Tree Operations
// ============================================================================

/// An in-memory representation of an extent tree
pub struct ExtentTree {
    pub depth: u16,
    pub root_header: Ext4ExtentHeader,
}

impl ExtentTree {
    /// Parse an extent tree from an inode
    pub fn parse(inode: &Ext2Inode, block_size: u32) -> Option<Self> {
        // In ext4, the extent header is stored in the first "block" pointer
        // which is actually replaced by the extent header when extents are used
        let first_block = inode.block[0];
        
        if first_block == 0 {
            return None;
        }
        
        // Read the extent header block
        let mut buffer = vec![0u8; block_size as usize];
        let sector = first_block as u64 * (block_size / 512) as u64;
        
        if super::superblock::read_sector(
            core::ptr::null_mut(),  // Will be provided by caller
            sector,
            &mut buffer
        ).is_err() {
            return None;
        }
        
        let header = unsafe {
            core::ptr::read_unaligned(buffer.as_ptr() as *const Ext4ExtentHeader)
        };
        
        if !header.is_valid() {
            return None;
        }
        
        Some(Self {
            depth: header.depth,
            root_header: header,
        })
    }

    /// Find the physical block for a given logical block
    pub fn find_physical(
        &self,
        device: *mut (),
        inode: &Ext2Inode,
        block_size: u32,
        logical: u32,
    ) -> Option<u64> {
        let first_block = inode.block[0];
        
        if first_block == 0 {
            return None;
        }
        
        // Start from the root and traverse the tree
        self.find_in_node(device, first_block, block_size, logical)
    }

    /// Find physical block in a node (could be root or child)
    fn find_in_node(
        &self,
        device: *mut (),
        node_block: u32,
        block_size: u32,
        logical: u32,
    ) -> Option<u64> {
        let mut buffer = vec![0u8; block_size as usize];
        let sector = node_block as u64 * (block_size / 512) as u64;
        
        if super::superblock::read_sector(device, sector, &mut buffer).is_err() {
            return None;
        }
        
        let header = unsafe {
            core::ptr::read_unaligned(buffer.as_ptr() as *const Ext4ExtentHeader)
        };
        
        if !header.is_valid() {
            return None;
        }
        
        if header.is_leaf() {
            // Leaf node - search extent entries
            let entry_size = core::mem::size_of::<Ext4Extent>();
            let header_size = core::mem::size_of::<Ext4ExtentHeader>();
            
            for i in 0..header.entries as usize {
                let offset = header_size + i * entry_size;
                if offset + entry_size > buffer.len() {
                    break;
                }
                
                let extent = unsafe {
                    core::ptr::read_unaligned(
                        buffer.as_ptr().add(offset) as *const Ext4Extent
                    )
                };
                
                if extent.covers(logical) {
                    return extent.logical_to_physical(logical);
                }
            }
            
            None
        } else {
            // Index node - find the right child
            let entry_size = core::mem::size_of::<Ext4ExtentIdx>();
            let header_size = core::mem::size_of::<Ext4ExtentHeader>();
            
            // Find the first index that covers our logical block
            let mut chosen_idx: Option<Ext4ExtentIdx> = None;
            
            for i in 0..header.entries as usize {
                let offset = header_size + i * entry_size;
                if offset + entry_size > buffer.len() {
                    break;
                }
                
                let idx: Ext4ExtentIdx = unsafe {
                    core::ptr::read_unaligned(
                        buffer.as_ptr().add(offset) as *const Ext4ExtentIdx
                    )
                };
                
                if idx.covers(logical) {
                    chosen_idx = Some(idx);
                    break;
                }
            }
            
            // Use the last index if no index covers our logical block
            if chosen_idx.is_none() && header.entries > 0 {
                let offset = header_size + ((header.entries - 1) as usize) * entry_size;
                if offset + entry_size <= buffer.len() {
                    chosen_idx = Some(unsafe {
                        core::ptr::read_unaligned(
                            buffer.as_ptr().add(offset) as *const Ext4ExtentIdx
                        )
                    });
                }
            }
            
            if let Some(ref idx) = chosen_idx {
                // Recurse into child node
                self.find_in_node(device, idx.get_child_block() as u32, block_size, logical)
            } else {
                None
            }
        }
    }
}

// ============================================================================
// Extent Formatting
// ============================================================================

/// Format an extent header for a leaf node
pub fn format_leaf_header(entries: u16, max_entries: u16) -> Ext4ExtentHeader {
    Ext4ExtentHeader {
        magic: EXT4_EXTENT_MAGIC,
        entries,
        max_entries,
        depth: 0,  // Leaf nodes have depth 0
        generation: 0,
    }
}

/// Format an extent header for an index node
pub fn format_index_header(entries: u16, max_entries: u16, depth: u16) -> Ext4ExtentHeader {
    Ext4ExtentHeader {
        magic: EXT4_EXTENT_MAGIC,
        entries,
        max_entries,
        depth,
        generation: 0,
    }
}

/// Create an extent entry
pub fn create_extent(logical: u32, physical: u64, len: u32) -> Ext4Extent {
    Ext4Extent::new(logical, physical, len)
}

/// Create an extent index entry
pub fn create_extent_idx(logical: u32, child_block: u64) -> Ext4ExtentIdx {
    Ext4ExtentIdx::new(logical, child_block)
}

// ============================================================================
// Extent Validation
// ============================================================================

/// Check if an inode uses extents
pub fn inode_uses_extents(inode: &Ext2Inode) -> bool {
    (inode.flags & 0x00080000) != 0  // EXT2_EXTENTS_FL
}

/// Validate an extent entry
pub fn validate_extent(extent: &Ext4Extent, max_logical: u32) -> bool {
    // Check magic
    // Note: We don't have the header here, so we can't check magic
    
    // Check length is valid (1-32768 blocks)
    let len = extent.get_len();
    if len == 0 || len > 32768 {
        return false;
    }
    
    // Check logical block is within range
    if extent.ee_block > max_logical {
        return false;
    }
    
    // Check for overflow
    let end = extent.ee_block as u64 + len as u64;
    if end > max_logical as u64 + 32768 {
        return false;
    }
    
    true
}

/// Validate an extent index entry
pub fn validate_extent_idx(idx: &Ext4ExtentIdx) -> bool {
    // Check that child block is not zero
    idx.get_child_block() != 0
}

// ============================================================================
// Debug Output
// ============================================================================

/// Print extent tree for debugging
pub fn debug_print_tree(
    device: *mut (),
    inode: &Ext2Inode,
    sb: &Ext2SuperBlock,
) {
    let block_size = sb.get_block_size();
    
    if !inode_uses_extents(inode) {
        // kprintln!("[EXT4] Inode does not use extents")  // kprintln disabled (memcpy crash workaround);
        return;
    }
    
    let first_block = inode.block[0];
    if first_block == 0 {
        // kprintln!("[EXT4] Extent tree root is zero")  // kprintln disabled (memcpy crash workaround);
        return;
    }
    
    // kprintln!("[EXT4] Extent tree root at block {}", first_block)  // kprintln disabled (memcpy crash workaround);
    debug_print_node(device, first_block, block_size, 0);
}

/// Recursively print extent tree nodes
fn debug_print_node(device: *mut (), block: u32, block_size: u32, depth: usize) {
    let _indent = "  ".repeat(depth);
    
    let mut buffer = vec![0u8; block_size as usize];
    let sector = block as u64 * (block_size / 512) as u64;
    
    if super::superblock::read_sector(device, sector, &mut buffer).is_err() {
        // kprintln!("{}Failed to read extent block {}", indent, block)  // kprintln disabled (memcpy crash workaround);
        return;
    }
    
    let header = unsafe {
        core::ptr::read_unaligned(buffer.as_ptr() as *const Ext4ExtentHeader)
    };
    
    if !header.is_valid() {
        // kprintln!("{}Invalid extent header at block {}", indent, block)  // kprintln disabled (memcpy crash workaround);
        return;
    }
    
    // kprintln!("{}{}extent header: depth={}, entries={}/{}",   // kprintln disabled (memcpy crash workaround)
//         indent,
//         if header.is_leaf() { "[LEAF]" } else { "[INDEX]" },
//         header.depth,
//         header.entries,
//         header.max_entries
//     );
    
    if header.is_leaf() {
        // Print extent entries
        let entry_size = core::mem::size_of::<Ext4Extent>();
        let header_size = core::mem::size_of::<Ext4ExtentHeader>();
        
        for i in 0..core::cmp::min(header.entries as usize, 10) {
            let offset = header_size + i * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }
            
            let extent = unsafe {
                core::ptr::read_unaligned(
                    buffer.as_ptr().add(offset) as *const Ext4Extent
                )
            };
            // Reference extent fields to preserve API contract
            let _ = (extent.ee_block, extent.get_physical(), extent.get_len());
        }
        
        if header.entries > 10 {
            // kprintln!("{}  ... and {} more entries", indent, header.entries - 10)  // kprintln disabled (memcpy crash workaround);
        }
    } else {
        // Print index entries
        let entry_size = core::mem::size_of::<Ext4ExtentIdx>();
        let header_size = core::mem::size_of::<Ext4ExtentHeader>();
        
        for i in 0..core::cmp::min(header.entries as usize, 5) {
            let offset = header_size + i * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }
            
            let idx = unsafe {
                core::ptr::read_unaligned(
                    buffer.as_ptr().add(offset) as *const Ext4ExtentIdx
                )
            };
            // Reference idx fields to preserve API contract
            let _ = (idx.ei_block, idx.get_child_block());
        }
        
        // Recurse into first child for demo
        if header.entries > 0 {
            let offset = header_size;
            let idx = unsafe {
                core::ptr::read_unaligned(
                    buffer.as_ptr().add(offset) as *const Ext4ExtentIdx
                )
            };
            
            debug_print_node(device, idx.get_child_block() as u32, block_size, depth + 1);
        }
    }
}
