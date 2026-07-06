//! ext2 Block Group Management
//
//! Implements block group descriptor reading and management.
//! Block group descriptors are stored in the block immediately following
//! the superblock.
//
//! ## Block Group Descriptor Table
//! The block group descriptor table (GDT) contains one 32-byte (or 64-byte)
//! descriptor for each block group. It starts at the first block after
//! the superblock.
//
//! ## Block Group Descriptor
//! Each descriptor contains:
//! - Block bitmap block number
//! - Inode bitmap block number
//! - Inode table start block number
//! - Free blocks/inodes/used directories counts

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use super::superblock::{Ext2SuperBlock, SUPERBLOCK_OFFSET};

// ============================================================================
// Block Group Descriptor Constants
// ============================================================================

/// Size of a block group descriptor (old format)
pub const EXT2_BGDESC_SIZE_OLD: usize = 32;

/// Size of a block group descriptor (new format with 64-bit support)
pub const EXT2_BGDESC_SIZE_NEW: usize = 64;

/// Block group number for the primary superblock
pub const EXT2_PRIMARY_SUPER_BGDNUM: u32 = 0;

// ============================================================================
// Block Group Descriptor Structure
// ============================================================================

/// ext2 Block Group Descriptor (32 bytes for old format)
/// Contains information about a specific block group.
#[repr(C)]
pub struct Ext2GroupDesc {
    /// Block address of block bitmap
    pub block_bitmap: u32,
    /// Block address of inode bitmap
    pub inode_bitmap: u32,
    /// Starting block address of inode table
    pub inode_table: u32,
    /// Free blocks count in this group
    pub free_blocks_count: u16,
    /// Free inodes count in this group
    pub free_inodes_count: u16,
    /// Directory count in this group
    pub used_dirs_count: u16,
    /// Padding (align to 32 bits)
    pub pad: u16,
    /// Reserved for future use
    pub reserved: [u32; 3],
}

/// ext2 Block Group Descriptor with 64-bit support
/// Used when the filesystem has 64-bit feature flag set.
#[repr(C)]
pub struct Ext2GroupDesc64 {
    /// Base descriptor (same as 32-bit version)
    pub base: Ext2GroupDesc,
    /// Block address of block bitmap (upper 32 bits)
    pub block_bitmap_hi: u32,
    /// Block address of inode bitmap (upper 32 bits)
    pub inode_bitmap_hi: u32,
    /// Starting block address of inode table (upper 32 bits)
    pub inode_table_hi: u32,
    /// Reserved
    pub reserved: [u32; 2],
}

impl Ext2GroupDesc {
    // ========================================================================
    // Bitmap Block Access
    // ========================================================================

    /// Get the block number of the block bitmap for this group
    pub fn get_block_bitmap_block(&self) -> u64 {
        self.block_bitmap as u64
    }

    /// Get the block number of the inode bitmap for this group
    pub fn get_inode_bitmap_block(&self) -> u64 {
        self.inode_bitmap as u64
    }

    /// Get the starting block of the inode table for this group
    pub fn get_inode_table_block(&self) -> u64 {
        self.inode_table as u64
    }

    // ========================================================================
    // Count Access
    // ========================================================================

    /// Get the number of free blocks in this group
    pub fn get_free_blocks(&self) -> u16 {
        self.free_blocks_count
    }

    /// Get the number of free inodes in this group
    pub fn get_free_inodes(&self) -> u16 {
        self.free_inodes_count
    }

    /// Get the number of directories in this group
    pub fn get_directory_count(&self) -> u16 {
        self.used_dirs_count
    }

    // ========================================================================
    // Bitmap Block to LBA Conversion
    // ========================================================================

    /// Convert a block number to absolute LBA (sector * 512)
    pub fn block_to_lba(block: u64, sb: &Ext2SuperBlock) -> u64 {
        block * (sb.get_block_size() / 512) as u64
    }

    /// Get the LBA of the block bitmap
    pub fn block_bitmap_lba(&self, sb: &Ext2SuperBlock) -> u64 {
        Self::block_to_lba(self.get_block_bitmap_block(), sb)
    }

    /// Get the LBA of the inode bitmap
    pub fn inode_bitmap_lba(&self, sb: &Ext2SuperBlock) -> u64 {
        Self::block_to_lba(self.get_inode_bitmap_block(), sb)
    }

    /// Get the LBA of the inode table
    pub fn inode_table_lba(&self, sb: &Ext2SuperBlock) -> u64 {
        Self::block_to_lba(self.get_inode_table_block(), sb)
    }
}

// ============================================================================
// Block Group Table
// ============================================================================

/// A cached view of the block group descriptor table
pub struct Ext2GroupDescTable {
    /// Array of group descriptors
    pub descriptors: Vec<Ext2GroupDesc>,
    /// Number of groups
    pub group_count: u32,
    /// Size of each descriptor in bytes
    pub desc_size: usize,
}

impl Ext2GroupDescTable {
    /// Create a new empty group descriptor table
    pub fn new() -> Self {
        Self {
            descriptors: Vec::new(),
            group_count: 0,
            desc_size: 0,
        }
    }

    /// Get the descriptor for a specific block group
    pub fn get(&self, group: u32) -> Option<&Ext2GroupDesc> {
        if (group as usize) < self.descriptors.len() {
            Some(&self.descriptors[group as usize])
        } else {
            None
        }
    }

    /// Get the descriptor for a specific block group (mutable)
    pub fn get_mut(&mut self, group: u32) -> Option<&mut Ext2GroupDesc> {
        if (group as usize) < self.descriptors.len() {
            Some(&mut self.descriptors[group as usize])
        } else {
            None
        }
    }
}

// ============================================================================
// Group Descriptor Table Functions
// ============================================================================

/// Calculate the size of the group descriptor table
pub fn calculate_gdt_size(sb: &Ext2SuperBlock) -> usize {
    let group_count = sb.get_group_count() as usize;
    let desc_size = if sb.is_dynamic_rev() && sb.inode_size >= 255 {
        EXT2_BGDESC_SIZE_NEW
    } else {
        EXT2_BGDESC_SIZE_OLD
    };
    
    // Round up to block boundary
    let total = group_count * desc_size;
    let block_size = sb.get_block_size() as usize;
    ((total + block_size - 1) / block_size) * block_size
}

/// Calculate the block number where the GDT starts
/// The GDT starts in the block immediately after the superblock
pub fn get_gdt_start_block(sb: &Ext2SuperBlock) -> u64 {
    // Superblock is at byte 1024, which may be in block 0 or 1
    // depending on block size. The GDT always starts at the block
    // immediately after the superblock.
    let superblock_block = SUPERBLOCK_OFFSET / (sb.get_block_size() as u64);
    superblock_block + 1
}

/// Read the entire group descriptor table from disk
pub fn read_group_desc_table(
    device: *mut (),
    sb: &Ext2SuperBlock,
) -> Option<Ext2GroupDescTable> {
    let group_count = sb.get_group_count();
    let block_size = sb.get_block_size() as usize;
    
    // Determine descriptor size
    let desc_size = if sb.is_dynamic_rev() && sb.inode_size >= 255 {
        EXT2_BGDESC_SIZE_NEW
    } else {
        EXT2_BGDESC_SIZE_OLD
    };
    
    // Calculate total size needed
    let total_size = (group_count as usize) * desc_size;
    let blocks_needed = (total_size + block_size - 1) / block_size;
    
    // Read the GDT
    let gdt_start = get_gdt_start_block(sb);
    let mut buffer = vec![0u8; blocks_needed * block_size];
    
    if super::superblock::read_sectors(device, gdt_start, blocks_needed as u32, &mut buffer).is_err() {
        // kprintln!("[EXT2] Failed to read group descriptor table")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Parse descriptors
    let mut descriptors = Vec::with_capacity(group_count as usize);
    for i in 0..group_count {
        let offset = (i as usize) * desc_size;
        if offset + EXT2_BGDESC_SIZE_OLD <= buffer.len() {
            let desc = unsafe {
                core::ptr::read_unaligned(
                    buffer.as_ptr().add(offset) as *const Ext2GroupDesc
                )
            };
            descriptors.push(desc);
        }
    }
    
    Some(Ext2GroupDescTable {
        descriptors,
        group_count,
        desc_size,
    })
}

/// Read a single group descriptor
pub fn read_group_descriptor(
    device: *mut (),
    sb: &Ext2SuperBlock,
    group_num: u32,
) -> Option<Ext2GroupDesc> {
    let group_count = sb.get_group_count();
    if group_num >= group_count {
        // kprintln!("[EXT2] Group number {} out of range (max {})", group_num, group_count)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Determine descriptor size
    let desc_size = if sb.is_dynamic_rev() && sb.inode_size >= 255 {
        EXT2_BGDESC_SIZE_NEW
    } else {
        EXT2_BGDESC_SIZE_OLD
    };
    
    // Calculate block and offset
    let block_size = sb.get_block_size() as usize;
    let gdt_start = get_gdt_start_block(sb);
    let desc_offset = (group_num as usize) * desc_size;
    let block_offset = desc_offset % block_size;
    let block_num = desc_offset / block_size;
    
    // Read the block
    let mut buffer = vec![0u8; block_size];
    let sector = (gdt_start + block_num as u64) * (block_size / 512) as u64;
    
    if super::superblock::read_sector(device, sector, &mut buffer).is_err() {
        // kprintln!("[EXT2] Failed to read GDT block for group {}", group_num)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Parse descriptor
    Some(unsafe {
        core::ptr::read_unaligned(
            buffer.as_ptr().add(block_offset) as *const Ext2GroupDesc
        )
    })
}

// ============================================================================
// Block Group Utility Functions
// ============================================================================

/// Get the first block of a block group
pub fn group_first_block(sb: &Ext2SuperBlock, group: u32) -> u64 {
    if sb.blocks_per_group == 0 {
        return 0;
    }
    (group as u64) * (sb.blocks_per_group as u64) + (sb.first_data_block as u64)
}

/// Get the last block of a block group
pub fn group_last_block(sb: &Ext2SuperBlock, group: u32) -> u64 {
    let first = group_first_block(sb, group);
    first + (sb.blocks_per_group as u64) - 1
}

/// Get the inode table start block for a group.
/// The actual value depends on the block group's inode_table field
/// which should be read via read_group_descriptor().
pub fn group_inode_table_start(_sb: &Ext2SuperBlock, _group: u32) -> u64 {
    // The inode table start is stored in the block group descriptor.
    // Callers should use read_group_descriptor(group_idx).inode_table
    // to obtain the correct value. This helper returns 0 as a safe
    // default when the descriptor is not available.
    0
}

/// Check if a block group has a backup superblock
/// According to the sparse super feature, backups exist at:
/// - Group 0 always
/// - Groups 1, 3, 5, 7 (powers of 2 - 1) for sparse_super
pub fn has_backup_superblock(sb: &Ext2SuperBlock, group: u32) -> bool {
    if group == 0 {
        return true; // Primary superblock
    }
    
    if !sb.has_sparse_super() {
        // All groups have backup if not sparse
        return true;
    }
    
    // Sparse super: backups at groups 1, 3, 5, 7, 9, 25, 27...
    // (powers of 2 minus 1, up to a reasonable limit)
    if group == 1 || group == 3 || group == 5 || group == 7 || group == 9 {
        return true;
    }
    
    // Groups like 25, 27, 29, 31 for larger filesystems
    if group >= 25 && group <= 27 {
        return true;
    }
    
    false
}

/// Get the backup superblock block number for a group
pub fn backup_superblock_block(sb: &Ext2SuperBlock, group: u32) -> u64 {
    group_first_block(sb, group)
}

/// Get the backup GDT block number for a group
pub fn backup_gdt_block(sb: &Ext2SuperBlock, group: u32) -> u64 {
    group_first_block(sb, group) + 1
}

// ============================================================================
// Block Group Calculations
// ============================================================================

/// Calculate which block group contains a given block
pub fn block_to_group(sb: &Ext2SuperBlock, block: u64) -> u32 {
    if block < sb.first_data_block as u64 {
        return 0;
    }
    ((block - sb.first_data_block as u64) / sb.blocks_per_group as u64) as u32
}

/// Calculate which block group contains a given inode
pub fn inode_to_group(sb: &Ext2SuperBlock, inode: u32) -> u32 {
    if inode == 0 {
        return 0;
    }
    (inode - 1) / sb.inodes_per_group
}

/// Calculate the first inode number in a block group
pub fn group_first_inode(sb: &Ext2SuperBlock, group: u32) -> u32 {
    group * sb.inodes_per_group + 1
}

/// Calculate the last inode number in a block group
pub fn group_last_inode(sb: &Ext2SuperBlock, group: u32) -> u32 {
    let first = group_first_inode(sb, group);
    let count = sb.inodes_per_group;
    if group == sb.get_group_count() - 1 {
        // Last group may have fewer inodes
        sb.inodes_count - first + 1
    } else {
        count
    }
}

// ============================================================================
// Uninitialized Block Groups
// ============================================================================

/// Check if a block group is uninitialized (sparse_super backup)
pub fn is_uninit_group(sb: &Ext2SuperBlock, group: u32) -> bool {
    // In sparse_super filesystems, groups that don't have backups
    // are marked as uninitialized
    if sb.has_sparse_super() && !has_backup_superblock(sb, group) {
        return true;
    }
    
    // With meta_bg, groups in meta_bg > 0 may be uninitialized
    if (sb.incompatible_features & 0x10) != 0 {
        // meta_bg feature - groups may have different layouts
        return false; // Simplified for now
    }
    
    false
}

/// Get the block group descriptor for flex_bg
/// In flex_bg, the first group in each flex_bg contains shared metadata
pub fn flex_bg_first_group(_sb: &Ext2SuperBlock, group: u32, log_groups_per_flex: u32) -> u32 {
    if log_groups_per_flex == 0 {
        return group;
    }
    
    let groups_per_flex = 1u32 << log_groups_per_flex;
    (group / groups_per_flex) * groups_per_flex
}
