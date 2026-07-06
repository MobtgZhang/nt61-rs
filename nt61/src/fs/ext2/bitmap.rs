//! ext2 Bitmap Management
//
//! Implements block and inode bitmap operations for allocation and deallocation.
//! Bitmaps are stored in one block per block group.
//
//! ## Bitmap Structure
//! Each bit represents one block or inode:
//! - Bit 0 = first item in the group
//! - Bit 1 = second item in the group
//! - etc.
//
//! A bit value of 0 means free, 1 means allocated.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use super::group::read_group_descriptor;
use super::superblock::Ext2SuperBlock;

// ============================================================================
// Bitmap Constants
// ============================================================================

/// Bitmap magic number (for validation)
pub const BITMAP_VALID_MAGIC: u32 = 0x50494E47; // "PING"

/// Maximum number of bits in a bitmap block
/// For a 4096-byte block with u32 entries
pub const BITS_PER_BLOCK: usize = 4096 * 8;

/// Bits per u32 for iteration
pub const BITS_PER_U32: usize = 32;

// ============================================================================
// Bitmap Block Operations
// ============================================================================

/// Read a block bitmap from disk
pub fn read_block_bitmap(
    device: *mut (),
    sb: &Ext2SuperBlock,
    group_num: u32,
) -> Option<Vec<u8>> {
    // Get group descriptor
    let group_desc = read_group_descriptor(device, sb, group_num)?;
    let block_bitmap = group_desc.get_block_bitmap_block();
    
    let block_size = sb.get_block_size() as usize;
    let mut bitmap = vec![0u8; block_size];
    
    // Convert block number to LBA
    let lba = block_bitmap * (block_size / 512) as u64;
    
    if super::superblock::read_sector(device, lba, &mut bitmap).is_err() {
        // kprintln!("[EXT2] Failed to read block bitmap for group {}", group_num)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    Some(bitmap)
}

/// Read an inode bitmap from disk
pub fn read_inode_bitmap(
    device: *mut (),
    sb: &Ext2SuperBlock,
    group_num: u32,
) -> Option<Vec<u8>> {
    // Get group descriptor
    let group_desc = read_group_descriptor(device, sb, group_num)?;
    let inode_bitmap = group_desc.get_inode_bitmap_block();
    
    let block_size = sb.get_block_size() as usize;
    let mut bitmap = vec![0u8; block_size];
    
    // Convert block number to LBA
    let lba = inode_bitmap * (block_size / 512) as u64;
    
    if super::superblock::read_sector(device, lba, &mut bitmap).is_err() {
        // kprintln!("[EXT2] Failed to read inode bitmap for group {}", group_num)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    Some(bitmap)
}

// ============================================================================
// Bitmap Bit Operations
// ============================================================================

/// Test if a bit is set in a bitmap
pub fn test_bit(bitmap: &[u8], bit: usize) -> bool {
    let byte_index = bit / 8;
    let bit_index = bit % 8;
    
    if byte_index >= bitmap.len() {
        return false;
    }
    
    (bitmap[byte_index] & (1 << bit_index)) != 0
}

/// Set a bit in a bitmap
pub fn set_bit(bitmap: &mut [u8], bit: usize) {
    let byte_index = bit / 8;
    let bit_index = bit % 8;
    
    if byte_index < bitmap.len() {
        bitmap[byte_index] |= 1 << bit_index;
    }
}

/// Clear a bit in a bitmap
pub fn clear_bit(bitmap: &mut [u8], bit: usize) {
    let byte_index = bit / 8;
    let bit_index = bit % 8;
    
    if byte_index < bitmap.len() {
        bitmap[byte_index] &= !(1 << bit_index);
    }
}

/// Find the first zero bit in a bitmap
pub fn find_first_zero(bitmap: &[u8], max_bits: usize) -> Option<usize> {
    for (byte_index, &byte) in bitmap.iter().enumerate() {
        if byte != 0xFF {
            // Not all bits are set, find the first zero
            for bit in 0..8 {
                let global_bit = byte_index * 8 + bit;
                if global_bit < max_bits && (byte & (1 << bit)) == 0 {
                    return Some(global_bit);
                }
            }
        }
    }
    None
}

/// Count the number of set bits in a bitmap
pub fn count_bits(bitmap: &[u8]) -> usize {
    bitmap.iter().map(|&byte| byte.count_ones() as usize).sum()
}

/// Count the number of free bits in a bitmap
pub fn count_free_bits(bitmap: &[u8], max_bits: usize) -> usize {
    let total_bits = bitmap.len() * 8;
    let effective_bits = core::cmp::min(total_bits, max_bits);
    let used_bits = count_bits(bitmap);
    // Only count bits within max_bits range
    let _extra_bits = if total_bits > max_bits {
        total_bits - max_bits
    } else {
        0
    };
    effective_bits.saturating_sub(used_bits.saturating_sub(
        if total_bits > max_bits {
            // Count set bits in the extra region
            let extra_bytes = (total_bits - max_bits + 7) / 8;
            let start = bitmap.len() - extra_bytes;
            bitmap[start..].iter().map(|&b| b.count_ones() as usize).sum()
        } else {
            0
        }
    ))
}

// ============================================================================
// Block Allocation
// ============================================================================

/// Allocate a free block in a specific block group
pub fn allocate_block_in_group(
    device: *mut (),
    sb: &Ext2SuperBlock,
    group_num: u32,
) -> Option<u32> {
    let mut bitmap = read_block_bitmap(device, sb, group_num)?;
    let group_desc = read_group_descriptor(device, sb, group_num)?;
    
    let blocks_per_group = sb.blocks_per_group;
    let _first_block = if group_num == 0 {
        sb.first_data_block
    } else {
        group_num * blocks_per_group + sb.first_data_block
    };
    
    // Find a free block in this bitmap
    let mut block_index = 0;
    while block_index < blocks_per_group as usize {
        if !test_bit(&bitmap, block_index) {
            // Found a free block
            set_bit(&mut bitmap, block_index);
            
            // Write bitmap back
            let block_bitmap = group_desc.get_block_bitmap_block();
            let lba = block_bitmap * (sb.get_block_size() / 512) as u64;
            if super::superblock::write_sector(device, lba, &bitmap).is_err() {
                return None;
            }
            
            // Update superblock free block count
            let block_num = (group_num * blocks_per_group + block_index as u32) + sb.first_data_block;
            return Some(block_num);
        }
        block_index += 1;
    }
    
    None
}

/// Allocate a free block anywhere in the filesystem
pub fn allocate_block(
    device: *mut (),
    sb: &Ext2SuperBlock,
) -> Option<u32> {
    let group_count = sb.get_group_count();
    
    // Search each block group for a free block
    for group in 0..group_count {
        if let Some(block) = allocate_block_in_group(device, sb, group) {
            return Some(block);
        }
    }
    
    // kprintln!("[EXT2] No free blocks available")  // kprintln disabled (memcpy crash workaround);
    None
}

/// Free a block
pub fn free_block(
    device: *mut (),
    sb: &Ext2SuperBlock,
    block_num: u64,
) -> Result<(), ()> {
    let blocks_per_group = sb.blocks_per_group as u64;
    
    // Calculate which group this block belongs to
    let group_num = ((block_num - sb.first_data_block as u64) / blocks_per_group) as u32;
    let block_index = ((block_num - sb.first_data_block as u64) % blocks_per_group) as usize;
    
    // Read bitmap
    let mut bitmap = match read_block_bitmap(device, sb, group_num) {
        Some(b) => b,
        None => return Err(()),
    };
    
    // Clear the bit
    if !test_bit(&bitmap, block_index) {
        // Block was already free
        return Ok(());
    }
    clear_bit(&mut bitmap, block_index);
    
    // Write bitmap back
    let group_desc = match read_group_descriptor(device, sb, group_num) {
        Some(gd) => gd,
        None => return Err(()),
    };
    
    let lba = group_desc.get_block_bitmap_block() * (sb.get_block_size() / 512) as u64;
    super::superblock::write_sector(device, lba, &bitmap)?;
    
    Ok(())
}

/// Check if a block is allocated
pub fn is_block_allocated(
    device: *mut (),
    sb: &Ext2SuperBlock,
    block_num: u64,
) -> bool {
    let blocks_per_group = sb.blocks_per_group as u64;
    
    let group_num = ((block_num - sb.first_data_block as u64) / blocks_per_group) as u32;
    let block_index = ((block_num - sb.first_data_block as u64) % blocks_per_group) as usize;
    
    let bitmap = match read_block_bitmap(device, sb, group_num) {
        Some(b) => b,
        None => return false,
    };
    
    test_bit(&bitmap, block_index)
}

// ============================================================================
// Inode Allocation
// ============================================================================

/// Allocate a free inode in a specific block group
pub fn allocate_inode_in_group(
    device: *mut (),
    sb: &Ext2SuperBlock,
    group_num: u32,
    _is_dir: bool,
) -> Option<u32> {
    let mut bitmap = read_inode_bitmap(device, sb, group_num)?;
    
    let inodes_per_group = sb.inodes_per_group;
    let first_inode = if group_num == 0 {
        1 // Inode 1 is reserved
    } else {
        group_num * inodes_per_group + 1
    };
    
    // Find a free inode in this bitmap
    let mut inode_index = 0;
    while inode_index < inodes_per_group as usize {
        // Skip inode 0 and reserved inodes
        let global_inode = first_inode + inode_index as u32;
        if global_inode == 0 || global_inode < sb.first_ino {
            inode_index += 1;
            continue;
        }
        
        if !test_bit(&bitmap, inode_index) {
            // Found a free inode
            set_bit(&mut bitmap, inode_index);
            
            // Write bitmap back
            let group_desc = match read_group_descriptor(device, sb, group_num) {
                Some(gd) => gd,
                None => return None,
            };
            
            let inode_bitmap = group_desc.get_inode_bitmap_block();
            let lba = inode_bitmap * (sb.get_block_size() / 512) as u64;
            if super::superblock::write_sector(device, lba, &bitmap).is_err() {
                return None;
            }
            
            return Some(global_inode);
        }
        inode_index += 1;
    }
    
    None
}

/// Allocate a free inode anywhere in the filesystem
pub fn allocate_inode(
    device: *mut (),
    sb: &Ext2SuperBlock,
    preferred_group: Option<u32>,
    is_dir: bool,
) -> Option<u32> {
    let group_count = sb.get_group_count();
    
    // Try preferred group first
    if let Some(group) = preferred_group {
        if let Some(inode) = allocate_inode_in_group(device, sb, group, is_dir) {
            return Some(inode);
        }
    }
    
    // Search each block group for a free inode
    // Prefer groups with more free inodes
    let mut best_group: Option<u32> = None;
    let mut best_free = 0u32;
    
    for group in 0..group_count {
        if let Some(gd) = read_group_descriptor(device, sb, group) {
            let free = gd.get_free_inodes() as u32;
            if free > best_free {
                best_free = free;
                best_group = Some(group);
            }
        }
    }
    
    if let Some(group) = best_group {
        return allocate_inode_in_group(device, sb, group, is_dir);
    }
    
    // kprintln!("[EXT2] No free inodes available")  // kprintln disabled (memcpy crash workaround);
    None
}

/// Free an inode
pub fn free_inode(
    device: *mut (),
    sb: &Ext2SuperBlock,
    inode_num: u32,
) -> Result<(), ()> {
    if inode_num == 0 || inode_num > sb.inodes_count {
        return Err(());
    }
    
    let inodes_per_group = sb.inodes_per_group;
    let group_num = (inode_num - 1) / inodes_per_group;
    let inode_index = ((inode_num - 1) % inodes_per_group) as usize;
    
    // Read bitmap
    let mut bitmap = match read_inode_bitmap(device, sb, group_num) {
        Some(b) => b,
        None => return Err(()),
    };
    
    // Clear the bit
    if !test_bit(&bitmap, inode_index) {
        // Inode was already free
        return Ok(());
    }
    clear_bit(&mut bitmap, inode_index);
    
    // Write bitmap back
    let group_desc = match read_group_descriptor(device, sb, group_num) {
        Some(gd) => gd,
        None => return Err(()),
    };
    
    let inode_bitmap = group_desc.get_inode_bitmap_block();
    let lba = inode_bitmap * (sb.get_block_size() / 512) as u64;
    super::superblock::write_sector(device, lba, &bitmap)?;
    
    Ok(())
}

/// Check if an inode is allocated
pub fn is_inode_allocated(
    device: *mut (),
    sb: &Ext2SuperBlock,
    inode_num: u32,
) -> bool {
    if inode_num == 0 || inode_num > sb.inodes_count {
        return false;
    }
    
    let inodes_per_group = sb.inodes_per_group;
    let group_num = (inode_num - 1) / inodes_per_group;
    let inode_index = ((inode_num - 1) % inodes_per_group) as usize;
    
    let bitmap = match read_inode_bitmap(device, sb, group_num) {
        Some(b) => b,
        None => return false,
    };
    
    test_bit(&bitmap, inode_index)
}

// ============================================================================
// Bitmap Write Functions
// ============================================================================

/// Write a block bitmap to disk
pub fn write_block_bitmap(
    device: *mut (),
    sb: &Ext2SuperBlock,
    group_num: u32,
    bitmap: &[u8],
) -> Result<(), ()> {
    let group_desc = match read_group_descriptor(device, sb, group_num) {
        Some(gd) => gd,
        None => return Err(()),
    };
    
    let lba = group_desc.get_block_bitmap_block() * (sb.get_block_size() / 512) as u64;
    super::superblock::write_sector(device, lba, bitmap)
}

/// Write an inode bitmap to disk
pub fn write_inode_bitmap(
    device: *mut (),
    sb: &Ext2SuperBlock,
    group_num: u32,
    bitmap: &[u8],
) -> Result<(), ()> {
    let group_desc = match read_group_descriptor(device, sb, group_num) {
        Some(gd) => gd,
        None => return Err(()),
    };
    
    let lba = group_desc.get_inode_bitmap_block() * (sb.get_block_size() / 512) as u64;
    super::superblock::write_sector(device, lba, bitmap)
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get the block group for a given block number
pub fn get_block_group(sb: &Ext2SuperBlock, block_num: u32) -> u32 {
    sb.get_block_group(block_num)
}

/// Get the block group for a given inode number
pub fn get_inode_group(sb: &Ext2SuperBlock, inode_num: u32) -> u32 {
    sb.get_inode_group(inode_num)
}

/// Get the bit offset within the bitmap for a block
pub fn get_block_bit_offset(sb: &Ext2SuperBlock, block_num: u32) -> usize {
    ((block_num - sb.first_data_block) % sb.blocks_per_group) as usize
}

/// Get the bit offset within the bitmap for an inode
pub fn get_inode_bit_offset(sb: &Ext2SuperBlock, inode_num: u32) -> usize {
    ((inode_num - 1) % sb.inodes_per_group) as usize
}
