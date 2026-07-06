//! ext2 Inode Operations
//
//! Implements inode reading, writing, and manipulation.
//! Inodes are the fundamental metadata structures in ext2/3/4.
//
//! ## Inode Structure
//! Each file or directory is represented by an inode containing:
//! - File type and permissions (mode)
//! - Owner and group IDs
//! - File size (up to 4GB for old format, larger with INLINE_DATA)
//! - Timestamps (access, modify, change)
//! - Direct, indirect, and double/triple indirect block pointers
//! - Extended attributes (ext4)
//
//! ## Inode Table
//! Inodes are stored in the inode table within each block group.

extern crate alloc;

use alloc::vec;

use super::group::read_group_descriptor;
use super::superblock::{Ext2SuperBlock, EXT2_FEATURE_RO_COMPAT_LARGE_FILE, SUPERBLOCK_OFFSET};
use super::extent::Ext4ExtentHeader;

// ============================================================================
// Inode Constants
// ============================================================================

/// Inode size for old revision (fixed)
pub const EXT2_OLD_INODE_SIZE: u16 = 128;

/// Number of direct block pointers in inode
pub const EXT2_NDIR_BLOCKS: usize = 12;

/// Number of block pointers in indirect block
pub const EXT2_IND_BLOCK: usize = 12;

/// Number of block pointers in double indirect block
pub const EXT2_DIND_BLOCK: usize = 13;

/// Number of block pointers in triple indirect block
pub const EXT2_TIND_BLOCK: usize = 14;

/// Index of first indirect block pointer in inode
pub const EXT2_FIRST_INDIRECT_BLOCK: usize = EXT2_NDIR_BLOCKS;

/// Index of double indirect block pointer in inode
pub const EXT2_DOUBLE_INDIRECT_BLOCK: usize = EXT2_IND_BLOCK;

/// Index of triple indirect block pointer in inode
pub const EXT2_TRIPLE_INDIRECT_BLOCK: usize = EXT2_DIND_BLOCK;

/// ext2 inode flags
pub const EXT2_SECRM_FL: u32 = 0x00000001;      // Secure deletion
pub const EXT2_UNRM_FL: u32 = 0x00000002;       // Undelete
pub const EXT2_COMPR_FL: u32 = 0x00000004;      // Compress
pub const EXT2_SYNC_FL: u32 = 0x00000008;       // Synchronous updates
pub const EXT2_IMMUTABLE_FL: u32 = 0x00000010;  // Immutable
pub const EXT2_APPEND_FL: u32 = 0x00000020;     // Append only
pub const EXT2_NODUMP_FL: u32 = 0x00000040;      // No dump
pub const EXT2_NOATIME_FL: u32 = 0x00000080;    // No atime updates
pub const EXT2_COMPRBLK_FL: u32 = 0x00000100;   // Compressed blocks
pub const EXT2_DIRSYNC_FL: u32 = 0x00010000;    // Synchronous directory
pub const EXT2_TOPDIR_FL: u32 = 0x00020000;     // Top of directory
pub const EXT2_HUGE_FILE_FL: u32 = 0x00040000;  // Huge file
pub const EXT2_EXTENTS_FL: u32 = 0x00080000;     // Extents
pub const EXT2_EA_INODE_FL: u32 = 0x00200000;    // EA in inode
pub const EXT2_EOFBLOCKS_FL: u32 = 0x00400000;  // Blocks allocated beyond EOF
pub const EXT2_SNAPFILE_FL: u32 = 0x01000000;   // Snapshot
pub const EXT2_DAX_FL: u32 = 0x10000000;         // DAX
pub const EXT2_INLINE_DATA_FL: u32 = 0x10000000; // ext4 inline data

// ============================================================================
// File Mode Constants
// ============================================================================

/// Inode mode: file type mask
pub const EXT2_S_IFMT: u16 = 0xF000;

/// Inode mode: socket
pub const EXT2_S_IFSOCK: u16 = 0xC000;

/// Inode mode: symbolic link
pub const EXT2_S_IFLNK: u16 = 0xA000;

/// Inode mode: regular file
pub const EXT2_S_IFREG: u16 = 0x8000;

/// Inode mode: block device
pub const EXT2_S_IFBLK: u16 = 0x6000;

/// Inode mode: character device
pub const EXT2_S_IFCHR: u16 = 0x2000;

/// Inode mode: named pipe / FIFO
pub const EXT2_S_IFIFO: u16 = 0x1000;

/// Inode mode: directory
pub const EXT2_S_IFDIR: u16 = 0x4000;

/// Inode mode: Unix socket
pub const S_IFSOCK: u16 = 0xC000;

/// Permission bits
pub const EXT2_S_IRUSR: u16 = 0x0100;  // Owner read
pub const EXT2_S_IWUSR: u16 = 0x0080;  // Owner write
pub const EXT2_S_IXUSR: u16 = 0x0040;  // Owner execute
pub const EXT2_S_IRGRP: u16 = 0x0020;  // Group read
pub const EXT2_S_IWGRP: u16 = 0x0010;  // Group write
pub const EXT2_S_IXGRP: u16 = 0x0008;  // Group execute
pub const EXT2_S_IROTH: u16 = 0x0004;  // Others read
pub const EXT2_S_IWOTH: u16 = 0x0002;  // Others write
pub const EXT2_S_IXOTH: u16 = 0x0001;  // Others execute

/// Common permission combinations
pub const EXT2_S_IRWXU: u16 = 0x01C0;  // Owner: rwx
pub const EXT2_S_IRWXG: u16 = 0x0038;  // Group: rwx
pub const EXT2_S_IRWXO: u16 = 0x0007;  // Others: rwx

// ============================================================================
// Inode Structure
// ============================================================================

/// ext2 Inode structure (128 bytes for old format, variable for revision 1)
/// The inode contains all metadata about a file or directory.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ext2Inode {
    /// File mode (type + permissions)
    pub mode: u16,
    /// Lower 16 bits of user ID
    pub uid: u16,
    /// Lower 32 bits of file size
    pub size: u32,
    /// Last access time (Unix timestamp)
    pub atime: u32,
    /// Creation time (Unix timestamp)
    pub ctime: u32,
    /// Last modification time (Unix timestamp)
    pub mtime: u32,
    /// Deletion time (Unix timestamp, 0 if not deleted)
    pub dtime: u32,
    /// Lower 16 bits of group ID
    pub gid: u16,
    /// Hard link count
    pub links_count: u16,
    /// Lower 32 bits of blocks count (512-byte blocks)
    pub blocks: u32,
    /// File flags
    pub flags: u32,
    /// OS specific value (usually 0)
    pub osd1: u32,
    /// Direct block pointers (12 x 4 bytes)
    pub block: [u32; EXT2_NDIR_BLOCKS],
    /// Single indirect block pointer
    pub i_block: u32,
    /// Double indirect block pointer
    pub i_double_block: u32,
    /// Triple indirect block pointer
    pub i_triple_block: u32,
    /// File version (NFS)
    pub generation: u32,
    /// File ACL (upper 32 bits of size for large files)
    pub file_acl: u32,
    /// Upper 32 bits of size (if huge_file feature)
    pub dir_acl: u32,
    /// Fragment address (unused in Linux)
    pub faddr: u32,
    /// File fragment block number (unused)
    pub frag: u8,
    /// Fragment block size (unused)
    pub fsize: u8,
    /// User permissions (upper bits of uid)
    pub uid_high: u16,
    /// Group permissions (upper bits of gid)
    pub gid_high: u16,
    /// Reserved for future use
    pub reserved: u32,
    // Note: With larger inode sizes (ext4), there can be additional
    // fields for extended attributes and extents
}

impl Ext2Inode {
    // ========================================================================
    // File Type Checking
    // ========================================================================

    /// Check if this is a regular file
    pub fn is_file(&self) -> bool {
        (self.mode & EXT2_S_IFMT) == EXT2_S_IFREG
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        (self.mode & EXT2_S_IFMT) == EXT2_S_IFDIR
    }

    /// Check if this is a symbolic link
    pub fn is_symlink(&self) -> bool {
        (self.mode & EXT2_S_IFMT) == EXT2_S_IFLNK
    }

    /// Check if this is a block device
    pub fn is_blk(&self) -> bool {
        (self.mode & EXT2_S_IFMT) == EXT2_S_IFBLK
    }

    /// Check if this is a character device
    pub fn is_chr(&self) -> bool {
        (self.mode & EXT2_S_IFMT) == EXT2_S_IFCHR
    }

    /// Check if this is a FIFO/named pipe
    pub fn is_fifo(&self) -> bool {
        (self.mode & EXT2_S_IFMT) == EXT2_S_IFIFO
    }

    /// Check if this is a socket
    pub fn is_socket(&self) -> bool {
        (self.mode & EXT2_S_IFMT) == EXT2_S_IFSOCK
    }

    /// Get the file type as a string
    pub fn get_type_string(&self) -> &'static str {
        match self.mode & EXT2_S_IFMT {
            EXT2_S_IFREG => "regular file",
            EXT2_S_IFDIR => "directory",
            EXT2_S_IFLNK => "symbolic link",
            EXT2_S_IFBLK => "block device",
            EXT2_S_IFCHR => "character device",
            EXT2_S_IFIFO => "FIFO/pipe",
            EXT2_S_IFSOCK => "socket",
            _ => "unknown",
        }
    }

    /// Check if this inode represents a directory
    pub fn is_directory(&self) -> bool {
        self.is_dir()
    }

    /// Check if this inode represents a regular file
    pub fn is_regular_file(&self) -> bool {
        self.is_file()
    }

    // ========================================================================
    // Size Access
    // ========================================================================

    /// Get the file size in bytes (handles 64-bit sizes)
    pub fn get_size(&self, sb: &Ext2SuperBlock) -> u64 {
        // Check for large file feature (upper 32 bits)
        if (sb.ro_compatible_features & EXT2_FEATURE_RO_COMPAT_LARGE_FILE) != 0
            || sb.is_dynamic_rev()
        {
            ((self.dir_acl as u64) << 32) | (self.size as u64)
        } else {
            self.size as u64
        }
    }

    /// Get the allocated blocks count (in 512-byte blocks)
    pub fn get_blocks(&self) -> u32 {
        self.blocks
    }

    /// Get the actual data size (blocks * 512)
    pub fn get_data_size(&self) -> u64 {
        (self.blocks as u64) * 512
    }

    // ========================================================================
    // Permission Access
    // ========================================================================

    /// Get file permissions (mode without file type)
    pub fn get_perms(&self) -> u16 {
        self.mode & 0x0FFF
    }

    /// Get owner UID
    pub fn get_uid(&self) -> u32 {
        ((self.uid_high as u32) << 16) | (self.uid as u32)
    }

    /// Get group GID
    pub fn get_gid(&self) -> u32 {
        ((self.gid_high as u32) << 16) | (self.gid as u32)
    }

    /// Get hard link count
    pub fn get_links(&self) -> u16 {
        self.links_count
    }

    /// Check if file is setuid
    pub fn is_suid(&self) -> bool {
        (self.mode & 0x0800) != 0
    }

    /// Check if file is setgid
    pub fn is_sgid(&self) -> bool {
        (self.mode & 0x0400) != 0
    }

    /// Check if file has sticky bit
    pub fn is_sticky(&self) -> bool {
        (self.mode & 0x0200) != 0
    }

    // ========================================================================
    // Timestamp Access
    // ========================================================================

    /// Get last access time
    pub fn atime(&self) -> u32 {
        self.atime
    }

    /// Get creation time
    pub fn ctime(&self) -> u32 {
        self.ctime
    }

    /// Get last modification time
    pub fn mtime(&self) -> u32 {
        self.mtime
    }

    /// Get deletion time (0 if not deleted)
    pub fn dtime(&self) -> u32 {
        self.dtime
    }

    /// Check if inode is deleted
    pub fn is_deleted(&self) -> bool {
        self.dtime != 0
    }

    // ========================================================================
    // Block Access
    // ========================================================================

    /// Get a direct block pointer
    pub fn get_direct_block(&self, index: usize) -> Option<u32> {
        if index < EXT2_NDIR_BLOCKS {
            Some(self.block[index])
        } else {
            None
        }
    }

    /// Get the single indirect block pointer
    pub fn get_indirect_block(&self) -> u32 {
        self.i_block
    }

    /// Get the double indirect block pointer
    pub fn get_double_indirect_block(&self) -> u32 {
        self.i_double_block
    }

    /// Get the triple indirect block pointer
    pub fn get_triple_indirect_block(&self) -> u32 {
        self.i_triple_block
    }

    /// Check if file has inline data (ext4)
    pub fn has_inline_data(&self) -> bool {
        (self.flags & EXT2_INLINE_DATA_FL) != 0
    }

    /// Check if file uses extents (ext4)
    pub fn has_extents(&self) -> bool {
        (self.flags & EXT2_EXTENTS_FL) != 0
    }
}

// ============================================================================
// Inode Table Operations
// ============================================================================

/// Calculate the byte offset of an inode within the inode table
pub fn inode_table_offset(sb: &Ext2SuperBlock, inode_num: u32) -> u64 {
    let inode_size = sb.get_inode_size() as u64;
    let inodes_per_group = sb.inodes_per_group as u64;
    let block_size = sb.get_block_size() as u64;
    
    // Calculate which group this inode is in
    let group = ((inode_num - 1) as u64) / (inodes_per_group as u64);
    
    // Get group descriptor for this group
    // For simplicity, we'll calculate based on standard layout
    
    // The inode table starts at the block specified in the group descriptor
    // For now, assume standard layout where GDT follows superblock
    let _gdt_block = SUPERBLOCK_OFFSET / block_size + 1;
    let gdt_size = super::group::calculate_gdt_size(sb) as u64;
    
    // Group starts at first_data_block + group * blocks_per_group
    let group_start = (sb.first_data_block as u64) + (group * sb.blocks_per_group as u64);
    
    // Inode table starts at the first block after GDT
    let inode_table_block = group_start + gdt_size / block_size;
    
    // Calculate offset within inode table
    let inode_index = ((inode_num - 1) as u64) % (inodes_per_group as u64);
    let byte_offset = inode_index * inode_size;
    
    // Convert to absolute LBA (assuming 512-byte sectors)
    (inode_table_block * block_size + byte_offset) / 512
}

/// Read an inode from disk
pub fn read_inode(
    device: *mut (),
    sb: &Ext2SuperBlock,
    inode_num: u32,
) -> Option<Ext2Inode> {
    if inode_num == 0 || inode_num > sb.inodes_count {
        // kprintln!("[EXT2] Invalid inode number: {}", inode_num)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    let inode_size = sb.get_inode_size() as usize;
    let inodes_per_group = sb.inodes_per_group as usize;
    
    // Calculate which group this inode is in
    let group = ((inode_num - 1) as usize / inodes_per_group) as u32;
    
    // Read group descriptor to get inode table location
    let group_desc = read_group_descriptor(device, sb, group)?;
    
    // Calculate byte offset within inode table
    let inode_index = ((inode_num - 1) as usize % inodes_per_group) as usize;
    let byte_offset = inode_index * inode_size;
    
    // Calculate block and sector
    let block_size = sb.get_block_size() as usize;
    let inode_table_start = group_desc.get_inode_table_block() as usize;
    let block_offset = byte_offset % block_size;
    let block_num = inode_table_start + byte_offset / block_size;
    
    // Read the block containing this inode
    let mut buffer = vec![0u8; block_size];
    let sector = block_num * (block_size / 512);
    
    if super::superblock::read_sector(device, sector as u64, &mut buffer).is_err() {
        // kprintln!("[EXT2] Failed to read inode {} block", inode_num)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Parse inode from buffer
    let inode_ptr = unsafe { buffer.as_ptr().add(block_offset) } as *const Ext2Inode;
    Some(unsafe { core::ptr::read_unaligned(inode_ptr) })
}

/// Write an inode to disk
pub fn write_inode(
    device: *mut (),
    sb: &Ext2SuperBlock,
    inode_num: u32,
    inode: &Ext2Inode,
) -> Result<(), ()> {
    if inode_num == 0 || inode_num > sb.inodes_count {
        return Err(());
    }
    
    let inode_size = sb.get_inode_size() as usize;
    let inodes_per_group = sb.inodes_per_group as usize;
    
    // Calculate which group this inode is in
    let group = ((inode_num - 1) as usize / inodes_per_group) as u32;
    
    // Read group descriptor to get inode table location
    let group_desc = match read_group_descriptor(device, sb, group) {
        Some(gd) => gd,
        None => return Err(()),
    };
    
    // Calculate byte offset within inode table
    let inode_index = ((inode_num - 1) as usize % inodes_per_group) as usize;
    let byte_offset = inode_index * inode_size;
    
    // Calculate block and sector
    let block_size = sb.get_block_size() as usize;
    let inode_table_start = group_desc.get_inode_table_block() as usize;
    let block_offset = byte_offset % block_size;
    let block_num = inode_table_start + byte_offset / block_size;
    
    // Read-modify-write the block
    let mut buffer = vec![0u8; block_size];
    let sector = block_num * (block_size / 512);
    
    if super::superblock::read_sector(device, sector as u64, &mut buffer).is_err() {
        return Err(());
    }
    
    // Copy inode into buffer
    unsafe {
        core::ptr::copy_nonoverlapping(
            inode as *const Ext2Inode as *const u8,
            buffer.as_mut_ptr().add(block_offset),
            inode_size,
        );
    }
    
    // Write back
    if super::superblock::write_sector(device, sector as u64, &buffer).is_err() {
        return Err(());
    }
    
    Ok(())
}

// ============================================================================
// Block Number to LBA Conversion
// ============================================================================

/// Convert a file's logical block number to an absolute LBA (sector number)
/// This handles extents (ext4) first, then falls back to direct/indirect blocks
pub fn logical_to_lba(
    device: *mut (),
    sb: &Ext2SuperBlock,
    inode: &Ext2Inode,
    block_num: u32,
) -> Option<u64> {
    let block_size = sb.get_block_size();

    // Try extent-based lookup first (ext4)
    if inode.has_extents() || sb.has_extents() {
        if let Some(physical) = extent_lookup(device, sb, inode, block_num) {
            return Some(physical * (block_size / 512) as u64);
        }
    }

    // Fall back to traditional block pointer approach (ext2/ext3)
    let entries_per_block = block_size / 4; // 4 bytes per block pointer
    
    // Direct blocks (0-11)
    if block_num < EXT2_NDIR_BLOCKS as u32 {
        let block = inode.get_direct_block(block_num as usize)?;
        if block == 0 {
            return None;
        }
        return Some(block as u64 * (block_size / 512) as u64);
    }
    
    // Single indirect blocks (12)
    let single_indirect = inode.get_indirect_block();
    if block_num < (EXT2_NDIR_BLOCKS as u32).saturating_add(entries_per_block) {
        if single_indirect == 0 {
            return None;
        }
        
        // Read indirect block
        let mut indirect_buffer = vec![0u8; block_size as usize];
        let indirect_sector = single_indirect as u64 * (block_size / 512) as u64;
        if super::superblock::read_sector(device, indirect_sector, &mut indirect_buffer).is_err() {
            return None;
        }
        
        let index = (block_num - EXT2_NDIR_BLOCKS as u32) as usize;
        let block_ptr = unsafe { indirect_buffer.as_ptr().add(index * 4) } as *const u32;
        let block = u32::from_le(unsafe { core::ptr::read_unaligned(block_ptr) });
        if block == 0 {
            return None;
        }
        return Some(block as u64 * (block_size / 512) as u64);
    }
    
    // Double indirect blocks (13)
    let double_indirect = inode.get_double_indirect_block();
    let entries_per_block_u32 = entries_per_block as u32;
    let double_start = EXT2_NDIR_BLOCKS as u32 + entries_per_block_u32;
    let double_end = double_start + entries_per_block_u32 * entries_per_block_u32;
    
    if block_num < double_end {
        if double_indirect == 0 {
            return None;
        }
        
        // Read first level indirect block
        let mut double_buffer = vec![0u8; block_size as usize];
        let double_sector = double_indirect as u64 * (block_size / 512) as u64;
        if super::superblock::read_sector(device, double_sector, &mut double_buffer).is_err() {
            return None;
        }
        
        let index1 = (block_num - double_start) / entries_per_block_u32;
        let block_ptr1 = unsafe { double_buffer.as_ptr().add((index1 as usize) * 4) } as *const u32;
        let indirect_block = u32::from_le(unsafe { core::ptr::read_unaligned(block_ptr1) });
        if indirect_block == 0 {
            return None;
        }
        
        // Read second level indirect block
        let mut indirect_buffer = vec![0u8; block_size as usize];
        let indirect_sector = indirect_block as u64 * (block_size / 512) as u64;
        if super::superblock::read_sector(device, indirect_sector, &mut indirect_buffer).is_err() {
            return None;
        }
        
        let index2 = (block_num - double_start) % entries_per_block_u32;
        let block_ptr2 = unsafe { indirect_buffer.as_ptr().add((index2 as usize) * 4) } as *const u32;
        let block = u32::from_le(unsafe { core::ptr::read_unaligned(block_ptr2) });
        if block == 0 {
            return None;
        }
        return Some(block as u64 * (block_size / 512) as u64);
    }
    
    // Triple indirect blocks (14)
    // For simplicity, return None for blocks in triple indirect range
    // Full implementation would be similar to double indirect
    None
}

/// Look up a physical block number using the extent tree (ext4)
/// This is called from logical_to_lba when extents are available
fn extent_lookup(
    device: *mut (),
    sb: &Ext2SuperBlock,
    inode: &Ext2Inode,
    logical_block: u32,
) -> Option<u64> {
    let block_size = sb.get_block_size() as usize;

    // In ext4, the extent header is stored in the inode's block array at index 0
    // We need to read the first block which contains the extent header
    let extent_block_num = inode.get_direct_block(0)?;

    // Read the extent header block
    let extent_sector = extent_block_num as u64 * (block_size / 512) as u64;
    let mut extent_data = vec![0u8; block_size];

    if super::superblock::read_sector(device, extent_sector, &mut extent_data).is_err() {
        return None;
    }

    // Parse extent header
    let header = unsafe {
        &*(extent_data.as_ptr() as *const Ext4ExtentHeader)
    };

    if !header.is_valid() {
        return None;
    }

    // Walk the extent tree to find the block
    find_in_extent_node(device, &extent_data, header.depth, logical_block)
}

/// Recursively search an extent node for a logical block
/// Returns the physical block number, or None if not found
fn find_in_extent_node(
    device: *mut (),
    data: &[u8],
    depth: u16,
    logical_block: u32,
) -> Option<u64> {
    let header = unsafe {
        &*(data.as_ptr() as *const Ext4ExtentHeader)
    };

    if header.magic != Ext4ExtentHeader::new(0, 0).magic {
        // Invalid header
        return None;
    }

    let num_entries = header.entries as usize;
    let header_size = core::mem::size_of::<Ext4ExtentHeader>();
    let extent_size = core::mem::size_of::<super::extent::Ext4Extent>();
    let index_size = core::mem::size_of::<super::extent::Ext4ExtentIdx>();

    for i in 0..num_entries {
        if depth == 0 {
            // Leaf node - extent entries
            let entry_offset = header_size + i * extent_size;
            if entry_offset + extent_size > data.len() {
                break;
            }

            let extent = unsafe {
                &*(data.as_ptr().add(entry_offset) as *const super::extent::Ext4Extent)
            };

            if extent.covers(logical_block) {
                return extent.logical_to_physical(logical_block);
            }
        } else {
            // Index node - extent index entries
            let entry_offset = header_size + i * index_size;
            if entry_offset + index_size > data.len() {
                break;
            }

            let index = unsafe {
                &*(data.as_ptr().add(entry_offset) as *const super::extent::Ext4ExtentIdx)
            };

            // Check if this index covers our logical block
            if logical_block >= index.ei_block {
                // We need to search this child node
                let child_block = index.get_child_block();
                let child_sector = child_block * 512;  // Assuming 512-byte sectors

                let block_size = 4096;  // Default block size
                let mut child_data = vec![0u8; block_size];

                if super::superblock::read_sector(device, child_sector, &mut child_data).is_err() {
                    continue;
                }

                if let Some(physical) = find_in_extent_node(device, &child_data, depth - 1, logical_block) {
                    return Some(physical);
                }
            }
        }
    }

    None
}

/// Read data from a file at a given offset
pub fn read_file_data(
    device: *mut (),
    sb: &Ext2SuperBlock,
    inode: &Ext2Inode,
    offset: u64,
    buffer: &mut [u8],
) -> usize {
    let block_size = sb.get_block_size() as u64;
    let file_size = inode.get_size(sb);
    
    if offset >= file_size {
        return 0;
    }
    
    let bytes_to_read = core::cmp::min(
        buffer.len() as u64,
        file_size - offset,
    ) as usize;
    
    let mut bytes_read = 0;
    let mut current_offset = offset;
    
    while bytes_read < bytes_to_read {
        let block_num = (current_offset / block_size) as u32;
        let block_offset = (current_offset % block_size) as usize;
        
        let lba = match logical_to_lba(device, sb, inode, block_num) {
            Some(l) => l,
            None => break,
        };
        
        // Read one block
        let mut block_data = vec![0u8; block_size as usize];
        if super::superblock::read_sector(device, lba, &mut block_data).is_err() {
            break;
        }
        
        // Copy data to output buffer
        let copy_len = core::cmp::min(
            bytes_to_read - bytes_read,
            (block_size as usize) - block_offset,
        );
        buffer[bytes_read..bytes_read + copy_len]
            .copy_from_slice(&block_data[block_offset..block_offset + copy_len]);
        
        bytes_read += copy_len;
        current_offset += copy_len as u64;
    }
    
    bytes_read
}
