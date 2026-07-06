//! ext2/3/4 Superblock Parsing
//
//! Implements superblock reading, validation, and feature detection for
//! the Second Extended File System (ext2/ext3/ext4).
//
//! ## Superblock Location
//! The superblock is always at offset 1024 bytes (byte 1024) from the
//! start of the partition. For small filesystems, backup copies exist
//! at block 1 of each block group.
//
//! ## On-Disk Format
//! The superblock is 1024 bytes (2 sectors) and contains all key
//! filesystem parameters.

extern crate alloc;

use crate::fs::{FsError, FsResult};

// ============================================================================
// Superblock Constants
// ============================================================================

/// ext2 Magic number
pub const EXT2_SUPER_MAGIC: u16 = 0xEF53;

/// Superblock offset (1024 bytes from partition start)
pub const SUPERBLOCK_OFFSET: u64 = 1024;

/// ext2 revision levels
pub const EXT2_GOOD_OLD_REV: u32 = 0;  // Revision 0
pub const EXT2_CURRENT_REV: u32 = 1;   // Revision 1 with dynamic inode size

/// Feature compatibility flags - Compatible features can be ignored safely
pub const EXT2_FEATURE_COMPAT_DIR_PREALLOC: u32 = 0x0001;
pub const EXT2_FEATURE_COMPAT_IMAGIC_INODES: u32 = 0x0002;
pub const EXT2_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0004;  // ext3 journal
pub const EXT2_FEATURE_COMPAT_EXT_ATTR: u32 = 0x0008;
pub const EXT2_FEATURE_COMPAT_RESIZE_INODE: u32 = 0x0010;
pub const EXT2_FEATURE_COMPAT_DIR_INDEX: u32 = 0x0020;

/// Feature incompatibility flags - Must be supported
pub const EXT2_FEATURE_INCOMPAT_COMPRESSION: u32 = 0x0001;
pub const EXT2_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
pub const EXT2_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;    // ext3 needs recovery
pub const EXT2_FEATURE_INCOMPAT_JOURNAL_DEV: u32 = 0x0008; // Journal device
pub const EXT2_FEATURE_INCOMPAT_META_BG: u32 = 0x0010;
pub const EXT2_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;     // ext4 extents
pub const EXT2_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0020;     // Flexible block groups
pub const EXT2_FEATURE_INCOMPAT_EA_INODE: u32 = 0x0080;    // Extended attributes in inode
pub const EXT2_FEATURE_INCOMPAT_DIRDATA: u32 = 0x0100;    // Data in directory entry
pub const EXT2_FEATURE_INCOMPAT_BG_USE_META_BG: u32 = 0x0200;
pub const EXT2_FEATURE_INCOMPAT_BIGALLOC: u32 = 0x0400;     // ext4 bigalloc
pub const EXT2_FEATURE_INCOMPAT_METADATA_CSUM: u32 = 0x0800; // ext4 metadata checksum
pub const EXT2_FEATURE_INCOMPAT_LARGEDIR: u32 = 0x4000;    // >2GB directories
pub const EXT2_FEATURE_INCOMPAT_INLINE_DATA: u32 = 0x8000; // ext4 inline data
pub const EXT2_FEATURE_INCOMPAT_ENCRYPT: u32 = 0x10000;    // ext4 encryption

/// Read-only compatible features - Can be mounted read-only if not supported
pub const EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
pub const EXT2_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002;
pub const EXT2_FEATURE_RO_COMPAT_BTREE_DIR: u32 = 0x0004;
pub const EXT2_FEATURE_RO_COMPAT_HUGE_FILE: u32 = 0x0008;
pub const EXT2_FEATURE_RO_COMPAT_GDT_CSUM: u32 = 0x0010;
pub const EXT2_FEATURE_RO_COMPAT_DIR_NLINK: u32 = 0x0020;
pub const EXT2_FEATURE_RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
pub const EXT2_FEATURE_RO_COMPAT_HAS_SNAPSHOT: u32 = 0x0080;
pub const EXT2_FEATURE_RO_COMPAT_QUOTA: u32 = 0x0100;
pub const EXT2_FEATURE_RO_COMPAT_BIGALLOC: u32 = 0x0200;
pub const EXT2_FEATURE_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
pub const EXT2_FEATURE_RO_COMPAT_REPLICA: u32 = 0x0800;
pub const EXT2_FEATURE_RO_COMPAT_READONLY: u32 = 0x1000;

/// Filesystem states
pub const EXT2_FS_STATE_CLEAN: u16 = 0x0001;
pub const EXT2_FS_STATE_ERRORS: u16 = 0x0002;
pub const EXT2_FS_STATE_ORPHAN: u16 = 0x0004;

/// Error handling behavior
pub const EXT2_ERRORS_CONTINUE: u16 = 0x0001;
pub const EXT2_ERRORS_RO: u16 = 0x0002;
pub const EXT2_ERRORS_PANIC: u16 = 0x0003;

/// Creator OS codes
pub const EXT2_OS_LINUX: u32 = 0;
pub const EXT2_OS_HURD: u32 = 1;
pub const EXT2_OS_MASIX: u32 = 2;
pub const EXT2_OS_FREEBSD: u32 = 3;
pub const EXT2_OS_LITES: u32 = 4;

/// Default directory inode number
pub const EXT2_ROOT_INO: u32 = 2;

// ============================================================================
// Superblock Structure
// ============================================================================

/// ext2/3/4 Superblock (1024 bytes)
/// The superblock is always located at byte offset 1024 from the partition start.
/// All fields are in little-endian byte order on x86.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ext2SuperBlock {
    /// Total inode count
    pub inodes_count: u32,
    /// Total block count
    pub blocks_count: u32,
    /// Reserved blocks for superuser
    pub r_blocks_count: u32,
    /// Free blocks count
    pub free_blocks: u32,
    /// Free inodes count
    pub free_inodes: u32,
    /// First data block number (usually 1 for block size >= 1024)
    pub first_data_block: u32,
    /// Block size = 1024 << block_size_shift
    pub block_size: u32,
    /// Fragment size (usually same as block size)
    pub fragment_size: u32,
    /// Number of blocks per group
    pub blocks_per_group: u32,
    /// Number of fragments per group
    pub fragments_per_group: u32,
    /// Number of inodes per group
    pub inodes_per_group: u32,
    /// Last mount time (Unix timestamp)
    pub mtime: u32,
    /// Last write time (Unix timestamp)
    pub wtime: u32,
    /// Number of times mounted since last fsck
    pub mnt_count: u16,
    /// Maximum number of mounts before forced fsck
    pub max_mnt_count: u16,
    /// Magic number (0xEF53)
    pub magic: u16,
    /// Filesystem state
    pub state: u16,
    /// Error handling behavior
    pub errors: u16,
    /// Minor revision level
    pub minor_rev_level: u16,
    /// Last filesystem check time (Unix timestamp)
    pub lastcheck: u32,
    /// Maximum time between forced checks
    pub checkinterval: u32,
    /// Creator OS ID
    pub creator_os: u32,
    /// Revision level (0=old, 1=dynamic)
    pub rev_level: u32,
    /// Default uid for reserved blocks
    pub def_resuid: u16,
    /// Default gid for reserved blocks
    pub def_resgid: u16,
    /// First non-reserved inode (usually 11 for modern fs)
    pub first_ino: u32,
    /// Size of inode structure
    pub inode_size: u16,
    /// Block group number of this superblock copy
    pub block_group_nr: u16,
    /// Compatible feature flags
    pub compatible_features: u32,
    /// Incompatible feature flags
    pub incompatible_features: u32,
    /// Read-only compatible feature flags
    pub ro_compatible_features: u32,
    /// UUID (128-bit)
    pub uuid: [u8; 16],
    /// Volume name (16 bytes, null-terminated)
    pub volume_name: [u8; 16],
    /// Path where last mounted (64 bytes)
    pub last_mounted: [u8; 64],
    /// Algorithm usage bitmap (for compression)
    pub algo_bitmap: u32,
    /// Pre-allocated blocks for directories
    pub prealloc_blocks: u8,
    /// Pre-allocated directory blocks
    pub prealloc_dir_blocks: u8,
    /// Unused padding
    pub padding1: u16,
    /// Journal UUID
    pub journal_uuid: [u8; 16],
    /// Inode number of journal file
    pub journal_inode: u32,
    /// Device number of journal file
    pub journal_dev: u32,
    /// Start of journal orphaned inode list
    pub journal_last_org: u32,
    /// Hash seed for directory indexing
    pub hash_seed: [u32; 4],
    /// Default hash version
    pub def_hash_version: u8,
    /// Reserved padding
    pub reserved_char_pad: u8,
    /// Reserved padding
    pub reserved_word_pad: u16,
    /// Default mount options
    pub default_mount_opts: u32,
    /// First metadata block group (for meta_bg)
    pub first_meta_bg: u32,
    /// Reserved for filesystemcksum
    pub mkfs_time: u32,
    /// Backup block group for superblock
    pub jnl_blocks: [u32; 17],
    /// 64-bit support
    pub blocks_count_hi: u32,
    pub r_blocks_count_hi: u32,
    pub free_blocks_hi: u32,
    pub min_extra_isize: u16,
    pub want_extra_isize: u16,
    pub flags: u32,
    pub raid_stride: u16,
    pub mmp_update_interval: u16,
    pub mmp_block: u64,
    pub raid_stripe_width: u32,
    pub log_groups_per_flex: u8,
    pub lua_state: u8,
    pub reserved2: [u32; 162],
}

impl Ext2SuperBlock {
    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Check if this is a valid ext2/3/4 superblock
    pub fn is_valid(&self) -> bool {
        self.magic == EXT2_SUPER_MAGIC
    }

    /// Check if this is an ext3 volume (has journal)
    pub fn is_ext3(&self) -> bool {
        (self.compatible_features & EXT2_FEATURE_COMPAT_HAS_JOURNAL) != 0
    }

    /// Check if this is an ext4 volume (has extents or other ext4 features)
    pub fn is_ext4(&self) -> bool {
        (self.incompatible_features & EXT2_FEATURE_INCOMPAT_EXTENTS) != 0
            || (self.incompatible_features & EXT2_FEATURE_INCOMPAT_FLEX_BG) != 0
            || (self.incompatible_features & EXT2_FEATURE_INCOMPAT_BIGALLOC) != 0
            || (self.incompatible_features & EXT2_FEATURE_INCOMPAT_METADATA_CSUM) != 0
    }

    /// Check if this is a dynamic revision filesystem
    pub fn is_dynamic_rev(&self) -> bool {
        self.rev_level >= EXT2_CURRENT_REV
    }

    /// Check if sparse superblock feature is set
    pub fn has_sparse_super(&self) -> bool {
        (self.ro_compatible_features & EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER) != 0
    }

    /// Check if this filesystem has 64-bit support
    pub fn has_64bit(&self) -> bool {
        self.is_dynamic_rev() && (self.incompatible_features & 0x200) != 0
    }

    /// Check if journal is present
    pub fn has_journal(&self) -> bool {
        (self.compatible_features & EXT2_FEATURE_COMPAT_HAS_JOURNAL) != 0
    }

    /// Check if extents are used (ext4)
    pub fn has_extents(&self) -> bool {
        (self.incompatible_features & EXT2_FEATURE_INCOMPAT_EXTENTS) != 0
    }

    /// Check if flex_bg feature is set (ext4)
    pub fn has_flex_bg(&self) -> bool {
        (self.incompatible_features & EXT2_FEATURE_INCOMPAT_FLEX_BG) != 0
    }

    /// Check if bigalloc feature is set (ext4)
    pub fn has_bigalloc(&self) -> bool {
        (self.ro_compatible_features & EXT2_FEATURE_RO_COMPAT_BIGALLOC) != 0
    }

    /// Check if metadata checksum is enabled (ext4)
    pub fn has_metadata_csum(&self) -> bool {
        (self.ro_compatible_features & EXT2_FEATURE_RO_COMPAT_METADATA_CSUM) != 0
    }

    // ========================================================================
    // Size Calculation Methods
    // ========================================================================

    /// Get the actual block size in bytes
    /// Block size is stored as a shift value: size = 1024 << block_size
    /// block_size = 0 means 1024 bytes, block_size = 1 means 2048 bytes, etc.
    pub fn get_block_size(&self) -> u32 {
        1024u32 << self.block_size
    }

    /// Get block size shift (for efficient division/multiplication)
    pub fn get_block_size_shift(&self) -> u32 {
        10u32 + self.block_size
    }

    /// Get fragment size in bytes
    pub fn get_fragment_size(&self) -> u32 {
        1024u32 << self.fragment_size
    }

    /// Get total number of blocks (64-bit aware)
    pub fn get_total_blocks(&self) -> u64 {
        if self.has_64bit() {
            ((self.blocks_count_hi as u64) << 32) | (self.blocks_count as u64)
        } else {
            self.blocks_count as u64
        }
    }

    /// Get total number of inodes
    pub fn get_total_inodes(&self) -> u32 {
        self.inodes_count
    }

    /// Get the number of block groups
    pub fn get_group_count(&self) -> u32 {
        let blocks_per_group = self.blocks_per_group;
        if blocks_per_group == 0 {
            return 0;
        }
        (self.blocks_count + blocks_per_group - 1) / blocks_per_group
    }

    /// Get the number of inode groups
    pub fn get_inode_group_count(&self) -> u32 {
        let inodes_per_group = self.inodes_per_group;
        if inodes_per_group == 0 {
            return 0;
        }
        (self.inodes_count + inodes_per_group - 1) / inodes_per_group
    }

    /// Get the inode size (for dynamic revision)
    pub fn get_inode_size(&self) -> u16 {
        if self.is_dynamic_rev() {
            if self.inode_size >= 128 {
                self.inode_size
            } else {
                128 // Minimum inode size for revision 1
            }
        } else {
            128 // Old revision always has 128-byte inodes
        }
    }

    /// Get the bytes needed for block bitmap in each group
    pub fn get_block_bitmap_size(&self) -> u32 {
        let blocks_per_group = self.blocks_per_group;
        (blocks_per_group + 7) / 8
    }

    /// Get the bytes needed for inode bitmap in each group
    pub fn get_inode_bitmap_size(&self) -> u32 {
        let inodes_per_group = self.inodes_per_group;
        (inodes_per_group + 7) / 8
    }

    /// Get the bytes needed for inode table in each group
    pub fn get_inode_table_size(&self) -> u32 {
        let inode_size = self.get_inode_size() as u32;
        let inodes_per_group = self.inodes_per_group;
        ((inode_size * inodes_per_group) + self.get_block_size() - 1) / self.get_block_size()
    }

    /// Get the total number of reserved blocks
    pub fn get_reserved_blocks(&self) -> u32 {
        self.r_blocks_count
    }

    /// Get free blocks for a specific user (based on reserved blocks)
    pub fn get_free_blocks_for_user(&self) -> u32 {
        self.free_blocks.saturating_sub(self.get_reserved_blocks())
    }

    // ========================================================================
    // Block Group Calculation Methods
    // ========================================================================

    /// Get the block group number for a given block number
    pub fn get_block_group(&self, block_num: u32) -> u32 {
        if self.blocks_per_group == 0 {
            return 0;
        }
        (block_num - self.first_data_block) / self.blocks_per_group
    }

    /// Get the block group number for a given inode number
    pub fn get_inode_group(&self, inode_num: u32) -> u32 {
        if self.inodes_per_group == 0 {
            return 0;
        }
        (inode_num - 1) / self.inodes_per_group
    }

    /// Get the relative block number within a block group
    pub fn get_block_index(&self, block_num: u32) -> u32 {
        if self.blocks_per_group == 0 {
            return block_num;
        }
        (block_num - self.first_data_block) % self.blocks_per_group
    }

    /// Get the relative inode number within an inode group
    pub fn get_inode_index(&self, inode_num: u32) -> u32 {
        if self.inodes_per_group == 0 {
            return inode_num - 1;
        }
        (inode_num - 1) % self.inodes_per_group
    }

    // ========================================================================
    // Time Methods
    // ========================================================================

    /// Get last mount time as Unix timestamp
    pub fn last_mount_time(&self) -> u32 {
        self.mtime
    }

    /// Get last write time as Unix timestamp
    pub fn last_write_time(&self) -> u32 {
        self.wtime
    }

    /// Get last fsck time as Unix timestamp
    pub fn last_fsck_time(&self) -> u32 {
        self.lastcheck
    }

    /// Check if filesystem needs forced fsck
    pub fn needs_fsck(&self) -> bool {
        self.state != EXT2_FS_STATE_CLEAN
            || self.errors != 0
            || (self.max_mnt_count > 0 && self.mnt_count >= self.max_mnt_count)
    }

    // ========================================================================
    // Error Handling
    // ========================================================================

    /// Check error handling behavior
    pub fn get_error_behavior(&self) -> Ext2ErrorBehavior {
        match self.errors {
            EXT2_ERRORS_CONTINUE => Ext2ErrorBehavior::Continue,
            EXT2_ERRORS_RO => Ext2ErrorBehavior::ReadOnly,
            EXT2_ERRORS_PANIC => Ext2ErrorBehavior::Panic,
            _ => Ext2ErrorBehavior::Continue,
        }
    }

    /// Check if mount count exceeded
    pub fn mount_count_exceeded(&self) -> bool {
        self.max_mnt_count > 0 && self.mnt_count >= self.max_mnt_count
    }
}

/// Error handling behavior for filesystem errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext2ErrorBehavior {
    Continue,
    ReadOnly,
    Panic,
}

/// Filesystem version information
#[derive(Debug, Clone, Copy)]
pub struct Ext2Version {
    pub major: u32,
    pub minor: u32,
    pub is_dynamic: bool,
}

impl Ext2SuperBlock {
    /// Get filesystem version information
    pub fn get_version(&self) -> Ext2Version {
        if self.is_dynamic_rev() {
            Ext2Version {
                major: 1,
                minor: self.minor_rev_level as u32,
                is_dynamic: true,
            }
        } else {
            Ext2Version {
                major: 0,
                minor: 0,
                is_dynamic: false,
            }
        }
    }

    /// Get a string representation of the filesystem type
    pub fn get_fs_type_string(&self) -> &'static str {
        if self.is_ext4() {
            "ext4"
        } else if self.is_ext3() {
            "ext3"
        } else {
            "ext2"
        }
    }
}

// ============================================================================
// Superblock Read Functions
// ============================================================================

/// Read the superblock from a device at the given offset
/// Returns the superblock if successful, None otherwise
/// Read the ext2/3/4 superblock at the standard partition-relative
/// offset (byte 1024, sector 2). `offset` is added on top of that
/// when the caller wants to probe a non-zero partition start. For
/// the typical "mount this partition" case the caller passes 0
/// and we read the canonical ext superblock position regardless of
/// caller bookkeeping. The previous implementation took the
/// caller's `offset` verbatim and silently read sector 0 when
/// callers passed 0, so `is_valid()` failed (magic = 0) and mount
/// returned None even though the partition was a perfectly valid
/// ext2/3/4 filesystem.
pub fn read_superblock(device: *mut (), offset: u64) -> Option<Ext2SuperBlock> {
    let mut buffer = [0u8; 1024];
    // The ext superblock is always at byte 1024 of the partition.
    // Read the two adjacent 512-byte sectors (2 and 3) into our 1024
    // byte buffer. `offset` is added on top so callers can still
    // probe alternate locations if they want.
    let sb_byte_offset = SUPERBLOCK_OFFSET + offset;
    let sb_sector = sb_byte_offset / 512;
    // Two adjacent sectors cover the 1024-byte superblock.
    if read_sectors(device, sb_sector, 2, &mut buffer).is_err() {
        // kprintln!("[EXT2] Failed to read superblock at sector {}", sb_sector)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    let sb = unsafe { core::ptr::read_unaligned(buffer.as_ptr() as *const Ext2SuperBlock) };
    
    if !sb.is_valid() {
        // kprintln!("[EXT2] Invalid superblock magic: 0x{:04x}", sb.magic)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    Some(sb)
}

/// Validate a superblock and check for unsupported features
/// Returns Ok(()) if the filesystem is supported, Err(reason) otherwise
pub fn validate_superblock(sb: &Ext2SuperBlock) -> FsResult<()> {
    // Check magic number
    if sb.magic != EXT2_SUPER_MAGIC {
        // kprintln!("[EXT2] Invalid magic number: 0x{:04x}", sb.magic)  // kprintln disabled (memcpy crash workaround);
        return Err(FsError::DiskCorrupt);
    }
    
    // Check revision level
    if sb.rev_level > EXT2_CURRENT_REV + 1 {
        // kprintln!("[EXT2] Unsupported revision level: {}", sb.rev_level)  // kprintln disabled (memcpy crash workaround);
        return Err(FsError::FileSystemLimit);
    }
    
    // Check for incompatible features we don't support
    let incompat = sb.incompatible_features;
    
    if (incompat & EXT2_FEATURE_INCOMPAT_COMPRESSION) != 0 {
        // kprintln!("[EXT2] Compression not supported")  // kprintln disabled (memcpy crash workaround);
        return Err(FsError::FileSystemLimit);
    }
    
    if (incompat & EXT2_FEATURE_INCOMPAT_JOURNAL_DEV) != 0 {
        // kprintln!("[EXT2] Journal device not supported")  // kprintln disabled (memcpy crash workaround);
        return Err(FsError::FileSystemLimit);
    }
    
    // ext3 features are ok
    if (incompat & EXT2_FEATURE_INCOMPAT_RECOVER) != 0 {
        // kprintln!("[EXT2] Filesystem needs recovery")  // kprintln disabled (memcpy crash workaround);
        // This is not an error, just a warning
    }
    
    // Check inode size for dynamic revision
    if sb.is_dynamic_rev() && sb.inode_size < 128 {
        // kprintln!("[EXT2] Inode size too small: {}", sb.inode_size)  // kprintln disabled (memcpy crash workaround);
        return Err(FsError::DiskCorrupt);
    }
    
    // Check for sane values
    if sb.blocks_per_group == 0 || sb.inodes_per_group == 0 {
        // kprintln!("[EXT2] Invalid group sizes")  // kprintln disabled (memcpy crash workaround);
        return Err(FsError::DiskCorrupt);
    }
    
    if sb.first_data_block == 0 && sb.block_size == 0 {
        // kprintln!("[EXT2] Invalid first data block")  // kprintln disabled (memcpy crash workaround);
        return Err(FsError::DiskCorrupt);
    }
    
    // Check for 64-bit features we don't support
    if sb.has_64bit() {
        // kprintln!("[EXT2] 64-bit filesystem support is limited")  // kprintln disabled (memcpy crash workaround);
        // Continue anyway, we have partial support
    }
    
    // Log filesystem type
    // kprintln!("[EXT2] Detected {} filesystem", sb.get_fs_type_string())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("[EXT2]   Block size: {} bytes", sb.get_block_size())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("[EXT2]   Total blocks: {} ({} groups)", sb.blocks_count, sb.get_group_count())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("[EXT2]   Total inodes: {} ({} per group)", sb.inodes_count, sb.inodes_per_group)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("[EXT2]   Inode size: {} bytes", sb.get_inode_size())  // kprintln disabled (memcpy crash workaround);
    
    Ok(())
}

/// Check if a feature is supported
pub fn check_feature_support(sb: &Ext2SuperBlock) -> Ext2FeatureSupport {
    Ext2FeatureSupport {
        has_journal: sb.has_journal(),
        has_extents: sb.has_extents(),
        has_flex_bg: sb.has_flex_bg(),
        has_bigalloc: sb.has_bigalloc(),
        has_metadata_csum: sb.has_metadata_csum(),
        has_sparse_super: sb.has_sparse_super(),
        has_large_file: (sb.ro_compatible_features & EXT2_FEATURE_RO_COMPAT_LARGE_FILE) != 0,
        has_htree_dir: (sb.ro_compatible_features & EXT2_FEATURE_RO_COMPAT_BTREE_DIR) != 0,
        has_quota: (sb.ro_compatible_features & EXT2_FEATURE_RO_COMPAT_QUOTA) != 0,
        has_unix_epochs: (sb.compatible_features & 0x1000) != 0, // ext4 feature
    }
}

/// Feature support information for an ext2/3/4 filesystem
#[derive(Debug, Clone, Copy)]
pub struct Ext2FeatureSupport {
    pub has_journal: bool,
    pub has_extents: bool,
    pub has_flex_bg: bool,
    pub has_bigalloc: bool,
    pub has_metadata_csum: bool,
    pub has_sparse_super: bool,
    pub has_large_file: bool,
    pub has_htree_dir: bool,
    pub has_quota: bool,
    pub has_unix_epochs: bool,
}

impl Ext2FeatureSupport {
    /// Check if filesystem is ext3
    pub fn is_ext3(&self) -> bool {
        self.has_journal
    }
    
    /// Check if filesystem is ext4
    pub fn is_ext4(&self) -> bool {
        self.has_extents || self.has_flex_bg || self.has_bigalloc || self.has_metadata_csum
    }
}

// ============================================================================
// Device Read/Write Helper
// ============================================================================

/// Read a sector from the device (helper function)
pub fn read_sector(_device: *mut (), sector: u64, buffer: &mut [u8]) -> Result<(), ()> {
    if buffer.len() < 512 {
        return Err(());
    }
    
    // Route to RAM disk for bootstrap filesystem operations
    let sector_num = sector as usize;
    if crate::drivers::storage::ramdisk::read(sector_num, buffer) {
        Ok(())
    } else {
        // Try AHCI
        #[cfg(target_arch = "x86_64")]
        {
            if crate::drivers::storage::ahci::read_sector(0, 0, sector as u32, buffer) {
                return Ok(());
            }
        }
        Err(())
    }
}

/// Read multiple sectors from device
pub fn read_sectors(device: *mut (), start_sector: u64, count: u32, buffer: &mut [u8]) -> Result<(), ()> {
    let sector_size = 512usize;
    let needed = (count as usize) * sector_size;

    if buffer.len() < needed {
        return Err(());
    }

    // `start_sector` is a sector index, not a byte offset. Pass
    // the per-sector index straight through to `read_sector`,
    // which itself hands it to `ramdisk::read(sector_num, …)`.
    // The previous code multiplied by `sector_size` here, which
    // produced a byte offset that `ramdisk::read` then treated as
    // a sector index — so reading the ext superblock at the
    // canonical offset (sector 2) actually requested sector 1024
    // of the system partition mirror, returning a buffer full of
    // zeroes for any ext superblock smaller than 512 KiB.
    for i in 0..count as usize {
        let sector = start_sector + (i as u64);
        if read_sector(device, sector, &mut buffer[i * sector_size..(i + 1) * sector_size]).is_err() {
            return Err(());
        }
    }

    Ok(())
}

/// Write a sector to the device
pub fn write_sector(_device: *mut (), sector: u64, buffer: &[u8]) -> Result<(), ()> {
    if buffer.len() < 512 {
        return Err(());
    }
    
    // Route to RAM disk or AHCI
    let sector_num = sector as usize;
    if crate::drivers::storage::ramdisk::write(sector_num, buffer) {
        Ok(())
    } else {
        // Try AHCI
        #[cfg(target_arch = "x86_64")]
        {
            if crate::drivers::storage::ahci::write_sector(0, 0, sector as u32, buffer) {
                return Ok(());
            }
        }
        Err(())
    }
}

// ============================================================================
// Debug Output
// ============================================================================

impl Ext2SuperBlock {
    /// Print superblock information for debugging
    pub fn debug_print(&self) {
        // kprintln!("[EXT2] Superblock Information:")  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Magic:              0x{:04x}", self.magic)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Revision:           {}.{}",   // kprintln disabled (memcpy crash workaround)
//             if self.is_dynamic_rev() { 1 } else { 0 },
//             self.minor_rev_level);
        // kprintln!("  Filesystem type:    {}", self.get_fs_type_string())  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Block size:        {} bytes (shift={})",   // kprintln disabled (memcpy crash workaround)
//             self.get_block_size(), self.block_size);
        // kprintln!("  Fragment size:     {} bytes", self.get_fragment_size())  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Total blocks:      {} (groups: {})",   // kprintln disabled (memcpy crash workaround)
//             self.blocks_count, self.get_group_count());
        // kprintln!("  Total inodes:      {} (per group: {})",   // kprintln disabled (memcpy crash workaround)
//             self.inodes_count, self.inodes_per_group);
        // kprintln!("  Blocks per group:  {}", self.blocks_per_group)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Inode size:       {} bytes", self.get_inode_size())  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  State:             0x{:04x}", self.state)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Errors:           0x{:04x}", self.errors)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Mount count:      {}/{}", self.mnt_count, self.max_mnt_count)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Compatible:       0x{:08x}", self.compatible_features)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Incompatible:     0x{:08x}", self.incompatible_features)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Read-only compat:  0x{:08x}", self.ro_compatible_features)  // kprintln disabled (memcpy crash workaround);
        
        if self.has_journal() {
            // kprintln!("  Journal inode:     {}", self.journal_inode)  // kprintln disabled (memcpy crash workaround);
        }
        
        if self.has_extents() {
            // kprintln!("  Extents:           ENABLED")  // kprintln disabled (memcpy crash workaround);
        }
    }
}
