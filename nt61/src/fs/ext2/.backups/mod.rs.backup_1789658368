//! ext2/ext3/ext4 File System Driver
//
//! Main module for the Second Extended File System (ext2/ext3/ext4).
//! This module provides the file system driver interface and main entry points.
//
//! ## Features
//! - ext2: Basic read/write support
//! - ext3: Journal replay support
//! - ext4: Extent-based file storage support
//
//! ## Architecture
//! This module provides the high-level interface while submodules handle:
//! - superblock.rs: Superblock reading and validation
//! - group.rs: Block group descriptor management
//! - inode.rs: Inode operations
//! - bitmap.rs: Block and inode allocation
//! - dir.rs: Directory operations
//! - extent.rs: ext4 extent tree (optional)
//! - journal.rs: ext3 journaling (optional)

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use crate::fs::{FileSystem, FileSystemType};
use core::ptr::null_mut;

// Submodules
pub mod superblock;
pub mod group;
pub mod inode;
pub mod bitmap;
pub mod dir;
pub mod extent;
pub mod journal;

// Re-export commonly used types
pub use superblock::{Ext2SuperBlock, EXT2_SUPER_MAGIC, EXT2_ROOT_INO};
pub use group::Ext2GroupDesc;
pub use inode::Ext2Inode;
pub use dir::{Ext2DirEntry, Ext2DirEntryInfo, EXT2_FT_REG_FILE, EXT2_FT_DIR};

// ============================================================================
// File System Instance
// ============================================================================

/// ext2/ext3/ext4 file system instance
pub struct Ext2FileSystem {
    /// Base file system structure
    pub base: FileSystem,
    /// Superblock data
    pub superblock: Ext2SuperBlock,
    /// Block size in bytes
    pub block_size: u32,
    /// Block size shift (for efficient division)
    pub block_size_shift: u32,
    /// Inode size
    pub inode_size: u16,
    /// First data block number
    pub first_data_block: u32,
    /// Number of block groups
    pub group_count: u32,
    /// Journal inode number (0 if no journal)
    pub journal_inode: u32,
    /// Is this an ext3 filesystem?
    pub is_ext3: bool,
    /// Is this an ext4 filesystem?
    pub is_ext4: bool,
}

impl Ext2FileSystem {
    /// Create a new ext2 filesystem structure
    pub fn new() -> Self {
        Self {
            base: FileSystem {
                driver: null_mut(),
                device: null_mut(),
                volume_name: [0; 64],
                fs_type: FileSystemType::Ext2,
                sector_size: 512,
                cluster_size: 4096,
                total_clusters: 0,
                free_clusters: 0,
            },
            superblock: unsafe { core::mem::zeroed() },
            block_size: 4096,
            block_size_shift: 12,
            inode_size: 128,
            first_data_block: 1,
            group_count: 0,
            journal_inode: 0,
            is_ext3: false,
            is_ext4: false,
        }
    }

    /// Get the block size
    pub fn get_block_size(&self) -> u32 {
        self.block_size
    }

    /// Get the filesystem type as string
    pub fn get_fs_type_string(&self) -> &'static str {
        if self.is_ext4 {
            "ext4"
        } else if self.is_ext3 {
            "ext3"
        } else {
            "ext2"
        }
    }

    /// Check if this filesystem has journaling
    pub fn has_journal(&self) -> bool {
        self.is_ext3
    }
}

/// File handle for open files
pub struct Ext2Handle {
    /// Inode number
    pub inode_num: u32,
    /// Current position in file
    pub current_position: u64,
    /// Is this a directory?
    pub is_directory: bool,
    /// File size
    pub file_size: u64,
    /// Inode data (cached)
    pub inode: Ext2Inode,
}

impl Ext2Handle {
    /// Create a new file handle
    pub fn new(inode_num: u32, inode: &Ext2Inode, sb: &Ext2SuperBlock) -> Self {
        Self {
            inode_num,
            current_position: 0,
            is_directory: inode.is_dir(),
            file_size: inode.get_size(sb),
            inode: *inode,
        }
    }

    /// Check if we're at end of file
    pub fn at_eof(&self) -> bool {
        self.current_position >= self.file_size
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> u64 {
        self.file_size.saturating_sub(self.current_position)
    }
}

// ============================================================================
// Device I/O
// ============================================================================

/// Read a sector from the device
pub fn read_sector(_device: *mut (), sector: u64, buffer: &mut [u8]) -> Result<(), ()> {
    if buffer.len() < 512 {
        return Err(());
    }

    // CRITICAL: Mask IRQ0 (PIT timer) during disk reads to prevent IRQ interference.
    // NTFS driver does this and never unmask - we follow the same pattern.
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::pic::mask_irq(0);

    // Prefer the *active* partition mirror, when one is set by
    // the dispatcher in `fs::mod`. This is what lets EXT2 mount
    // and read from the system partition properly.
    let result = if let Some(base) = crate::fs::active_partition_ramdisk() {
        let off = (sector as usize) * 512;
        let max_size = crate::fs::active_partition_size().unwrap_or(usize::MAX);
        if off + 512 > max_size {
            Err(())
        } else {
            // Dispatch to sys_ramdisk_read for the system partition
            let sys_base = crate::fs::sys_mirror_address();
            if Some(base) == sys_base {
                // Use sys_ramdisk_read which has its own serial prints
                let n = crate::fs::sys_ramdisk_read(off as u64, buffer);
                if n >= 512 { Ok(()) } else { Err(()) }
            } else {
                let n = crate::fs::esp_ramdisk_read(off as u64, buffer);
                if n >= 512 { Ok(()) } else { Err(()) }
            }
        }
    } else {
        // Fallback: try ramdisk first
        let sector_num = sector as usize;
        if crate::drivers::storage::ramdisk::read(sector_num, buffer) {
            Ok(())
        } else {
            // Try AHCI
            #[cfg(target_arch = "x86_64")]
            {
                if crate::drivers::storage::ahci::read_sector(0, 0, sector as u32, buffer) {
                    Ok(())
                } else {
                    Err(())
                }
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                Err(())
            }
        }
    };

    result
}

/// Write a sector to the device
pub fn write_sector(_device: *mut (), sector: u64, buffer: &[u8]) -> Result<(), ()> {
    if buffer.len() < 512 {
        return Err(());
    }

    // Try RAM disk first
    let sector_num = sector as usize;
    if crate::drivers::storage::ramdisk::write(sector_num, buffer) {
        return Ok(());
    }

    // Try AHCI
    #[cfg(target_arch = "x86_64")]
    {
        // AHCI write needs mutable buffer - create a copy
        let mut buf = [0u8; 512];
        buf.copy_from_slice(&buffer[..512]);
        if crate::drivers::storage::ahci::write_sector(0, 0, sector as u32, &mut buf) {
            return Ok(());
        }
    }

    Err(())
}

// ============================================================================
// Mount/Unmount Operations
// ============================================================================

/// Mount an ext2/ext3/ext4 filesystem
pub fn mount(device: *mut (), offset: u64) -> Option<&'static mut Ext2FileSystem> {
    // kprintln!("[EXT2] Mounting ext2/ext3/ext4 filesystem...")  // kprintln disabled (memcpy crash workaround);

    // Read superblock
    let sb = match superblock::read_superblock(device, offset) {
        Some(s) => s,
        None => {
            // kprintln!("[EXT2] Failed to read superblock")  // kprintln disabled (memcpy crash workaround);
            return None;
        }
    };

    // Validate superblock
    if superblock::validate_superblock(&sb).is_err() {
        // kprintln!("[EXT2] Superblock validation failed")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Create filesystem instance
    let fs_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Ext2FileSystem>(),
    ) as *mut Ext2FileSystem;
    
    if fs_ptr.is_null() {
        // kprintln!("[EXT2] Failed to allocate filesystem structure")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    unsafe {
        (*fs_ptr) = Ext2FileSystem::new();
        (*fs_ptr).base.device = device;
        (*fs_ptr).superblock = sb;
        (*fs_ptr).block_size = sb.get_block_size();
        (*fs_ptr).block_size_shift = sb.get_block_size_shift();
        (*fs_ptr).inode_size = sb.get_inode_size();
        (*fs_ptr).first_data_block = sb.first_data_block;
        (*fs_ptr).group_count = sb.get_group_count();
        (*fs_ptr).journal_inode = sb.journal_inode;
        (*fs_ptr).is_ext3 = sb.is_ext3();
        (*fs_ptr).is_ext4 = sb.is_ext4();
        (*fs_ptr).base.fs_type = if sb.is_ext4() {
            FileSystemType::Ext4
        } else if sb.is_ext3() {
            FileSystemType::Ext3
        } else {
            FileSystemType::Ext2
        };
        
        // Calculate cluster size
        (*fs_ptr).base.cluster_size = (*fs_ptr).block_size;
        (*fs_ptr).base.total_clusters = sb.get_total_blocks();
        (*fs_ptr).base.free_clusters = sb.free_blocks as u64;
    }
    
    // Print filesystem info
    let fs = unsafe { &*fs_ptr };
    // kprintln!("[EXT2] Mounted {} filesystem", fs.get_fs_type_string())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("[EXT2]   Block size: {} bytes", fs.block_size)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("[EXT2]   Block groups: {}", fs.group_count)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("[EXT2]   Inode size: {} bytes", fs.inode_size)  // kprintln disabled (memcpy crash workaround);
    
    if fs.has_journal() {
        // kprintln!("[EXT2]   Journal inode: {}", fs.journal_inode)  // kprintln disabled (memcpy crash workaround);
    }
    
    // Replay journal if needed (ext3/ext4)
    if fs.has_journal() {
        if journal::journal_needs_recovery(&fs.superblock) {
            // kprintln!("[EXT2] Journal needs recovery, replaying...")  // kprintln disabled (memcpy crash workaround);
            if let Ok(_count) = journal::replay_journal(device, &fs.superblock) {
                // kprintln!("[EXT2] Replayed {} blocks", count)  // kprintln disabled (memcpy crash workaround);
            }
        }
    }

    // Store globally so `get_mounted_fs()` / `is_mounted()` work for the
    // boot path (load_cmd_exe_from_disk).
    unsafe { EXT2_MOUNTED_FS = fs_ptr; }
    Some(unsafe { &mut *fs_ptr })
}

/// Unmount an ext2 filesystem
pub fn unmount(_fs: *mut Ext2FileSystem) {
    if !_fs.is_null() {
        // kprintln!("[EXT2] Filesystem unmounted")  // kprintln disabled (memcpy crash workaround);
        // In a full implementation, we would:
        // 1. Sync all buffers
        // 2. Write superblock
        // 3. Free resources
    }
}

// ============================================================================
// File Operations
// ============================================================================

/// Open a file by path
pub fn open_file(fs: &Ext2FileSystem, path: &[u8]) -> Option<Ext2Handle> {
    // Look up the path
    let inode_num = dir::path_lookup(fs.base.device, &fs.superblock, path)?;
    
    // Read the inode
    let inode = inode::read_inode(fs.base.device, &fs.superblock, inode_num)?;
    
    Some(Ext2Handle::new(inode_num, &inode, &fs.superblock))
}

/// Open a file by inode number
pub fn open_by_inode(fs: &Ext2FileSystem, inode_num: u32) -> Option<Ext2Handle> {
    let inode = inode::read_inode(fs.base.device, &fs.superblock, inode_num)?;
    Some(Ext2Handle::new(inode_num, &inode, &fs.superblock))
}

/// Read from a file handle
pub fn read_file(fs: &Ext2FileSystem, handle: &mut Ext2Handle, buffer: &mut [u8]) -> usize {
    if handle.at_eof() {
        return 0;
    }
    
    let bytes_to_read = core::cmp::min(
        buffer.len(),
        (handle.remaining() as usize).min(usize::MAX),
    );
    
    let bytes_read = inode::read_file_data(
        fs.base.device,
        &fs.superblock,
        &handle.inode,
        handle.current_position,
        &mut buffer[..bytes_to_read],
    );
    
    handle.current_position += bytes_read as u64;
    bytes_read
}

/// Read from a file at a specific offset
pub fn read_file_at(
    fs: &Ext2FileSystem,
    inode_num: u32,
    offset: u64,
    buffer: &mut [u8],
) -> Option<usize> {
    let inode = inode::read_inode(fs.base.device, &fs.superblock, inode_num)?;
    
    let file_size = inode.get_size(&fs.superblock);
    if offset >= file_size {
        return Some(0);
    }
    
    let bytes_to_read = core::cmp::min(
        buffer.len(),
        ((file_size - offset) as usize).min(usize::MAX),
    );
    
    let bytes_read = inode::read_file_data(
        fs.base.device,
        &fs.superblock,
        &inode,
        offset,
        &mut buffer[..bytes_to_read],
    );
    
    Some(bytes_read)
}

/// List directory contents
pub fn list_directory(fs: &Ext2FileSystem, inode_num: u32) -> Option<Vec<dir::Ext2DirEntryInfo>> {
    dir::list_directory(fs.base.device, &fs.superblock, inode_num)
}

/// Get file or directory info
pub fn get_entry(fs: &Ext2FileSystem, path: &[u8]) -> Option<dir::Ext2DirEntryInfo> {
    let inode_num = dir::path_lookup(fs.base.device, &fs.superblock, path)?;
    let entries = dir::list_directory(fs.base.device, &fs.superblock, inode_num)?;
    
    // Return the last component's entry
    let name = path.split(|&c| c == b'/').last()?;
    if name.is_empty() {
        return None;
    }
    
    entries.into_iter().find(|e| e.name.as_bytes() == name)
}

/// Read an entire file by path. Returns the raw bytes or an error message.
/// The `path` is converted internally from Windows-style ("C:\Windows\file")
/// to ext2-style ("/Windows/file").
pub fn read_whole_file(fs: &Ext2FileSystem, path: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
    // Convert Windows path to ext2 path
    let ext2_path = win_path_to_ext2(path);
    
    // Lookup inode number
    let inode_num = match dir::path_lookup(fs.base.device, &fs.superblock, ext2_path.as_bytes()) {
        Some(n) => n,
        None => return Err("ext2: path_lookup failed"),
    };
    
    // Read inode
    let inode = match inode::read_inode(fs.base.device, &fs.superblock, inode_num) {
        Some(i) => i,
        None => return Err("ext2: read_inode failed"),
    };
    
    let file_size = inode.get_size(&fs.superblock) as usize;
    if file_size == 0 {
        return Ok(Vec::new());
    }
    
    let mut buf: Vec<u8> = alloc::vec![0u8; file_size];
    let n = inode::read_file_data(
        fs.base.device,
        &fs.superblock,
        &inode,
        0,
        &mut buf,
    );
    if n == 0 {
        return Err("ext2: read_file_data returned 0");
    }
    buf.truncate(n);
    Ok(buf)
}

// ============================================================================
// Path Operations
// ============================================================================

/// Resolve a path to an inode number
pub fn resolve_path(fs: &Ext2FileSystem, path: &[u8]) -> Option<u32> {
    dir::path_lookup(fs.base.device, &fs.superblock, path)
}

/// Check if a path exists
pub fn path_exists(fs: &Ext2FileSystem, path: &[u8]) -> bool {
    resolve_path(fs, path).is_some()
}

/// Check if path is a directory
pub fn is_directory(fs: &Ext2FileSystem, path: &[u8]) -> bool {
    let inode_num = match resolve_path(fs, path) {
        Some(n) => n,
        None => return false,
    };
    let inode = match inode::read_inode(fs.base.device, &fs.superblock, inode_num) {
        Some(i) => i,
        None => return false,
    };
    inode.is_dir()
}

/// Check if path is a regular file
pub fn is_file(fs: &Ext2FileSystem, path: &[u8]) -> bool {
    let inode_num = match resolve_path(fs, path) {
        Some(n) => n,
        None => return false,
    };
    let inode = match inode::read_inode(fs.base.device, &fs.superblock, inode_num) {
        Some(i) => i,
        None => return false,
    };
    inode.is_file()
}

// ============================================================================
// Driver Registration
// ============================================================================

/// Global mount state - stores pointer to mounted filesystem
static mut EXT2_MOUNTED_FS: *mut Ext2FileSystem = core::ptr::null_mut();

/// Return true if an ext2/3/4 filesystem is currently mounted.
pub fn is_mounted() -> bool {
    !unsafe { EXT2_MOUNTED_FS.is_null() }
}

/// Convert a Windows-style path ("C:\Windows\file") to an ext2-style
/// path ("/Windows/file"). Strips the leading drive prefix if present.
fn win_path_to_ext2(path: &str) -> alloc::string::String {
    let p = path.trim_start_matches(|c| c == 'C' || c == 'c');
    let p = p.trim_start_matches(|c| c == ':' || c == '\\' || c == '/');
    let p = p.replace('\\', "/");
    if p.is_empty() || !p.starts_with('/') {
        alloc::format!("/{}", p)
    } else {
        p
    }
}

/// Mount the first ext2 partition found
pub fn mount_first(device: *mut (), offset: u64) -> Option<&'static mut Ext2FileSystem> {
    unsafe {
        if !EXT2_MOUNTED_FS.is_null() {
            return Some(&mut *EXT2_MOUNTED_FS);
        }
        
        let fs = mount(device, offset)?;
        EXT2_MOUNTED_FS = fs as *const _ as *mut Ext2FileSystem;
        Some(&mut *EXT2_MOUNTED_FS)
    }
}

/// Get the mounted filesystem
pub fn get_mounted_fs() -> Option<&'static mut Ext2FileSystem> {
    unsafe {
        if EXT2_MOUNTED_FS.is_null() {
            None
        } else {
            Some(&mut *EXT2_MOUNTED_FS)
        }
    }
}

/// Register the ext2 driver with the filesystem subsystem
pub fn register_driver() {
    // Note: In a full implementation, we would create a FileSystemDriver
    // structure and register it with the fs subsystem
    // kprintln!("    ext2/ext3/ext4 driver registered")  // kprintln disabled (memcpy crash workaround);
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get filesystem statistics
pub fn get_stats(fs: &Ext2FileSystem) -> Ext2Stats {
    Ext2Stats {
        total_blocks: fs.superblock.blocks_count as u64,
        free_blocks: fs.superblock.free_blocks as u64,
        total_inodes: fs.superblock.inodes_count as u64,
        free_inodes: fs.superblock.free_inodes as u64,
        block_size: fs.block_size,
        inode_size: fs.inode_size,
        block_groups: fs.group_count,
        fs_type: alloc::string::String::from(fs.get_fs_type_string()),
    }
}

/// Filesystem statistics
#[derive(Debug)]
pub struct Ext2Stats {
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
    pub block_size: u32,
    pub inode_size: u16,
    pub block_groups: u32,
    pub fs_type: String,
}

/// Convert a path string to bytes
pub fn path_to_bytes(path: &str) -> Vec<u8> {
    path.as_bytes().to_vec()
}

/// Convert bytes to a path string
pub fn bytes_to_path(bytes: &[u8]) -> String {
    match core::str::from_utf8(bytes) {
        Ok(s) => alloc::string::String::from(s),
        Err(_) => alloc::string::String::from(""),
    }
}
