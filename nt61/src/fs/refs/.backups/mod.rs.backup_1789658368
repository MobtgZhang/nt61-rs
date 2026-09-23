//! ReFS File System Driver
//
//! Main module for the Resilient File System (ReFS).
//! This module provides the file system driver interface and main entry points.
//
//! ## Features
//! - Read-only support for basic ReFS volumes
//! - Superblock parsing and validation
//! - B+ tree navigation for metadata
//! - CRC32C integrity verification
//! - Object ID support
//
//! ## Architecture
//! This module provides the high-level interface while submodules handle:
//! - superblock.rs: Superblock reading and validation
//! - btree.rs: B+ tree operations
//! - chunk.rs: Chunk (extent) allocation
//! - integrity.rs: CRC32C checksums
//! - object.rs: Object ID management

extern crate alloc;

use alloc::vec;
use alloc::string::{String, ToString};
use crate::fs::{FileSystem, FileSystemType};
use core::ptr::null_mut;

// Submodules
pub mod superblock;
pub mod btree;
pub mod chunk;
pub mod integrity;
pub mod object;

// Re-export commonly used types
pub use superblock::{RefsSuperBlock, REFS_SIGNATURE};
pub use btree::{RefsBtree, RefsBtreePage, RefsBtreeKey};
pub use chunk::{RefsChunkDescriptor, ChunkTable};
pub use integrity::crc32c;
pub use object::{ObjectIdTable, ObjectIdEntry, REFS_OBJECT_ID_ROOT};

// ============================================================================
// File System Instance
// ============================================================================

/// ReFS file system instance
pub struct RefsFileSystem {
    /// Base file system structure
    pub base: FileSystem,
    /// Superblock data
    pub superblock: RefsSuperBlock,
    /// Sector size in bytes
    pub sector_size: u32,
    /// Cluster size in bytes
    pub cluster_size: u32,
    /// Object ID table
    pub object_table: ObjectIdTable,
    /// Is integrity streams enabled?
    pub has_integrity: bool,
    /// Is read-only mount?
    pub read_only: bool,
}

impl RefsFileSystem {
    /// Create a new ReFS filesystem structure
    pub fn new() -> Self {
        Self {
            base: FileSystem {
                driver: null_mut(),
                device: null_mut(),
                volume_name: [0; 64],
                fs_type: FileSystemType::Refs,
                sector_size: 512,
                cluster_size: 65536,
                total_clusters: 0,
                free_clusters: 0,
            },
            superblock: unsafe { core::mem::zeroed() },
            sector_size: 512,
            cluster_size: 65536,
            object_table: ObjectIdTable::new(),
            has_integrity: false,
            read_only: true,
        }
    }

    /// Get the sector size
    pub fn get_sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Get the cluster size
    pub fn get_cluster_size(&self) -> u32 {
        self.cluster_size
    }

    /// Get the cluster size shift
    pub fn get_cluster_shift(&self) -> u32 {
        self.cluster_size.trailing_zeros()
    }

    /// Convert cluster to LBA
    pub fn cluster_to_lba(&self, cluster: u64) -> u64 {
        cluster * ((self.cluster_size / self.sector_size) as u64)
    }

    /// Convert LBA to cluster
    pub fn lba_to_cluster(&self, lba: u64) -> u64 {
        lba / ((self.cluster_size / self.sector_size) as u64)
    }

    /// Get the total size in bytes
    pub fn get_total_size(&self) -> u64 {
        self.base.total_clusters * (self.cluster_size as u64)
    }
}

/// File handle for open files
pub struct RefsHandle {
    /// Object ID
    pub object_id: u64,
    /// Sub-sequence (for versions)
    pub sub_sequence: u64,
    /// Current position in file
    pub current_position: u64,
    /// File size
    pub file_size: u64,
    /// Is this a directory?
    pub is_directory: bool,
    /// Chunk table
    pub chunk_table: ChunkTable,
}

impl RefsHandle {
    /// Create a new file handle
    pub fn new(object_id: u64, file_size: u64, is_directory: bool) -> Self {
        Self {
            object_id,
            sub_sequence: 0,
            current_position: 0,
            file_size,
            is_directory,
            chunk_table: ChunkTable::new(),
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
pub fn read_sector(_device: *mut (), lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    if buffer.len() < 512 {
        return Err(());
    }
    
    let sector_num = lba as usize;
    if crate::drivers::storage::ramdisk::read(sector_num, buffer) {
        return Ok(());
    }
    
    if crate::drivers::storage::ahci::read_sector(0, 0, lba as u32, buffer) {
        return Ok(());
    }
    
    Err(())
}

/// Read multiple sectors from the device
pub fn read_sectors(device: *mut (), lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), ()> {
    let sector_size = 512usize;
    let needed = (count as usize) * sector_size;
    
    if buffer.len() < needed {
        return Err(());
    }
    
    for i in 0..count as usize {
        let offset = (lba + (i as u64)) * (sector_size as u64);
        if read_sector(device, offset, &mut buffer[i * sector_size..(i + 1) * sector_size]).is_err() {
            return Err(());
        }
    }
    
    Ok(())
}

// ============================================================================
// Mount/Unmount Operations
// ============================================================================

/// Mount a ReFS filesystem
pub fn mount(device: *mut ()) -> Option<&'static mut RefsFileSystem> {
    // kprintln!("[REFS] Mounting ReFS filesystem...")  // kprintln disabled (memcpy crash workaround);
    
    // Read superblock
    let sb = match superblock::read_superblock(device) {
        Some(s) => s,
        None => {
            // kprintln!("[REFS] Failed to read superblock")  // kprintln disabled (memcpy crash workaround);
            return None;
        }
    };
    
    // Validate superblock
    if superblock::validate_superblock(&sb).is_err() {
        // kprintln!("[REFS] Superblock validation failed")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Create filesystem instance
    let fs_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<RefsFileSystem>(),
    ) as *mut RefsFileSystem;
    
    if fs_ptr.is_null() {
        // kprintln!("[REFS] Failed to allocate filesystem structure")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Extract values from superblock before moving it
    let sector_size = sb.get_sector_size();
    let cluster_size = sb.get_cluster_size();
    let total_clusters = sb.get_total_clusters();
    let read_only = sb.is_read_only();
    let object_table_lba = superblock::read_object_id_table_lba(&sb);
    
    unsafe {
        (*fs_ptr) = RefsFileSystem::new();
        (*fs_ptr).base.device = device;
        (*fs_ptr).sector_size = sector_size;
        (*fs_ptr).cluster_size = cluster_size;
        (*fs_ptr).superblock = sb;
        (*fs_ptr).base.fs_type = FileSystemType::Refs;
        (*fs_ptr).base.cluster_size = (*fs_ptr).cluster_size;
        (*fs_ptr).base.total_clusters = total_clusters;
        (*fs_ptr).base.sector_size = (*fs_ptr).sector_size;
        (*fs_ptr).read_only = read_only;
        
        // Initialize object ID table
        (*fs_ptr).object_table = ObjectIdTable::from_btree(object_table_lba);
    }
    
    let fs = unsafe { &*fs_ptr };
    
    // Print volume info
    fs.superblock.debug_print();
    
    // Check for integrity streams
    if fs.has_integrity {
        // kprintln!("[REFS] Integrity streams: ENABLED")  // kprintln disabled (memcpy crash workaround);
    }
    
    if fs.read_only {
        // kprintln!("[REFS] Mounted READ-ONLY")  // kprintln disabled (memcpy crash workaround);
    }
    
    Some(unsafe { &mut *fs_ptr })
}

/// Unmount a ReFS filesystem
pub fn unmount(_fs: *mut RefsFileSystem) {
    if !_fs.is_null() {
        // kprintln!("[REFS] Filesystem unmounted")  // kprintln disabled (memcpy crash workaround);
    }
}

// ============================================================================
// File Operations
// ============================================================================

/// Open a file by object ID
pub fn open_by_object_id(fs: &RefsFileSystem, object_id: u64) -> Option<RefsHandle> {
    // Look up object in the Object ID table
    let _entry = object::find_by_object_id(&fs.object_table, object_id)?;
    
    // For now, create a simple handle
    Some(RefsHandle::new(object_id, 0, false))
}

/// Read from a file handle
pub fn read_file(fs: &RefsFileSystem, handle: &mut RefsHandle, buffer: &mut [u8]) -> usize {
    if handle.at_eof() {
        return 0;
    }
    
    let bytes_to_read = core::cmp::min(
        buffer.len(),
        (handle.remaining() as usize).min(usize::MAX),
    );
    
    // Calculate which cluster this is
    let cluster_size = fs.cluster_size as u64;
    let current_cluster = handle.current_position / cluster_size;
    let offset_in_cluster = handle.current_position % cluster_size;
    
    // Find the chunk for this cluster
    if let Some(lba) = chunk::vcn_to_lba(
        &[],
        &fs.superblock,
        current_cluster
    ) {
        
        // Read from the cluster
        let mut cluster_data = vec![0u8; cluster_size as usize];
        let sectors_per_cluster = (cluster_size / fs.sector_size as u64) as u32;
        if read_sectors(fs.base.device, lba, sectors_per_cluster, &mut cluster_data).is_ok() {
            let copy_len = core::cmp::min(bytes_to_read, (cluster_size - offset_in_cluster) as usize);
            buffer[..copy_len].copy_from_slice(&cluster_data[offset_in_cluster as usize..offset_in_cluster as usize + copy_len]);
            handle.current_position += copy_len as u64;
            return copy_len;
        }
    }
    
    0
}

// ============================================================================
// B+ Tree Operations
// ============================================================================

/// Load a B+ tree page from disk
pub fn load_btree_page(device: *mut (), lba: u64) -> Option<RefsBtreePage> {
    let mut buffer = vec![0u8; 4096]; // Standard page size
    
    if read_sectors(device, lba, 8, &mut buffer).is_err() {
        // kprintln!("[REFS] Failed to read B+ tree page at LBA {}", lba)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    btree::parse_page(&buffer, lba)
}

/// Find in the Object ID B+ tree
pub fn find_in_object_tree(
    device: *mut (),
    fs: &RefsFileSystem,
    _object_id: u64,
) -> Option<RefsBtreePage> {
    // Load the Object ID tree root
    let root_lba = fs.object_table.root_lba;
    
    if root_lba == 0 {
        // kprintln!("[REFS] Object ID tree root not set")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    load_btree_page(device, root_lba)
}

// ============================================================================
// Driver Registration
// ============================================================================

/// Global mount state - stores pointer to mounted filesystem
static mut REFS_MOUNTED_FS: *mut RefsFileSystem = core::ptr::null_mut();

/// Mount the first ReFS partition found
pub fn mount_first(device: *mut ()) -> Option<&'static mut RefsFileSystem> {
    unsafe {
        if !REFS_MOUNTED_FS.is_null() {
            return Some(&mut *REFS_MOUNTED_FS);
        }
        let fs = mount(device)?;
        REFS_MOUNTED_FS = fs as *const _ as *mut RefsFileSystem;
        Some(&mut *REFS_MOUNTED_FS)
    }
}

/// Get the mounted filesystem
pub fn get_mounted_fs() -> Option<&'static mut RefsFileSystem> {
    unsafe {
        if REFS_MOUNTED_FS.is_null() {
            None
        } else {
            Some(&mut *REFS_MOUNTED_FS)
        }
    }
}

/// Register the ReFS driver with the filesystem subsystem
pub fn register_driver() {
    // Note: In a full implementation, we would create a FileSystemDriver
    // structure and register it with the fs subsystem
    // kprintln!("    ReFS driver registered")  // kprintln disabled (memcpy crash workaround);
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get filesystem statistics
pub fn get_stats(fs: &RefsFileSystem) -> RefsStats {
    RefsStats {
        total_clusters: fs.superblock.get_total_clusters(),
        total_size: fs.get_total_size(),
        sector_size: fs.sector_size,
        cluster_size: fs.cluster_size,
        fs_type: "ReFS".to_string(),
        read_only: fs.read_only,
        has_integrity: fs.has_integrity,
        volume_serial: fs.superblock.get_volume_serial(),
    }
}

/// Filesystem statistics
#[derive(Debug)]
pub struct RefsStats {
    pub total_clusters: u64,
    pub total_size: u64,
    pub sector_size: u32,
    pub cluster_size: u32,
    pub fs_type: String,
    pub read_only: bool,
    pub has_integrity: bool,
    pub volume_serial: u64,
}

/// CRC32C self-test
pub fn crc32c_self_test() -> bool {
    integrity::crc32c_self_test()
}
