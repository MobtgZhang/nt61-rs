//! ReFS File System Driver
//
//! Main module for the Resilient File System (ReFS).
//! This module provides the file system driver interface and main entry points.
//
//! ## Features
//! - read-only support for basic ReFS volumes
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
use crate::libs::ntdll::{status::STATUS_UNSUCCESSFUL, types::NTSTATUS};

extern crate alloc;

use crate::fs::{FileSystem, FileSystemType};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::null_mut;

// Submodules
pub mod btree;
pub mod chunk;
pub mod integrity;
pub mod object;
pub mod superblock;

// Re-export commonly used types
pub use btree::{RefsBtree, RefsBtreeKey, RefsBtreePage, RefsBtreeValue};
pub use chunk::{ChunkTable, RefsChunkDescriptor};
pub use integrity::crc32c;
pub use object::{ObjectIdEntry, ObjectIdTable, REFS_OBJECT_ID_ROOT};
pub use superblock::{RefsSuperBlock, REFS_SIGNATURE};

// ============================================================================
// File System Instance
// ============================================================================

/// Clusters at the start of the volume reserved for the superblock and
/// on-disk metadata trees. The CoW allocator never hands them out.
pub const REFS_METADATA_RESERVED_CLUSTERS: u64 = 4096;

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
    /// Free-cluster allocation bitmap (one bit per cluster).
    pub free_cluster_bitmap: Vec<u8>,
}

impl RefsFileSystem {
    /// create a new ReFS filesystem structure
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
            free_cluster_bitmap: Vec::new(),
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

impl Default for RefsFileSystem {
    fn default() -> Self {
        Self::new()
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
    /// On-disk metadata record location.
    pub metadata_record_lba: u64,
    /// Chunk table
    pub chunk_table: ChunkTable,
}

const REFS_OBJECT_RECORD_MAGIC: u32 = 0x5245464F;
const REFS_OBJECT_RECORD_SIZE: usize = 64;

impl RefsHandle {
    /// create a new file handle
    pub fn new(object_id: u64, file_size: u64, is_directory: bool) -> Self {
        Self {
            object_id,
            sub_sequence: 0,
            current_position: 0,
            file_size,
            is_directory,
            metadata_record_lba: 0,
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

/// read a sector from the device
pub fn read_sector(_device: *mut (), lba: u64, buffer: &mut [u8]) -> Result<(), NTSTATUS> {
    if buffer.len() < 512 {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let sector_num = lba as usize;
    if crate::drivers::storage::ramdisk::read(sector_num, buffer) {
        return Ok(());
    }

    if crate::drivers::storage::read_ahci_sector(lba as u32, buffer) {
        return Ok(());
    }

    Err(STATUS_UNSUCCESSFUL)
}

/// read multiple sectors from the device
pub fn read_sectors(
    device: *mut (),
    lba: u64,
    count: u32,
    buffer: &mut [u8],
) -> Result<(), NTSTATUS> {
    let sector_size = 512usize;
    let needed = (count as usize) * sector_size;

    if buffer.len() < needed {
        return Err(STATUS_UNSUCCESSFUL);
    }

    for i in 0..count as usize {
        let offset = (lba + (i as u64)) * (sector_size as u64);
        if read_sector(
            device,
            offset,
            &mut buffer[i * sector_size..(i + 1) * sector_size],
        )
        .is_err()
        {
            return Err(STATUS_UNSUCCESSFUL);
        }
    }

    Ok(())
}

/// Write one 512-byte sector to the device.
pub fn write_sector(_device: *mut (), lba: u64, buffer: &[u8]) -> Result<(), NTSTATUS> {
    if buffer.len() < 512 {
        return Err(STATUS_UNSUCCESSFUL);
    }
    let sector_num = lba as usize;
    if crate::drivers::storage::ramdisk::write(sector_num, buffer) {
        return Ok(());
    }
    if crate::drivers::storage::ahci::write_sector(0, 0, lba as u32, buffer) {
        return Ok(());
    }
    Err(STATUS_UNSUCCESSFUL)
}

/// Write multiple sectors to the device.
pub fn write_sectors(device: *mut (), lba: u64, count: u32, buffer: &[u8]) -> Result<(), NTSTATUS> {
    let sector_size = 512usize;
    let needed = (count as usize) * sector_size;
    if buffer.len() < needed {
        return Err(STATUS_UNSUCCESSFUL);
    }
    for i in 0..count as usize {
        let offset = (lba + (i as u64)) * (sector_size as u64);
        if write_sector(
            device,
            offset,
            &buffer[i * sector_size..(i + 1) * sector_size],
        )
        .is_err()
        {
            return Err(STATUS_UNSUCCESSFUL);
        }
    }
    Ok(())
}

// ============================================================================
// Mount/Unmount Operations
// ============================================================================

/// Mount a ReFS filesystem
pub fn mount(device: *mut ()) -> Option<&'static mut RefsFileSystem> {
    // kprintln!("[REFS] Mounting ReFS filesystem...");

    // read superblock
    let sb = match superblock::read_superblock(device) {
        Some(s) => s,
        None => {
            // kprintln!("[REFS] Failed to read superblock");
            return None;
        }
    };

    // Validate superblock
    if superblock::validate_superblock(&sb).is_err() {
        // kprintln!("[REFS] Superblock validation failed");
        return None;
    }

    // create filesystem instance
    let fs_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<RefsFileSystem>(),
    ) as *mut RefsFileSystem;

    if fs_ptr.is_null() {
        // kprintln!("[REFS] Failed to allocate filesystem structure");
        return None;
    }

    // Extract values from superblock before moving it
    let sector_size = sb.get_sector_size();
    let cluster_size = sb.get_cluster_size();
    let total_clusters = sb.get_total_clusters();
    let read_only = sb.is_read_only();
    let object_table_lba = match superblock::read_object_id_table_lba(&sb) {
        Ok(lba) => lba,
        Err(_) => return None,
    };

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

        // Allocate the free-cluster bitmap. The superblock and metadata
        // regions at the start of the volume are marked allocated so the
        // CoW allocator never hands them out; a real ReFS driver reads
        // the persisted allocation bitmap from disk. For the bootstrap
        // path the remaining clusters start free so that CoW allocation
        // can proceed on a freshly formatted volume.
        let bitmap_len = total_clusters.div_ceil(8) as usize;
        (*fs_ptr).free_cluster_bitmap = vec![0u8; bitmap_len];
        let reserved = total_clusters.min(REFS_METADATA_RESERVED_CLUSTERS);
        let fs = &mut *fs_ptr;
        for cluster in 0..reserved {
            let byte = (cluster / 8) as usize;
            let bit = (cluster % 8) as u32;
            fs.free_cluster_bitmap[byte] |= 1 << bit;
        }
    }

    let fs = unsafe { &*fs_ptr };

    // Print volume info
    fs.superblock.debug_print();

    // Check for integrity streams
    if fs.has_integrity {
        // kprintln!("[REFS] Integrity streams: ENABLED");
    }

    if fs.read_only {
        // kprintln!("[REFS] Mounted READ-ONLY");
    }

    Some(unsafe { &mut *fs_ptr })
}

/// Unmount a ReFS filesystem
pub fn unmount(_fs: *mut RefsFileSystem) {
    if !_fs.is_null() {
        // kprintln!("[REFS] Filesystem unmounted");
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

/// read from a file handle
pub fn read_file(fs: &RefsFileSystem, handle: &mut RefsHandle, buffer: &mut [u8]) -> usize {
    if handle.at_eof() {
        return 0;
    }

    let bytes_to_read = core::cmp::min(buffer.len(), handle.remaining() as usize);

    // Calculate which cluster this is
    let cluster_size = fs.cluster_size as u64;
    let current_cluster = handle.current_position / cluster_size;
    let offset_in_cluster = handle.current_position % cluster_size;

    // Find the chunk for this cluster in the handle's chunk table.
    if let Some(descriptor) = handle.chunk_table.descriptors.get(current_cluster as usize) {
        if descriptor.is_hole() {
            return 0;
        }
        let lba = descriptor.lcn_to_lba(&fs.superblock);
        // read from the cluster
        let mut cluster_data = vec![0u8; cluster_size as usize];
        let sectors_per_cluster = (cluster_size / fs.sector_size as u64) as u32;
        if read_sectors(fs.base.device, lba, sectors_per_cluster, &mut cluster_data).is_ok() {
            let copy_len =
                core::cmp::min(bytes_to_read, (cluster_size - offset_in_cluster) as usize);
            buffer[..copy_len].copy_from_slice(
                &cluster_data[offset_in_cluster as usize..offset_in_cluster as usize + copy_len],
            );
            handle.current_position += copy_len as u64;
            return copy_len;
        }
    }

    0
}

/// Write data to a file using copy-on-write semantics.
///
/// Each cluster written is allocated fresh (CoW): the new data plus its
/// integrity checksum are written to a new LCN, the chunk descriptor is
/// updated to point at the new cluster, and the old cluster is freed.
/// Returns the number of bytes written.
pub fn write_file(fs: &mut RefsFileSystem, handle: &mut RefsHandle, buffer: &[u8]) -> usize {
    if buffer.is_empty() {
        return 0;
    }
    if fs.read_only {
        return 0;
    }

    let cluster_size = fs.cluster_size as u64;
    let sectors_per_cluster = (cluster_size / fs.sector_size as u64) as u32;
    let mut bytes_written = 0usize;

    while bytes_written < buffer.len() {
        let vcn = handle.current_position / cluster_size;
        let offset_in_cluster = handle.current_position % cluster_size;
        let to_write = core::cmp::min(
            buffer.len() - bytes_written,
            (cluster_size - offset_in_cluster) as usize,
        );

        // Allocate a new cluster for the CoW copy.
        let descriptor = chunk::allocate_chunk(&fs.superblock, &mut fs.free_cluster_bitmap, 1)
            .ok_or(STATUS_UNSUCCESSFUL);
        let descriptor = match descriptor {
            Ok(value) => value,
            Err(_) => break,
        };

        // Read the old cluster if the write is partial.
        let mut cluster_data = vec![0u8; cluster_size as usize];
        if offset_in_cluster > 0 || to_write < cluster_size as usize {
            if let Some(old_descriptor) = handle.chunk_table.descriptors.get(vcn as usize) {
                let old_lba = old_descriptor.lcn_to_lba(&fs.superblock);
                let _ = read_sectors(
                    fs.base.device,
                    old_lba,
                    sectors_per_cluster,
                    &mut cluster_data,
                );
            }
        }
        cluster_data[offset_in_cluster as usize..offset_in_cluster as usize + to_write]
            .copy_from_slice(&buffer[bytes_written..bytes_written + to_write]);

        // Write the new cluster with its integrity checksum. The write
        // replaces the whole cluster, so the checksum always covers the
        // final on-disk contents.
        let new_lba = descriptor.lcn_to_lba(&fs.superblock);
        if write_sectors(fs.base.device, new_lba, sectors_per_cluster, &cluster_data).is_err() {
            // Roll the allocation back so the cluster is not leaked.
            let _ = chunk::free_chunk(&fs.superblock, &mut fs.free_cluster_bitmap, &descriptor);
            break;
        }
        let checksum = integrity::compute_chunk_checksum(&cluster_data);
        let new_descriptor = RefsChunkDescriptor {
            checksum,
            ..descriptor
        };

        // Free the previous physical copy only after the new copy is
        // durably on disk (true copy-on-write ordering).
        if let Some(old_descriptor) = handle.chunk_table.descriptors.get(vcn as usize) {
            if old_descriptor.lcn != 0 {
                let _ =
                    chunk::free_chunk(&fs.superblock, &mut fs.free_cluster_bitmap, old_descriptor);
            }
        }
        if handle.chunk_table.descriptors.len() <= vcn as usize {
            handle
                .chunk_table
                .descriptors
                .resize(vcn as usize + 1, RefsChunkDescriptor::EMPTY);
        }
        handle.chunk_table.descriptors[vcn as usize] = new_descriptor;

        handle.current_position += to_write as u64;
        bytes_written += to_write;
        if handle.current_position > handle.file_size {
            handle.file_size = handle.current_position;
        }
    }

    bytes_written
}

/// Create a new file entry in the object ID table.
pub fn create_file(fs: &mut RefsFileSystem, file_size: u64) -> Option<RefsHandle> {
    if fs.read_only {
        return None;
    }
    let (object_id, record_lba) = allocate_object_record(fs, file_size, false)?;
    Some(RefsHandle::new(object_id, file_size, false)).map(|mut handle| {
        handle.metadata_record_lba = record_lba;
        handle
    })
}

/// Create a new directory entry in the object ID table.
pub fn create_directory(fs: &mut RefsFileSystem) -> Option<RefsHandle> {
    if fs.read_only {
        return None;
    }
    let (object_id, record_lba) = allocate_object_record(fs, 0, true)?;
    Some(RefsHandle::new(object_id, 0, true)).map(|mut handle| {
        handle.metadata_record_lba = record_lba;
        handle
    })
}

pub fn delete_file(fs: &mut RefsFileSystem, object_id: u64) -> Result<(), NTSTATUS> {
    delete_object_id_entry(fs, object_id)
}

pub fn delete_directory(fs: &mut RefsFileSystem, object_id: u64) -> Result<(), NTSTATUS> {
    delete_object_id_entry(fs, object_id)
}

// ============================================================================
// B+ Tree Operations
// ============================================================================

/// Load a B+ tree page from disk
pub fn load_btree_page(device: *mut (), lba: u64) -> Option<RefsBtreePage> {
    let mut buffer = vec![0u8; 4096]; // Standard page size

    if read_sectors(device, lba, 8, &mut buffer).is_err() {
        // kprintln!("[REFS] Failed to read B+ tree page at LBA {}", lba);
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
        // kprintln!("[REFS] Object ID tree root not set");
        return None;
    }

    load_btree_page(device, root_lba)
}

pub fn write_btree_page(
    device: *mut (),
    page: &RefsBtreePage,
    page_size: usize,
) -> Result<(), NTSTATUS> {
    let bytes = btree::serialize_page(page, page_size)?;
    write_sectors(device, page.lba, (page_size / 512) as u32, &bytes)
}

pub fn load_object_table_root(fs: &RefsFileSystem) -> Result<RefsBtreePage, NTSTATUS> {
    let root_lba = fs.object_table.root_lba;
    if root_lba == 0 {
        return Err(STATUS_UNSUCCESSFUL);
    }
    load_btree_page(fs.base.device, root_lba).ok_or(STATUS_UNSUCCESSFUL)
}

pub fn insert_object_id_entry(
    fs: &mut RefsFileSystem,
    object_id: u64,
    sub_sequence: u64,
    record_lba: u64,
    _record_size: u32,
) -> Result<(), NTSTATUS> {
    let mut root = load_object_table_root(fs)?;
    let key = RefsBtreeKey {
        object_id,
        sub_sequence,
        code: 0,
        data: Vec::new(),
    };
    let value = RefsBtreeValue::new(record_lba.to_le_bytes().to_vec());
    let split = btree::insert_key(&mut root, &key, &value)?;
    if let Some(mut right) = split {
        right.lba = root.lba + 1;
        write_btree_page(fs.base.device, &right, 4096)?;
    }
    write_btree_page(fs.base.device, &root, 4096)?;
    Ok(())
}

pub fn delete_object_id_entry(fs: &mut RefsFileSystem, object_id: u64) -> Result<(), NTSTATUS> {
    let entry = fs
        .object_table
        .find_by_id(object_id)
        .ok_or(STATUS_UNSUCCESSFUL)?
        .value
        .record_lba;
    let mut root = load_object_table_root(fs)?;
    let key = RefsBtreeKey {
        object_id,
        sub_sequence: 0,
        code: 0,
        data: Vec::new(),
    };
    btree::delete_key(&mut root, &key)?;
    write_btree_page(fs.base.device, &root, 4096)?;
    let _ = object::delete_object_id(&mut fs.object_table, object_id).ok_or(STATUS_UNSUCCESSFUL)?;
    let cluster = fs.lba_to_cluster(entry);
    let chunk = RefsChunkDescriptor {
        flags: chunk::REFS_CHUNK_FLAG_NONE,
        lcn: cluster,
        vcn_length: 1,
        checksum: 0,
        reserved: 0,
    };
    let _ = chunk::free_chunk(&fs.superblock, &mut fs.free_cluster_bitmap, &chunk);
    Ok(())
}

pub fn build_object_record(
    file_size: u64,
    is_directory: bool,
    first_chunk: Option<&RefsChunkDescriptor>,
) -> Vec<u8> {
    let mut record = vec![0u8; REFS_OBJECT_RECORD_SIZE];
    record[0..4].copy_from_slice(&REFS_OBJECT_RECORD_MAGIC.to_le_bytes());
    record[4..8].copy_from_slice(&(is_directory as u32).to_le_bytes());
    record[8..16].copy_from_slice(&file_size.to_le_bytes());
    record[16..24].copy_from_slice(&(if first_chunk.is_some() { 1u64 } else { 0 }).to_le_bytes());
    if let Some(chunk) = first_chunk {
        record[24..32].copy_from_slice(&chunk.flags.to_le_bytes());
        record[32..40].copy_from_slice(&chunk.lcn.to_le_bytes());
        record[40..48].copy_from_slice(&chunk.vcn_length.to_le_bytes());
        record[48..52].copy_from_slice(&chunk.checksum.to_le_bytes());
        record[52..56].copy_from_slice(&chunk.reserved.to_le_bytes());
    }
    record
}

pub fn parse_object_record(bytes: &[u8]) -> Option<(u64, bool, Option<RefsChunkDescriptor>)> {
    if bytes.len() < REFS_OBJECT_RECORD_SIZE {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if magic != REFS_OBJECT_RECORD_MAGIC {
        return None;
    }
    let is_directory = u32::from_le_bytes(bytes[4..8].try_into().ok()?) != 0;
    let file_size = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let chunk_count = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
    let first_chunk = if chunk_count == 0 {
        None
    } else {
        Some(RefsChunkDescriptor {
            flags: u64::from_le_bytes(bytes[24..32].try_into().ok()?),
            lcn: u64::from_le_bytes(bytes[32..40].try_into().ok()?),
            vcn_length: u64::from_le_bytes(bytes[40..48].try_into().ok()?),
            checksum: u32::from_le_bytes(bytes[48..52].try_into().ok()?),
            reserved: u32::from_le_bytes(bytes[52..56].try_into().ok()?),
        })
    };
    Some((file_size, is_directory, first_chunk))
}

pub fn allocate_object_record(
    fs: &mut RefsFileSystem,
    file_size: u64,
    is_directory: bool,
) -> Option<(u64, u64)> {
    if fs.read_only {
        return None;
    }
    let object_id = object::create_object_id(&mut fs.object_table, 0, 0);
    let cluster = chunk::allocate_chunk(&fs.superblock, &mut fs.free_cluster_bitmap, 1)?;
    let record_lba = fs.cluster_to_lba(cluster.lcn);
    let record = build_object_record(file_size, is_directory, None);
    let mut sectors = vec![0u8; fs.cluster_size as usize];
    sectors[..record.len()].copy_from_slice(&record);
    write_sectors(
        fs.base.device,
        record_lba,
        fs.cluster_size / fs.sector_size,
        &sectors,
    )
    .ok()?;
    insert_object_id_entry(fs, object_id, 0, record_lba, REFS_OBJECT_RECORD_SIZE as u32).ok()?;
    fs.object_table.find_by_id_mut(object_id)?.value.record_lba = record_lba;
    Some((object_id, record_lba))
}

pub fn read_object_record(fs: &RefsFileSystem, object_id: u64) -> Option<Vec<u8>> {
    let entry = fs.object_table.find_by_id(object_id)?;
    let lba = entry.value.record_lba;
    let mut bytes = vec![0u8; REFS_OBJECT_RECORD_SIZE];
    read_sectors(fs.base.device, lba, 1, &mut bytes).ok()?;
    Some(bytes)
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
    // kprintln!("    ReFS driver registered");
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
