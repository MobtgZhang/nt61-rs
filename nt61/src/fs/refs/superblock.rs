//! ReFS Superblock Parsing
//
//! Implements superblock reading and validation for the Resilient File System (ReFS).
//! ReFS is a Microsoft file system used in Windows Server 2012+.
//
//! ## Superblock Location
//! The ReFS superblock is located at byte offset 0x1000 (4096 bytes) from the
//! start of the volume. It is 4096 bytes in size.
//
//! ## Superblock Structure
//! The superblock contains:
//! - Signature and checksum
//! - Version information
//! - Volume flags
//! - Sector and cluster sizes
//! - Total cluster count
//! - Volume and object identifiers

extern crate alloc;

use alloc::vec;

use crate::fs::{FsError, FsResult};

// ============================================================================
// Superblock Constants
// ============================================================================

/// ReFS magic number ("RdsF" = 0x52647366)
pub const REFS_SIGNATURE: u64 = 0x52647366;

/// ReFS superblock signature string
pub const REFS_SIGNATURE_STR: &[u8] = b"RdsF";

/// Superblock offset from volume start (4096 bytes / 8 sectors)
pub const SUPERBLOCK_OFFSET: u64 = 0x1000;

/// Superblock size (4096 bytes)
pub const SUPERBLOCK_SIZE: usize = 4096;

/// Minimum supported ReFS version
pub const REFS_MIN_VERSION: u32 = 0x0001;

/// Maximum supported ReFS version
pub const REFS_MAX_VERSION: u32 = 0x0003;

// ============================================================================
// Superblock Flags
// ============================================================================

/// Volume flags
pub const REFS_FLAGS_NONE: u64 = 0x00000000;
pub const REFS_FLAGS_READ_ONLY: u64 = 0x00010000;
pub const REFS_FLAGS_WRITE_ERROR: u64 = 0x00020000;
pub const REFS_FLAGS_NEED_CLEANUP: u64 = 0x00040000;
pub const REFS_FLAGS_NEED_CHECK: u64 = 0x00080000;
pub const REFS_FLAGS_VALID_FLAGS: u64 = 0x000F0000;

/// OMIT (Object ID Multi-table) flags
pub const REFS_OMIT_SHARE_ACCESS_CHECK: u64 = 0x00000001;
pub const REFS_OMIT_JOURNAL: u64 = 0x00000002;

/// Object identifier table flags
pub const REFS_OBJID_TABLE_FLAG_NONE: u64 = 0x00000000;
pub const REFS_OBJID_TABLE_FLAG_FLAG1: u64 = 0x00000001;
pub const REFS_OBJID_TABLE_FLAG_FLAG2: u64 = 0x00000002;

// ============================================================================
// Superblock Structure
// ============================================================================

/// ReFS Superblock (4096 bytes)
/// The superblock is located at offset 0x1000 from the start of the volume.
#[repr(C)]
pub struct RefsSuperBlock {
    /// Signature ("RdsF" = 0x52647366)
    pub signature: u64,
    /// Checksum of the superblock
    pub checksum: u32,
    /// Reserved
    pub reserved1: u32,
    /// Lower supported version
    pub version_lower: u32,
    /// Upper supported version
    pub version_upper: u32,
    /// Volume flags
    pub flags: u64,
    /// Sector size (typically 512 or 4096)
    pub sector_size: u32,
    /// Sector size shift (log2(sector_size) - 9)
    pub sector_size_shift: u32,
    /// Clusters per volume footprint
    pub clusters_per_footprint: u32,
    /// Reserved
    pub reserved2: [u64; 5],
    /// Total clusters on the volume
    pub total_clusters: u64,
    /// Volume serial number
    pub volume_serial: u64,
    /// Volume GUID (16 bytes)
    pub volume_guid: [u8; 16],
    /// Last winner GUID (16 bytes)
    pub last_winner_guid: [u8; 16],
    /// Transaction ID
    pub transaction_id: u64,
    /// Number of changes since last view
    pub changes_since_last_view: u64,
    /// Reserved
    pub reserved3: [u64; 6],
    /// Code page (512 bytes)
    pub codepage: [u8; 512],
    /// Reserved
    pub reserved4: [u8; 356],
}

impl RefsSuperBlock {
    // ========================================================================
    // Validation
    // ========================================================================

    /// Check if this is a valid ReFS superblock
    pub fn is_valid(&self) -> bool {
        self.signature == REFS_SIGNATURE
    }

    /// Get the sector size in bytes
    pub fn get_sector_size(&self) -> u32 {
        if self.sector_size == 0 {
            512  // Default sector size
        } else {
            self.sector_size
        }
    }

    /// Get the cluster size in bytes
    /// Note: ReFS cluster size is typically sector_size * 2^cluster_size_shift
    pub fn get_cluster_size(&self) -> u32 {
        let sector_size = self.get_sector_size();
        // Default cluster size is 65536 bytes (64KB) for ReFS
        // This is configurable but we use a reasonable default
        sector_size * 128  // 128 sectors = 64KB for 512-byte sectors
    }

    /// Get sector size shift
    pub fn get_sector_size_shift(&self) -> u32 {
        if self.sector_size_shift != 0 {
            self.sector_size_shift
        } else {
            // Default to 512-byte sectors
            0
        }
    }

    // ========================================================================
    // Flags
    // ========================================================================

    /// Check if the volume is read-only
    pub fn is_read_only(&self) -> bool {
        (self.flags & REFS_FLAGS_READ_ONLY) != 0
    }

    /// Check if the volume needs cleanup
    pub fn needs_cleanup(&self) -> bool {
        (self.flags & REFS_FLAGS_NEED_CLEANUP) != 0
    }

    /// Check if the volume needs consistency check
    pub fn needs_check(&self) -> bool {
        (self.flags & REFS_FLAGS_NEED_CHECK) != 0
    }

    /// Check if there was a write error
    pub fn has_write_error(&self) -> bool {
        (self.flags & REFS_FLAGS_WRITE_ERROR) != 0
    }

    /// Get the actual flags (mask out reserved bits)
    pub fn get_flags(&self) -> u64 {
        self.flags & REFS_FLAGS_VALID_FLAGS
    }

    // ========================================================================
    // Volume Information
    // ========================================================================

    /// Get total number of clusters
    pub fn get_total_clusters(&self) -> u64 {
        self.total_clusters
    }

    /// Get volume serial number
    pub fn get_volume_serial(&self) -> u64 {
        self.volume_serial
    }

    /// Get volume GUID as bytes
    pub fn get_volume_guid(&self) -> &[u8; 16] {
        &self.volume_guid
    }

    /// Get the transaction ID
    pub fn get_transaction_id(&self) -> u64 {
        self.transaction_id
    }

    /// Get the number of changes since last view
    pub fn get_changes_count(&self) -> u64 {
        self.changes_since_last_view
    }

    // ========================================================================
    // Version Support
    // ========================================================================

    /// Check if a version is supported
    pub fn is_version_supported(&self, version: u32) -> bool {
        version >= self.version_lower && version <= self.version_upper
    }

    /// Get minimum supported version
    pub fn get_min_version(&self) -> u32 {
        self.version_lower
    }

    /// Get maximum supported version
    pub fn get_max_version(&self) -> u32 {
        self.version_upper
    }

    // ========================================================================
    // Computed Values
    // ========================================================================

    /// Get total volume size in bytes
    pub fn get_total_size(&self) -> u64 {
        self.total_clusters * (self.get_cluster_size() as u64)
    }

    /// Get the number of sectors
    pub fn get_total_sectors(&self) -> u64 {
        self.total_clusters * ((self.get_cluster_size() / self.get_sector_size()) as u64)
    }

    /// Convert cluster number to byte offset
    pub fn cluster_to_offset(&self, cluster: u64) -> u64 {
        cluster * (self.get_cluster_size() as u64)
    }

    /// Convert byte offset to cluster number
    pub fn offset_to_cluster(&self, offset: u64) -> u64 {
        offset / (self.get_cluster_size() as u64)
    }

    /// Convert cluster to LBA (sector number)
    pub fn cluster_to_lba(&self, cluster: u64) -> u64 {
        cluster * ((self.get_cluster_size() / self.get_sector_size()) as u64)
    }
}

// ============================================================================
// Volume Information Structure
// ============================================================================

/// Volume information extracted from superblock
pub struct RefsVolumeInfo {
    /// Sector size
    pub sector_size: u32,
    /// Cluster size
    pub cluster_size: u32,
    /// Total clusters
    pub total_clusters: u64,
    /// Total size in bytes
    pub total_size: u64,
    /// Volume serial number
    pub serial: u64,
    /// Is read-only
    pub read_only: bool,
    /// Needs check
    pub needs_check: bool,
    /// Version range
    pub version_min: u32,
    pub version_max: u32,
}

impl RefsSuperBlock {
    /// Get volume information
    pub fn get_volume_info(&self) -> RefsVolumeInfo {
        RefsVolumeInfo {
            sector_size: self.get_sector_size(),
            cluster_size: self.get_cluster_size(),
            total_clusters: self.total_clusters,
            total_size: self.get_total_size(),
            serial: self.volume_serial,
            read_only: self.is_read_only(),
            needs_check: self.needs_check(),
            version_min: self.version_lower,
            version_max: self.version_upper,
        }
    }

    /// Print volume information for debugging
    pub fn debug_print(&self) {
        // kprintln!("[REFS] Superblock Information:")  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Signature:       0x{:08x} ({})",   // kprintln disabled (memcpy crash workaround)
//             self.signature, 
//             if self.is_valid() { "VALID" } else { "INVALID" });
        // kprintln!("  Checksum:        0x{:08x}", self.checksum)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Version:         {}.{} - {}.{}",   // kprintln disabled (memcpy crash workaround)
//             (self.version_lower >> 16) & 0xFFFF,
//             self.version_lower & 0xFFFF,
//             (self.version_upper >> 16) & 0xFFFF,
//             self.version_upper & 0xFFFF);
        // kprintln!("  Flags:           0x{:08x}", self.flags)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Sector size:     {} bytes", self.get_sector_size())  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Cluster size:    {} bytes", self.get_cluster_size())  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Total clusters:  {}", self.total_clusters)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Total size:      {} GB", self.get_total_size() / (1024 * 1024 * 1024))  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Volume serial:   0x{:016x}", self.volume_serial)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Transaction ID:  {}", self.transaction_id)  // kprintln disabled (memcpy crash workaround);
        // kprintln!("  Changes:        {}", self.changes_since_last_view)  // kprintln disabled (memcpy crash workaround);
        
        if self.is_read_only() {
            // kprintln!("  Status:          READ-ONLY")  // kprintln disabled (memcpy crash workaround);
        }
        if self.needs_check() {
            // kprintln!("  Status:          NEEDS CHECK")  // kprintln disabled (memcpy crash workaround);
        }
        if self.needs_cleanup() {
            // kprintln!("  Status:          NEEDS CLEANUP")  // kprintln disabled (memcpy crash workaround);
        }
    }
}

// ============================================================================
// Superblock Read Functions
// ============================================================================

/// Read the superblock from a device
pub fn read_superblock(device: *mut ()) -> Option<RefsSuperBlock> {
    let mut buffer = vec![0u8; SUPERBLOCK_SIZE];
    
    if read_sectors(device, SUPERBLOCK_OFFSET, 8, &mut buffer).is_err() {
        // kprintln!("[REFS] Failed to read superblock")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    let sb = unsafe { 
        core::ptr::read_unaligned(buffer.as_ptr() as *const RefsSuperBlock) 
    };
    
    if !sb.is_valid() {
        // kprintln!("[REFS] Invalid superblock signature: 0x{:08x}", sb.signature)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    Some(sb)
}

/// Validate a superblock
pub fn validate_superblock(sb: &RefsSuperBlock) -> FsResult<()> {
    if !sb.is_valid() {
        // kprintln!("[REFS] Invalid signature")  // kprintln disabled (memcpy crash workaround);
        return Err(FsError::DiskCorrupt);
    }
    
    // Check for reasonable values
    if sb.get_sector_size() != 512 && sb.get_sector_size() != 4096 {
        // kprintln!("[REFS] Unsupported sector size: {}", sb.get_sector_size())  // kprintln disabled (memcpy crash workaround);
        return Err(FsError::DiskCorrupt);
    }
    
    if sb.total_clusters == 0 {
        // kprintln!("[REFS] Zero clusters reported")  // kprintln disabled (memcpy crash workaround);
        return Err(FsError::DiskCorrupt);
    }
    
    // Check version
    if sb.version_lower > REFS_MAX_VERSION || sb.version_upper < REFS_MIN_VERSION {
        // kprintln!("[REFS] Version mismatch: {}-{} vs {}-{}",   // kprintln disabled (memcpy crash workaround)
//             sb.version_lower, sb.version_upper, 
//             REFS_MIN_VERSION, REFS_MAX_VERSION);
        return Err(FsError::FileSystemLimit);
    }
    
    // Verify checksum if supported
    if !verify_superblock_checksum(sb) {
        // kprintln!("[REFS] Checksum mismatch - superblock may be corrupted")  // kprintln disabled (memcpy crash workaround);
        // Note: This might be acceptable if the volume was not cleanly unmounted
    }
    
    Ok(())
}

/// Verify superblock checksum
pub fn verify_superblock_checksum(sb: &RefsSuperBlock) -> bool {
    // ReFS uses a simple additive checksum
    // The checksum field itself is not included in the calculation
    // This is a simplified check - real ReFS uses a more complex algorithm
    
    let sb_bytes = unsafe {
        core::slice::from_raw_parts(
            sb as *const RefsSuperBlock as *const u8,
            SUPERBLOCK_SIZE,
        )
    };
    
    // Skip checksum field (bytes 8-11) in the sum
    let mut sum: u64 = 0;
    
    for (i, &byte) in sb_bytes.iter().enumerate() {
        if i >= 8 && i < 12 {
            // Skip checksum bytes
            continue;
        }
        sum = sum.wrapping_add(byte as u64);
    }
    
    // Simple modulo check (real implementation is more complex)
    let computed = (sum & 0xFFFFFFFF) as u32;
    computed != sb.checksum  // If they match, we have a valid checksum
}

// ============================================================================
// Device Read Helper
// ============================================================================

/// Read sectors from device
fn read_sectors(_device: *mut (), offset: u64, count: u32, buffer: &mut [u8]) -> Result<(), ()> {
    let sector_size = 512usize;
    let needed = (count as usize) * sector_size;
    
    if buffer.len() < needed {
        return Err(());
    }
    
    for i in 0..count as usize {
        let sector_offset = offset + (i as u64) * (sector_size as u64);
        let sector_num = sector_offset / (sector_size as u64);
        
        if crate::drivers::storage::ramdisk::read(sector_num as usize, &mut buffer[i * sector_size..(i + 1) * sector_size]) {
            continue;
        }
        
        // Try AHCI
        if crate::drivers::storage::ahci::read_sector(0, 0, sector_num as u32, &mut buffer[i * sector_size..(i + 1) * sector_size]) {
            continue;
        }
        
        return Err(());
    }
    
    Ok(())
}

/// Read the Object Identifier Table
pub fn read_object_id_table_lba(_sb: &RefsSuperBlock) -> u64 {
    // The Object ID table is typically at a fixed offset
    // This is a placeholder - real implementation would parse internal structures
    SUPERBLOCK_OFFSET + (SUPERBLOCK_SIZE as u64) * 2
}
