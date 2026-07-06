//! FAT32 Pagefile Support
//
//! This module implements pagefile.sys creation and management on FAT32 volumes.
//
//! ## Overview
//
//! On FAT32, the pagefile.sys must be:
//! - Located in the root directory
//! - Pre-allocated (contiguous clusters preferred)
//! - Hidden and system attributes set
//
//! ## Implementation
//
//! This module provides functions to:
//! - Create pagefile.sys with the requested size
//! - Open existing pagefile.sys
//! - Read/write pagefile sectors

use crate::kprintln_info;
use crate::kprintln_warn;
use crate::kprintln_error;
use crate::mm::pagefile;
use crate::drivers::storage::block;

/// Minimum pagefile size in MB
pub const MIN_PAGEFILE_SIZE_MB: u64 = 2;

/// Pagefile handle structure
#[derive(Debug, Clone, Copy)]
pub struct Fat32PagefileHandle {
    /// Starting cluster
    pub start_cluster: u32,
    /// File size in bytes
    pub size_bytes: u64,
    /// Number of clusters
    pub cluster_count: u32,
    /// Whether handle is valid
    pub valid: bool,
}

impl Default for Fat32PagefileHandle {
    fn default() -> Self {
        Self {
            start_cluster: 0,
            size_bytes: 0,
            cluster_count: 0,
            valid: false,
        }
    }
}

/// FAT32 pagefile metadata stored in the boot sector area
#[derive(Debug, Clone, Copy)]
pub struct Fat32PagefileMeta {
    /// Pagefile start cluster
    pub start_cluster: u32,
    /// Pagefile size in bytes
    pub size_bytes: u64,
    /// Pagefile size in MB
    pub size_mb: u64,
    /// Whether pagefile exists
    pub exists: bool,
    /// Whether pagefile is valid
    pub valid: bool,
}

impl Default for Fat32PagefileMeta {
    fn default() -> Self {
        Self {
            start_cluster: 0,
            size_bytes: 0,
            size_mb: 0,
            exists: false,
            valid: false,
        }
    }
}

/// Open or create a pagefile on a FAT32 volume.
///
pub fn open_or_create(
    fs_start_sector: u64,
    sectors_per_cluster: u32,
    cluster_size: u32,
    fat_start_sector: u64,
    data_start_sector: u64,
    device_id: usize,
    size_mb: u64,
) -> Option<Fat32PagefileHandle> {
    let requested_size_mb = size_mb.max(MIN_PAGEFILE_SIZE_MB);
    let size_bytes = requested_size_mb * 1024 * 1024;
    let size_clusters = ((size_bytes + cluster_size as u64 - 1) / cluster_size as u64) as u32;
    
    kprintln_info!("FAT32", "open_or_create: requesting {} MB ({} clusters)", 
                   requested_size_mb, size_clusters);
    
    // Try to find existing pagefile.sys
    if let Some(handle) = find_pagefile(
        fs_start_sector,
        sectors_per_cluster,
        cluster_size,
        fat_start_sector,
        data_start_sector,
        device_id,
    ) {
        kprintln_info!("FAT32", "Found existing pagefile.sys: {} MB", 
                       handle.size_bytes / (1024 * 1024));
        
        // Check if existing size is sufficient
        if handle.size_bytes >= size_bytes {
            return Some(handle);
        }
        
        // Need to resize - for now, return the existing one
        // Full resize would require defragmentation
        kprintln_warn!("FAT32", "Existing pagefile too small, using {} MB",
                       handle.size_bytes / (1024 * 1024));
        return Some(handle);
    }
    
    // Create new pagefile
    kprintln_info!("FAT32", "Creating new pagefile.sys...");
    create_pagefile(
        fs_start_sector,
        sectors_per_cluster,
        cluster_size,
        fat_start_sector,
        data_start_sector,
        device_id,
        size_clusters,
        size_bytes,
    )
}

/// Find an existing pagefile.sys in the root directory.
fn find_pagefile(
    _fs_start_sector: u64,
    sectors_per_cluster: u32,
    cluster_size: u32,
    _fat_start_sector: u64,
    data_start_sector: u64,
    device_id: usize,
) -> Option<Fat32PagefileHandle> {
    // Read root directory
    let root_cluster = 2u32; // FAT32 root directory starts at cluster 2
    let mut buffer = alloc::vec![0u8; 4096];
    
    // Read first cluster of root directory
    if !read_cluster(device_id, data_start_sector, root_cluster, sectors_per_cluster, &mut buffer) {
        kprintln_warn!("FAT32", "Failed to read root directory for pagefile search");
        return None;
    }
    
    // Search for pagefile.sys entry
    let entry_size = 32usize;
    let entries_per_sector = 512 / entry_size;
    let sectors_per_buffer = buffer.len() / 512;
    
    for sector in 0..sectors_per_buffer {
        for entry in 0..entries_per_sector {
            let offset = sector * 512 + entry * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }
            
            let entry_data = &buffer[offset..offset + entry_size];
            
            // Check if entry is valid
            if entry_data[0] == 0x00 || entry_data[0] == 0xE5 {
                continue;
            }
            
            // Check for long filename entry
            let attributes = entry_data[11];
            if attributes == 0x0F {
                continue; // Long filename entry
            }
            
            // Check for PAGEFILE.SYS
            // The name is in 8.3 format: "PAGEFILE SYS"
            let name = &entry_data[0..11];
            
            // Check if this is pagefile.sys (hidden + system)
            let is_hidden = (attributes & 0x02) != 0;
            let is_system = (attributes & 0x04) != 0;
            // Variables retained for documentation purposes - actual matching uses byte comparison below
            let _ = (is_hidden, is_system);
            let is_directory = (attributes & 0x10) != 0;
            
            if is_directory {
                continue;
            }
            
            // Try to match "PAGEFILE SYS" (padded with spaces)
            let matches = name[0] == b'P' 
                && name[1] == b'A'
                && name[2] == b'G'
                && name[3] == b'E'
                && name[4] == b'F'
                && name[5] == b'I'
                && name[6] == b'L'
                && name[7] == b'E'
                && name[8] == b' '
                && name[9] == b'S'
                && name[10] == b'Y'
                && (name[8] == b' ' || name[8] == 0x00); // Space or null
            
            if matches || (name[0] == b'P' && name[1] == b'A' && name[2] == b'G') {
                // Found pagefile.sys
                let first_cluster_low = u16::from_le_bytes([entry_data[26], entry_data[27]]) as u32;
                let first_cluster_high = u16::from_le_bytes([entry_data[20], entry_data[21]]) as u32;
                let start_cluster = (first_cluster_high << 16) | first_cluster_low;
                let file_size = u32::from_le_bytes([
                    entry_data[28], entry_data[29], entry_data[30], entry_data[31]
                ]) as u64;
                
                kprintln_info!("FAT32",
                    "Found pagefile.sys: cluster={}, size={} bytes",
                    start_cluster, file_size);
                
                return Some(Fat32PagefileHandle {
                    start_cluster,
                    size_bytes: file_size,
                    cluster_count: ((file_size + cluster_size as u64 - 1) / cluster_size as u64) as u32,
                    valid: true,
                });
            }
        }
    }
    
    None
}

/// Create a new pagefile.sys.
///
fn create_pagefile(
    fs_start_sector: u64,
    sectors_per_cluster: u32,
    _cluster_size: u32,
    fat_start_sector: u64,
    data_start_sector: u64,
    device_id: usize,
    cluster_count: u32,
    size_bytes: u64,
) -> Option<Fat32PagefileHandle> {
    kprintln_info!("FAT32",
        "Creating pagefile.sys: {} clusters, {} bytes",
        cluster_count, size_bytes);

    // Find free clusters
    let start_cluster = find_free_clusters(device_id, fat_start_sector, cluster_count)?;

    kprintln_info!("FAT32",
        "Allocated cluster chain: {} clusters starting at {}",
        cluster_count, start_cluster);

    // Mark clusters as used in FAT
    if !mark_clusters_used(device_id, fat_start_sector, start_cluster, cluster_count) {
        kprintln_error!("FAT32",
            "Failed to mark clusters in FAT");
        return None;
    }

    // Create directory entry
    if !create_pagefile_entry(
        device_id,
        fs_start_sector,
        data_start_sector,
        start_cluster,
        size_bytes,
    ) {
        kprintln_error!("FAT32",
            "Failed to create directory entry");
        return None;
    }

    // Register with pagefile manager
    let start_sector = data_start_sector + ((start_cluster as u64 - 2) * sectors_per_cluster as u64);
    let size_pages = size_bytes / 4096;

    pagefile::set_disk_pagefile(
        0, // Pagefile number
        crate::fs::FileSystemType::Fat32,
        device_id,
        start_sector,
        size_pages,
    );

    kprintln_info!("FAT32",
        "Pagefile created successfully");

    Some(Fat32PagefileHandle {
        start_cluster,
        size_bytes,
        cluster_count,
        valid: true,
    })
}

/// Find free clusters in the FAT.
///
fn find_free_clusters(device_id: usize, fat_start_sector: u64, count: u32) -> Option<u32> {
    let _buffer = [0u8; 512];
    let mut current_cluster: u32 = 2;
    let mut consecutive_free: u32 = 0;
    let mut chain_start: u32 = 0;
    
    loop {
        // Read FAT entry
        let entry = read_fat_entry(device_id, fat_start_sector, current_cluster)?;
        
        if entry == 0 {
            // Free cluster
            if consecutive_free == 0 {
                chain_start = current_cluster;
            }
            consecutive_free += 1;
            
            if consecutive_free >= count {
                return Some(chain_start);
            }
        } else {
            // Occupied or end of chain
            consecutive_free = 0;
        }
        
        current_cluster += 1;
        
        // Safety limit
        if current_cluster > 0x0FFFFFEF {
            break;
        }
    }
    
    // Try to find any free cluster even if not contiguous
    // (FAT can chain non-contiguous clusters)
    kprintln_warn!("FAT32",
        "No contiguous clusters found (needed {}), using non-contiguous allocation", count);
    
    // For simplicity, try finding first free cluster
    current_cluster = 2;
    loop {
        let entry = read_fat_entry(device_id, fat_start_sector, current_cluster)?;
        
        if entry == 0 {
            // Check if we can allocate count clusters total
            let available = count_available_clusters(device_id, fat_start_sector, current_cluster)?;
            if available >= count {
                return Some(current_cluster);
            }
            current_cluster += available + 1;
        } else {
            current_cluster += 1;
        }
        
        if current_cluster > 0x0FFFFFEF {
            break;
        }
    }
    
    kprintln_error!("FAT32", "Not enough free clusters for pagefile");
    None
}

/// Count available free clusters starting from a position.
///
fn count_available_clusters(device_id: usize, fat_start_sector: u64, start: u32) -> Option<u32> {
    let mut count: u32 = 0;
    let mut cluster = start;
    
    loop {
        let entry = read_fat_entry(device_id, fat_start_sector, cluster)?;
        
        if entry != 0 {
            break; // Cluster is used
        }
        
        count += 1;
        cluster += 1;
        
        if cluster > 0x0FFFFFEF {
            break;
        }
    }
    
    Some(count)
}

/// Read a FAT entry for a cluster.
///
fn read_fat_entry(device_id: usize, fat_start_sector: u64, cluster: u32) -> Option<u32> {
    let mut buffer = [0u8; 512];
    
    // Each FAT entry is 4 bytes (32-bit for FAT32)
    let entry_offset = (cluster as u64) * 4;
    let fat_sector = fat_start_sector + (entry_offset / 512);
    let offset_in_sector = (entry_offset % 512) as usize;
    
    if !block::read_block(device_id, fat_sector, &mut buffer) {
        return None;
    }
    
    let value = u32::from_le_bytes([
        buffer[offset_in_sector],
        buffer[offset_in_sector + 1],
        buffer[offset_in_sector + 2],
        buffer[offset_in_sector + 3],
    ]);
    
    // Mask to 28 bits for FAT32
    Some(value & 0x0FFFFFFF)
}

/// Mark clusters as used in the FAT.
///
fn mark_clusters_used(device_id: usize, fat_start_sector: u64, start_cluster: u32, count: u32) -> bool {
    let _buffer = [0u8; 512];
    let mut current = start_cluster;
    let _prev = current;
    
    for i in 0..count {
        current = start_cluster + i;
        
        if i == count - 1 {
            // Last cluster - mark as EOC
            if !write_fat_entry(device_id, fat_start_sector, current, 0x0FFFFFFF) {
                return false;
            }
        } else {
            // Chain to next cluster
            if !write_fat_entry(device_id, fat_start_sector, current, current + 1) {
                return false;
            }
        }
        
        // Track current cluster for potential future use
        let _ = current;
    }
    
    true
}

/// Write a FAT entry for a cluster.
///
fn write_fat_entry(device_id: usize, fat_start_sector: u64, cluster: u32, value: u32) -> bool {
    let mut buffer = [0u8; 512];
    
    // Each FAT entry is 4 bytes (32-bit for FAT32)
    let entry_offset = (cluster as u64) * 4;
    let fat_sector = fat_start_sector + (entry_offset / 512);
    let offset_in_sector = (entry_offset % 512) as usize;
    
    // Read current sector
    if !block::read_block(device_id, fat_sector, &mut buffer) {
        return false;
    }
    
    // Modify the entry
    let existing = u32::from_le_bytes([
        buffer[offset_in_sector],
        buffer[offset_in_sector + 1],
        buffer[offset_in_sector + 2],
        buffer[offset_in_sector + 3],
    ]);
    
    // Preserve high 4 bits
    let new_value = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
    
    buffer[offset_in_sector] = (new_value & 0xFF) as u8;
    buffer[offset_in_sector + 1] = ((new_value >> 8) & 0xFF) as u8;
    buffer[offset_in_sector + 2] = ((new_value >> 16) & 0xFF) as u8;
    buffer[offset_in_sector + 3] = ((new_value >> 24) & 0xFF) as u8;
    
    // Write sector back
    if !block::write_block(device_id, fat_sector, &buffer) {
        return false;
    }
    
    // Also update backup FAT (sector + sectors_per_fat)
    // For simplicity, assume FAT2 starts right after FAT1
    // This should be calculated from boot sector
    let backup_sector = fat_start_sector + 1; // Placeholder
    if !block::read_block(device_id, backup_sector, &mut buffer) {
        return false;
    }
    
    buffer[offset_in_sector] = (new_value & 0xFF) as u8;
    buffer[offset_in_sector + 1] = ((new_value >> 8) & 0xFF) as u8;
    buffer[offset_in_sector + 2] = ((new_value >> 16) & 0xFF) as u8;
    buffer[offset_in_sector + 3] = ((new_value >> 24) & 0xFF) as u8;
    
    let _ = block::write_block(device_id, backup_sector, &buffer);
    
    true
}

/// Create the pagefile.sys directory entry in the root directory.
///
fn create_pagefile_entry(
    device_id: usize,
    _fs_start_sector: u64,
    data_start_sector: u64,
    start_cluster: u32,
    size_bytes: u64,
) -> bool {
    let mut buffer = alloc::vec![0u8; 4096];
    
    // Read root directory cluster
    let root_cluster = 2u32;
    if !read_cluster(device_id, data_start_sector, root_cluster, 8, &mut buffer) {
        kprintln_error!("FAT32", "Failed to read root directory");
        return false;
    }
    
    // Find a free entry slot
    let entry_size = 32usize;
    let mut found_offset: Option<usize> = None;
    let entries_per_sector = 512 / entry_size;
    let sectors_per_buffer = buffer.len() / 512;
    
    for sector in 0..sectors_per_buffer {
        for entry in 0..entries_per_sector {
            let offset = sector * 512 + entry * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }
            
            let entry_data = &buffer[offset..offset + entry_size];
            
            // Check for free slot (deleted or never used)
            if entry_data[0] == 0x00 || entry_data[0] == 0xE5 {
                found_offset = Some(offset);
                break;
            }
        }
        if found_offset.is_some() {
            break;
        }
    }
    
    let offset = match found_offset {
        Some(o) => o,
        None => {
            kprintln_error!("FAT32",
                "No free directory entry slots");
            return false;
        }
    };
    
    // Create directory entry for PAGEFILE.SYS
    let entry = &mut buffer[offset..offset + entry_size];
    
    // Filename: "PAGEFILE SYS"
    entry[0] = b'P';
    entry[1] = b'A';
    entry[2] = b'G';
    entry[3] = b'E';
    entry[4] = b'F';
    entry[5] = b'I';
    entry[6] = b'L';
    entry[7] = b'E';
    entry[8] = b' ';  // Space
    entry[9] = b'S';
    entry[10] = b'Y';
    
    // Attributes: Hidden + System
    entry[11] = 0x02 | 0x04; // HIDDEN | SYSTEM
    
    // Reserved
    entry[12] = 0;
    
    // Creation time tenth of seconds
    entry[13] = 0;
    
    // Creation time
    entry[14] = 0;
    entry[15] = 0;
    
    // Creation date
    entry[16] = 0;
    entry[17] = 0;
    
    // Last access date
    entry[18] = 0;
    entry[19] = 0;
    
    // First cluster high (bits 16-31)
    entry[20] = ((start_cluster >> 16) & 0xFF) as u8;
    entry[21] = ((start_cluster >> 24) & 0xFF) as u8;
    
    // Modification time
    entry[22] = 0;
    entry[23] = 0;
    
    // Modification date
    entry[24] = 0;
    entry[25] = 0;
    
    // First cluster low (bits 0-15)
    entry[26] = (start_cluster & 0xFF) as u8;
    entry[27] = ((start_cluster >> 8) & 0xFF) as u8;
    
    // File size
    let size_u32 = size_bytes.min(u32::MAX as u64) as u32;
    entry[28] = (size_u32 & 0xFF) as u8;
    entry[29] = ((size_u32 >> 8) & 0xFF) as u8;
    entry[30] = ((size_u32 >> 16) & 0xFF) as u8;
    entry[31] = ((size_u32 >> 24) & 0xFF) as u8;
    
    // Write the entry back
    let sector = offset / 512;
    let sector_offset = offset % 512;
    let mut sector_buffer = [0u8; 512];
    
    // Read the sector first
    let sector_lba = data_start_sector + sector as u64;
    if !block::read_block(device_id, sector_lba, &mut sector_buffer) {
        return false;
    }
    
    // Modify the entry
    sector_buffer[sector_offset..sector_offset + entry_size]
        .copy_from_slice(&buffer[offset..offset + entry_size]);
    
    // Write back
    if !block::write_block(device_id, sector_lba, &sector_buffer) {
        return false;
    }
    
    kprintln_info!("FAT32",
        "Directory entry created for pagefile.sys");
    true
}

/// Read a cluster from the filesystem.
///
fn read_cluster(
    device_id: usize,
    data_start_sector: u64,
    cluster: u32,
    sectors_per_cluster: u32,
    buffer: &mut [u8],
) -> bool {
    let cluster_size = (sectors_per_cluster * 512) as usize;
    if buffer.len() < cluster_size {
        return false;
    }
    
    let first_sector = data_start_sector + ((cluster as u64 - 2) * sectors_per_cluster as u64);
    
    for i in 0..sectors_per_cluster {
        let mut sector_buf = [0u8; 512];
        if !block::read_block(device_id, first_sector + i as u64, &mut sector_buf) {
            return false;
        }
        let offset = (i as usize) * 512;
        buffer[offset..offset + 512].copy_from_slice(&sector_buf);
    }
    
    true
}

/// Write a cluster to the filesystem.
/// 
/// Low-level primitive for writing a single cluster (sectors_per_cluster
/// sectors) at the location computed from the FAT32 data area layout.
/// Exposed as a helper for callers that need to write cluster-sized
/// chunks (e.g. when extending the pagefile or performing relocation).
pub fn write_cluster(
    device_id: usize,
    data_start_sector: u64,
    cluster: u32,
    sectors_per_cluster: u32,
    buffer: &[u8],
) -> bool {
    let cluster_size = (sectors_per_cluster * 512) as usize;
    if buffer.len() < cluster_size {
        return false;
    }
    
    let first_sector = data_start_sector + ((cluster as u64 - 2) * sectors_per_cluster as u64);
    
    for i in 0..sectors_per_cluster {
        let offset = (i as usize) * 512;
        let sector_buf = &buffer[offset..offset + 512];
        if !block::write_block(device_id, first_sector + i as u64, sector_buf) {
            return false;
        }
    }
    
    true
}

/// Read from the pagefile at a given offset.
///
pub fn read_pagefile_sectors(
    device_id: usize,
    start_sector: u64,
    offset_sectors: u64,
    count: u32,
    buffer: &mut [u8],
) -> bool {
    let required_size = (count as usize) * 512;
    if buffer.len() < required_size {
        return false;
    }
    
    let start_lba = start_sector + offset_sectors;
    
    for i in 0..count {
        let mut sector_buf = [0u8; 512];
        if !block::read_block(device_id, start_lba + i as u64, &mut sector_buf) {
            return false;
        }
        let offset = (i as usize) * 512;
        buffer[offset..offset + 512].copy_from_slice(&sector_buf);
    }
    
    true
}

/// Write to the pagefile at a given offset.
///
pub fn write_pagefile_sectors(
    device_id: usize,
    start_sector: u64,
    offset_sectors: u64,
    count: u32,
    buffer: &[u8],
) -> bool {
    let required_size = (count as usize) * 512;
    if buffer.len() < required_size {
        return false;
    }
    
    let start_lba = start_sector + offset_sectors;
    
    for i in 0..count {
        let offset = (i as usize) * 512;
        let sector_buf = &buffer[offset..offset + 512];
        if !block::write_block(device_id, start_lba + i as u64, sector_buf) {
            return false;
        }
    }
    
    true
}

/// Check if pagefile exists on the volume.
///
pub fn pagefile_exists(
    fs_start_sector: u64,
    sectors_per_cluster: u32,
    cluster_size: u32,
    fat_start_sector: u64,
    data_start_sector: u64,
    device_id: usize,
) -> Fat32PagefileMeta {
    if let Some(handle) = find_pagefile(
        fs_start_sector,
        sectors_per_cluster,
        cluster_size,
        fat_start_sector,
        data_start_sector,
        device_id,
    ) {
        Fat32PagefileMeta {
            start_cluster: handle.start_cluster,
            size_bytes: handle.size_bytes,
            size_mb: handle.size_bytes / (1024 * 1024),
            exists: true,
            valid: handle.valid,
        }
    } else {
        Fat32PagefileMeta::default()
    }
}

/// Get pagefile statistics.
///
pub fn get_pagefile_stats(device_id: usize, fat_start_sector: u64) -> (u64, u64, u64) {
    let mut total_clusters: u64 = 0;
    let mut free_clusters: u64 = 0;
    let mut cluster: u32 = 2;
    
    loop {
        let entry = match read_fat_entry(device_id, fat_start_sector, cluster) {
            Some(e) => e,
            None => break,
        };
        
        total_clusters += 1;
        
        if entry == 0 {
            free_clusters += 1;
        }
        
        cluster += 1;
        
        // Safety limit
        if cluster > 0x0FFFFFEF {
            break;
        }
    }
    
    (total_clusters, free_clusters, total_clusters - free_clusters)
}
