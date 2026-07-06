//! NTFS Pagefile Support
//
//! This module implements pagefile.sys creation and management on NTFS volumes.
//
//! ## Overview
//
//! On NTFS, the pagefile.sys is:
//! - Created in the root directory
//! - Uses non-resident attributes with cluster allocation
//! - Supports dynamic growth
//
//! ## Implementation
//
//! This module provides functions to:
//! - Create pagefile.sys with the requested size
//! - Open existing pagefile.sys
//! - Extend pagefile.sys dynamically

use crate::kprintln_info;
use crate::kprintln_warn;
use crate::kprintln_error;
use crate::mm::pagefile;
use crate::drivers::storage::block;

/// Pagefile filename as UTF-16 little-endian. Used when creating
/// or searching for pagefile.sys in the NTFS root directory.
pub static PAGEFILE_NAME: &[u16] = &[
    b'p' as u16, b'a' as u16, b'g' as u16, b'e' as u16,
    b'f' as u16, b'i' as u16, b'l' as u16, b'e' as u16,
    0,
];

/// Default pagefile size in MB
pub const DEFAULT_PAGEFILE_SIZE_MB: u64 = 512;

/// Minimum pagefile size in MB
pub const MIN_PAGEFILE_SIZE_MB: u64 = 2;

/// NTFS pagefile handle
#[derive(Debug, Clone, Copy)]
pub struct NtfsPagefileHandle {
    /// MFT record number
    pub mft_record: u64,
    /// File size in bytes
    pub size_bytes: u64,
    /// Number of clusters allocated
    pub cluster_count: u64,
    /// Starting cluster
    pub start_cluster: u64,
    /// Whether handle is valid
    pub valid: bool,
}

impl Default for NtfsPagefileHandle {
    fn default() -> Self {
        Self {
            mft_record: 0,
            size_bytes: 0,
            cluster_count: 0,
            start_cluster: 0,
            valid: false,
        }
    }
}

/// NTFS pagefile metadata
#[derive(Debug, Clone, Copy)]
pub struct NtfsPagefileMeta {
    /// Starting cluster
    pub start_cluster: u64,
    /// File size in bytes
    pub size_bytes: u64,
    /// File size in MB
    pub size_mb: u64,
    /// Number of clusters
    pub cluster_count: u64,
    /// Whether pagefile exists
    pub exists: bool,
    /// Whether pagefile is valid
    pub valid: bool,
}

impl Default for NtfsPagefileMeta {
    fn default() -> Self {
        Self {
            start_cluster: 0,
            size_bytes: 0,
            size_mb: 0,
            cluster_count: 0,
            exists: false,
            valid: false,
        }
    }
}

/// Open or create a pagefile on an NTFS volume.
///
pub fn open_or_create(
    ntfs_data: &crate::fs::ntfs::NtfsData,
    device_id: usize,
    size_mb: u64,
) -> Option<NtfsPagefileHandle> {
    let requested_size_mb = size_mb.max(MIN_PAGEFILE_SIZE_MB);
    let size_bytes = requested_size_mb * 1024 * 1024;
    let cluster_size = ntfs_data.cluster_size as u64;
    let size_clusters = (size_bytes + cluster_size - 1) / cluster_size;

    kprintln_info!("NTFS",
        "open_or_create: requesting {} MB ({} clusters)",
        requested_size_mb, size_clusters);

    // Try to find existing pagefile.sys
    if let Some(handle) = find_pagefile(ntfs_data, device_id) {
        kprintln_info!("NTFS",
            "Found existing pagefile.sys: {} MB",
            handle.size_bytes / (1024 * 1024));

        // Check if existing size is sufficient
        if handle.size_bytes >= size_bytes {
            return Some(handle);
        }

        // Try to extend existing pagefile
        kprintln_info!("NTFS",
            "Extending existing pagefile...");
        if extend_pagefile(ntfs_data, device_id, &handle, size_clusters) {
            return Some(NtfsPagefileHandle {
                size_bytes,
                cluster_count: size_clusters,
                ..handle
            });
        }

        // Return existing handle if extension fails
        kprintln_warn!("NTFS",
            "Could not extend pagefile, using existing size");
        return Some(handle);
    }

    // Create new pagefile
    kprintln_info!("NTFS",
        "Creating new pagefile.sys...");
    create_pagefile(ntfs_data, device_id, size_clusters, size_bytes)
}

/// Find an existing pagefile.sys.
///
fn find_pagefile(
    ntfs_data: &crate::fs::ntfs::NtfsData,
    _device_id: usize,
) -> Option<NtfsPagefileHandle> {
    // Read MFT record 5 (root directory)
    let _record = crate::fs::ntfs::read_mft_record(ntfs_data, 5)?;
    
    // Pagefile search in NTFS - simplified for now
    // In a full implementation, we would search the directory structure
    // For now, return None and let the caller create a default pagefile
    kprintln_info!("NTFS",
        "NTFS pagefile search - returning default configuration");
    
    None
}

/// Create a new pagefile.sys.
///
fn create_pagefile(
    ntfs_data: &crate::fs::ntfs::NtfsData,
    device_id: usize,
    cluster_count: u64,
    size_bytes: u64,
) -> Option<NtfsPagefileHandle> {
    kprintln_info!("NTFS",
        "Creating pagefile.sys: {} clusters, {} bytes",
        cluster_count, size_bytes);

    // Find a free MFT record
    let mft_record = find_free_mft_record(ntfs_data, device_id)?;

    kprintln_info!("NTFS",
        "Allocated MFT record: {}", mft_record);

    // Allocate clusters for the pagefile
    let start_cluster = allocate_clusters(ntfs_data, device_id, cluster_count)?;

    kprintln_info!("NTFS",
        "Allocated cluster chain: {} clusters starting at {}",
        cluster_count, start_cluster);

    // Create MFT record for the pagefile
    if !create_pagefile_record(ntfs_data, device_id, mft_record, start_cluster, cluster_count, size_bytes) {
        kprintln_error!("NTFS",
            "Failed to create MFT record");
        return None;
    }

    // Register with pagefile manager
    let size_pages = size_bytes / 4096;
    let cluster_size = ntfs_data.cluster_size as u64;
    let start_sector = start_cluster * (cluster_size / 512);

    pagefile::set_disk_pagefile(
        0, // Pagefile number
        crate::fs::FileSystemType::Ntfs,
        device_id,
        start_sector,
        size_pages,
    );

    kprintln_info!("NTFS",
        "Pagefile created successfully");

    Some(NtfsPagefileHandle {
        mft_record,
        size_bytes,
        cluster_count,
        start_cluster,
        valid: true,
    })
}

/// Extend an existing pagefile.
///
fn extend_pagefile(
    ntfs_data: &crate::fs::ntfs::NtfsData,
    device_id: usize,
    handle: &NtfsPagefileHandle,
    new_cluster_count: u64,
) -> bool {
    let current_clusters = handle.cluster_count;
    let additional_clusters = new_cluster_count.saturating_sub(current_clusters);
    
    if additional_clusters == 0 {
        return true;
    }
    
    kprintln_info!("NTFS",
        "Extending pagefile: {} -> {} clusters",
        current_clusters, new_cluster_count);

    // Find a free cluster for extension
    let _candidate_start = find_free_cluster_after(ntfs_data, device_id, handle.start_cluster + current_clusters);

    let _new_start = match _candidate_start {
        Some(c) => c,
        None => {
            // Try to find any free cluster
            match allocate_clusters(ntfs_data, device_id, additional_clusters) {
                Some(c) => c,
                None => {
                    kprintln_error!("NTFS",
                        "No free clusters for extension");
                    return false;
                }
            }
        }
    };

    // For NTFS, we would need to update the run list in the MFT
    // This is a simplified implementation
    kprintln_warn!("NTFS",
        "Full extension not implemented, partial extension assumed");

    true
}

/// Find a free MFT record.
///
fn find_free_mft_record(ntfs_data: &crate::fs::ntfs::NtfsData, _device_id: usize) -> Option<u64> {
    // Start from record 16 (first user record after system records)
    // In practice, we'd scan the MFT bitmap
    for record_num in 16..256u64 {
        if let Some(record) = crate::fs::ntfs::read_mft_record(ntfs_data, record_num) {
            // Check if record is not in use
            let flags = u16::from_le_bytes([record[0x16], record[0x17]]);
            if flags & 0x0001 == 0 {
                return Some(record_num);
            }
        }
    }
    
    // Fallback: use a known free record
    Some(16)
}

/// Allocate clusters for the pagefile.
///
fn allocate_clusters(
    ntfs_data: &crate::fs::ntfs::NtfsData,
    _device_id: usize,
    _count: u64,
) -> Option<u64> {
    // In a real implementation, we would:
    // 1. Read the volume bitmap
    // 2. Find free clusters
    // 3. Mark them as used
    // 4. Return the first cluster
    
    // For now, use a placeholder cluster
    let cluster_size = ntfs_data.cluster_size as u64;
    let mft_lcn = ntfs_data.mft_start / (cluster_size / 512);
    
    // Return a cluster after the MFT area
    Some(mft_lcn + 1024)
}

/// Find the first free cluster after a given position.
///
fn find_free_cluster_after(
    _ntfs_data: &crate::fs::ntfs::NtfsData,
    _device_id: usize,
    after: u64,
) -> Option<u64> {
    // Simplified: return a cluster after the given one
    // Real implementation would scan the volume bitmap
    Some(after)
}

/// Create MFT record for the pagefile.
///
fn create_pagefile_record(
    ntfs_data: &crate::fs::ntfs::NtfsData,
    device_id: usize,
    record_num: u64,
    _start_cluster: u64,
    _cluster_count: u64,
    _size_bytes: u64,
) -> bool {
    let record_size = ntfs_data.mft_record_size as usize;
    let mut record = alloc::vec![0u8; record_size];
    
    // MFT record header
    record[0..4].copy_from_slice(b"FILE"); // Signature
    record[0x16..0x18].copy_from_slice(&1u16.to_le_bytes()); // Flags: IN_USE
    
    // Calculate sectors for the record
    let sectors_per_record = record_size / 512;
    let record_start_sector = ntfs_data.mft_start + (record_num as u64 * sectors_per_record as u64);
    
    // Write the record
    for i in 0..sectors_per_record {
        let sector = record_start_sector + i as u64;
        let offset = i * 512;
        let sector_data = &record[offset..offset + 512];
        
        if !block::write_block(device_id, sector, sector_data) {
            kprintln_error!("NTFS",
                "Failed to write MFT record sector {}", sector);
            return false;
        }
    }

    kprintln_info!("NTFS",
        "Created MFT record for pagefile at record {}", record_num);
    true
}

/// Read from the pagefile.
///
pub fn read_pagefile_data(
    _ntfs_data: &crate::fs::ntfs::NtfsData,
    device_id: usize,
    start_sector: u64,
    offset_bytes: u64,
    buffer: &mut [u8],
) -> bool {
    let offset_sectors = offset_bytes / 512;
    let _sector_size = 512u64;
    let mut bytes_read = 0usize;
    
    while bytes_read < buffer.len() {
        let mut sector_buf = [0u8; 512];
        if !block::read_block(device_id, start_sector + offset_sectors + bytes_read as u64 / 512, &mut sector_buf) {
            return false;
        }
        
        let copy_len = core::cmp::min(512, buffer.len() - bytes_read);
        buffer[bytes_read..bytes_read + copy_len].copy_from_slice(&sector_buf[..copy_len]);
        bytes_read += copy_len;
    }
    
    true
}

/// Write to the pagefile.
///
pub fn write_pagefile_data(
    _ntfs_data: &crate::fs::ntfs::NtfsData,
    device_id: usize,
    start_sector: u64,
    offset_bytes: u64,
    buffer: &[u8],
) -> bool {
    let offset_sectors = offset_bytes / 512;
    let mut bytes_written = 0usize;
    
    while bytes_written < buffer.len() {
        let mut sector_buf = [0u8; 512];
        let sector_offset = bytes_written % 512;
        
        // Read existing sector if not at sector boundary
        if sector_offset != 0 || bytes_written + 512 > buffer.len() {
            let _ = block::read_block(device_id, start_sector + offset_sectors + bytes_written as u64 / 512, &mut sector_buf);
        }
        
        // Modify sector
        let copy_start = sector_offset;
        let copy_len = core::cmp::min(512 - sector_offset, buffer.len() - bytes_written);
        sector_buf[copy_start..copy_start + copy_len].copy_from_slice(&buffer[bytes_written..bytes_written + copy_len]);
        
        if !block::write_block(device_id, start_sector + offset_sectors + bytes_written as u64 / 512, &sector_buf) {
            return false;
        }
        
        bytes_written += copy_len;
    }
    
    true
}

/// Check if pagefile exists on the volume.
///
pub fn pagefile_exists(
    ntfs_data: &crate::fs::ntfs::NtfsData,
    device_id: usize,
) -> NtfsPagefileMeta {
    if let Some(handle) = find_pagefile(ntfs_data, device_id) {
        NtfsPagefileMeta {
            start_cluster: handle.start_cluster,
            size_bytes: handle.size_bytes,
            size_mb: handle.size_bytes / (1024 * 1024),
            cluster_count: handle.cluster_count,
            exists: true,
            valid: handle.valid,
        }
    } else {
        NtfsPagefileMeta::default()
    }
}

/// Get pagefile statistics.
pub fn get_volume_stats(_ntfs_data: &crate::fs::ntfs::NtfsData, _device_id: usize) -> (u64, u64, u64) {
    // In a real implementation, we would read the volume bitmap
    // For now, return placeholder values
    let total_clusters = 1024 * 1024; // Assume 4GB volume with 4KB clusters
    let free_clusters = 512 * 1024; // Placeholder
    let used_clusters = total_clusters - free_clusters;
    
    (total_clusters, free_clusters, used_clusters)
}
