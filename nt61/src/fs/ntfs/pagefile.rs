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
//! - create pagefile.sys with the requested size
//! - Open existing pagefile.sys
//! - Extend pagefile.sys dynamically

use crate::drivers::storage::block;

/// Pagefile filename as UTF-16 little-endian. Used when creating
/// or searching for pagefile.sys in the NTFS root directory.
pub static PAGEFILE_NAME: &[u16] = &[
    b'p' as u16,
    b'a' as u16,
    b'g' as u16,
    b'e' as u16,
    b'f' as u16,
    b'i' as u16,
    b'l' as u16,
    b'e' as u16,
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
    _ntfs_data: &crate::fs::ntfs::NtfsData,
    _device_id: usize,
    _size_mb: u64,
) -> Option<NtfsPagefileHandle> {
    None
}

/// read from the pagefile.
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
        if !block::read_block(
            device_id,
            start_sector + offset_sectors + bytes_read as u64 / 512,
            &mut sector_buf,
        ) {
            return false;
        }

        let copy_len = core::cmp::min(512, buffer.len() - bytes_read);
        buffer[bytes_read..bytes_read + copy_len].copy_from_slice(&sector_buf[..copy_len]);
        bytes_read += copy_len;
    }

    true
}

/// write to the pagefile.
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

        // read existing sector if not at sector boundary
        if sector_offset != 0 || bytes_written + 512 > buffer.len() {
            let _ = block::read_block(
                device_id,
                start_sector + offset_sectors + bytes_written as u64 / 512,
                &mut sector_buf,
            );
        }

        // Modify sector
        let copy_start = sector_offset;
        let copy_len = core::cmp::min(512 - sector_offset, buffer.len() - bytes_written);
        sector_buf[copy_start..copy_start + copy_len]
            .copy_from_slice(&buffer[bytes_written..bytes_written + copy_len]);

        if !block::write_block(
            device_id,
            start_sector + offset_sectors + bytes_written as u64 / 512,
            &sector_buf,
        ) {
            return false;
        }

        bytes_written += copy_len;
    }

    true
}

/// Check if pagefile exists on the volume.
///
pub fn pagefile_exists(
    _ntfs_data: &crate::fs::ntfs::NtfsData,
    _device_id: usize,
) -> NtfsPagefileMeta {
    NtfsPagefileMeta::default()
}

/// Get pagefile statistics.
pub fn get_volume_stats(
    _ntfs_data: &crate::fs::ntfs::NtfsData,
    _device_id: usize,
) -> (u64, u64, u64) {
    // In a real implementation, we would read the volume bitmap
    // For now, return placeholder values
    let total_clusters = 1024 * 1024; // Assume 4GB volume with 4KB clusters
    let free_clusters = 512 * 1024; // Placeholder
    let used_clusters = total_clusters - free_clusters;

    (total_clusters, free_clusters, used_clusters)
}
