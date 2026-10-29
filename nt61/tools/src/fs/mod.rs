//! Filesystem and Image Operations Module
//!
//! This module provides pure Rust implementations for:
//! - **Image Formats**: FAT32, EXT4, NTFS, ISO9660, QCOW2
//! - **Directory Operations**: mkdir, mdir (替代 mtools)
//! - **File Operations**: copy, remove
//! - **Build Operations**: Full build pipeline
//!
//! All these operations replace shell commands like `mkfs.fat`, `mcopy`, `mmd`, `cp`, and `mkdir`.

pub mod backend;
pub mod build;
pub mod copy;
pub mod dir;
pub mod esp;
pub mod ext4;
pub mod fat32;
pub mod image;
pub mod iso9660;
pub mod ntfs;
pub mod partition;
pub mod qcow2;
pub mod remove;
pub mod stubs;
pub mod system;

use std::sync::atomic::{AtomicU64, Ordering};

/// Generate a locally unique RFC 4122 version 4-shaped GUID without
/// pulling a random-number backend into the freestanding UEFI check.
pub fn new_guid_v4() -> uuid::Uuid {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or_else(|_| std::process::id() as u64);
    let mut state = nanos ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15);
    let mut bytes = [0u8; 16];
    for value in bytes.chunks_exact_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        value.copy_from_slice(&state.to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

// Re-exports for convenience
pub use backend::{DirEntry, FsBackend};
pub use copy::{copy_dir_recursive, copy_file, copy_files_from_dir};
pub use dir::{create_dir_all, dir_exists, remove_dir_all};
pub use remove::{remove_dir, remove_file, remove_matching, remove_path};

// Re-export image types
pub use ext4::Ext4Image;
pub use fat32::Fat32Image;
pub use image::{list_partitions, open_for_modify, ImageFormat, OpenedImage};
pub use iso9660::IsoImage;
pub use ntfs::NtfsImage;
pub use partition::PartitionInfo;
pub use qcow2::Qcow2Image;

// Re-export error types
pub use crate::error::{BuildError, Result};
