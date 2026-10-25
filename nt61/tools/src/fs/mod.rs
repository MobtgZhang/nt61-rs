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
