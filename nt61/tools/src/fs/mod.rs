//! Filesystem and Image Operations Module
//!
//! This module provides pure Rust implementations for:
//! - **Image Formats**: FAT32, EXT4, NTFS, ISO9660, QCOW2
//! - **Directory Operations**: mkdir, mdir (替代 mtools)
//! - **File Operations**: copy, remove
//! - **Build Operations**: Full build pipeline
//!
//! All these operations replace shell commands like `mkfs.fat`, `mcopy`, `mmd`, `cp`, and `mkdir`.

pub mod dir;
pub mod copy;
pub mod remove;
pub mod fat32;
pub mod ext4;
pub mod ntfs;
pub mod iso9660;
pub mod qcow2;
pub mod image;
pub mod esp;
pub mod system;
pub mod build;
pub mod partition;
pub mod backend;
pub mod stubs;

// Re-exports for convenience
pub use dir::{create_dir_all, remove_dir_all, dir_exists};
pub use copy::{copy_file, copy_dir_recursive, copy_files_from_dir};
pub use remove::{remove_file, remove_dir, remove_path, remove_matching};
pub use backend::{FsBackend, DirEntry};

// Re-export image types
pub use fat32::Fat32Image;
pub use ext4::Ext4Image;
pub use ntfs::NtfsImage;
pub use iso9660::IsoImage;
pub use qcow2::Qcow2Image;
pub use image::{ImageFormat, OpenedImage, open_for_modify, list_partitions};
pub use partition::PartitionInfo;

// Re-export error types
pub use crate::error::{BuildError, Result};
