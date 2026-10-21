//! Shared utilities for nt61-tools.
//!
//! This library provides utilities for building NT6.1.7601 disk images,
//! including support for FAT32, EXT4, NTFS, ISO9660, and QCOW2 formats.

pub mod error;
pub mod fs;
pub mod hive_gen;
pub mod logger;
pub mod regf;

// Re-export commonly used types
pub use error::{BuildError, Result};
pub use fs::{
    copy_dir_recursive, copy_file, create_dir_all, remove_dir_all, Ext4Image, Fat32Image,
    ImageFormat, IsoImage, NtfsImage, Qcow2Image,
};

// Re-export build functions
pub use fs::build::{build_boot, build_kernel, build_winload, full_build};

// Conditional kernel support
#[cfg(feature = "with-nt61")]
pub use nt61;
