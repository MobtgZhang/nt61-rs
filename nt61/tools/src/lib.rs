//! Shared utilities for nt61-tools.
//!
//! This library provides utilities for building NT6.1.7601 disk images,
//! including support for FAT32, EXT4, NTFS, ISO9660, and QCOW2 formats.

pub mod regf;
pub mod hive_gen;
pub mod error;
pub mod logger;
pub mod fs;

// Re-export commonly used types
pub use error::{BuildError, Result};
pub use fs::{
    Fat32Image, Ext4Image, NtfsImage, IsoImage, Qcow2Image,
    ImageFormat,
    create_dir_all, remove_dir_all, copy_file, copy_dir_recursive,
};

// Re-export build functions
pub use fs::build::{full_build, build_kernel, build_boot, build_winload};

// Conditional kernel support
#[cfg(feature = "with-nt61")]
pub use nt61;
