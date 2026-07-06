//! Unified error types for build_tool.
//!
//! This module provides a comprehensive error handling system for the NT6.1.7601
//! build tools, replacing scattered I/O errors with typed, descriptive errors.

use std::fmt;
use std::io;

/// Unified error type for all build tool operations.
#[derive(Debug)]
pub enum BuildError {
    /// I/O error from std::io
    Io(io::Error),
    /// File or directory not found
    MissingFile(String),
    /// Invalid file format
    InvalidFormat(String),
    /// Image creation failed
    ImageCreateFailed(String),
    /// FAT32-specific error
    Fat32Error(String),
    /// EXT4-specific error
    Ext4Error(String),
    /// NTFS-specific error
    NtfsError(String),
    /// ISO9660-specific error
    IsoError(String),
    /// QCOW2-specific error
    Qcow2Error(String),
    /// Partition error
    PartitionError(String),
    /// Registry hive error
    HiveError(String),
    /// PE file error
    PeError(String),
    /// CRC checksum mismatch
    CrcError { expected: u32, found: u32 },
    /// Invalid parameter
    InvalidParam(String),
    /// Out of space
    OutOfSpace { requested: u64, available: u64 },
    /// Feature not implemented
    NotImplemented(String),
    /// ReFS read-modify-write not supported (per user request)
    ReFsNotImplemented,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Io(e) => write!(f, "I/O error: {}", e),
            BuildError::MissingFile(path) => write!(f, "File not found: {}", path),
            BuildError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            BuildError::ImageCreateFailed(msg) => write!(f, "Image creation failed: {}", msg),
            BuildError::Fat32Error(msg) => write!(f, "FAT32 error: {}", msg),
            BuildError::Ext4Error(msg) => write!(f, "EXT4 error: {}", msg),
            BuildError::NtfsError(msg) => write!(f, "NTFS error: {}", msg),
            BuildError::IsoError(msg) => write!(f, "ISO error: {}", msg),
            BuildError::Qcow2Error(msg) => write!(f, "QCOW2 error: {}", msg),
            BuildError::PartitionError(msg) => write!(f, "Partition error: {}", msg),
            BuildError::HiveError(msg) => write!(f, "Registry hive error: {}", msg),
            BuildError::PeError(msg) => write!(f, "PE file error: {}", msg),
            BuildError::CrcError { expected, found } => {
                write!(f, "CRC mismatch: expected 0x{:08X}, found 0x{:08X}", expected, found)
            }
            BuildError::InvalidParam(msg) => write!(f, "Invalid parameter: {}", msg),
            BuildError::OutOfSpace { requested, available } => {
                write!(f, "Out of space: requested {} bytes, {} available", requested, available)
            }
            BuildError::NotImplemented(feature) => {
                write!(f, "Feature not implemented: {}", feature)
            }
            BuildError::ReFsNotImplemented => {
                write!(
                    f,
                    "ReFS read-modify-write is not supported by build-tool. \
                     ReFS support is excluded by design."
                )
            }
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BuildError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BuildError {
    fn from(err: io::Error) -> Self {
        BuildError::Io(err)
    }
}

/// Result type alias for build tool operations.
pub type Result<T> = std::result::Result<T, BuildError>;

/// Helper function to convert an optional error message to a BuildError.
#[allow(dead_code)]
pub fn invalid_format(msg: impl Into<String>) -> BuildError {
    BuildError::InvalidFormat(msg.into())
}

/// Helper function to create a missing file error.
#[allow(dead_code)]
pub fn missing_file(path: impl Into<String>) -> BuildError {
    BuildError::MissingFile(path.into())
}

/// Helper function to create an image creation error.
#[allow(dead_code)]
pub fn image_failed(msg: impl Into<String>) -> BuildError {
    BuildError::ImageCreateFailed(msg.into())
}
