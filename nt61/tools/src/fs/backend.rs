//! Unified filesystem backend trait.
//!
//! Every filesystem we support (FAT32, NTFS, EXT4, ISO9660) is wrapped in a
//! `Box<dyn FsBackend>` by [`OpenedImage`](crate::fs::image::OpenedImage). The
//! CLI then dispatches `--cp`, `--mkdir`, `--rm`, `--directory` against this
//! trait instead of having to know which filesystem is in the partition.

use crate::error::Result;

/// One directory entry returned by [`FsBackend::list_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// File/dir name (no path components).
    pub name: String,
    /// True if this is a directory, false for a regular file.
    pub is_dir: bool,
    /// File size in bytes (0 for directories).
    pub size: u64,
}

impl DirEntry {
    pub fn file(name: impl Into<String>, size: u64) -> Self {
        Self { name: name.into(), is_dir: false, size }
    }
    pub fn dir(name: impl Into<String>) -> Self {
        Self { name: name.into(), is_dir: true, size: 0 }
    }
}

/// Common interface implemented by every filesystem backend.
///
/// All path arguments are forward-slash POSIX style (`a/b/c`) and are
/// case-sensitive (callers should normalize). A bare empty string or `"/"`
/// refers to the root directory.
pub trait FsBackend {
    /// Returns a short string identifier ("fat32", "ntfs", "ext4", "iso9660")
    /// for logging/diagnostics.
    fn kind(&self) -> &'static str;

    /// Enumerate the immediate children of `path`. Returns Err if the path
    /// does not exist or is not a directory.
    fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>>;

    /// Read the full contents of the file at `path`.
    fn read_file(&self, path: &str) -> Result<Vec<u8>>;

    /// Write `data` to `path`, creating parent directories as needed. If the
    /// path already exists as a file, it is overwritten.
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<()>;

    /// Create the directory at `path` (and any missing parents, a la `mkdir -p`).
    fn mkdir(&mut self, path: &str) -> Result<()>;

    /// Remove a file or directory (recursive for directories, a la `rm -rf`).
    /// Missing paths are not an error.
    fn remove(&mut self, path: &str) -> Result<()>;

    /// Encode the current in-memory state back to a complete image byte buffer.
    /// The returned buffer must be exactly `partition_size` bytes (the caller
    /// will pad or truncate as needed).
    fn finalize(&mut self) -> Result<Vec<u8>>;

    /// Downcast helper used by legacy API surfaces that need a concrete type
    /// (e.g. `OpenedImage::fs() -> &mut Fat32Image`). Default returns `None` so
    /// the downcast fails on non-matching types.
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        None
    }
}
