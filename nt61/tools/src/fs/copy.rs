//! File copy operations module.
//!
//! Replaces shell `cp` and `cp -r` commands with pure Rust implementation.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use crate::error::{BuildError, Result};

/// Copy a single file from source to destination.
///
/// # Arguments
/// * `src` - Source file path
/// * `dst` - Destination file path
///
/// # Returns
/// Number of bytes copied
pub fn copy_file(src: &Path, dst: &Path) -> Result<u64> {
    if !src.exists() {
        return Err(BuildError::MissingFile(src.display().to_string()));
    }

    if !src.is_file() {
        return Err(BuildError::InvalidFormat(format!(
            "Source is not a file: {:?}",
            src
        )));
    }

    // Ensure parent directory exists
    if let Some(parent) = dst.parent() {
        super::dir::create_dir_all(parent)?;
    }

    let mut src_file = fs::File::open(src)
        .map_err(|e| BuildError::Io(e))?;
    
    let mut dst_file = fs::File::create(dst)
        .map_err(|e| BuildError::Io(e))?;

    let mut buffer = [0u8; 8192];
    let mut total: u64 = 0;

    loop {
        let bytes_read = src_file.read(&mut buffer)
            .map_err(|e| BuildError::Io(e))?;
        
        if bytes_read == 0 {
            break;
        }

        dst_file.write_all(&buffer[..bytes_read])
            .map_err(|e| BuildError::Io(e))?;
        
        total += bytes_read as u64;
    }

    // Copy permissions (if possible)
    if let Ok(metadata) = src.metadata() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mut perms) = dst.metadata().map(|m| m.permissions()) {
                perms.set_mode(metadata.permissions().mode());
                let _ = fs::set_permissions(dst, perms);
            }
        }
    }

    Ok(total)
}

/// Recursively copy a directory and all its contents.
///
/// # Arguments
/// * `src` - Source directory path
/// * `dst` - Destination directory path
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !src.exists() {
        return Err(BuildError::MissingFile(src.display().to_string()));
    }

    if !src.is_dir() {
        return Err(BuildError::InvalidFormat(format!(
            "Source is not a directory: {:?}",
            src
        )));
    }

    // Create destination directory
    super::dir::create_dir_all(dst)?;

    // Read source directory entries
    for entry in fs::read_dir(src).map_err(|e| BuildError::Io(e))? {
        let entry = entry.map_err(|e| BuildError::Io(e))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            copy_file(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

/// Copy files from a source directory to a destination directory,
/// flattening the structure (files only, no recursion into subdirectories).
///
/// # Arguments
/// * `src` - Source directory path
/// * `dst` - Destination directory path
pub fn copy_files_from_dir(src: &Path, dst: &Path) -> Result<usize> {
    if !src.exists() || !src.is_dir() {
        return Err(BuildError::InvalidFormat(format!(
            "Source is not a directory: {:?}",
            src
        )));
    }

    super::dir::create_dir_all(dst)?;

    let mut count = 0;
    for entry in fs::read_dir(src).map_err(|e| BuildError::Io(e))? {
        let entry = entry.map_err(|e| BuildError::Io(e))?;
        let src_path = entry.path();

        if src_path.is_file() {
            let dst_path = dst.join(entry.file_name());
            copy_file(&src_path, &dst_path)?;
            count += 1;
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, TempPath};

    #[test]
    fn test_copy_file() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("source.txt");
        let dst = temp.path().join("dest.txt");

        fs::write(&src, b"Hello, World!").unwrap();
        let bytes = copy_file(&src, &dst).unwrap();
        
        assert_eq!(bytes, 13);
        assert_eq!(fs::read(&dst).unwrap(), b"Hello, World!");
    }

    #[test]
    fn test_copy_dir_recursive() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        let dst = temp.path().join("dst");

        fs::create_dir_all(&src.join("a/b")).unwrap();
        fs::write(src.join("a/file1.txt"), b"file1").unwrap();
        fs::write(src.join("a/b/file2.txt"), b"file2").unwrap();

        copy_dir_recursive(&src, &dst).unwrap();

        assert!(dst.join("a/file1.txt").exists());
        assert!(dst.join("a/b/file2.txt").exists());
    }
}
