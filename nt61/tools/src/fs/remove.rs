//! File and directory removal operations module.
//!
//! Replaces shell `rm` and `rm -r` commands with pure Rust implementation.

use std::fs;
use std::path::Path;
use crate::error::{BuildError, Result};

/// Remove a file.
///
/// # Arguments
/// * `path` - Path to the file to remove
pub fn remove_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if !path.is_file() {
        return Err(BuildError::InvalidFormat(format!(
            "Path is not a file: {:?}",
            path
        )));
    }

    fs::remove_file(path).map_err(|e| BuildError::Io(e))?;
    Ok(())
}

/// Remove an empty directory.
///
/// # Arguments
/// * `path` - Path to the directory to remove
pub fn remove_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if !path.is_dir() {
        return Err(BuildError::InvalidFormat(format!(
            "Path is not a directory: {:?}",
            path
        )));
    }

    fs::remove_dir(path).map_err(|e| BuildError::Io(e))?;
    Ok(())
}

/// Remove a file or directory recursively (replaces `rm -rf`).
///
/// # Arguments
/// * `path` - Path to remove
pub fn remove_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if path.is_dir() {
        fs::remove_dir_all(path).map_err(|e| BuildError::Io(e))?;
    } else {
        fs::remove_file(path).map_err(|e| BuildError::Io(e))?;
    }

    Ok(())
}

/// Remove all files matching a pattern from a directory.
///
/// # Arguments
/// * `dir` - Directory to search
/// * `pattern` - Extension to match (e.g., ".tmp")
pub fn remove_matching(dir: &Path, extension: &str) -> Result<usize> {
    if !dir.exists() || !dir.is_dir() {
        return Err(BuildError::InvalidFormat(format!(
            "Not a directory: {:?}",
            dir
        )));
    }

    let mut count = 0;
    for entry in fs::read_dir(dir).map_err(|e| BuildError::Io(e))? {
        let entry = entry.map_err(|e| BuildError::Io(e))?;
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == extension {
                    fs::remove_file(&path).map_err(|e| BuildError::Io(e))?;
                    count += 1;
                }
            }
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_remove_file() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("test.txt");
        fs::write(&file, b"test").unwrap();
        assert!(file.exists());
        
        remove_file(&file).unwrap();
        assert!(!file.exists());
    }

    #[test]
    fn test_remove_path() {
        let temp = TempDir::new().unwrap();
        
        // Test removing file
        let file = temp.path().join("file.txt");
        fs::write(&file, b"test").unwrap();
        remove_path(&file).unwrap();
        assert!(!file.exists());

        // Test removing directory
        let dir = temp.path().join("dir");
        fs::create_dir_all(&dir).unwrap();
        remove_path(&dir).unwrap();
        assert!(!dir.exists());
    }
}
