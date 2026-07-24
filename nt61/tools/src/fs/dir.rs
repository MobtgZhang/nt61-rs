//! Directory operations module.
//!
//! Replaces shell `mkdir` command with pure Rust implementation.

use std::fs;
use std::path::Path;
use crate::error::Result;

/// Check if a directory exists.
pub fn dir_exists(path: &Path) -> bool {
    path.is_dir()
}

/// Create a directory and all parent directories (replaces `mkdir -p`).
///
/// # Arguments
/// * `path` - Path to the directory to create
///
/// # Example
/// ```
/// use nt61_tools::fs::dir::create_dir_all;
/// use std::path::Path;
/// create_dir_all(Path::new("/tmp/test/deep/nested/dir")).unwrap();
/// ```
pub fn create_dir_all(path: &Path) -> Result<()> {
    if path.exists() {
        if path.is_dir() {
            return Ok(());
        } else {
            return Err(crate::error::BuildError::InvalidFormat(format!(
                "Path exists but is not a directory: {:?}",
                path
            )));
        }
    }

    fs::create_dir_all(path).map_err(crate::error::BuildError::Io)?;
    Ok(())
}

/// Remove a directory and all its contents (replaces `rm -rf`).
///
/// # Arguments
/// * `path` - Path to the directory to remove
pub fn remove_dir_all(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if !path.is_dir() {
        return Err(crate::error::BuildError::InvalidFormat(format!(
            "Path is not a directory: {:?}",
            path
        )));
    }

    fs::remove_dir_all(path).map_err(crate::error::BuildError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_create_dir_all() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("a/b/c/d");
        assert!(!path.exists());
        create_dir_all(&path).unwrap();
        assert!(path.exists());
        assert!(path.is_dir());
    }

    #[test]
    fn test_dir_exists() {
        let temp = TempDir::new().unwrap();
        assert!(dir_exists(temp.path()));
        assert!(!dir_exists(&PathBuf::from("/nonexistent/path")));
    }
}
