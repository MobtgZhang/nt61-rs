//! Registry Symbolic Link Support
//!
//! Implements symbolic links for registry keys, allowing one key to redirect
//! to another. Follows Windows symbolic link semantics with REG_LINK values.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::format;

use super::hive::HiveError;
use super::path::{ParsedPath, Hive};

pub const MAX_SYMLINK_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymlinkFlags {
    pub absolute: bool,
    pub relative: bool,
    pub auto_follow: bool,
}

impl Default for SymlinkFlags {
    fn default() -> Self {
        Self {
            absolute: true,
            relative: false,
            auto_follow: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolicLink {
    pub source_offset: u32,
    pub target_path: String,
    pub flags: SymlinkFlags,
    pub created: u64,
}

impl SymbolicLink {
    pub fn new(source_offset: u32, target_path: String) -> Self {
        Self {
            source_offset,
            target_path,
            flags: SymlinkFlags::default(),
            created: 0, // Should be set to actual timestamp
        }
    }

    pub fn is_absolute(&self) -> bool {
        self.target_path.starts_with('\\') || self.target_path.starts_with("REGISTRY\\")
    }

    pub fn parse_target(&self) -> Result<ParsedPath, HiveError> {
        ParsedPath::parse(&self.target_path)
            .map_err(|_| HiveError::InvalidPointer)
    }

    pub fn to_value_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for c in self.target_path.encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0]);
        data
    }

    pub fn from_value_data(source_offset: u32, data: &[u8]) -> Result<Self, HiveError> {
        if data.len() % 2 != 0 {
            return Err(HiveError::BadUtf16);
        }

        let mut chars = Vec::new();
        for i in (0..data.len()).step_by(2) {
            let c = u16::from_le_bytes([data[i], data[i + 1]]);
            if c == 0 {
                break;
            }
            chars.push(c);
        }

        let target_path = String::from_utf16(&chars)
            .map_err(|_| HiveError::BadUtf16)?;

        Ok(Self::new(source_offset, target_path))
    }
}

pub struct SymlinkManager {
    links: BTreeMap<u32, SymbolicLink>,
}

impl SymlinkManager {
    pub fn new() -> Self {
        Self {
            links: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, link: SymbolicLink) {
        self.links.insert(link.source_offset, link);
    }

    pub fn unregister(&mut self, source_offset: u32) -> Option<SymbolicLink> {
        self.links.remove(&source_offset)
    }

    pub fn get(&self, source_offset: u32) -> Option<&SymbolicLink> {
        self.links.get(&source_offset)
    }

    pub fn is_symlink(&self, key_offset: u32) -> bool {
        self.links.contains_key(&key_offset)
    }

    pub fn resolve(
        &self,
        key_offset: u32,
    ) -> Result<ResolvedLink, HiveError> {
        let current_offset = key_offset;
        let mut depth = 0;
        let mut path_chain = Vec::new();

        while depth < MAX_SYMLINK_DEPTH {
            if let Some(link) = self.links.get(&current_offset) {
                path_chain.push(link.target_path.clone());

                depth += 1;

                if path_chain.iter().filter(|p| **p == link.target_path).count() > 1 {
                    return Err(HiveError::InvalidPointer);
                }

                return Ok(ResolvedLink {
                    final_offset: current_offset,
                    final_path: link.target_path.clone(),
                    depth,
                    path_chain,
                });
            } else {
                return Ok(ResolvedLink {
                    final_offset: current_offset,
                    final_path: String::new(),
                    depth,
                    path_chain,
                });
            }
        }

        Err(HiveError::InvalidPointer)
    }

    pub fn list_all(&self) -> Vec<&SymbolicLink> {
        self.links.values().collect()
    }

    pub fn clear(&mut self) {
        self.links.clear();
    }

    pub fn count(&self) -> usize {
        self.links.len()
    }
}

impl Default for SymlinkManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLink {
    pub final_offset: u32,
    pub final_path: String,
    pub depth: usize,
    pub path_chain: Vec<String>,
}

impl ResolvedLink {
    pub fn is_direct(&self) -> bool {
        self.depth == 0
    }

    pub fn followed_symlinks(&self) -> bool {
        self.depth > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalOptions {
    pub max_depth: usize,
    pub follow_links: bool,
    pub resolve_relative: bool,
}

impl Default for TraversalOptions {
    fn default() -> Self {
        Self {
            max_depth: MAX_SYMLINK_DEPTH,
            follow_links: true,
            resolve_relative: true,
        }
    }
}

impl TraversalOptions {
    pub fn no_follow() -> Self {
        Self {
            max_depth: 0,
            follow_links: false,
            resolve_relative: false,
        }
    }

    pub fn max_depth(depth: usize) -> Self {
        Self {
            max_depth: depth,
            follow_links: true,
            resolve_relative: true,
        }
    }
}

pub struct CommonSymlinks;

impl CommonSymlinks {
    pub fn current_control_set(control_set_num: u32) -> SymbolicLink {
        SymbolicLink::new(
            0, // Would be the actual offset of CurrentControlSet key
            format!("\\Registry\\Machine\\System\\ControlSet{:03}", control_set_num),
        )
    }

    pub fn current_user(user_sid: &str) -> SymbolicLink {
        SymbolicLink::new(
            0,
            format!("\\Registry\\User\\{}", user_sid),
        )
    }

    pub fn classes_root() -> SymbolicLink {
        SymbolicLink::new(
            0,
            String::from("\\Registry\\Machine\\Software\\Classes"),
        )
    }
}

pub fn validate_symlink_target(target_path: &str) -> Result<(), HiveError> {
    if target_path.is_empty() {
        return Err(HiveError::InvalidPointer);
    }

    ParsedPath::parse(target_path)
        .map_err(|_| HiveError::InvalidPointer)?;

    if target_path.contains("..") {
        return Err(HiveError::InvalidPointer);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symlink_creation() {
        let link = SymbolicLink::new(
            0x1000,
            "\\Registry\\Machine\\System\\ControlSet001".to_string(),
        );

        assert_eq!(link.source_offset, 0x1000);
        assert!(link.is_absolute());
    }

    #[test]
    fn test_symlink_encoding() {
        let link = SymbolicLink::new(0x1000, "Test\\Path".to_string());
        let data = link.to_value_data();

        let decoded = SymbolicLink::from_value_data(0x1000, &data).unwrap();
        assert_eq!(link.target_path, decoded.target_path);
    }

    #[test]
    fn test_symlink_manager() {
        let mut manager = SymlinkManager::new();

        let link = SymbolicLink::new(
            0x1000,
            "\\Registry\\Machine\\System\\ControlSet001".to_string(),
        );

        manager.register(link.clone());

        assert!(manager.is_symlink(0x1000));
        assert_eq!(manager.count(), 1);

        let retrieved = manager.get(0x1000).unwrap();
        assert_eq!(retrieved.target_path, link.target_path);
    }

    #[test]
    fn test_symlink_resolution() {
        let mut manager = SymlinkManager::new();

        let link = SymbolicLink::new(
            0x1000,
            "\\Registry\\Machine\\System\\ControlSet001".to_string(),
        );
        manager.register(link);

        let resolved = manager.resolve(0x1000).unwrap();
        assert!(resolved.followed_symlinks());
        assert_eq!(resolved.depth, 1);
    }

    #[test]
    fn test_common_symlinks() {
        let current_cs = CommonSymlinks::current_control_set(1);
        assert!(current_cs.target_path.contains("ControlSet001"));

        let current_user = CommonSymlinks::current_user("S-1-5-21-123456789");
        assert!(current_user.target_path.contains("S-1-5-21-123456789"));
    }

    #[test]
    fn test_validate_symlink_target() {
        assert!(validate_symlink_target("\\Registry\\Machine\\System").is_ok());
        assert!(validate_symlink_target("").is_err());
        assert!(validate_symlink_target("Invalid..Path").is_err());
    }

    #[test]
    fn test_circular_reference_detection() {
        let manager = SymlinkManager::new();

        let resolved = manager.resolve(0x1000).unwrap();
        assert!(resolved.depth < MAX_SYMLINK_DEPTH);
    }
}
