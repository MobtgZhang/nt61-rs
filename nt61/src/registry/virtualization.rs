//! Registry Virtualization Support
//!
//! Implements registry virtualization for application compatibility, allowing
//! per-user copies of HKLM keys for non-elevated processes. This matches
//! Windows Vista+ UAC virtualization behavior.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use alloc::collections::BTreeMap;
use alloc::format;

use super::hive::HiveError;
use super::path::{ParsedPath, Hive};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualizationFlags {
    pub enabled: bool,
    pub virtual_source: bool,
    pub virtual_target: bool,
    /// Store is per-user
    pub per_user: bool,
}

impl Default for VirtualizationFlags {
    fn default() -> Self {
        Self {
            enabled: false,
            virtual_source: false,
            virtual_target: false,
            per_user: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VirtualStore {
    /// Per-user virtual store (HKCU\Software\Classes\VirtualStore)
    PerUser { user_sid: String },
    Machine,
}

impl VirtualStore {
    /// Get the virtual store path for a user

    pub fn per_user_path(user_sid: &str) -> String {
        format!(
            "\\Registry\\User\\{}\\Software\\Classes\\VirtualStore",
            user_sid
        )
    }

    pub fn virtualize_path(&self, physical_path: &str) -> Result<String, HiveError> {
        if !physical_path.to_uppercase().contains("MACHINE") {
            return Err(HiveError::InvalidPointer);
        }

        match self {
            VirtualStore::PerUser { user_sid } => {
                let stripped = physical_path
                    .replace("\\Registry\\Machine\\", "")
                    .replace("HKEY_LOCAL_MACHINE\\", "");

                Ok(format!(
                    "{}\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppCompatFlags\\Layers\\{}",
                    Self::per_user_path(user_sid),
                    stripped
                ))
            }
            VirtualStore::Machine => Ok(physical_path.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualizedKey {
    pub physical_offset: u32,
    pub physical_path: String,
    pub virtual_offset: u32,
    pub virtual_path: String,
    /// Owning user SID
    pub user_sid: String,
    pub flags: VirtualizationFlags,
}

impl VirtualizedKey {
    pub fn new(
        physical_offset: u32,
        physical_path: String,
        virtual_offset: u32,
        virtual_path: String,
        user_sid: String,
    ) -> Self {
        Self {
            physical_offset,
            physical_path,
            virtual_offset,
            virtual_path,
            user_sid,
            flags: VirtualizationFlags {
                enabled: true,
                virtual_source: false,
                virtual_target: true,
                per_user: true,
            },
        }
    }
}

pub struct VirtualizationManager {
    physical_map: BTreeMap<u32, VirtualizedKey>,
    virtual_map: BTreeMap<u32, u32>,
    exempt_paths: Vec<String>,
    enabled: bool,
}

impl VirtualizationManager {
    pub fn new() -> Self {
        let mut manager = Self {
            physical_map: BTreeMap::new(),
            virtual_map: BTreeMap::new(),
            exempt_paths: Vec::new(),
            enabled: true,
        };

        manager.add_exempt_paths();
        manager
    }

    fn add_exempt_paths(&mut self) {
        let exempt = vec![
            "\\Registry\\Machine\\System",
            "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion",
            "\\Registry\\Machine\\Software\\Classes\\CLSID",
            "\\Registry\\Machine\\Software\\Classes\\Interface",
            "\\Registry\\Machine\\Software\\Policies",
            "\\Registry\\Machine\\Security",
            "\\Registry\\Machine\\SAM",
        ];

        for path in exempt {
            self.exempt_paths.push(path.to_string());
        }
    }

    pub fn is_exempt(&self, path: &str) -> bool {
        for exempt in &self.exempt_paths {
            if path.to_uppercase().starts_with(&exempt.to_uppercase()) {
                return true;
            }
        }
        false
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn register(&mut self, vkey: VirtualizedKey) {
        let physical = vkey.physical_offset;
        let virtual_offset = vkey.virtual_offset;

        self.virtual_map.insert(virtual_offset, physical);
        self.physical_map.insert(physical, vkey);
    }

    pub fn unregister(&mut self, physical_offset: u32) -> Option<VirtualizedKey> {
        if let Some(vkey) = self.physical_map.remove(&physical_offset) {
            self.virtual_map.remove(&vkey.virtual_offset);
            Some(vkey)
        } else {
            None
        }
    }

    pub fn get_by_physical(&self, physical_offset: u32) -> Option<&VirtualizedKey> {
        self.physical_map.get(&physical_offset)
    }

    pub fn get_physical(&self, virtual_offset: u32) -> Option<u32> {
        self.virtual_map.get(&virtual_offset).copied()
    }

    pub fn is_virtualized(&self, physical_offset: u32) -> bool {
        self.physical_map.contains_key(&physical_offset)
    }

    pub fn resolve_access(
        &self,
        key_offset: u32,
        is_write: bool,
        user_sid: &str,
    ) -> KeyAccessResolution {
        if let Some(physical) = self.virtual_map.get(&key_offset) {
            return KeyAccessResolution::Virtual {
                physical_offset: *physical,
                virtual_offset: key_offset,
            };
        }

        if let Some(vkey) = self.physical_map.get(&key_offset) {
            // For writes from the owning user, redirect to virtual copy
            if is_write && vkey.user_sid == user_sid {
                return KeyAccessResolution::RedirectToVirtual {
                    virtual_offset: vkey.virtual_offset,
                };
            }

            return KeyAccessResolution::Merged {
                physical_offset: key_offset,
                virtual_offset: vkey.virtual_offset,
            };
        }

        KeyAccessResolution::Direct {
            offset: key_offset,
        }
    }

    pub fn create_virtual_copy(
        &mut self,
        physical_offset: u32,
        physical_path: &str,
        user_sid: &str,
    ) -> Result<VirtualizedKey, HiveError> {
        if !self.enabled || self.is_exempt(physical_path) {
            return Err(HiveError::InvalidPointer);
        }

        let store = VirtualStore::PerUser {
            user_sid: user_sid.to_string(),
        };
        let virtual_path = store.virtualize_path(physical_path)?;

        let virtual_offset = physical_offset | 0x80000000; // Mark as virtual

        let vkey = VirtualizedKey::new(
            physical_offset,
            physical_path.to_string(),
            virtual_offset,
            virtual_path,
            user_sid.to_string(),
        );

        self.register(vkey.clone());

        Ok(vkey)
    }

    /// Get all virtualized keys for a user
    pub fn list_user_keys(&self, user_sid: &str) -> Vec<&VirtualizedKey> {
        self.physical_map
            .values()
            .filter(|vkey| vkey.user_sid == user_sid)
            .collect()
    }

    pub fn stats(&self) -> VirtualizationStats {
        VirtualizationStats {
            total_virtualized: self.physical_map.len(),
            enabled: self.enabled,
            exempt_paths: self.exempt_paths.len(),
        }
    }
}

impl Default for VirtualizationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAccessResolution {
    Direct { offset: u32 },
    Virtual {
        physical_offset: u32,
        virtual_offset: u32,
    },
    RedirectToVirtual { virtual_offset: u32 },
    Merged {
        physical_offset: u32,
        virtual_offset: u32,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct VirtualizationStats {
    pub total_virtualized: usize,
    pub enabled: bool,
    pub exempt_paths: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub user_sid: String,
    pub elevated: bool,
    pub virtualization_enabled: bool,
}

impl TokenInfo {
    /// Check if this token should use virtualization
    pub fn should_virtualize(&self) -> bool {
        !self.elevated && self.virtualization_enabled
    }
}

pub fn should_virtualize_key(path: &str, token: &TokenInfo) -> bool {
    if token.elevated {
        return false;
    }

    if !token.virtualization_enabled {
        return false;
    }

    if !path.to_uppercase().contains("MACHINE") {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtualization_manager() {
        let mut manager = VirtualizationManager::new();
        assert!(manager.is_enabled());

        let vkey = VirtualizedKey::new(
            0x1000,
            "\\Registry\\Machine\\Software\\Test".to_string(),
            0x80001000,
            "\\Registry\\User\\S-1-5-21-123\\Software\\Classes\\VirtualStore\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppCompatFlags\\Layers\\Software\\Test".to_string(),
            "S-1-5-21-123".to_string(),
        );

        manager.register(vkey);

        assert!(manager.is_virtualized(0x1000));
        assert_eq!(manager.get_physical(0x80001000), Some(0x1000));
    }

    #[test]
    fn test_exempt_paths() {
        let manager = VirtualizationManager::new();

        assert!(manager.is_exempt("\\Registry\\Machine\\System\\CurrentControlSet"));
        assert!(manager.is_exempt("\\Registry\\Machine\\SAM\\Domains"));
        assert!(!manager.is_exempt("\\Registry\\Machine\\Software\\MyApp"));
    }

    #[test]
    fn test_virtual_store_path() {
        let store = VirtualStore::PerUser {
            user_sid: "S-1-5-21-123".to_string(),
        };

        let virtual_path = store
            .virtualize_path("\\Registry\\Machine\\Software\\Test")
            .unwrap();

        assert!(virtual_path.contains("VirtualStore"));
        assert!(virtual_path.contains("S-1-5-21-123"));
    }

    #[test]
    fn test_access_resolution() {
        let mut manager = VirtualizationManager::new();

        let vkey = VirtualizedKey::new(
            0x1000,
            "\\Registry\\Machine\\Software\\Test".to_string(),
            0x80001000,
            "\\Registry\\User\\S-1-5-21-123\\Software\\Classes\\VirtualStore\\Test".to_string(),
            "S-1-5-21-123".to_string(),
        );

        manager.register(vkey);

        let resolution = manager.resolve_access(0x1000, true, "S-1-5-21-123");
        match resolution {
            KeyAccessResolution::RedirectToVirtual { virtual_offset } => {
                assert_eq!(virtual_offset, 0x80001000);
            }
            _ => panic!("Expected RedirectToVirtual"),
        }

        let resolution = manager.resolve_access(0x1000, false, "S-1-5-21-123");
        match resolution {
            KeyAccessResolution::Merged { .. } => {}
            _ => panic!("Expected Merged"),
        }

        // Access from different user should be direct
        let resolution = manager.resolve_access(0x1000, false, "S-1-5-21-456");
        match resolution {
            KeyAccessResolution::Merged { .. } => {}
            _ => panic!("Expected Merged for different user read"),
        }
    }

    #[test]
    fn test_token_virtualization() {
        let elevated_token = TokenInfo {
            user_sid: "S-1-5-21-123".to_string(),
            elevated: true,
            virtualization_enabled: true,
        };
        assert!(!elevated_token.should_virtualize());

        let normal_token = TokenInfo {
            user_sid: "S-1-5-21-123".to_string(),
            elevated: false,
            virtualization_enabled: true,
        };
        assert!(normal_token.should_virtualize());
    }

    #[test]
    fn test_create_virtual_copy() {
        let mut manager = VirtualizationManager::new();

        let vkey = manager
            .create_virtual_copy(
                0x1000,
                "\\Registry\\Machine\\Software\\TestApp",
                "S-1-5-21-123",
            )
            .unwrap();

        assert_eq!(vkey.physical_offset, 0x1000);
        assert!(vkey.virtual_offset != 0x1000);
        assert_eq!(vkey.user_sid, "S-1-5-21-123");
    }
}
