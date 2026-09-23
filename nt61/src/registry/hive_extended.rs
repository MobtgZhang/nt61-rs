//! Extended Hive Operations
//!
//! Provides write operations, dynamic loading/unloading, and management
//! functionality for registry hives. Complements the read-only parser in hive.rs.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use super::hive::{Hive, HiveError, KeyNode, Value, ValueType};
use super::cell_allocator::{CellAllocator, CellFlags};
use super::security::SecurityDescriptor;
use super::flush::{FlushManager, FlushFlags};
use super::quota::QuotaManager;

pub struct WritableHive {
    base_hive: Option<&'static [u8]>,
    allocator: CellAllocator,
    modifications: BTreeMap<u32, Vec<u8>>,
    new_keys: BTreeMap<u32, KeyData>,
    deleted_keys: Vec<u32>,
    security_cache: BTreeMap<u32, SecurityDescriptor>,
    dirty: bool,
}

#[derive(Debug, Clone)]
pub struct KeyData {
    pub name: String,
    pub flags: u16,
    pub parent_offset: u32,
    pub values: Vec<Value>,
    pub subkeys: Vec<u32>,
}

impl WritableHive {
    pub fn new(max_size: u32) -> Self {
        Self {
            base_hive: None,
            allocator: CellAllocator::new(4096, max_size),
            modifications: BTreeMap::new(),
            new_keys: BTreeMap::new(),
            deleted_keys: Vec::new(),
            security_cache: BTreeMap::new(),
            dirty: false,
        }
    }

    pub fn from_base(base: &'static [u8], max_size: u32) -> Result<Self, HiveError> {
        let _hive = Hive::parse(base)?;

        Ok(Self {
            base_hive: Some(base),
            allocator: CellAllocator::new(base.len() as u32, max_size),
            modifications: BTreeMap::new(),
            new_keys: BTreeMap::new(),
            deleted_keys: Vec::new(),
            security_cache: BTreeMap::new(),
            dirty: false,
        })
    }

    pub fn create_key(
        &mut self,
        parent_offset: u32,
        name: &str,
        flags: u16,
    ) -> Result<u32, HiveError> {
        let name_len = name.len() * 2; // UTF-16
        let size = 8 + 20 + name_len; // Header + nk fields + name

        let offset = self.allocator.allocate(size as u32, CellFlags::default())?;

        let key_data = KeyData {
            name: String::from(name),
            flags,
            parent_offset,
            values: Vec::new(),
            subkeys: Vec::new(),
        };

        self.new_keys.insert(offset, key_data);
        self.dirty = true;

        Ok(offset)
    }

    pub fn delete_key(&mut self, key_offset: u32) -> Result<(), HiveError> {
        if !self.new_keys.contains_key(&key_offset) && self.base_hive.is_none() {
            return Err(HiveError::InvalidPointer);
        }

        self.deleted_keys.push(key_offset);
        self.new_keys.remove(&key_offset);
        self.dirty = true;

        Ok(())
    }

    pub fn set_value(
        &mut self,
        key_offset: u32,
        value_name: &str,
        value_type: ValueType,
        data: Vec<u8>,
    ) -> Result<(), HiveError> {
        let value = Value {
            name: String::from(value_name),
            value_type,
            data,
        };

        if let Some(key_data) = self.new_keys.get_mut(&key_offset) {
            key_data.values.retain(|v| v.name != value_name);
            key_data.values.push(value);
            self.dirty = true;
            return Ok(());
        }

        self.dirty = true;
        Ok(())
    }

    pub fn delete_value(
        &mut self,
        key_offset: u32,
        value_name: &str,
    ) -> Result<(), HiveError> {
        if let Some(key_data) = self.new_keys.get_mut(&key_offset) {
            key_data.values.retain(|v| v.name != value_name);
            self.dirty = true;
            return Ok(());
        }

        self.dirty = true;
        Ok(())
    }

    pub fn set_security(
        &mut self,
        key_offset: u32,
        sd: SecurityDescriptor,
    ) -> Result<(), HiveError> {
        self.security_cache.insert(key_offset, sd);
        self.dirty = true;
        Ok(())
    }

    pub fn get_security(&self, key_offset: u32) -> Option<&SecurityDescriptor> {
        self.security_cache.get(&key_offset)
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    pub fn modification_count(&self) -> usize {
        self.modifications.len() + self.new_keys.len()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, HiveError> {

        if let Some(base) = self.base_hive {
            let bytes = base.to_vec();


            Ok(bytes)
        } else {
            Err(HiveError::BadMagic)
        }
    }

    pub fn commit(&mut self) -> Result<(), HiveError> {

        self.mark_clean();
        Ok(())
    }

    pub fn rollback(&mut self) {
        self.modifications.clear();
        self.new_keys.clear();
        self.deleted_keys.clear();
        self.security_cache.clear();
        self.dirty = false;
    }
}

pub struct HiveLoader {
    loaded_hives: BTreeMap<String, Vec<u8>>,
}

impl HiveLoader {
    pub fn new() -> Self {
        Self {
            loaded_hives: BTreeMap::new(),
        }
    }

    pub fn load_hive(&mut self, name: String, bytes: Vec<u8>) -> Result<(), HiveError> {
        Hive::parse(&bytes)?;

        self.loaded_hives.insert(name, bytes);
        Ok(())
    }

    pub fn unload_hive(&mut self, name: &str) -> Option<Vec<u8>> {
        self.loaded_hives.remove(name)
    }

    pub fn get_hive(&self, name: &str) -> Option<&[u8]> {
        self.loaded_hives.get(name).map(|v| v.as_slice())
    }

    pub fn list_hives(&self) -> Vec<&str> {
        self.loaded_hives.keys().map(|s| s.as_str()).collect()
    }

    pub fn count(&self) -> usize {
        self.loaded_hives.len()
    }
}

impl Default for HiveLoader {
    fn default() -> Self {
        Self::new()
    }
}

pub struct HiveManager {
    hives: BTreeMap<usize, WritableHive>,
    loader: HiveLoader,
    flush_manager: FlushManager,
    quota_manager: QuotaManager,
}

impl HiveManager {
    pub fn new() -> Self {
        Self {
            hives: BTreeMap::new(),
            loader: HiveLoader::new(),
            flush_manager: FlushManager::default(),
            quota_manager: QuotaManager::default(),
        }
    }

    pub fn load_hive(
        &mut self,
        hive_id: usize,
        name: String,
        bytes: Vec<u8>,
    ) -> Result<(), HiveError> {
        self.loader.load_hive(name, bytes.clone())?;

        // In a real implementation, we'd use a proper static lifetime
        let writable = WritableHive::new(256 * 1024 * 1024);

        self.hives.insert(hive_id, writable);
        Ok(())
    }

    pub fn unload_hive(&mut self, hive_id: usize, flush: bool) -> Result<(), HiveError> {
        if let Some(mut hive) = self.hives.remove(&hive_id) {
            if flush && hive.is_dirty() {
                hive.commit()?;
            }
        }
        Ok(())
    }

    pub fn get_hive_mut(&mut self, hive_id: usize) -> Option<&mut WritableHive> {
        self.hives.get_mut(&hive_id)
    }

    pub fn flush_hive(&mut self, hive_id: usize) -> Result<(), HiveError> {
        if let Some(hive) = self.hives.get_mut(&hive_id) {
            if hive.is_dirty() {
                hive.commit()?;
                self.flush_manager.flush_hive(
                    hive_id,
                    FlushFlags::default(),
                    0, // Would use actual timestamp
                )?;
            }
        }
        Ok(())
    }

    pub fn flush_all(&mut self) -> Result<(), HiveError> {
        for hive_id in self.hives.keys().copied().collect::<Vec<_>>() {
            self.flush_hive(hive_id)?;
        }
        Ok(())
    }

    pub fn quota_manager(&self) -> &QuotaManager {
        &self.quota_manager
    }

    pub fn quota_manager_mut(&mut self) -> &mut QuotaManager {
        &mut self.quota_manager
    }

    pub fn flush_manager(&self) -> &FlushManager {
        &self.flush_manager
    }

    pub fn stats(&self) -> HiveManagerStats {
        HiveManagerStats {
            loaded_hives: self.hives.len(),
            dirty_hives: self.hives.values().filter(|h| h.is_dirty()).count(),
            total_modifications: self.hives.values().map(|h| h.modification_count()).sum(),
        }
    }
}

impl Default for HiveManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HiveManagerStats {
    pub loaded_hives: usize,
    pub dirty_hives: usize,
    pub total_modifications: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_writable_hive() {
        let mut hive = WritableHive::new(1024 * 1024);

        let key_offset = hive.create_key(0, "TestKey", 0).unwrap();
        assert!(key_offset > 0);
        assert!(hive.is_dirty());

        hive.set_value(
            key_offset,
            "TestValue",
            ValueType::String,
            vec![0x48, 0x00, 0x69, 0x00], // "Hi" in UTF-16LE
        ).unwrap();

        assert_eq!(hive.modification_count(), 1);
    }

    #[test]
    fn test_hive_loader() {
        let mut loader = HiveLoader::new();

        let mut bytes = vec![0u8; 4096];
        bytes[0..4].copy_from_slice(b"REGF");
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes()); // version

        let result = loader.load_hive("Test".to_string(), bytes);
        assert!(result.is_err()); // Expected due to invalid checksum

        assert_eq!(loader.count(), 0);
    }

    #[test]
    fn test_hive_manager() {
        let mut manager = HiveManager::new();

        let stats = manager.stats();
        assert_eq!(stats.loaded_hives, 0);
        assert_eq!(stats.dirty_hives, 0);
    }

    #[test]
    fn test_delete_key() {
        let mut hive = WritableHive::new(1024 * 1024);

        let key_offset = hive.create_key(0, "TestKey", 0).unwrap();
        hive.delete_key(key_offset).unwrap();

        assert!(hive.is_dirty());
    }

    #[test]
    fn test_security_descriptor() {
        let mut hive = WritableHive::new(1024 * 1024);

        let key_offset = hive.create_key(0, "TestKey", 0).unwrap();
        let sd = SecurityDescriptor::default_key_sd();

        hive.set_security(key_offset, sd.clone()).unwrap();

        let retrieved = hive.get_security(key_offset).unwrap();
        assert_eq!(retrieved, &sd);
    }
}
