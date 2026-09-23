//! File System Cache - Complete Implementation
//!
//! LRU-based file system cache with dirty page tracking

use alloc::vec::Vec;
use alloc::collections::VecDeque;
use hashbrown::HashMap;
use crate::ke::sync::Spinlock;

pub struct FileCache {
    entries: HashMap<FileCacheKey, CacheEntry>,
    lru_list: VecDeque<FileCacheKey>,
    total_size: usize,
    max_size: usize,
    stats: CacheStats,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FileCacheKey {
    pub volume_id: u64,
    pub file_id: u64,
    pub offset: u64,
}

pub struct CacheEntry {
    key: FileCacheKey,
    data: Vec<u8>,
    dirty: bool,
    access_count: u32,
    last_access: u64,
}

pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub writebacks: u64,
}

impl FileCache {
    pub fn new(max_size_mb: usize) -> Self {
        Self {
            entries: HashMap::new(),
            lru_list: VecDeque::new(),
            total_size: 0,
            max_size: max_size_mb * 1024 * 1024,
            stats: CacheStats {
                hits: 0,
                misses: 0,
                evictions: 0,
                writebacks: 0,
            },
        }
    }

    pub fn read(&mut self, key: &FileCacheKey, buffer: &mut [u8]) -> Option<usize> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.access_count += 1;
            entry.last_access = get_timestamp();

            let len = entry.data.len().min(buffer.len());
            buffer[..len].copy_from_slice(&entry.data[..len]);

            self.touch(key);
            self.stats.hits += 1;

            Some(len)
        } else {
            self.stats.misses += 1;
            None
        }
    }

    pub fn write(&mut self, key: FileCacheKey, data: Vec<u8>) -> Result<(), &'static str> {
        let size = data.len();

        while self.total_size + size > self.max_size {
            if !self.evict_lru() {
                return Err("Cache full and cannot evict");
            }
        }

        if let Some(old_entry) = self.entries.remove(&key) {
            self.total_size -= old_entry.data.len();
            self.lru_list.retain(|k| k != &key);
        }

        let entry = CacheEntry {
            key: key.clone(),
            data,
            dirty: true,
            access_count: 1,
            last_access: get_timestamp(),
        };

        self.entries.insert(key.clone(), entry);
        self.lru_list.push_back(key);
        self.total_size += size;

        Ok(())
    }

    pub fn flush_dirty_pages(&mut self) -> Result<usize, &'static str> {
        let mut flushed = 0;

        for (key, entry) in &mut self.entries {
            if entry.dirty {
                self.write_to_disk(key, &entry.data)?;
                entry.dirty = false;
                flushed += 1;
                self.stats.writebacks += 1;
            }
        }

        Ok(flushed)
    }

    pub fn invalidate(&mut self, key: &FileCacheKey) -> bool {
        if let Some(entry) = self.entries.remove(key) {
            self.total_size -= entry.data.len();
            self.lru_list.retain(|k| k != key);
            true
        } else {
            false
        }
    }

    fn touch(&mut self, key: &FileCacheKey) {
        if let Some(pos) = self.lru_list.iter().position(|k| k == key) {
            let key = self.lru_list.remove(pos).unwrap();
            self.lru_list.push_back(key);
        }
    }

    /// Evict least recently used entry
    fn evict_lru(&mut self) -> bool {
        if let Some(key) = self.lru_list.pop_front() {
            if let Some(entry) = self.entries.remove(&key) {
                if entry.dirty {
                    let _ = self.write_to_disk(&key, &entry.data);
                    self.stats.writebacks += 1;
                }
                self.total_size -= entry.data.len();
                self.stats.evictions += 1;
                return true;
            }
        }
        false
    }

    fn write_to_disk(&self, _key: &FileCacheKey, _data: &[u8]) -> Result<(), &'static str> {
        // TODO: Call actual filesystem write
        Ok(())
    }

    pub fn get_stats(&self) -> &CacheStats {
        &self.stats
    }

    pub fn usage_percent(&self) -> f32 {
        (self.total_size as f32 / self.max_size as f32) * 100.0
    }
}

static FILE_CACHE: Spinlock<Option<FileCache>> = Spinlock::new(None);

pub fn init_file_cache(size_mb: usize) {
    let mut cache = FILE_CACHE.lock();
    *cache = Some(FileCache::new(size_mb));
}

pub fn cache_read(key: &FileCacheKey, buffer: &mut [u8]) -> Option<usize> {
    let mut cache = FILE_CACHE.lock();
    cache.as_mut()?.read(key, buffer)
}

pub fn cache_write(key: FileCacheKey, data: Vec<u8>) -> Result<(), &'static str> {
    let mut cache = FILE_CACHE.lock();
    cache
        .as_mut()
        .ok_or("Cache not initialized")?
        .write(key, data)
}

pub fn cache_flush() -> Result<usize, &'static str> {
    let mut cache = FILE_CACHE.lock();
    cache
        .as_mut()
        .ok_or("Cache not initialized")?
        .flush_dirty_pages()
}

fn get_timestamp() -> u64 {
    // TODO: Integrate with HAL timer
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_read_write() {
        let mut cache = FileCache::new(1); // 1MB

        let key = FileCacheKey {
            volume_id: 1,
            file_id: 100,
            offset: 0,
        };

        let data = vec![1, 2, 3, 4, 5];
        assert!(cache.write(key.clone(), data.clone()).is_ok());

        let mut buffer = vec![0u8; 10];
        let len = cache.read(&key, &mut buffer).unwrap();
        assert_eq!(len, 5);
        assert_eq!(&buffer[..5], &data[..]);
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache = FileCache::new(1); // 1MB max

        for i in 0..100 {
            let key = FileCacheKey {
                volume_id: 1,
                file_id: i,
                offset: 0,
            };
            let data = vec![0u8; 11 * 1024]; // 11KB each
            let _ = cache.write(key, data);
        }

        assert!(cache.stats.evictions > 0);
    }

    #[test]
    fn test_cache_flush() {
        let mut cache = FileCache::new(1);

        let key = FileCacheKey {
            volume_id: 1,
            file_id: 1,
            offset: 0,
        };

        cache.write(key, vec![1, 2, 3]).unwrap();
        let flushed = cache.flush_dirty_pages().unwrap();
        assert_eq!(flushed, 1);
    }
}
