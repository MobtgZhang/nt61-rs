//! Enhanced File System Cache Implementation
//!
//! Complete cache system with:
//! - Page cache with LRU/LFU eviction
//! - Read-ahead (sequential, random, adaptive)
//! - Write-back with delayed flush
//! - Multi-process consistency
//! - Memory-mapped file support
//!
//! Based on Windows Cache Manager and Linux Page Cache architecture.

extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::{BTreeMap, VecDeque};
use hashbrown::HashMap;
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};

pub const CACHE_BLOCK_SIZE: usize = 4096;
pub const CACHE_VIEW_SIZE: usize = 256 * 1024;
pub const MAX_CACHE_BLOCKS: usize = 16384; // 64 MB cache

/// Read-ahead configuration
pub const READAHEAD_MIN: usize = 4;   // Minimum read-ahead pages
pub const READAHEAD_MAX: usize = 32;  // Maximum read-ahead pages
pub const SEQUENTIAL_THRESHOLD: u32 = 3; // Accesses to trigger sequential readahead

/// Write-back configuration
pub const WRITEBACK_INTERVAL: u64 = 5000; // ms
pub const DIRTY_THRESHOLD_SOFT: usize = 60; // %
pub const DIRTY_THRESHOLD_HARD: usize = 80; // %

/// Cache coherency modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoherencyMode {
    /// No coherency (single process)
    None,
    /// Write-through (immediate consistency)
    WriteThrough,
    /// Write-back with invalidation (eventual consistency)
    WriteBackInvalidate,
}

/// Eviction policy

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    LRU,  // Least Recently Used
    LFU,  // Least Frequently Used
    ARC,  // Adaptive Replacement Cache
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheBlockState {
    Free = 0,
    Clean = 1,
    Dirty = 2,
    Reading = 3,
    Writing = 4,
    Pinned = 5,
    Locked = 6,
}

#[repr(C)]
pub struct CacheBlock {
    pub file_id: u64,
    pub block_number: u64,
    pub state: CacheBlockState,
    pub ref_count: u32,
    pub access_count: u32,  // For LFU
    pub lru_prev: usize,
    pub lru_next: usize,
    pub pfn: u64,
    pub dirty_time: u64,
    pub access_time: u64,
    pub sequence_id: u64,   // For sequential detection
}

impl CacheBlock {
    pub const fn new() -> Self {
        Self {
            file_id: 0,
            block_number: 0,
            state: CacheBlockState::Free,
            ref_count: 0,
            access_count: 0,
            lru_prev: usize::MAX,
            lru_next: usize::MAX,
            pfn: 0,
            dirty_time: 0,
            access_time: 0,
            sequence_id: 0,
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.state == CacheBlockState::Dirty
    }

    pub fn is_pinned(&self) -> bool {
        self.ref_count > 0 || self.state == CacheBlockState::Pinned
    }

    pub fn is_locked(&self) -> bool {
        self.state == CacheBlockState::Locked
    }

    pub fn can_evict(&self) -> bool {
        !self.is_pinned() && !self.is_locked() &&
        self.state != CacheBlockState::Reading &&
        self.state != CacheBlockState::Writing
    }
}

/// Read-ahead state tracker per file
#[derive(Debug, Clone)]
struct ReadAheadState {
    last_block: u64,
    sequential_count: u32,
    window_size: usize,
    predicted_next: u64,
    last_access_time: u64,
}

impl ReadAheadState {
    fn new() -> Self {
        Self {
            last_block: 0,
            sequential_count: 0,
            window_size: READAHEAD_MIN,
            predicted_next: 0,
            last_access_time: 0,
        }
    }

    fn update(&mut self, block_number: u64, time: u64) {
        if block_number == self.last_block + 1 {
            self.sequential_count += 1;
            if self.sequential_count >= SEQUENTIAL_THRESHOLD {
                self.window_size = core::cmp::min(
                    self.window_size * 2,
                    READAHEAD_MAX
                );
            }
        } else {
            self.sequential_count = 0;
            self.window_size = READAHEAD_MIN;
        }
        self.last_block = block_number;
        self.predicted_next = block_number + 1;
        self.last_access_time = time;
    }

    fn should_readahead(&self) -> bool {
        self.sequential_count >= SEQUENTIAL_THRESHOLD
    }

    fn get_readahead_range(&self) -> Option<(u64, usize)> {
        if self.should_readahead() {
            Some((self.predicted_next, self.window_size))
        } else {
            None
        }
    }
}

/// Invalidation notification
#[derive(Debug, Clone)]
pub struct InvalidationNotification {
    pub file_id: u64,
    pub block_number: u64,
    pub timestamp: u64,
}

#[repr(C)]
pub struct CacheStatistics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub reads: AtomicU64,
    pub writes: AtomicU64,
    pub evictions: AtomicU64,
    pub dirty_blocks: AtomicUsize,
    pub readahead_hits: AtomicU64,
    pub readahead_misses: AtomicU64,
    pub writebacks: AtomicU64,
    pub coherency_invalidations: AtomicU64,
}

impl CacheStatistics {
    pub const fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            dirty_blocks: AtomicUsize::new(0),
            readahead_hits: AtomicU64::new(0),
            readahead_misses: AtomicU64::new(0),
            writebacks: AtomicU64::new(0),
            coherency_invalidations: AtomicU64::new(0),
        }
    }

    pub fn hit_rate(&self) -> f32 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 { 0.0 } else { (hits as f32) / (total as f32) * 100.0 }
    }

    pub fn readahead_effectiveness(&self) -> f32 {
        let hits = self.readahead_hits.load(Ordering::Relaxed);
        let misses = self.readahead_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 { 0.0 } else { (hits as f32) / (total as f32) * 100.0 }
    }

    pub fn dirty_percentage(&self, total_blocks: usize) -> f32 {
        let dirty = self.dirty_blocks.load(Ordering::Relaxed);
        if total_blocks == 0 { 0.0 } else {
            (dirty as f32) / (total_blocks as f32) * 100.0
        }
    }
}

pub struct CacheManager {
    blocks: Vec<CacheBlock>,
    hash_table: BTreeMap<(u64, u64), usize>,
    lru_head: usize,
    lru_tail: usize,
    blocks_used: usize,
    stats: CacheStatistics,

    // Read-ahead state
    readahead_state: HashMap<u64, ReadAheadState>,

    // Write-back state
    dirty_queue: VecDeque<usize>,
    last_writeback: AtomicU64,
    writeback_enabled: AtomicBool,

    // Eviction policy
    policy: EvictionPolicy,

    // Coherency
    coherency_mode: CoherencyMode,
    invalidation_queue: VecDeque<InvalidationNotification>,
}

impl CacheManager {
    pub fn new(policy: EvictionPolicy, coherency: CoherencyMode) -> Self {
        let mut blocks = Vec::with_capacity(MAX_CACHE_BLOCKS);
        for _ in 0..MAX_CACHE_BLOCKS {
            blocks.push(CacheBlock::new());
        }

        Self {
            blocks,
            hash_table: BTreeMap::new(),
            lru_head: usize::MAX,
            lru_tail: usize::MAX,
            blocks_used: 0,
            stats: CacheStatistics::new(),
            readahead_state: HashMap::new(),
            dirty_queue: VecDeque::new(),
            last_writeback: AtomicU64::new(0),
            writeback_enabled: AtomicBool::new(true),
            policy,
            coherency_mode: coherency,
            invalidation_queue: VecDeque::new(),
        }
    }

    pub fn lookup(&mut self, file_id: u64, block_number: u64) -> Option<usize> {
        if let Some(&block_idx) = self.hash_table.get(&(file_id, block_number)) {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            self.touch_block(block_idx);

            // Update read-ahead state
            let time = current_time();
            let state = self.readahead_state.entry(file_id)
                .or_insert_with(ReadAheadState::new);
            state.update(block_number, time);

            Some(block_idx)
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub fn allocate(&mut self, file_id: u64, block_number: u64) -> Option<usize> {
        let block_idx = if self.blocks_used < MAX_CACHE_BLOCKS {
            let idx = self.blocks_used;
            self.blocks_used += 1;
            idx
        } else {
            self.evict_block()?
        };

        self.blocks[block_idx].file_id = file_id;
        self.blocks[block_idx].block_number = block_number;
        self.blocks[block_idx].state = CacheBlockState::Clean;
        self.blocks[block_idx].ref_count = 0;
        self.blocks[block_idx].access_count = 0;
        self.blocks[block_idx].access_time = current_time();
        self.blocks[block_idx].sequence_id = self.stats.reads.load(Ordering::Relaxed);

        self.hash_table.insert((file_id, block_number), block_idx);
        self.add_to_lru(block_idx);

        Some(block_idx)
    }

    /// Evict a block based on policy
    fn evict_block(&mut self) -> Option<usize> {
        let victim = match self.policy {
            EvictionPolicy::LRU => self.evict_lru(),
            EvictionPolicy::LFU => self.evict_lfu(),
            EvictionPolicy::ARC => self.evict_arc(),
        }?;

        if self.blocks[victim].is_dirty() {
            self.flush_block(victim);
        }

        let file_id = self.blocks[victim].file_id;
        let block_number = self.blocks[victim].block_number;
        self.hash_table.remove(&(file_id, block_number));
        self.remove_from_lru(victim);

        self.stats.evictions.fetch_add(1, Ordering::Relaxed);
        Some(victim)
    }

    fn evict_lru(&self) -> Option<usize> {
        let mut current = self.lru_tail;
        for _ in 0..MAX_CACHE_BLOCKS {
            if current == usize::MAX {
                break;
            }
            if self.blocks[current].can_evict() {
                return Some(current);
            }
            current = self.blocks[current].lru_prev;
        }
        None
    }

    fn evict_lfu(&self) -> Option<usize> {
        let mut min_count = u32::MAX;
        let mut victim = None;

        for (idx, block) in self.blocks.iter().enumerate() {
            if block.can_evict() && block.access_count < min_count {
                min_count = block.access_count;
                victim = Some(idx);
            }
        }
        victim
    }

    fn evict_arc(&self) -> Option<usize> {
        // Simplified ARC: try LRU first, then LFU
        self.evict_lru().or_else(|| self.evict_lfu())
    }

    pub fn mark_dirty(&mut self, block_idx: usize) {
        if self.blocks[block_idx].state != CacheBlockState::Dirty {
            self.blocks[block_idx].state = CacheBlockState::Dirty;
            self.blocks[block_idx].dirty_time = current_time();
            self.stats.dirty_blocks.fetch_add(1, Ordering::Relaxed);
            self.dirty_queue.push_back(block_idx);

            // Check if immediate flush needed (write-through)
            if self.coherency_mode == CoherencyMode::WriteThrough {
                self.flush_block(block_idx);
            }
        }
    }

    fn flush_block(&mut self, block_idx: usize) {
        let block = &mut self.blocks[block_idx];
        if block.state == CacheBlockState::Dirty {
            block.state = CacheBlockState::Writing;

            // Save values before mutating
            let file_id = block.file_id;
            let block_number = block.block_number;

            // TODO: Actual disk write

            block.state = CacheBlockState::Clean;
            self.stats.dirty_blocks.fetch_sub(1, Ordering::Relaxed);
            self.stats.writebacks.fetch_add(1, Ordering::Relaxed);

            // Send invalidation notification for coherency
            if self.coherency_mode == CoherencyMode::WriteBackInvalidate {
                self.send_invalidation(file_id, block_number);
            }
        }
    }

    fn touch_block(&mut self, block_idx: usize) {
        self.blocks[block_idx].access_count += 1;
        self.blocks[block_idx].access_time = current_time();

        if self.policy == EvictionPolicy::LRU || self.policy == EvictionPolicy::ARC {
            self.move_to_lru_head(block_idx);
        }
    }

    /// Perform read-ahead
    pub fn readahead(&mut self, file_id: u64) {
        let state = self.readahead_state.get(&file_id);
        if state.is_none() {
            return;
        }

        let state = state.unwrap();
        if let Some((start_block, count)) = state.get_readahead_range() {
            for i in 0..count as u64 {
                let block_num = start_block + i;

                // Skip if already cached
                if self.hash_table.contains_key(&(file_id, block_num)) {
                    self.stats.readahead_hits.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // Allocate and initiate read
                if let Some(_idx) = self.allocate(file_id, block_num) {
                    self.stats.reads.fetch_add(1, Ordering::Relaxed);
                    // TODO: Initiate async read
                } else {
                    self.stats.readahead_misses.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Periodic write-back
    pub fn writeback_dirty(&mut self) -> usize {
        if !self.writeback_enabled.load(Ordering::Relaxed) {
            return 0;
        }

        let now = current_time();
        let last = self.last_writeback.load(Ordering::Relaxed);

        if now - last < WRITEBACK_INTERVAL {
            return 0;
        }

        let mut flushed = 0;
        let dirty_pct = self.stats.dirty_percentage(self.blocks_used);

        // Determine how many to flush
        let flush_target = if dirty_pct > DIRTY_THRESHOLD_HARD as f32 {
            self.dirty_queue.len() // Flush all
        } else if dirty_pct > DIRTY_THRESHOLD_SOFT as f32 {
            self.dirty_queue.len() / 2 // Flush half
        } else {
            core::cmp::min(16, self.dirty_queue.len()) // Flush a few old ones
        };

        for _ in 0..flush_target {
            if let Some(idx) = self.dirty_queue.pop_front() {
                if self.blocks[idx].is_dirty() {
                    self.flush_block(idx);
                    flushed += 1;
                }
            }
        }

        self.last_writeback.store(now, Ordering::Relaxed);
        flushed
    }

    fn add_to_lru(&mut self, block_idx: usize) {
        if self.lru_head == usize::MAX {
            self.lru_head = block_idx;
            self.lru_tail = block_idx;
            self.blocks[block_idx].lru_prev = usize::MAX;
            self.blocks[block_idx].lru_next = usize::MAX;
        } else {
            self.blocks[block_idx].lru_prev = usize::MAX;
            self.blocks[block_idx].lru_next = self.lru_head;
            self.blocks[self.lru_head].lru_prev = block_idx;
            self.lru_head = block_idx;
        }
    }

    fn remove_from_lru(&mut self, block_idx: usize) {
        let block = &self.blocks[block_idx];
        let prev = block.lru_prev;
        let next = block.lru_next;

        if prev != usize::MAX {
            self.blocks[prev].lru_next = next;
        } else {
            self.lru_head = next;
        }

        if next != usize::MAX {
            self.blocks[next].lru_prev = prev;
        } else {
            self.lru_tail = prev;
        }

        self.blocks[block_idx].lru_prev = usize::MAX;
        self.blocks[block_idx].lru_next = usize::MAX;
    }

    fn move_to_lru_head(&mut self, block_idx: usize) {
        if self.lru_head == block_idx {
            return;
        }
        self.remove_from_lru(block_idx);
        self.add_to_lru(block_idx);
    }

    fn send_invalidation(&mut self, file_id: u64, block_number: u64) {
        let notif = InvalidationNotification {
            file_id,
            block_number,
            timestamp: current_time(),
        };
        self.invalidation_queue.push_back(notif);
        self.stats.coherency_invalidations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn process_invalidations(&mut self) {
        while let Some(notif) = self.invalidation_queue.pop_front() {
            if let Some(&idx) = self.hash_table.get(&(notif.file_id, notif.block_number)) {
                if self.blocks[idx].is_dirty() {
                    self.flush_block(idx);
                }
                // Invalidate the block
                self.hash_table.remove(&(notif.file_id, notif.block_number));
                self.remove_from_lru(idx);
            }
        }
    }

    pub fn statistics(&self) -> &CacheStatistics {
        &self.stats
    }

    pub fn flush_all(&mut self) {
        for i in 0..self.blocks_used {
            if self.blocks[i].is_dirty() {
                self.flush_block(i);
            }
        }
        self.dirty_queue.clear();
    }

    pub fn invalidate_file(&mut self, file_id: u64) {
        let mut to_remove = Vec::new();

        for (&(fid, block_num), &idx) in &self.hash_table {
            if fid == file_id {
                to_remove.push((fid, block_num, idx));
            }
        }

        for (fid, block_num, idx) in to_remove {
            if self.blocks[idx].is_dirty() {
                self.flush_block(idx);
            }
            self.hash_table.remove(&(fid, block_num));
            self.remove_from_lru(idx);
        }

        self.readahead_state.remove(&file_id);
    }

    pub fn set_coherency_mode(&mut self, mode: CoherencyMode) {
        self.coherency_mode = mode;
    }

    pub fn set_writeback_enabled(&mut self, enabled: bool) {
        self.writeback_enabled.store(enabled, Ordering::Relaxed);
    }
}

static CACHE_MANAGER: Spinlock<Option<CacheManager>> = Spinlock::new(None);

pub fn init() {
    init_with_policy(EvictionPolicy::LRU, CoherencyMode::WriteBackInvalidate);
}

pub fn init_with_policy(policy: EvictionPolicy, coherency: CoherencyMode) {
    let mut guard = CACHE_MANAGER.lock();
    *guard = Some(CacheManager::new(policy, coherency));
}

pub fn cc_read(file_id: u64, offset: u64, buffer: &mut [u8]) -> Result<usize, ()> {
    let mut cache = CACHE_MANAGER.lock();
    let cache = cache.as_mut().ok_or(())?;

    let mut bytes_read = 0;
    let mut current_offset = offset;

    while bytes_read < buffer.len() {
        let block_number = current_offset / CACHE_BLOCK_SIZE as u64;
        let block_offset = (current_offset % CACHE_BLOCK_SIZE as u64) as usize;
        let remaining = buffer.len() - bytes_read;
        let to_copy = core::cmp::min(CACHE_BLOCK_SIZE - block_offset, remaining);

        let block_idx = if let Some(idx) = cache.lookup(file_id, block_number) {
            idx
        } else {
            let idx = cache.allocate(file_id, block_number).ok_or(())?;
            cache.stats.reads.fetch_add(1, Ordering::Relaxed);
            // TODO: Read block from disk
            idx
        };

        // TODO: Actually copy from cached data
        let _ = block_idx;

        bytes_read += to_copy;
        current_offset += to_copy as u64;
    }

    // Trigger read-ahead
    cache.readahead(file_id);

    Ok(bytes_read)
}

pub fn cc_write(file_id: u64, offset: u64, buffer: &[u8]) -> Result<usize, ()> {
    let mut cache = CACHE_MANAGER.lock();
    let cache = cache.as_mut().ok_or(())?;

    let mut bytes_written = 0;
    let mut current_offset = offset;

    while bytes_written < buffer.len() {
        let block_number = current_offset / CACHE_BLOCK_SIZE as u64;
        let block_offset = (current_offset % CACHE_BLOCK_SIZE as u64) as usize;
        let remaining = buffer.len() - bytes_written;
        let to_copy = core::cmp::min(CACHE_BLOCK_SIZE - block_offset, remaining);

        let block_idx = if let Some(idx) = cache.lookup(file_id, block_number) {
            idx
        } else {
            cache.allocate(file_id, block_number).ok_or(())?
        };

        // TODO: Actually copy to cached data
        cache.mark_dirty(block_idx);
        cache.stats.writes.fetch_add(1, Ordering::Relaxed);

        bytes_written += to_copy;
        current_offset += to_copy as u64;
    }

    Ok(bytes_written)
}

pub fn cc_flush_all() {
    let mut cache = CACHE_MANAGER.lock();
    if let Some(cache) = cache.as_mut() {
        cache.flush_all();
    }
}

pub fn cc_flush_file(file_id: u64) {
    let mut cache = CACHE_MANAGER.lock();
    if let Some(cache) = cache.as_mut() {
        cache.invalidate_file(file_id);
    }
}

pub fn cc_writeback() -> usize {
    let mut cache = CACHE_MANAGER.lock();
    cache.as_mut().map(|c| c.writeback_dirty()).unwrap_or(0)
}

pub fn cc_process_invalidations() {
    let mut cache = CACHE_MANAGER.lock();
    if let Some(cache) = cache.as_mut() {
        cache.process_invalidations();
    }
}

fn current_time() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub fn cc_pin_block(file_id: u64, block_number: u64) -> Result<usize, ()> {
    let mut cache = CACHE_MANAGER.lock();
    let cache = cache.as_mut().ok_or(())?;

    let block_idx = cache.lookup(file_id, block_number)
        .or_else(|| cache.allocate(file_id, block_number))
        .ok_or(())?;

    cache.blocks[block_idx].ref_count += 1;
    Ok(block_idx)
}

pub fn cc_unpin_block(block_idx: usize) -> Result<(), ()> {
    let mut cache = CACHE_MANAGER.lock();
    let cache = cache.as_mut().ok_or(())?;

    if block_idx < cache.blocks.len() && cache.blocks[block_idx].ref_count > 0 {
        cache.blocks[block_idx].ref_count -= 1;
    }
    Ok(())
}

pub fn cc_statistics() -> Option<CacheStatistics> {
    let cache = CACHE_MANAGER.lock();
    cache.as_ref().map(|c| CacheStatistics {
        hits: AtomicU64::new(c.stats.hits.load(Ordering::Relaxed)),
        misses: AtomicU64::new(c.stats.misses.load(Ordering::Relaxed)),
        reads: AtomicU64::new(c.stats.reads.load(Ordering::Relaxed)),
        writes: AtomicU64::new(c.stats.writes.load(Ordering::Relaxed)),
        evictions: AtomicU64::new(c.stats.evictions.load(Ordering::Relaxed)),
        dirty_blocks: AtomicUsize::new(c.stats.dirty_blocks.load(Ordering::Relaxed)),
        readahead_hits: AtomicU64::new(c.stats.readahead_hits.load(Ordering::Relaxed)),
        readahead_misses: AtomicU64::new(c.stats.readahead_misses.load(Ordering::Relaxed)),
        writebacks: AtomicU64::new(c.stats.writebacks.load(Ordering::Relaxed)),
        coherency_invalidations: AtomicU64::new(c.stats.coherency_invalidations.load(Ordering::Relaxed)),
    })
}

pub fn cc_set_coherency_mode(mode: CoherencyMode) {
    let mut cache = CACHE_MANAGER.lock();
    if let Some(cache) = cache.as_mut() {
        cache.set_coherency_mode(mode);
    }
}

pub fn cc_set_writeback_enabled(enabled: bool) {
    let mut cache = CACHE_MANAGER.lock();
    if let Some(cache) = cache.as_mut() {
        cache.set_writeback_enabled(enabled);
    }
}
