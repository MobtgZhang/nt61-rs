//! Cache Manager Subsystem
//!
//! High-level cache management layer for file system operations.
//! Implements Windows-style Cache Manager (Cc) functionality.
//!
//! Features:
//! - Unified buffer cache with read-ahead
//! - Lazy writer (background flush)
//! - Cache coherency and consistency
//! - Pinned and mapped cache views
//! - Write-through and write-back modes

use alloc::vec::Vec;
use alloc::collections::VecDeque;
use hashbrown::HashMap;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use crate::ke::sync::Spinlock;
use crate::mm::page_cache::{PageKey, EvictionPolicy};

/// View size for cache mapping (256 KB)
pub const CACHE_VIEW_SIZE: usize = 256 * 1024;

/// Buffer size (4 KB)
pub const BUFFER_SIZE: usize = 4096;

/// Maximum buffers in pool
pub const MAX_BUFFERS: usize = 8192; // 32 MB

/// Lazy writer flush interval (milliseconds)
pub const LAZY_WRITER_INTERVAL: u64 = 1000;

/// Dirty page threshold for forced flush (percentage)
pub const DIRTY_THRESHOLD: usize = 80;

/// Write mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Write-through: immediate disk write
    WriteThrough,
    /// Write-back: delayed disk write
    WriteBack,
}

/// Buffer state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BufferState {
    Free = 0,
    Clean = 1,
    Dirty = 2,
    Locked = 3,
    IoInProgress = 4,
}

/// Cache buffer
#[derive(Debug)]
pub struct CacheBuffer {
    /// Buffer ID
    pub id: usize,
    /// File identifier

    pub file_id: u64,
    /// Offset in file
    pub offset: u64,
    /// Buffer size
    pub size: usize,
    /// Current state
    pub state: BufferState,
    /// Reference count
    pub ref_count: u32,
    /// Physical frame number
    pub pfn: u64,
    /// Dirty timestamp
    pub dirty_time: u64,
    /// Last access timestamp
    pub last_access: u64,
}

impl CacheBuffer {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            file_id: 0,
            offset: 0,
            size: BUFFER_SIZE,
            state: BufferState::Free,
            ref_count: 0,
            pfn: 0,
            dirty_time: 0,
            last_access: 0,
        }
    }

    pub fn is_free(&self) -> bool {
        self.state == BufferState::Free
    }

    pub fn is_dirty(&self) -> bool {
        self.state == BufferState::Dirty
    }

    pub fn is_locked(&self) -> bool {
        self.ref_count > 0 || self.state == BufferState::Locked
    }

    pub fn can_evict(&self) -> bool {
        !self.is_locked() && self.state != BufferState::IoInProgress
    }
}

/// Buffer pool for cache management
pub struct BufferPool {
    /// All buffers
    buffers: Vec<CacheBuffer>,
    /// Free buffer queue
    free_list: VecDeque<usize>,
    /// Dirty buffer list
    dirty_list: Vec<usize>,
    /// Buffer lookup map
    buffer_map: HashMap<(u64, u64), usize>,
    /// Statistics
    allocations: AtomicU64,
    deallocations: AtomicU64,
}

impl BufferPool {
    pub fn new() -> Self {
        let mut buffers = Vec::new();
        let mut free_list = VecDeque::new();

        for i in 0..MAX_BUFFERS {
            buffers.push(CacheBuffer::new(i));
            free_list.push_back(i);
        }

        Self {
            buffers,
            free_list,
            dirty_list: Vec::new(),
            buffer_map: HashMap::new(),
            allocations: AtomicU64::new(0),
            deallocations: AtomicU64::new(0),
        }
    }

    /// Allocate a buffer
    pub fn allocate(&mut self, file_id: u64, offset: u64) -> Result<usize, &'static str> {
        // Check if already allocated
        if let Some(&id) = self.buffer_map.get(&(file_id, offset)) {
            self.buffers[id].ref_count += 1;
            self.buffers[id].last_access = get_timestamp();
            return Ok(id);
        }

        // Get free buffer
        let id = self.free_list.pop_front()
            .ok_or("No free buffers available")?;

        // Initialize buffer
        self.buffers[id].file_id = file_id;
        self.buffers[id].offset = offset;
        self.buffers[id].state = BufferState::Clean;
        self.buffers[id].ref_count = 1;
        self.buffers[id].last_access = get_timestamp();

        self.buffer_map.insert((file_id, offset), id);
        self.allocations.fetch_add(1, Ordering::Relaxed);

        Ok(id)
    }

    /// Release a buffer
    pub fn release(&mut self, id: usize) -> Result<(), &'static str> {
        if id >= self.buffers.len() {
            return Err("Invalid buffer ID");
        }

        if self.buffers[id].ref_count > 0 {
            self.buffers[id].ref_count -= 1;
        }

        if self.buffers[id].ref_count == 0 && self.buffers[id].state == BufferState::Clean {
            self.free_buffer(id);
        }

        Ok(())
    }

    /// Mark buffer as dirty
    pub fn mark_dirty(&mut self, id: usize) {
        if id >= self.buffers.len() {
            return;
        }

        if self.buffers[id].state != BufferState::Dirty {
            self.buffers[id].state = BufferState::Dirty;
            self.buffers[id].dirty_time = get_timestamp();
            self.dirty_list.push(id);
        }
    }

    /// Free a buffer
    fn free_buffer(&mut self, id: usize) {
        let file_id = self.buffers[id].file_id;
        let offset = self.buffers[id].offset;

        self.buffer_map.remove(&(file_id, offset));
        self.buffers[id].state = BufferState::Free;
        self.buffers[id].file_id = 0;
        self.buffers[id].offset = 0;

        self.free_list.push_back(id);
        self.deallocations.fetch_add(1, Ordering::Relaxed);
    }

    /// Get all dirty buffers
    pub fn get_dirty_buffers(&self) -> &[usize] {
        &self.dirty_list
    }

    /// Clear dirty state after flush
    pub fn clear_dirty(&mut self, id: usize) {
        if id < self.buffers.len() {
            self.buffers[id].state = BufferState::Clean;
        }
        self.dirty_list.retain(|&x| x != id);
    }

    /// Get buffer count
    pub fn buffer_count(&self) -> usize {
        self.buffer_map.len()
    }

    /// Get dirty buffer count
    pub fn dirty_count(&self) -> usize {
        self.dirty_list.len()
    }

    /// Get free buffer count
    pub fn free_count(&self) -> usize {
        self.free_list.len()
    }
}

/// Cache view for file mapping
#[derive(Debug)]
pub struct CacheView {
    /// File identifier
    pub file_id: u64,
    /// Start offset in file
    pub offset: u64,
    /// View size
    pub size: usize,
    /// Associated buffers
    pub buffers: Vec<usize>,
    /// Pinned flag
    pub pinned: bool,
}

impl CacheView {
    pub fn new(file_id: u64, offset: u64, size: usize) -> Self {
        Self {
            file_id,
            offset,
            size,
            buffers: Vec::new(),
            pinned: false,
        }
    }
}

/// Lazy writer for background flushing
#[derive(Debug)]
pub struct LazyWriter {
    /// Enabled flag
    enabled: AtomicBool,
    /// Last flush time
    last_flush: AtomicU64,
    /// Flush interval
    interval: u64,
    /// Total flushes
    flush_count: AtomicU64,
    /// Total bytes written
    bytes_written: AtomicU64,
}

impl LazyWriter {
    pub fn new(interval: u64) -> Self {
        Self {
            enabled: AtomicBool::new(true),
            last_flush: AtomicU64::new(0),
            interval,
            flush_count: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
        }
    }

    /// Check if flush is needed
    pub fn should_flush(&self, current_time: u64) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return false;
        }

        let last = self.last_flush.load(Ordering::Relaxed);
        current_time - last >= self.interval
    }

    /// Record flush
    pub fn record_flush(&self, current_time: u64, bytes: u64) {
        self.last_flush.store(current_time, Ordering::Relaxed);
        self.flush_count.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Enable/disable lazy writer
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// Cache Manager
pub struct CacheManager {
    /// Buffer pool
    buffer_pool: BufferPool,
    /// Cache views
    views: HashMap<u64, Vec<CacheView>>,
    /// Write mode
    write_mode: WriteMode,
    /// Lazy writer
    lazy_writer: LazyWriter,
    /// Statistics
    read_count: AtomicU64,
    write_count: AtomicU64,
    flush_count: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

impl CacheManager {
    pub fn new(write_mode: WriteMode) -> Self {
        Self {
            buffer_pool: BufferPool::new(),
            views: HashMap::new(),
            write_mode,
            lazy_writer: LazyWriter::new(LAZY_WRITER_INTERVAL),
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
            flush_count: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        }
    }

    /// Read data from cache
    pub fn read(&mut self, file_id: u64, offset: u64, buffer: &mut [u8]) -> Result<usize, &'static str> {
        self.read_count.fetch_add(1, Ordering::Relaxed);

        let mut bytes_read = 0;
        let mut current_offset = offset;

        while bytes_read < buffer.len() {
            let buffer_offset = (current_offset / BUFFER_SIZE as u64) * BUFFER_SIZE as u64;
            let offset_in_buffer = (current_offset % BUFFER_SIZE as u64) as usize;
            let to_read = core::cmp::min(
                BUFFER_SIZE - offset_in_buffer,
                buffer.len() - bytes_read
            );

            // Try to get from cache
            let buffer_id = match self.buffer_pool.buffer_map.get(&(file_id, buffer_offset)) {
                Some(&id) => {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    id
                }
                None => {
                    self.cache_misses.fetch_add(1, Ordering::Relaxed);
                    let id = self.buffer_pool.allocate(file_id, buffer_offset)?;
                    // TODO: Read from disk
                    id
                }
            };

            // TODO: Copy from buffer to output
            // For now, just simulate
            self.buffer_pool.buffers[buffer_id].last_access = get_timestamp();

            bytes_read += to_read;
            current_offset += to_read as u64;
        }

        // Trigger read-ahead
        self.readahead(file_id, offset);

        Ok(bytes_read)
    }

    /// Write data to cache
    pub fn write(&mut self, file_id: u64, offset: u64, buffer: &[u8]) -> Result<usize, &'static str> {
        self.write_count.fetch_add(1, Ordering::Relaxed);

        let mut bytes_written = 0;
        let mut current_offset = offset;

        while bytes_written < buffer.len() {
            let buffer_offset = (current_offset / BUFFER_SIZE as u64) * BUFFER_SIZE as u64;
            let offset_in_buffer = (current_offset % BUFFER_SIZE as u64) as usize;
            let to_write = core::cmp::min(
                BUFFER_SIZE - offset_in_buffer,
                buffer.len() - bytes_written
            );

            // Allocate or get buffer
            let buffer_id = self.buffer_pool.allocate(file_id, buffer_offset)?;

            // TODO: Copy data to buffer

            // Mark as dirty unless write-through
            match self.write_mode {
                WriteMode::WriteThrough => {
                    // Immediate write
                    self.flush_buffer(buffer_id)?;
                }
                WriteMode::WriteBack => {
                    // Delayed write
                    self.buffer_pool.mark_dirty(buffer_id);
                }
            }

            self.buffer_pool.release(buffer_id)?;

            bytes_written += to_write;
            current_offset += to_write as u64;
        }

        // Check if we need forced flush
        self.check_flush_threshold()?;

        Ok(bytes_written)
    }

    /// Flush a specific buffer
    fn flush_buffer(&mut self, buffer_id: usize) -> Result<(), &'static str> {
        if buffer_id >= self.buffer_pool.buffers.len() {
            return Err("Invalid buffer ID");
        }

        let buffer = &mut self.buffer_pool.buffers[buffer_id];
        if !buffer.is_dirty() {
            return Ok(());
        }

        buffer.state = BufferState::IoInProgress;

        // TODO: Actual disk write

        self.buffer_pool.clear_dirty(buffer_id);
        self.flush_count.fetch_add(1, Ordering::Relaxed);
        self.lazy_writer.record_flush(get_timestamp(), BUFFER_SIZE as u64);

        Ok(())
    }

    /// Flush all dirty buffers
    pub fn flush_all(&mut self) -> Result<usize, &'static str> {
        let dirty_buffers: Vec<usize> = self.buffer_pool.get_dirty_buffers().to_vec();
        let mut flushed = 0;

        for &buffer_id in &dirty_buffers {
            self.flush_buffer(buffer_id)?;
            flushed += 1;
        }

        Ok(flushed)
    }

    /// Flush buffers for a specific file
    pub fn flush_file(&mut self, file_id: u64) -> Result<usize, &'static str> {
        let dirty_buffers: Vec<usize> = self.buffer_pool.get_dirty_buffers()
            .iter()
            .filter(|&&id| self.buffer_pool.buffers[id].file_id == file_id)
            .copied()
            .collect();

        let mut flushed = 0;
        for buffer_id in dirty_buffers {
            self.flush_buffer(buffer_id)?;
            flushed += 1;
        }

        Ok(flushed)
    }

    /// Check if dirty threshold exceeded
    fn check_flush_threshold(&mut self) -> Result<(), &'static str> {
        let total = self.buffer_pool.buffer_count();
        let dirty = self.buffer_pool.dirty_count();

        if total > 0 && (dirty * 100 / total) >= DIRTY_THRESHOLD {
            self.flush_all()?;
        }

        Ok(())
    }

    /// Perform read-ahead
    fn readahead(&mut self, file_id: u64, offset: u64) {
        // Simple sequential read-ahead
        const READAHEAD_SIZE: u64 = 16 * BUFFER_SIZE as u64;

        let start = ((offset / BUFFER_SIZE as u64) + 1) * BUFFER_SIZE as u64;
        let end = start + READAHEAD_SIZE;

        for ra_offset in (start..end).step_by(BUFFER_SIZE) {
            // Skip if already cached
            if self.buffer_pool.buffer_map.contains_key(&(file_id, ra_offset)) {
                continue;
            }

            // Allocate and initiate read
            if let Ok(_id) = self.buffer_pool.allocate(file_id, ra_offset) {
                // TODO: Initiate async read
            }
        }
    }

    /// Create a cache view
    pub fn create_view(&mut self, file_id: u64, offset: u64, size: usize) -> Result<usize, &'static str> {
        let view = CacheView::new(file_id, offset, size);
        let view_list = self.views.entry(file_id).or_insert_with(Vec::new);
        view_list.push(view);
        Ok(view_list.len() - 1)
    }

    /// Pin a cache view
    pub fn pin_view(&mut self, file_id: u64, view_id: usize) -> Result<(), &'static str> {
        let view_list = self.views.get_mut(&file_id)
            .ok_or("File not found")?;

        if view_id >= view_list.len() {
            return Err("Invalid view ID");
        }

        view_list[view_id].pinned = true;
        Ok(())
    }

    /// Unpin a cache view
    pub fn unpin_view(&mut self, file_id: u64, view_id: usize) -> Result<(), &'static str> {
        let view_list = self.views.get_mut(&file_id)
            .ok_or("File not found")?;

        if view_id >= view_list.len() {
            return Err("Invalid view ID");
        }

        view_list[view_id].pinned = false;
        Ok(())
    }

    /// Invalidate cache for a file
    pub fn invalidate_file(&mut self, file_id: u64) -> Result<(), &'static str> {
        // Flush first
        self.flush_file(file_id)?;

        // Remove views
        self.views.remove(&file_id);

        // Remove buffers
        let to_remove: Vec<_> = self.buffer_pool.buffer_map.iter()
            .filter(|((fid, _), _)| *fid == file_id)
            .map(|((fid, offset), _)| (*fid, *offset))
            .collect();

        for (fid, offset) in to_remove {
            if let Some(&id) = self.buffer_pool.buffer_map.get(&(fid, offset)) {
                self.buffer_pool.free_buffer(id);
            }
        }

        Ok(())
    }

    /// Background flush (called by lazy writer)
    pub fn background_flush(&mut self) -> Result<usize, &'static str> {
        let current_time = get_timestamp();

        if !self.lazy_writer.should_flush(current_time) {
            return Ok(0);
        }

        // Flush old dirty buffers
        let threshold_time = current_time.saturating_sub(self.lazy_writer.interval);
        let old_dirty: Vec<usize> = self.buffer_pool.get_dirty_buffers()
            .iter()
            .filter(|&&id| self.buffer_pool.buffers[id].dirty_time < threshold_time)
            .copied()
            .collect();

        let mut flushed = 0;
        for buffer_id in old_dirty {
            self.flush_buffer(buffer_id)?;
            flushed += 1;
        }

        Ok(flushed)
    }

    /// Set write mode
    pub fn set_write_mode(&mut self, mode: WriteMode) {
        self.write_mode = mode;
    }

    /// Get write mode
    pub fn write_mode(&self) -> WriteMode {
        self.write_mode
    }

    /// Get statistics
    pub fn statistics(&self) -> CacheManagerStats {
        CacheManagerStats {
            read_count: self.read_count.load(Ordering::Relaxed),
            write_count: self.write_count.load(Ordering::Relaxed),
            flush_count: self.flush_count.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            buffer_count: self.buffer_pool.buffer_count(),
            dirty_count: self.buffer_pool.dirty_count(),
            free_count: self.buffer_pool.free_count(),
            lazy_writer_enabled: self.lazy_writer.is_enabled(),
        }
    }
}

/// Cache manager statistics
#[derive(Debug, Clone)]
pub struct CacheManagerStats {
    pub read_count: u64,
    pub write_count: u64,
    pub flush_count: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub buffer_count: usize,
    pub dirty_count: usize,
    pub free_count: usize,
    pub lazy_writer_enabled: bool,
}

impl CacheManagerStats {
    pub fn hit_rate(&self) -> f32 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            (self.cache_hits as f32) / (total as f32) * 100.0
        }
    }

    pub fn dirty_percentage(&self) -> f32 {
        if self.buffer_count == 0 {
            0.0
        } else {
            (self.dirty_count as f32) / (self.buffer_count as f32) * 100.0
        }
    }
}

fn get_timestamp() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// Global cache manager instance
static CACHE_MANAGER: Spinlock<Option<CacheManager>> = Spinlock::new(None);

/// Initialize cache manager
pub fn init(write_mode: WriteMode) {
    let mut cm = CACHE_MANAGER.lock();
    *cm = Some(CacheManager::new(write_mode));
}

/// Read from cache
pub fn cc_read(file_id: u64, offset: u64, buffer: &mut [u8]) -> Result<usize, &'static str> {
    let mut cm = CACHE_MANAGER.lock();
    cm.as_mut().ok_or("Cache manager not initialized")?.read(file_id, offset, buffer)
}

/// Write to cache
pub fn cc_write(file_id: u64, offset: u64, buffer: &[u8]) -> Result<usize, &'static str> {
    let mut cm = CACHE_MANAGER.lock();
    cm.as_mut().ok_or("Cache manager not initialized")?.write(file_id, offset, buffer)
}

/// Flush all dirty buffers
pub fn cc_flush_all() -> Result<usize, &'static str> {
    let mut cm = CACHE_MANAGER.lock();
    cm.as_mut().ok_or("Cache manager not initialized")?.flush_all()
}

/// Flush file buffers
pub fn cc_flush_file(file_id: u64) -> Result<usize, &'static str> {
    let mut cm = CACHE_MANAGER.lock();
    cm.as_mut().ok_or("Cache manager not initialized")?.flush_file(file_id)
}

/// Invalidate file cache
pub fn cc_invalidate_file(file_id: u64) -> Result<(), &'static str> {
    let mut cm = CACHE_MANAGER.lock();
    cm.as_mut().ok_or("Cache manager not initialized")?.invalidate_file(file_id)
}

/// Background flush
pub fn cc_background_flush() -> Result<usize, &'static str> {
    let mut cm = CACHE_MANAGER.lock();
    cm.as_mut().ok_or("Cache manager not initialized")?.background_flush()
}

/// Get statistics
pub fn cc_statistics() -> Result<CacheManagerStats, &'static str> {
    let cm = CACHE_MANAGER.lock();
    Ok(cm.as_ref().ok_or("Cache manager not initialized")?.statistics())
}
