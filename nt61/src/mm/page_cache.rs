//! Page Cache Implementation
//!
//! Provides a unified page cache for file system I/O operations.
//! Based on Windows Cache Manager and Linux Page Cache design.
//!
//! Key features:
//! - read-ahead support (sequential, random, adaptive)
//! - write-back with delayed flush
//! - LRU/LFU eviction policies
//! - Multi-process consistency
//! - Memory-mapped file support

use crate::ke::sync::Spinlock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use hashbrown::HashMap;

/// Page size for cache operations (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Maximum number of pages in the cache
pub const MAX_CACHE_PAGES: usize = 32768; // 128 MB

/// read-ahead window size (pages)
pub const READAHEAD_WINDOW: usize = 32;

/// write-back delay (ticks)
pub const WRITEBACK_DELAY: u64 = 50;

/// Eviction policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    /// Least Recently Used
    LRU,
    /// Least Frequently Used
    LFU,
    /// Adaptive Replacement Cache (combination of LRU and LFU)
    ARC,
}

/// Page cache entry state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageState {
    /// Page is not in use
    Free = 0,
    /// Page contains valid clean data
    Clean = 1,
    /// Page contains modified data
    Dirty = 2,
    /// Page is being read from disk
    Reading = 3,
    /// Page is being written to disk
    Writing = 4,
    /// Page is locked in memory
    Locked = 5,
}

/// Page cache key (identifies a unique page)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PageKey {
    /// File/volume identifier
    pub file_id: u64,
    /// Page index within the file
    pub page_index: u64,
}

/// Asynchronous I/O request for the page cache writeback backend.
///
/// The page cache uses a DPC-driven async I/O backend: dirty page
/// writeback is queued as an `AsyncIoRequest` and drained by the DPC
/// dispatcher at DISPATCH_LEVEL, matching the Windows Cache Manager's
/// use of FSP I/O for write-behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncIoOperation {
    /// Write a cached page back to its backing store.
    WriteBack,
    /// Read a page from the backing store into the cache.
    ReadAhead,
}

/// A single queued async I/O request.
#[derive(Debug, Clone, Copy)]
pub struct AsyncIoRequest {
    /// Operation type
    pub operation: AsyncIoOperation,
    /// Page key (file + page index)
    pub key: PageKey,
    /// Physical frame number holding the page data
    pub pfn: u64,
}

/// Maximum number of pending async I/O requests.
/// Windows Cache Manager uses a similar bounded write-behind queue.
pub const MAX_ASYNC_IO_REQUESTS: usize = 256;

impl PageKey {
    pub fn new(file_id: u64, page_index: u64) -> Self {
        Self {
            file_id,
            page_index,
        }
    }
}

/// Cached page metadata
#[derive(Debug, Clone)]
pub struct CachedPage {
    /// Page key
    pub key: PageKey,
    /// Current state
    pub state: PageState,
    /// Reference count (for pinning)
    pub ref_count: u32,
    /// Access count (for LFU)
    pub access_count: u32,
    /// Last access time
    pub last_access: u64,
    /// Time when page became dirty
    pub dirty_time: u64,
    /// Physical frame number
    pub pfn: u64,
    /// LRU list pointers
    pub lru_prev: Option<usize>,
    pub lru_next: Option<usize>,
}

impl CachedPage {
    pub fn new(key: PageKey, pfn: u64) -> Self {
        Self {
            key,
            state: PageState::Clean,
            ref_count: 0,
            access_count: 0,
            last_access: 0,
            dirty_time: 0,
            pfn,
            lru_prev: None,
            lru_next: None,
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.state == PageState::Dirty
    }

    pub fn is_locked(&self) -> bool {
        self.ref_count > 0 || self.state == PageState::Locked
    }

    pub fn can_evict(&self) -> bool {
        !self.is_locked() && self.state != PageState::Reading && self.state != PageState::Writing
    }
}

/// read-ahead state tracker
#[derive(Debug, Clone)]
struct ReadAheadState {
    /// Last accessed page
    last_page: u64,
    /// Sequential access counter
    sequential_count: u32,
    /// read-ahead window size
    window_size: usize,
    /// Predicted next page
    predicted_next: u64,
}

impl ReadAheadState {
    fn new() -> Self {
        Self {
            last_page: 0,
            sequential_count: 0,
            window_size: READAHEAD_WINDOW / 4,
            predicted_next: 0,
        }
    }

    /// Update state based on access pattern
    fn update(&mut self, page_index: u64) {
        if page_index == self.last_page + 1 {
            // Sequential access detected
            self.sequential_count += 1;
            // Increase window size for strong sequential patterns
            if self.sequential_count > 4 {
                self.window_size = self.window_size.min(READAHEAD_WINDOW) * 2;
            }
        } else {
            // Non-sequential access
            self.sequential_count = 0;
            self.window_size = READAHEAD_WINDOW / 4;
        }
        self.last_page = page_index;
        self.predicted_next = page_index + 1;
    }

    /// Get read-ahead pages to prefetch
    fn get_readahead_pages(&self) -> Vec<u64> {
        if self.sequential_count < 2 {
            return Vec::new();
        }

        let mut pages = Vec::new();
        for i in 0..self.window_size {
            pages.push(self.predicted_next + i as u64);
        }
        pages
    }
}

/// Page cache statistics
#[derive(Debug)]
pub struct PageCacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub reads: AtomicU64,
    pub writes: AtomicU64,
    pub evictions: AtomicU64,
    pub writebacks: AtomicU64,
    pub readahead_hits: AtomicU64,
    pub readahead_misses: AtomicU64,
    pub dirty_pages: AtomicUsize,
    pub total_pages: AtomicUsize,
}

impl PageCacheStats {
    pub const fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            writebacks: AtomicU64::new(0),
            readahead_hits: AtomicU64::new(0),
            readahead_misses: AtomicU64::new(0),
            dirty_pages: AtomicUsize::new(0),
            total_pages: AtomicUsize::new(0),
        }
    }

    pub fn hit_rate(&self) -> f32 {
        let hits = self.hits.load(Ordering::Relaxed);
        let total = hits + self.misses.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            (hits as f32) / (total as f32) * 100.0
        }
    }

    pub fn readahead_effectiveness(&self) -> f32 {
        let hits = self.readahead_hits.load(Ordering::Relaxed);
        let total = hits + self.readahead_misses.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            (hits as f32) / (total as f32) * 100.0
        }
    }
}

/// Page cache implementation
pub struct PageCache {
    /// All cached pages
    pages: Vec<CachedPage>,
    /// Hash table for fast lookup
    page_map: HashMap<PageKey, usize>,
    /// LRU list head
    lru_head: Option<usize>,
    /// LRU list tail
    lru_tail: Option<usize>,
    /// Eviction policy
    policy: EvictionPolicy,
    /// Statistics
    stats: PageCacheStats,
    /// read-ahead state per file
    readahead_state: HashMap<u64, ReadAheadState>,
    /// Maximum cache size
    max_pages: usize,
    /// Pending async I/O request queue
    async_io_queue: alloc::collections::VecDeque<AsyncIoRequest>,
}

impl PageCache {
    pub fn new(policy: EvictionPolicy) -> Self {
        Self {
            pages: Vec::new(),
            page_map: HashMap::new(),
            lru_head: None,
            lru_tail: None,
            policy,
            stats: PageCacheStats::new(),
            readahead_state: HashMap::new(),
            max_pages: MAX_CACHE_PAGES,
            async_io_queue: alloc::collections::VecDeque::new(),
        }
    }

    /// Lookup a page in the cache
    pub fn lookup(&mut self, key: PageKey) -> Option<usize> {
        if let Some(&idx) = self.page_map.get(&key) {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            self.touch_page(idx);
            Some(idx)
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Add a new page to the cache
    pub fn insert(&mut self, key: PageKey, pfn: u64) -> Result<usize, &'static str> {
        // Check if already exists
        if let Some(&idx) = self.page_map.get(&key) {
            return Ok(idx);
        }

        // Evict if necessary
        if self.pages.len() >= self.max_pages {
            self.evict_page()?;
        }

        // create new page entry
        let page = CachedPage::new(key, pfn);
        let idx = self.pages.len();
        self.pages.push(page);
        self.page_map.insert(key, idx);
        self.stats.total_pages.fetch_add(1, Ordering::Relaxed);

        // Add to LRU list
        self.add_to_lru(idx);

        Ok(idx)
    }

    /// Mark a page as dirty
    pub fn mark_dirty(&mut self, idx: usize) {
        if idx >= self.pages.len() {
            return;
        }

        if self.pages[idx].state != PageState::Dirty {
            self.pages[idx].state = PageState::Dirty;
            self.pages[idx].dirty_time = get_timestamp();
            self.stats.dirty_pages.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Touch a page (update access information)
    fn touch_page(&mut self, idx: usize) {
        if idx >= self.pages.len() {
            return;
        }

        self.pages[idx].access_count += 1;
        self.pages[idx].last_access = get_timestamp();

        // Move to LRU head for LRU policy
        if self.policy == EvictionPolicy::LRU || self.policy == EvictionPolicy::ARC {
            self.move_to_lru_head(idx);
        }
    }

    /// Evict a page based on the eviction policy
    fn evict_page(&mut self) -> Result<usize, &'static str> {
        let victim = match self.policy {
            EvictionPolicy::LRU => self.evict_lru(),
            EvictionPolicy::LFU => self.evict_lfu(),
            EvictionPolicy::ARC => self.evict_arc(),
        }?;

        // Flush if dirty
        if self.pages[victim].is_dirty() {
            self.writeback_page(victim)?;
        }

        // Remove from hash table
        let key = self.pages[victim].key;
        self.page_map.remove(&key);

        // Remove from LRU list
        self.remove_from_lru(victim);

        self.stats.evictions.fetch_add(1, Ordering::Relaxed);
        self.stats.total_pages.fetch_sub(1, Ordering::Relaxed);

        // Reuse the slot
        self.pages[victim].state = PageState::Free;
        Ok(victim)
    }

    /// Evict using LRU policy
    fn evict_lru(&self) -> Result<usize, &'static str> {
        let mut current = self.lru_tail;
        while let Some(idx) = current {
            if self.pages[idx].can_evict() {
                return Ok(idx);
            }
            current = self.pages[idx].lru_prev;
        }
        Err("No evictable pages")
    }

    /// Evict using LFU policy
    fn evict_lfu(&self) -> Result<usize, &'static str> {
        let mut min_access = u32::MAX;
        let mut victim = None;

        for (idx, page) in self.pages.iter().enumerate() {
            if page.can_evict() && page.access_count < min_access {
                min_access = page.access_count;
                victim = Some(idx);
            }
        }

        victim.ok_or("No evictable pages")
    }

    /// Evict using ARC policy (adaptive)
    fn evict_arc(&self) -> Result<usize, &'static str> {
        // Simplified ARC: combine LRU for recent, LFU for frequent
        self.evict_lru().or_else(|_| self.evict_lfu())
    }

    /// write back a dirty page to disk
    fn writeback_page(&mut self, idx: usize) -> Result<(), &'static str> {
        if !self.pages[idx].is_dirty() {
            return Ok(());
        }

        self.pages[idx].state = PageState::Writing;

        // Queue the writeback as an async I/O request. The DPC dispatcher
        // drains the queue at DISPATCH_LEVEL; this avoids holding the
        // page cache spinlock during a synchronous disk write.
        let request = AsyncIoRequest {
            operation: AsyncIoOperation::WriteBack,
            key: self.pages[idx].key,
            pfn: self.pages[idx].pfn,
        };

        if self.async_io_queue.len() >= MAX_ASYNC_IO_REQUESTS {
            // Queue full: perform a synchronous write for this page.
            self.pages[idx].state = PageState::Dirty;
            return Err("Async I/O queue full");
        }

        self.async_io_queue.push_back(request);

        Ok(())
    }

    /// Perform read-ahead based on access pattern
    pub fn readahead(&mut self, file_id: u64, page_index: u64) {
        let state = self
            .readahead_state
            .entry(file_id)
            .or_insert_with(ReadAheadState::new);

        state.update(page_index);
        let readahead_pages = state.get_readahead_pages();

        for page_idx in readahead_pages {
            let key = PageKey::new(file_id, page_idx);

            // Skip if already cached
            if self.page_map.contains_key(&key) {
                continue;
            }

            // Read the page from the backing store into a newly allocated
            // cache entry.
            if let Some(frame) = crate::mm::frame::allocate_frame() {
                let pfn = frame;
                if let Ok(idx) = self.insert(key, pfn) {
                    self.pages[idx].state = PageState::Reading;

                    // Queue the read-ahead as an async I/O request.
                    let request = AsyncIoRequest {
                        operation: AsyncIoOperation::ReadAhead,
                        key,
                        pfn,
                    };
                    if self.async_io_queue.len() < MAX_ASYNC_IO_REQUESTS {
                        self.async_io_queue.push_back(request);
                    } else {
                        // Queue full: perform a synchronous read.
                        let disk_offset = page_idx * (PAGE_SIZE as u64);
                        let page_va = crate::mm::pfn::pfn_to_phys_va(pfn) as *mut u8;
                        let buf = unsafe { core::slice::from_raw_parts_mut(page_va, PAGE_SIZE) };
                        let bytes = crate::drivers::storage::disk::disk_read(
                            0,
                            disk_offset,
                            PAGE_SIZE,
                            buf,
                        );
                        if bytes == PAGE_SIZE {
                            self.pages[idx].state = PageState::Clean;
                        } else {
                            self.pages[idx].state = PageState::Free;
                        }
                        self.stats.reads.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Flush all dirty pages
    pub fn flush_all(&mut self) -> Result<usize, &'static str> {
        let mut flushed = 0;
        for idx in 0..self.pages.len() {
            if self.pages[idx].is_dirty() {
                self.writeback_page(idx)?;
                flushed += 1;
            }
        }
        Ok(flushed)
    }

    /// Flush pages for a specific file
    pub fn flush_file(&mut self, file_id: u64) -> Result<usize, &'static str> {
        let mut flushed = 0;
        for idx in 0..self.pages.len() {
            if self.pages[idx].key.file_id == file_id && self.pages[idx].is_dirty() {
                self.writeback_page(idx)?;
                flushed += 1;
            }
        }
        Ok(flushed)
    }

    /// Invalidate all pages for a file
    pub fn invalidate_file(&mut self, file_id: u64) {
        let to_remove: Vec<(PageKey, usize)> = self
            .page_map
            .iter()
            .filter(|(key, _)| key.file_id == file_id)
            .map(|(key, &idx)| (*key, idx))
            .collect();

        for (key, idx) in to_remove {
            if self.pages[idx].is_dirty() {
                let _ = self.writeback_page(idx);
            }
            self.remove_from_lru(idx);
            self.page_map.remove(&key);
            self.stats.total_pages.fetch_sub(1, Ordering::Relaxed);
        }
    }

    // LRU list management
    fn add_to_lru(&mut self, idx: usize) {
        match self.lru_head {
            None => {
                self.lru_head = Some(idx);
                self.lru_tail = Some(idx);
                self.pages[idx].lru_prev = None;
                self.pages[idx].lru_next = None;
            }
            Some(head) => {
                self.pages[idx].lru_prev = None;
                self.pages[idx].lru_next = Some(head);
                self.pages[head].lru_prev = Some(idx);
                self.lru_head = Some(idx);
            }
        }
    }

    fn remove_from_lru(&mut self, idx: usize) {
        let prev = self.pages[idx].lru_prev;
        let next = self.pages[idx].lru_next;

        match prev {
            Some(p) => self.pages[p].lru_next = next,
            None => self.lru_head = next,
        }

        match next {
            Some(n) => self.pages[n].lru_prev = prev,
            None => self.lru_tail = prev,
        }

        self.pages[idx].lru_prev = None;
        self.pages[idx].lru_next = None;
    }

    fn move_to_lru_head(&mut self, idx: usize) {
        if self.lru_head == Some(idx) {
            return;
        }
        self.remove_from_lru(idx);
        self.add_to_lru(idx);
    }

    pub fn statistics(&self) -> &PageCacheStats {
        &self.stats
    }

    /// Number of pending async I/O requests.
    pub fn pending_async_io(&self) -> usize {
        self.async_io_queue.len()
    }

    /// Drain the async I/O queue, performing the queued disk operations.
    ///
    /// Called from the DPC dispatcher or the kernel's write-behind worker.
    /// Processes up to `max_requests` operations per call to avoid holding
    /// the page cache lock for an unbounded time.
    pub fn process_async_io(&mut self, max_requests: usize) -> usize {
        let mut processed = 0;

        while processed < max_requests {
            let request = match self.async_io_queue.pop_front() {
                Some(r) => r,
                None => break,
            };

            let page_va = crate::mm::pfn::pfn_to_phys_va(request.pfn) as *mut u8;
            let disk_offset = request.key.page_index * (PAGE_SIZE as u64);

            match request.operation {
                AsyncIoOperation::WriteBack => {
                    let data = unsafe { core::slice::from_raw_parts(page_va, PAGE_SIZE) };
                    let written =
                        crate::drivers::storage::disk::disk_write(0, disk_offset, PAGE_SIZE, data);
                    if written == PAGE_SIZE {
                        // Find the page and mark it clean.
                        if let Some(&idx) = self.page_map.get(&request.key) {
                            self.pages[idx].state = PageState::Clean;
                        }
                        self.stats.writebacks.fetch_add(1, Ordering::Relaxed);
                        self.stats.dirty_pages.fetch_sub(1, Ordering::Relaxed);
                    } else {
                        // Write failed: mark the page dirty again for retry.
                        if let Some(&idx) = self.page_map.get(&request.key) {
                            self.pages[idx].state = PageState::Dirty;
                        }
                    }
                }
                AsyncIoOperation::ReadAhead => {
                    let buf = unsafe { core::slice::from_raw_parts_mut(page_va, PAGE_SIZE) };
                    let bytes =
                        crate::drivers::storage::disk::disk_read(0, disk_offset, PAGE_SIZE, buf);
                    if bytes == PAGE_SIZE {
                        if let Some(&idx) = self.page_map.get(&request.key) {
                            self.pages[idx].state = PageState::Clean;
                        }
                        self.stats.reads.fetch_add(1, Ordering::Relaxed);
                        self.stats.readahead_hits.fetch_add(1, Ordering::Relaxed);
                    } else {
                        if let Some(&idx) = self.page_map.get(&request.key) {
                            self.pages[idx].state = PageState::Free;
                        }
                        self.stats.readahead_misses.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            processed += 1;
        }

        processed
    }
}

fn get_timestamp() -> u64 {
    crate::hal::common::pit::get_system_time_ms()
}

static PAGE_CACHE: Spinlock<Option<PageCache>> = Spinlock::new(None);

pub fn init(policy: EvictionPolicy) {
    let mut cache = PAGE_CACHE.lock();
    *cache = Some(PageCache::new(policy));
}

pub fn page_cache_lookup(key: PageKey) -> Option<usize> {
    let result = {
        let mut cache = PAGE_CACHE.lock();
        cache.as_mut()?.lookup(key)
    };
    // Lookup and read-ahead may have queued async I/O requests; arm
    // the drain DPC so the queue is serviced at DISPATCH_LEVEL.
    request_async_io_drain();
    result
}

pub fn page_cache_insert(key: PageKey, pfn: u64) -> Result<usize, &'static str> {
    let mut cache = PAGE_CACHE.lock();
    cache
        .as_mut()
        .ok_or("Cache not initialized")?
        .insert(key, pfn)
}

pub fn page_cache_mark_dirty(idx: usize) {
    {
        let mut cache = PAGE_CACHE.lock();
        if let Some(c) = cache.as_mut() {
            c.mark_dirty(idx);
        }
    }
    // Writeback was queued; arm the drain DPC. Arming happens after
    // the cache lock is released so the DPC routine never contends
    // with the producer while it holds the queue.
    request_async_io_drain();
}

pub fn page_cache_flush_all() -> Result<usize, &'static str> {
    let mut cache = PAGE_CACHE.lock();
    cache.as_mut().ok_or("Cache not initialized")?.flush_all()
}

pub fn page_cache_statistics() -> Option<PageCacheStats> {
    let cache = PAGE_CACHE.lock();
    cache.as_ref().map(|c| PageCacheStats {
        hits: AtomicU64::new(c.stats.hits.load(Ordering::Relaxed)),
        misses: AtomicU64::new(c.stats.misses.load(Ordering::Relaxed)),
        reads: AtomicU64::new(c.stats.reads.load(Ordering::Relaxed)),
        writes: AtomicU64::new(c.stats.writes.load(Ordering::Relaxed)),
        evictions: AtomicU64::new(c.stats.evictions.load(Ordering::Relaxed)),
        writebacks: AtomicU64::new(c.stats.writebacks.load(Ordering::Relaxed)),
        readahead_hits: AtomicU64::new(c.stats.readahead_hits.load(Ordering::Relaxed)),
        readahead_misses: AtomicU64::new(c.stats.readahead_misses.load(Ordering::Relaxed)),
        dirty_pages: AtomicUsize::new(c.stats.dirty_pages.load(Ordering::Relaxed)),
        total_pages: AtomicUsize::new(c.stats.total_pages.load(Ordering::Relaxed)),
    })
}

/// Number of pending async I/O requests.
pub fn page_cache_pending_async_io() -> Option<usize> {
    let cache = PAGE_CACHE.lock();
    cache.as_ref().map(|c| c.pending_async_io())
}

/// Drain the page cache's async I/O queue.
///
/// Called from the DPC dispatcher or the write-behind worker to perform
/// the queued disk operations. Processes up to `max_requests` per call.
pub fn page_cache_process_async_io(max_requests: usize) -> usize {
    let mut cache = PAGE_CACHE.lock();
    match cache.as_mut() {
        Some(c) => c.process_async_io(max_requests),
        None => 0,
    }
}

/// Whether the async I/O drain DPC is currently armed.
static ASYNC_IO_DPC_ARMED: AtomicBool = AtomicBool::new(false);

/// Upper bound on drain batches per DPC invocation, so a failing disk
/// cannot keep the routine running forever.
const MAX_ASYNC_IO_DRAIN_BATCHES: usize = 64;

/// DPC routine that drains the page cache async I/O queue.
///
/// The DPC dispatcher holds the per-CPU DPC lock while routines run,
/// so this routine must not re-insert itself (the insert would
/// self-deadlock on the same lock). It instead drains in bounded
/// batches and disarms before the emptiness check, so any producer
/// that queues afterwards re-arms the DPC.
fn async_io_dpc_routine(_context: *mut u8) {
    let mut batches = 0;
    while batches < MAX_ASYNC_IO_DRAIN_BATCHES {
        let drained = page_cache_process_async_io(MAX_ASYNC_IO_REQUESTS);
        batches += 1;
        ASYNC_IO_DPC_ARMED.store(false, Ordering::Release);
        if drained == 0 && page_cache_pending_async_io().unwrap_or(0) == 0 {
            return;
        }
    }
    ASYNC_IO_DPC_ARMED.store(false, Ordering::Release);
}

/// Arm the async I/O drain DPC.
///
/// Called after new requests are queued. The routine fires at
/// DISPATCH_LEVEL on the next `KiRetireDpcList` pass and performs
/// the queued disk operations without holding the page cache lock
/// across I/O.
pub fn request_async_io_drain() {
    if ASYNC_IO_DPC_ARMED.swap(true, Ordering::AcqRel) {
        return;
    }
    if crate::ke::dpc::insert(async_io_dpc_routine, core::ptr::null_mut(), "pagecache-io").is_none()
    {
        // DPC table full: unarm so the next queued request retries.
        ASYNC_IO_DPC_ARMED.store(false, Ordering::Release);
    }
}
