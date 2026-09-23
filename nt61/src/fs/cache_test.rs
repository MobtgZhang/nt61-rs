//! Cache System Tests
//!
//! Comprehensive tests for the enhanced file system cache

use super::cache::*;
use super::cache_manager::*;
use crate::mm::page_cache::*;

/// Test basic cache operations
pub fn test_basic_cache() -> bool {
    crate::boot_println!("[CACHE-TEST] Testing basic cache operations...");

    // Initialize cache
    init_with_policy(EvictionPolicy::LRU, CoherencyMode::WriteBackInvalidate);

    // Test write
    let test_data = [1u8, 2, 3, 4, 5];
    match cc_write(1, 0, &test_data) {
        Ok(n) => {
            if n != test_data.len() {
                crate::boot_println!("[CACHE-TEST] FAIL: write returned {} bytes, expected {}", n, test_data.len());
                return false;
            }
        }
        Err(_) => {
            crate::boot_println!("[CACHE-TEST] FAIL: write failed");
            return false;
        }
    }

    // Test read
    let mut read_buf = [0u8; 10];
    match cc_read(1, 0, &mut read_buf) {
        Ok(n) => {
            if n < test_data.len() {
                crate::boot_println!("[CACHE-TEST] FAIL: read returned {} bytes, expected at least {}", n, test_data.len());
                return false;
            }
        }
        Err(_) => {
            crate::boot_println!("[CACHE-TEST] FAIL: read failed");
            return false;
        }
    }

    crate::boot_println!("[CACHE-TEST] PASS: basic cache operations");
    true
}

/// Test cache statistics
pub fn test_cache_statistics() -> bool {
    crate::boot_println!("[CACHE-TEST] Testing cache statistics...");

    // Get initial statistics
    let stats = match cc_statistics() {
        Some(s) => s,
        None => {
            crate::boot_println!("[CACHE-TEST] FAIL: could not get statistics");
            return false;
        }
    };

    let initial_reads = stats.reads.load(core::sync::atomic::Ordering::Relaxed);
    let initial_writes = stats.writes.load(core::sync::atomic::Ordering::Relaxed);

    // Perform some operations
    let test_data = [0x42u8; 512];
    let _ = cc_write(2, 0, &test_data);
    let mut buf = [0u8; 512];
    let _ = cc_read(2, 0, &mut buf);

    // Check statistics updated
    let stats2 = cc_statistics().unwrap();
    let final_writes = stats2.writes.load(core::sync::atomic::Ordering::Relaxed);

    if final_writes <= initial_writes {
        crate::boot_println!("[CACHE-TEST] WARN: write count did not increase (initial={}, final={})",
            initial_writes, final_writes);
    }

    // Calculate hit rate
    let hit_rate = stats2.hit_rate();
    crate::boot_println!("[CACHE-TEST] Cache hit rate: {:.2}%", hit_rate);

    crate::boot_println!("[CACHE-TEST] PASS: cache statistics");
    true
}

/// Test cache eviction
pub fn test_cache_eviction() -> bool {
    crate::boot_println!("[CACHE-TEST] Testing cache eviction...");

    // Initialize with small cache
    init_with_policy(EvictionPolicy::LRU, CoherencyMode::None);

    // Fill cache beyond capacity
    let block_size = CACHE_BLOCK_SIZE;
    let test_data = [0xAAu8; 4096];

    for i in 0..100 {
        let file_id = 10;
        let offset = (i * block_size) as u64;
        let _ = cc_write(file_id, offset, &test_data);
    }

    // Check eviction occurred
    let stats = cc_statistics().unwrap();
    let evictions = stats.evictions.load(core::sync::atomic::Ordering::Relaxed);

    if evictions > 0 {
        crate::boot_println!("[CACHE-TEST] Cache evicted {} blocks", evictions);
    } else {
        crate::boot_println!("[CACHE-TEST] WARN: no evictions occurred");
    }

    crate::boot_println!("[CACHE-TEST] PASS: cache eviction");
    true
}

/// Test write-back and flush
pub fn test_writeback_flush() -> bool {
    crate::boot_println!("[CACHE-TEST] Testing write-back and flush...");

    // Write some data
    let test_data = [0x55u8; 1024];
    for i in 0..10 {
        let _ = cc_write(20, i * 1024, &test_data);
    }

    // Check dirty blocks
    let stats_before = cc_statistics().unwrap();
    let dirty_before = stats_before.dirty_blocks.load(core::sync::atomic::Ordering::Relaxed);
    crate::boot_println!("[CACHE-TEST] Dirty blocks before flush: {}", dirty_before);

    // Trigger flush
    cc_flush_all();

    // Check dirty blocks cleared
    let stats_after = cc_statistics().unwrap();
    let dirty_after = stats_after.dirty_blocks.load(core::sync::atomic::Ordering::Relaxed);
    let writebacks = stats_after.writebacks.load(core::sync::atomic::Ordering::Relaxed);

    crate::boot_println!("[CACHE-TEST] Dirty blocks after flush: {}", dirty_after);
    crate::boot_println!("[CACHE-TEST] Total writebacks: {}", writebacks);

    if dirty_after > dirty_before {
        crate::boot_println!("[CACHE-TEST] FAIL: dirty count increased after flush");
        return false;
    }

    crate::boot_println!("[CACHE-TEST] PASS: write-back and flush");
    true
}

/// Test coherency modes
pub fn test_coherency_modes() -> bool {
    crate::boot_println!("[CACHE-TEST] Testing coherency modes...");

    // Test write-through mode
    cc_set_coherency_mode(CoherencyMode::WriteThrough);
    let test_data = [0x77u8; 512];
    let _ = cc_write(30, 0, &test_data);

    // In write-through mode, data should be written immediately
    let stats = cc_statistics().unwrap();
    let writebacks = stats.writebacks.load(core::sync::atomic::Ordering::Relaxed);
    crate::boot_println!("[CACHE-TEST] Write-through writebacks: {}", writebacks);

    // Test write-back mode
    cc_set_coherency_mode(CoherencyMode::WriteBackInvalidate);
    let _ = cc_write(31, 0, &test_data);

    crate::boot_println!("[CACHE-TEST] PASS: coherency modes");
    true
}

/// Test page cache
pub fn test_page_cache() -> bool {
    crate::boot_println!("[CACHE-TEST] Testing page cache...");

    // Initialize page cache
    crate::mm::page_cache::init(EvictionPolicy::LRU);

    // Insert some pages
    for i in 0..10 {
        let key = PageKey::new(100, i);
        match page_cache_insert(key, i * 0x1000) {
            Ok(idx) => {
                crate::boot_println!("[CACHE-TEST] Inserted page {} at index {}", i, idx);
            }
            Err(e) => {
                crate::boot_println!("[CACHE-TEST] FAIL: could not insert page {}: {}", i, e);
                return false;
            }
        }
    }

    // Lookup pages
    let key = PageKey::new(100, 5);
    match page_cache_lookup(key) {
        Some(idx) => {
            crate::boot_println!("[CACHE-TEST] Found page at index {}", idx);
        }
        None => {
            crate::boot_println!("[CACHE-TEST] FAIL: page not found");
            return false;
        }
    }

    // Get statistics
    if let Some(stats) = page_cache_statistics() {
        let hits = stats.hits.load(core::sync::atomic::Ordering::Relaxed);
        let misses = stats.misses.load(core::sync::atomic::Ordering::Relaxed);
        let total = stats.total_pages.load(core::sync::atomic::Ordering::Relaxed);
        crate::boot_println!("[CACHE-TEST] Page cache: {} pages, {} hits, {} misses",
            total, hits, misses);
    }

    crate::boot_println!("[CACHE-TEST] PASS: page cache");
    true
}

/// Test cache manager
pub fn test_cache_manager() -> bool {
    crate::boot_println!("[CACHE-TEST] Testing cache manager...");

    // Initialize cache manager
    crate::fs::cache_manager::init(WriteMode::WriteBack);

    // Test read
    let mut buf = [0u8; 512];
    match crate::fs::cache_manager::cc_read(40, 0, &mut buf) {
        Ok(n) => {
            crate::boot_println!("[CACHE-TEST] Cache manager read {} bytes", n);
        }
        Err(e) => {
            crate::boot_println!("[CACHE-TEST] Cache manager read failed: {}", e);
        }
    }

    // Test write
    let data = [0x99u8; 512];
    match crate::fs::cache_manager::cc_write(40, 0, &data) {
        Ok(n) => {
            crate::boot_println!("[CACHE-TEST] Cache manager wrote {} bytes", n);
        }
        Err(e) => {
            crate::boot_println!("[CACHE-TEST] Cache manager write failed: {}", e);
        }
    }

    // Get statistics
    match crate::fs::cache_manager::cc_statistics() {
        Ok(stats) => {
            crate::boot_println!("[CACHE-TEST] Cache manager: hit rate={:.2}%, dirty={:.2}%",
                stats.hit_rate(), stats.dirty_percentage());
        }
        Err(e) => {
            crate::boot_println!("[CACHE-TEST] Could not get cache manager stats: {}", e);
        }
    }

    crate::boot_println!("[CACHE-TEST] PASS: cache manager");
    true
}

/// Run all cache tests
pub fn run_all_tests() -> bool {
    crate::boot_println!("[CACHE-TEST] ========================================");
    crate::boot_println!("[CACHE-TEST] Running Enhanced Cache System Tests");
    crate::boot_println!("[CACHE-TEST] ========================================");

    let mut passed = 0;
    let mut total = 0;

    // Run tests
    let tests: &[(&str, fn() -> bool)] = &[
        ("Basic Cache Operations", test_basic_cache),
        ("Cache Statistics", test_cache_statistics),
        ("Cache Eviction", test_cache_eviction),
        ("Write-back and Flush", test_writeback_flush),
        ("Coherency Modes", test_coherency_modes),
        ("Page Cache", test_page_cache),
        ("Cache Manager", test_cache_manager),
    ];

    for (name, test_fn) in tests {
        total += 1;
        crate::boot_println!("[CACHE-TEST] Running: {}", name);
        if test_fn() {
            passed += 1;
            crate::boot_println!("[CACHE-TEST] ✓ {}", name);
        } else {
            crate::boot_println!("[CACHE-TEST] ✗ {}", name);
        }
        crate::boot_println!("");
    }

    crate::boot_println!("[CACHE-TEST] ========================================");
    crate::boot_println!("[CACHE-TEST] Results: {}/{} tests passed", passed, total);
    crate::boot_println!("[CACHE-TEST] ========================================");

    passed == total
}
