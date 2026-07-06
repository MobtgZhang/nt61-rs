//! BTL — translation cache (TC) management.
//!
//! The TC holds pairs of (guest RIP → host code pointer). When a
//! guest block is compiled, an entry is inserted; subsequent
//! executions hit the cache and run the host code directly without
//! re-decoding.

#![cfg(target_arch = "loongarch64")]

use core::sync::atomic::{AtomicU32, Ordering};

/// Translation cache entry metadata.
#[derive(Copy, Clone)]
pub struct TranslationCacheEntry {
    pub guest_rip: u64,
    pub host_code: u64,
    pub guest_size: u32,
    pub host_size: u32,
}

impl TranslationCacheEntry {
    pub const fn empty() -> Self {
        Self { guest_rip: 0, host_code: 0, guest_size: 0, host_size: 0 }
    }
}

/// Translation cache (array-backed for the moment). Sized for the
/// initial bring-up; production would use a hash table or radix tree.
pub struct TranslationCache {
    pub entries: [TranslationCacheEntry; 1024],
    pub count: AtomicU32,
}

impl TranslationCache {
    const fn new() -> Self {
        const EMPTY: TranslationCacheEntry = TranslationCacheEntry::empty();
        Self {
            entries: [EMPTY; 1024],
            count: AtomicU32::new(0),
        }
    }

    pub fn lookup(&self, guest_rip: u64) -> Option<&TranslationCacheEntry> {
        let n = self.count.load(Ordering::Acquire) as usize;
        for e in &self.entries[..n] {
            if e.guest_rip == guest_rip {
                return Some(e);
            }
        }
        None
    }
}

static TC: TranslationCache = TranslationCache::new();

pub fn init() {
    // No work required: TC is `const`-initialised. The hook is left
    // here so the boot sequence can later wire up JIT memory
    // allocation / W^X policy.
}

pub fn translation_cache() -> &'static TranslationCache { &TC }
