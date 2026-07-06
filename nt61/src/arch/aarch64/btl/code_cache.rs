//! BTL Code Cache.
//!
//! Manages the executable memory region used to store translated
//! AArch64 code. Each [`TranslationUnit`] owns a slice of the WX
//! region and the source mapping that produced it.
//!
//! The cache is implemented as a fixed-size linear region
//! (`CODE_CACHE_SIZE`) that's been `mmap`-style allocated with RWX
//! permissions. A simple hash table maps `source_addr` to its
//! translated unit.

use core::sync::atomic::{AtomicU64, Ordering};

/// Total size of the code cache (4 MiB).
pub const CODE_CACHE_SIZE: usize = 4 * 1024 * 1024;

/// Alignment requirement for translated code (16 bytes is the
/// AArch64 instruction alignment requirement).
pub const CODE_ALIGNMENT: usize = 16;

static mut CODE_BASE: [u8; CODE_CACHE_SIZE] = [0; CODE_CACHE_SIZE];

/// Current allocation pointer (free-pointer allocator).
static CODE_ALLOC_PTR: AtomicU64 = AtomicU64::new(0);

/// One translated piece of guest code.
#[derive(Debug, Clone)]
pub struct TranslationUnit {
    pub source_addr: u64,
    pub translated_ptr: u64,
    pub code_len: usize,
    pub source_arch: SourceArch,
    pub access_count: AtomicU64,
    pub last_access_ns: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceArch {
    X86_64,
    X86_32,
    ARM32,
    Unknown,
}

impl TranslationUnit {
    pub const fn empty() -> Self {
        Self {
            source_addr: 0,
            translated_ptr: 0,
            code_len: 0,
            source_arch: SourceArch::Unknown,
            access_count: AtomicU64::new(0),
            last_access_ns: AtomicU64::new(0),
        }
    }
}

/// Simple in-memory code cache. Uses a single linear buffer for the
/// bootstrap; a real implementation would use a slab allocator.
pub struct CodeCache {
    /// Hash table mapping source_addr -> TranslationUnit.
    pub units: [Option<TranslationUnit>; 1024],
}

impl CodeCache {
    pub const fn empty() -> Self {
        const NONE: Option<TranslationUnit> = None;
        Self { units: [NONE; 1024] }
    }

    /// Look up the translation unit that owns `source_addr`.
    pub fn lookup(&self, source_addr: u64) -> Option<&TranslationUnit> {
        let h = (source_addr as usize) % self.units.len();
        if let Some(unit) = &self.units[h] {
            if unit.source_addr == source_addr {
                return Some(unit);
            }
        }
        None
    }

    /// Insert `unit` into the cache.
    pub fn insert(&mut self, unit: TranslationUnit) -> Option<&TranslationUnit> {
        let h = (unit.source_addr as usize) % self.units.len();
        self.units[h] = Some(unit);
        self.units[h].as_ref()
    }
}

/// Allocate `size` bytes from the code cache, returning the
/// resulting aligned pointer (or 0 on overflow).
pub fn allocate_code(size: usize) -> u64 {
    let mut pos = CODE_ALLOC_PTR.load(Ordering::Acquire);
    loop {
        let aligned = (pos + (CODE_ALIGNMENT as u64 - 1)) & !(CODE_ALIGNMENT as u64 - 1);
        let next = aligned + size as u64;
        if next > CODE_CACHE_SIZE as u64 {
            return 0;
        }
        match CODE_ALLOC_PTR.compare_exchange(pos, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return unsafe { CODE_BASE.as_ptr().add(aligned as usize) as u64 },
            Err(observed) => pos = observed,
        }
    }
}

/// Reset the code cache (used for cache invalidation when a
/// guest code page is replaced, e.g. via `mprotect`).
pub fn reset_code_cache() {
    CODE_ALLOC_PTR.store(0, Ordering::Release);
}

/// Insert `unit` into `cache` at its hash slot.
pub fn insert_unit(cache: &mut CodeCache, unit: TranslationUnit) {
    cache.insert(unit);
}

pub fn smoke_test() -> bool {
    // Allocate a few bytes; if it succeeds, the cache is reachable.
    let p = allocate_code(16);
    p != 0
}
