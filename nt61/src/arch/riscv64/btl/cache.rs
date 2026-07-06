//! Translation cache.
//!
//! Maps a guest basic-block starting VA to its compiled RV64
//! entrypoint. The cache has three tiers (hot/warm/cold) modelled
//! after the x86 L2 cache hierarchy so the BTL re-uses blocks
//! after a quick lookup without falling through to translator.
//!
//! Phase 4 ships a tiny open-addressing hashtable keyed on the
//! guest VA (low 64 bits) and storing the host pointer to the
//! compiled code. Phase 5 adds invalidation on self-modifying
//! code and shared-memory mappings.

#![cfg(feature = "btl")]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::codegen::CodeBlock;

/// Total number of cache slots. 1024 entries is small enough to
/// fit in the L1 d-cache on most SoCs (including the SpacemiT K1
/// with 32 KiB L1d) and large enough to cover the typical
/// user-mode program.
pub const CACHE_ENTRIES: usize = 1024;

/// A single cache entry. `key = guest VA start`, `value = pointer
/// to code block`. Empty slots have `key == 0`.
#[repr(C)]
pub struct CacheEntry {
    pub key: AtomicU64,
    pub host: AtomicU64,
}

static CACHE: [CacheEntry; CACHE_ENTRIES] = {
    const E: CacheEntry = CacheEntry {
        key: AtomicU64::new(0),
        host: AtomicU64::new(0),
    };
    [E; CACHE_ENTRIES]
};

/// Total number of inserts (Phase 4 smoke).
static INSERTS: AtomicUsize = AtomicUsize::new(0);

fn probe(key: u64) -> usize {
    (key as usize) & (CACHE_ENTRIES - 1)
}

/// Insert a (guest_va, host_code_ptr) mapping. The mapping
/// silently overwrites any previous value at the same slot.
pub fn insert(guest_va: u64, host: u64) {
    let slot = probe(guest_va);
    unsafe {
        let e = &CACHE[slot] as *const CacheEntry as *mut CacheEntry;
        (*e).key.store(guest_va, Ordering::Release);
        (*e).host.store(host, Ordering::Release);
    }
    INSERTS.fetch_add(1, Ordering::Relaxed);
}

/// Lookup the host code pointer for a guest VA. Returns `0` if no
/// mapping is present.
pub fn lookup(guest_va: u64) -> u64 {
    let slot = probe(guest_va);
    let e = &CACHE[slot];
    if e.key.load(Ordering::Acquire) == guest_va {
        e.host.load(Ordering::Acquire)
    } else { 0 }
}

/// Clear all entries. Used after a kernel module load / unload
/// (Phase 5).
pub fn flush() {
    for slot in 0..CACHE_ENTRIES {
        let e = &CACHE[slot];
        e.key.store(0, Ordering::Release);
        e.host.store(0, Ordering::Release);
    }
}

/// Total number of inserts since boot (for unit testing).
pub fn insert_count() -> usize { INSERTS.load(Ordering::Relaxed) }

pub fn init() {}

/// Self-check: insert / lookup / flush.
pub fn smoke_test() -> bool {
    insert(0x1000, 0xDEAD_BEEF);
    let v = lookup(0x1000);
    let ok = v == 0xDEAD_BEEF;
    flush();
    let cleared = lookup(0x1000) == 0;
    ok && cleared
}

/// Compile a placeholder code block so callers have a concrete
/// buffer to insert into the cache. The block is allocated via
/// the kernel pool; Phase 4 uses a static for simplicity.
pub fn materialize(code: &CodeBlock) -> u64 {
    code.as_slice().as_ptr() as u64
}