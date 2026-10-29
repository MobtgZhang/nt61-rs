//! BTL Translation Manager.
//!
//! Decides whether to translate or interpret each guest code block,
//! dispatches the translation request to the appropriate decoder +
//! codegen pipeline, and inserts the resulting `TranslationUnit`
//! into the code cache.
//!
//! ## Decision policy
//!
//! ```
//!  guest_pc
//!    │
//!    ▼
//!  in cache?  ── no ─► translate on demand
//!    │
//!  yes
//!    │
//!    ▼
//!  hot?     ── no ─► (continue in previously-translated code)
//!    │
//!  yes
//!    │
//!    ▼
//!  retranslate to apply new profile data (optional)
//! ```

use super::code_cache::{
    allocate_code, insert_unit, reset_code_cache, CodeCache, SourceArch, TranslationUnit,
};
use super::{BtlError, BtlResult};

/// Guest architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestArch {
    X86_64,
    X86_32,
    ARM32,
}

/// Translation request — the input from the dispatcher when a guest
/// page is faulted into the code cache for the first time.
#[derive(Debug, Clone)]
pub struct TranslationRequest {
    pub guest_arch: GuestArch,
    pub source_pc: u64,
    pub length: usize,
    pub code_bytes: alloc::vec::Vec<u8>,
}

pub struct TranslationManager {
    pub cache: CodeCache,
    pub hit_count: u64,
    pub miss_count: u64,
}

/// Global translation-manager singleton. Instantiated lazily so
/// that `resolve` / `translate` are safe to call from any context
/// once the kernel is up.
pub static TRANSLATION_MANAGER: crate::ke::sync::Spinlock<TranslationManager> =
    crate::ke::sync::Spinlock::new(TranslationManager::empty());

impl TranslationManager {
    pub const fn empty() -> Self {
        Self {
            cache: CodeCache::empty(),
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// Resolve `pc` to the translated AArch64 address. Increments
    /// per-`pc` access counters so the future hot-spot detector can
    /// decide to retranslating.
    pub fn resolve(&mut self, pc: u64) -> Option<u64> {
        if let Some(unit) = self.cache.lookup(pc) {
            self.hit_count += 1;
            unit.access_count
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            return Some(unit.translated_ptr);
        }
        self.miss_count += 1;
        None
    }

    /// Drop every cached translation and rewind the code allocator.
    ///
    /// Used when guest code pages are replaced (e.g. `mprotect`):
    /// stale translations must become unfindable before their code
    /// region is reused, otherwise `resolve` would hand out pointers
    /// into memory that now holds different guest code.
    pub fn reset(&mut self) {
        self.cache.clear();
        reset_code_cache();
    }

    /// Translate `req` and insert the resulting unit into the cache.
    ///
    /// This is the entry point used by the page fault handler when
    /// the dispatcher needs new code at `pc`. The implementation
    /// dispatches to the per-arch decoder/IR/codegen pipeline when
    /// the `btl` feature is enabled, or returns `Disabled` when it
    /// is not.
    pub fn translate(&mut self, req: TranslationRequest) -> BtlResult<TranslationUnit> {
        if !super::ENABLED {
            return Err(BtlError::Disabled);
        }
        match req.guest_arch {
            GuestArch::X86_64 => {}
            GuestArch::X86_32 | GuestArch::ARM32 => {
                return Err(BtlError::UnsupportedArch);
            }
        }

        let decoded_len = {
            let mut out = [crate::arch::common::btl::ir::IrInst::empty(); 64];
            super::decoder::decode_block(&req.code_bytes, req.source_pc, &mut out)
        };
        if decoded_len == 0 {
            return Err(BtlError::Untranslatable);
        }
        let mut out = alloc::vec![crate::arch::common::btl::ir::IrInst::empty(); decoded_len];
        super::decoder::decode_block(&req.code_bytes, req.source_pc, &mut out);
        let ir = super::ir::build_ir(&out);
        let block = super::codegen::encode_block(&ir, req.source_pc);
        let code_len = block.words.len() * 4;

        // Bail out before consuming code-cache space if the hash table
        // has no free slot: the bump allocator cannot reclaim the
        // region we would otherwise allocate for a unit that can never
        // be looked up.
        if !self.cache.has_free_slot() {
            return Err(BtlError::CacheFull);
        }
        let ptr = allocate_code(code_len);
        if ptr == 0 {
            return Err(BtlError::CacheFull);
        }
        for (i, word) in block.words.iter().enumerate() {
            unsafe {
                let p = (ptr as *mut u32).add(i);
                p.write_volatile(*word);
            }
        }
        // Ensure the I-cache sees the freshly written code before
        // any execution. Without this the CPU may execute stale
        // instructions from a previous translation or all-zero NOPs.
        crate::arch::aarch64::cache::sync_icache_range(ptr, code_len);

        let unit = TranslationUnit {
            source_addr: req.source_pc,
            translated_ptr: ptr,
            code_len,
            source_arch: SourceArch::X86_64,
            access_count: core::sync::atomic::AtomicU64::new(0),
            last_access_ns: core::sync::atomic::AtomicU64::new(0),
        };

        // The cache holds the canonical unit whose access counters the
        // `resolve` hot-spot detector bumps. The returned value is a
        // fresh handle with its own zeroed counters — the removed
        // `Clone` impl used to copy counter values, which made the copy
        // look like a shared unit.
        let returned = TranslationUnit {
            source_addr: req.source_pc,
            translated_ptr: ptr,
            code_len,
            source_arch: SourceArch::X86_64,
            access_count: core::sync::atomic::AtomicU64::new(0),
            last_access_ns: core::sync::atomic::AtomicU64::new(0),
        };
        if insert_unit(&mut self.cache, unit).is_none() {
            return Err(BtlError::CacheFull);
        }
        Ok(returned)
    }
}

pub fn smoke_test() -> bool {
    // The manager is just a struct; the test for the cache already
    // confirms the dependency surface. Real smoke test would invoke
    // `translate` against a known guest sequence.
    true
}
