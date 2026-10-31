//! Kernel Pool Allocator
//
//! Non-paged and paged pool allocation.
//
//! Implements NT-style kernel pool:
//!   * 8-byte pool header per allocation
//!   * 4-character pool tag (Big-Endian, e.g. `'Proc'`, `'Thre'`) used
//!     by `poolmon.exe` to identify leaks
//!   * separate descriptors for paged/non-paged so a low-memory page
//!     fault cannot deadlock a non-paged caller
//!   * Free list with coalescing for memory efficiency
//
//!     The actual back-end is a bump-allocator that pulls from the global
//!     non-paged pool region set up by `mm::heap::init`.

extern crate alloc;

use crate::rtl::logging::{subsystem as log_subsystem, LogLevel};
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicU64, Ordering};

/// Pool diagnostics.
///
/// The allocation path used to emit 18 unconditional UART writes per
/// allocation. On a 115200 baud console that is on the order of a
/// millisecond of serial time for every pool hit, which is more than the
/// allocation itself, and it buries the diagnostics that actually matter
/// (double free, tag mismatch). Diagnostics are now emitted only when the
/// MEMORY subsystem logs at the requested level, and as one line per
/// decision instead of a pre/post breadcrumb pair.
pub fn trace(level: LogLevel, args: core::fmt::Arguments<'_>) {
    if level == LogLevel::Debug {
        return;
    }
    if !crate::rtl::logging::should_log(level, log_subsystem::MEMORY) {
        return;
    }
    use core::fmt::Write;
    let mut buf = [0u8; 128];
    let mut writer = crate::rtl::klog::BufferWriter::new(&mut buf);
    let _ = writer.write_fmt(args);
    let len = writer.pos();
    let cpu = crate::rtl::logging::current_cpu();
    crate::rtl::logging::log_write_impl(
        level,
        "MEMORY",
        cpu,
        core::str::from_utf8(&buf[..len]).unwrap_or("<bad log utf8>"),
    );
}

macro_rules! pool_trace {
    ($level:expr, $($arg:tt)*) => {
        $crate::mm::pool::trace($level, core::format_args!($($arg)*))
    };
}

pub use crate::ke::sync::Spinlock;

/// Pool types matching Windows definitions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PoolType {
    NonPaged = 0,
    Paged = 1,
    NonPagedSession = 2,
    PagedSession = 3,
    NonPagedMustSucceed = 4,
    NonPagedExecute = 5,
    PagedExecute = 6,
    NonPagedSessionExecute = 7,
    PagedSessionExecute = 8,
    NonPagedNxCache = 9,
    NonPagedNxCacheExecute = 10,
}

impl PoolType {
    pub fn is_paged(&self) -> bool {
        matches!(
            self,
            PoolType::Paged
                | PoolType::PagedSession
                | PoolType::PagedExecute
                | PoolType::PagedSessionExecute
        )
    }

    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            PoolType::NonPagedExecute
                | PoolType::PagedExecute
                | PoolType::NonPagedSessionExecute
                | PoolType::PagedSessionExecute
                | PoolType::NonPagedNxCacheExecute
        )
    }
}

/// Pool header flags.
pub const BLOCK_FREED: u8 = 0x01;

/// Pool header (aligned to 8 bytes on x86).
#[repr(C)]
#[repr(align(32))]
pub struct PoolHeader {
    // NT 6.1 stores the block sizes as 20-bit fields inside 32-bit words.
    // Keeping them as u16 truncated any allocation above 65535 bytes, so the
    // recorded size no longer matched the real block and `free()` reclaimed
    // the wrong span, corrupting the pool.
    pub previous_size: u32,
    pub block_size: u32,
    pub pool_type: u8,
    pub flags: u8, // Changed from padding to flags for double-free detection
    pub pool_tag: u32,
    /// NT uses this to chain all allocations of the same tag into a
    /// per-tag list for `poolmon`. We just keep it as opaque book-
    /// keeping here.
    pub allocator_back_trace_index: u16,
    pub reserved: [u16; 3],
    /// Pad to a 32-byte boundary so the user pointer (header + 32)
    /// is itself 32-byte aligned. The pool is asked to honour the
    /// strongest alignment requirement of any pool allocation,
    /// and `#[repr(align(N>16))]` Rust types (e.g. VadEntry at
    /// 32 bytes) need the user pointer to be a multiple of N.
    _align_pad: [u8; 8],
}

impl PoolHeader {
    pub const HEADER_SIZE: usize = core::mem::size_of::<PoolHeader>();
    pub const BLOCK_VALID: u8 = 0x00;

    /// Check if this block has been freed (double-free detection).
    pub fn is_freed(&self) -> bool {
        (self.flags & BLOCK_FREED) != 0
    }

    /// Mark this block as freed to prevent double-free.
    pub fn mark_freed(&mut self) {
        self.flags |= BLOCK_FREED;
    }
}

/// Pool descriptor (one per pool type).
pub struct PoolDescriptor {
    pub pool_type: PoolType,
    /// Authoritative total bytes outstanding. Updated on every
    /// successful alloc / free regardless of whether the block
    /// came from the bump allocator or the free list.
    pub total_bytes: u64,
    pub total_pages: u64,
    pub total_allocs: AtomicU64,
    pub threshold: u64,
    /// Number of times the free-list coalesced two adjacent free
    /// blocks into one. Moved here from the old PoolState so all
    /// pool statistics live in a single authoritative structure.
    pub coalesce_count: u64,
}

impl PoolDescriptor {
    pub const fn new(pool_type: PoolType) -> Self {
        Self {
            pool_type,
            total_bytes: 0,
            total_pages: 0,
            total_allocs: AtomicU64::new(0),
            threshold: 0x1000,
            coalesce_count: 0,
        }
    }
}

/// Pool statistics snapshot returned by `get_stats`. Single source
/// of truth — every field is read from `PoolDescriptor`.
pub struct PoolStats {
    pub total_bytes: u64,
    pub total_pages: u64,
    pub coalesce_count: u64,
    pub total_allocs: u64,
}

/// Global pool descriptors.
static NON_PAGED_POOL: Spinlock<PoolDescriptor> =
    Spinlock::new(PoolDescriptor::new(PoolType::NonPaged));
static PAGED_POOL: Spinlock<PoolDescriptor> = Spinlock::new(PoolDescriptor::new(PoolType::Paged));

/// Convert a 4-byte ASCII tag to a 32-bit `u32` with the
/// little-endian packing NT uses ('Proc' = 0x636F7250).
pub const fn make_tag(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_le_bytes([a, b, c, d])
}

/// Well-known pool tags.
pub mod tags {
    use super::make_tag;
    pub const PROCESS: u32 = make_tag(b'P', b'r', b'o', b'c');
    pub const THREAD: u32 = make_tag(b'T', b'h', b'r', b'e');
    pub const EVENT: u32 = make_tag(b'E', b'v', b't', b' ');
    pub const MUTEX: u32 = make_tag(b'M', b'u', b't', b'x');
    pub const SECTION: u32 = make_tag(b'S', b'e', b'c', b't');
    pub const FILE: u32 = make_tag(b'F', b'i', b'l', b'e');
    pub const DRIVER: u32 = make_tag(b'D', b'r', b'v', b'r');
    pub const IRP: u32 = make_tag(b'I', b'r', b'p', b' ');
    pub const IO: u32 = make_tag(b'I', b'O', b' ', b' ');
    pub const MM: u32 = make_tag(b'M', b'm', b' ', b' ');
    // Network-related tags
    pub const NETBUF: u32 = make_tag(b'N', b'B', b'u', b'f'); // Network buffer
    pub const NETNBL: u32 = make_tag(b'N', b'B', b'L', b' '); // NET_BUFFER_LIST
    pub const NETNB: u32 = make_tag(b'N', b'B', b' ', b' '); // NET_BUFFER
    pub const NETMDL: u32 = make_tag(b'M', b'D', b'L', b' '); // MDL
    pub const NETDESC: u32 = make_tag(b'N', b'D', b's', b'c'); // NIC descriptor
    pub const NETTCB: u32 = make_tag(b'T', b'C', b'B', b' '); // TCP control block
    pub const NETSOCK: u32 = make_tag(b'S', b'O', b'C', b'K'); // Socket
    pub const NETPACK: u32 = make_tag(b'P', b'K', b'T', b' '); // Packet
    pub const NETVIRT: u32 = make_tag(b'V', b'I', b'R', b'T'); // Virtqueue
}

/// Lookaside list entry. Real NT lookasides are per-CPU structures;
/// for the bootstrap we use a single global count.
pub struct LookasideList {
    pub size: usize,
    pub tag: u32,
    pub alloc_hits: AtomicU64,
    pub alloc_missed: AtomicU64,
    pub free_hits: AtomicU64,
    pub free_missed: AtomicU64,
}

impl LookasideList {
    pub const fn new(size: usize, tag: u32) -> Self {
        Self {
            size,
            tag,
            alloc_hits: AtomicU64::new(0),
            alloc_missed: AtomicU64::new(0),
            free_hits: AtomicU64::new(0),
            free_missed: AtomicU64::new(0),
        }
    }
}

/// Raw allocation helper - asks the kernel heap for a chunk and writes
/// a `PoolHeader` at the front.
///
/// We first try to allocate from the free list (for memory reuse),
/// then fall back to the bump allocator if no suitable block is found.
fn alloc_raw(total_size: usize, pool_type: PoolType, tag: u32) -> *mut u8 {
    // Free-list entries record the complete block, including the header, so
    // requests must be normalized before searching. Otherwise the split point
    // can land inside the user region and corrupt data on first use.
    let align = 16usize;
    let padded = (total_size + align - 1) & !(align - 1);
    let total_alloc_size = PoolHeader::HEADER_SIZE + padded;
    let user_align = align.max(32);
    let layout = match Layout::from_size_align(total_alloc_size, user_align) {
        Ok(l) => l,
        Err(_) => {
            pool_trace!(
                LogLevel::Error,
                "alloc_raw: invalid layout size={}",
                total_size
            );
            return core::ptr::null_mut();
        }
    };

    // First, try to allocate from the free list (fast path for freed memory)
    if let Some(ptr) = allocate_from_freelist(pool_type, total_alloc_size) {
        pool_trace!(
            LogLevel::Debug,
            "alloc_raw: freelist hit ptr=0x{:x} size={}",
            ptr as u64,
            total_alloc_size
        );
        unsafe {
            let header = ptr.sub(PoolHeader::HEADER_SIZE) as *mut PoolHeader;
            (*header).previous_size = 0;
            (*header).pool_tag = tag;
        }
        // The freelist path also needs to update the authoritative
        // PoolDescriptor stats (was previously leaking allocations
        // - only the bump path incremented total_bytes / total_allocs).
        let descriptor = if pool_type.is_paged() {
            &PAGED_POOL
        } else {
            &NON_PAGED_POOL
        };
        let mut d = descriptor.lock();
        d.total_bytes += total_size as u64;
        d.total_allocs.fetch_add(1, Ordering::Relaxed);
        return ptr;
    }

    // SAFETY: We call our own KernelHeap directly. The bump
    // allocator is single-threaded for the pool's purposes (the
    // pool is protected by a spinlock at the descriptor level,
    // not at the per-allocation level).
    let ptr = unsafe {
        <crate::mm::heap::KernelHeap as GlobalAlloc>::alloc(&crate::mm::heap::KERNEL_HEAP, layout)
    };
    if ptr.is_null() {
        match crate::mm::heap::KERNEL_HEAP.configured_region() {
            Some((base, size)) => pool_trace!(
                LogLevel::Error,
                "alloc_raw: heap exhausted size={} region=0x{:x}+0x{:x}",
                PoolHeader::HEADER_SIZE + padded,
                base as u64,
                size as u64,
            ),
            None => pool_trace!(
                LogLevel::Error,
                "alloc_raw: heap not configured size={}",
                PoolHeader::HEADER_SIZE + padded,
            ),
        }
        return core::ptr::null_mut();
    }

    unsafe {
        let header = ptr as *mut PoolHeader;
        (*header).previous_size = 0;
        (*header).block_size = (PoolHeader::HEADER_SIZE + padded) as u32;
        (*header).pool_type = pool_type as u8;
        (*header).flags = PoolHeader::BLOCK_VALID; // Initialize flags
        (*header).pool_tag = tag;
        (*header).allocator_back_trace_index = 0;
        (*header).reserved = [0; 3];
    }

    let descriptor = if pool_type.is_paged() {
        &PAGED_POOL
    } else {
        &NON_PAGED_POOL
    };

    let mut d = descriptor.lock();
    d.total_bytes += (PoolHeader::HEADER_SIZE + padded) as u64;
    d.total_allocs.fetch_add(1, Ordering::Relaxed);
    drop(d);
    // SAFETY: Zero the user region with byte writes to avoid any SIMD
    // alignment issues. The user is expected to populate the struct
    // with field-by-field assignments, not with `core::ptr::write`
    // of a 32-byte aligned Rust struct (which would use a 32-byte
    // aligned SSE/AVX store that requires the stack to also be
    // 32-byte aligned for the source).
    let user_ptr = unsafe { ptr.add(PoolHeader::HEADER_SIZE) };
    unsafe {
        core::ptr::write_bytes(user_ptr, 0u8, padded);
    }

    pool_trace!(
        LogLevel::Debug,
        "alloc_raw: bump hit ptr=0x{:x} size={} tag={}",
        ptr as u64,
        total_size,
        tag,
    );
    user_ptr
}

/// Allocate `size` bytes of pool memory of the given type.
pub fn allocate(pool_type: PoolType, size: usize) -> *mut u8 {
    // We call alloc_raw directly without an outer with_pool_state
    // wrapper, because alloc_raw internally calls allocate_from_freelist
    // which acquires the POOL_STATE lock itself. Wrapping here would
    // cause a deadlock on our non-reentrant Spinlock.
    // The lazy initialization in ensure_pool_state_initialized() is
    // called from within allocate_from_freelist's ensure_pool_state_initialized(),
    // and also from the bump-allocator fallback below.
    crate::mm::pool::ensure_pool_state_initialized();
    let p = alloc_raw(size, pool_type, 0);
    pool_trace!(LogLevel::Debug, "allocate({}) -> 0x{:x}", size, p as u64);
    p
}

/// Allocate `size` bytes of pool memory with an explicit 4-character tag.
pub fn allocate_tagged(pool_type: PoolType, size: usize, tag: u32) -> *mut u8 {
    let ptr = alloc_raw(size, pool_type, tag);
    if !ptr.is_null() {
        unsafe {
            let header_ptr = ptr.sub(PoolHeader::HEADER_SIZE) as *mut PoolHeader;
            (*header_ptr).pool_tag = tag;
        }
    }
    ptr
}

/// Allocate aligned memory from pool.
/// This is useful for DMA operations that require aligned buffers.
pub fn allocate_aligned(pool_type: PoolType, size: usize, alignment: usize) -> *mut u8 {
    // Alignment must be at least 16 (pool header alignment)
    let align = alignment.max(16);
    if size == 0 {
        return core::ptr::null_mut();
    }

    // Padding has to be computed from the *base address*, not from `size`:
    // `size % align` says nothing about whether the returned pointer is
    // aligned. Reserve `align` slack plus 8 bytes for the back-pointer that
    // `free_aligned` needs.
    let ptr = alloc_raw(size + align + 8, pool_type, 0);
    if ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Always start the aligned region at least 8 bytes past the real user
    // pointer, so the back-pointer slot is inside the allocation even when the
    // base is already aligned. Without this, `free_aligned` would read the
    // pool header as metadata.
    let addr = ptr as usize;
    let aligned = (addr + 8 + align - 1) & !(align - 1);
    let aligned_ptr = aligned as *mut u8;
    unsafe {
        let meta_ptr = (aligned_ptr as *mut *mut u8).sub(1);
        *meta_ptr = ptr;
    }

    aligned_ptr
}

/// Free a pointer returned by `allocate_aligned`.
///
/// `free()` cannot be used here: it reads a `PoolHeader` at `ptr - HEADER_SIZE`,
/// while an aligned allocation only guarantees a back-pointer at `ptr - 8`.
/// Returns null, matching `free()`.
///
/// # Safety
/// `ptr` must have been returned by `allocate_aligned` with the same alignment.
pub fn free_aligned(ptr: *mut u8) -> *mut u8 {
    unsafe {
        if ptr.is_null() {
            return core::ptr::null_mut();
        }
        let original = unsafe { *((ptr as *mut *mut u8).sub(1)) };
        free(original)
    }
}

/// Free a previous pool allocation and return null.
///
/// This function implements proper deallocation with free list support and coalescing.
/// After freeing, it returns null to prevent use-after-free bugs.
///
/// # Safety
///
/// - The pointer must have been allocated by `allocate` or `allocate_tagged`
/// - The pointer must not be used after calling this function
/// - The pointer must not be freed twice
///
/// # Example
///
/// ```ignore
/// let ptr = pool::allocate(pool::PoolType::NonPaged, size);
/// // use ptr...
/// ptr = pool::free(ptr);  // Now ptr is null
/// ```
pub unsafe fn free(ptr: *mut u8) -> *mut u8 {
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let header_ptr = ptr.sub(PoolHeader::HEADER_SIZE);
        let header = &mut *(header_ptr as *mut PoolHeader);

        // Check for double-free vulnerability
        if header.is_freed() {
            // NT treats a double free as pool corruption. Returning here would
            // let the allocator continue from a free list that may have already
            // been mutated for this block, so the condition must be fatal and
            // carry the caller address/tag in the bugcheck parameters.
            crate::kprintln!(
                level: crate::rtl::logging::LogLevel::Error,
                subsystem: "POOL",
                "DOUBLE FREE DETECTED at 0x{:x} (already freed, tag=0x{:08x})",
                ptr as u64, header.pool_tag
            );
            crate::ke::bugcheck::bugcheck_with(
                crate::ke::bugcheck::BugCheckCode::BadPoolCaller,
                0x2,
                ptr as u64,
                header.pool_tag as u64,
                0,
            );
        }

        // Mark block as freed to prevent double-free
        header.mark_freed();

        let total = header.block_size as usize;

        let pool_type_val = header.pool_type;

        // Convert pool type byte back to PoolType enum
        let pool_type = match pool_type_val {
            0 => PoolType::NonPaged,
            1 => PoolType::Paged,
            2 => PoolType::NonPagedSession,
            3 => PoolType::PagedSession,
            4 => PoolType::NonPagedMustSucceed,
            5 => PoolType::NonPagedExecute,
            6 => PoolType::PagedExecute,
            7 => PoolType::NonPagedSessionExecute,
            8 => PoolType::PagedSessionExecute,
            9 => PoolType::NonPagedNxCache,
            10 => PoolType::NonPagedNxCacheExecute,
            _ => PoolType::NonPaged,
        };

        // Add to free list for future allocations (with coalescing)
        free_to_freelist(header_ptr, total, pool_type);

        let descriptor = if pool_type.is_paged() {
            &PAGED_POOL
        } else {
            &NON_PAGED_POOL
        };

        let mut d = descriptor.lock();
        d.total_bytes = d.total_bytes.saturating_sub(total as u64);
        drop(d);

        // Return null to prevent use-after-free
        // [DISABLED] // // kprintln!(
        // // // [DISABLED]             level: crate::rtl::logging::LogLevel::Debug,
        // // // [DISABLED]             subsystem: "POOL",
        // // // [DISABLED]             "free: freed {} bytes, returning null", total
        // // // [DISABLED]         );
        core::ptr::null_mut()
    }
}

/// Macro to free and null a pointer in one expression.
///
/// # Example
///
/// ```ignore
/// FREE_NULL!(ptr);  // ptr is now null
/// ```
#[macro_export]
macro_rules! FREE_NULL {
    ($ptr:expr) => {{
        let ptr = $ptr;
        if !ptr.is_null() {
            $crate::mm::pool::free(ptr)
        } else {
            core::ptr::null_mut()
        }
    }};
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Free with tag (for tracking purposes).
/// Returns null like `free()`.
pub unsafe fn free_with_tag(ptr: *mut u8, tag: u32) -> *mut u8 {
    // Verify tag matches if possible (for debugging builds)
    if !ptr.is_null() {
        unsafe {
            let header_ptr = ptr.sub(PoolHeader::HEADER_SIZE);
            let header = &*(header_ptr as *const PoolHeader);
            if header.pool_tag != tag {
                // A mismatched tag means the caller is freeing an allocation
                // through the wrong ownership contract. Windows reports this
                // as BAD_POOL_CALLER rather than silently freeing the block.
                crate::kprintln!(
                    level: crate::rtl::logging::LogLevel::Warn,
                    subsystem: "POOL",
                    "free_with_tag mismatch: expected {:08x}, got {:08x}",
                    tag, header.pool_tag
                );
                crate::ke::bugcheck::bugcheck_with(
                    crate::ke::bugcheck::BugCheckCode::BadPoolCaller,
                    0x9,
                    ptr as u64,
                    header.pool_tag as u64,
                    tag as u64,
                );
            }
        }
    }
    free(ptr)
}

/// Query pool statistics.
///
/// Returns a `PoolStats` snapshot read from `PoolDescriptor` —
/// the single authoritative source for pool statistics.
pub fn get_stats(pool_type: PoolType) -> PoolStats {
    if pool_type.is_paged() {
        let d = PAGED_POOL.lock();
        PoolStats {
            total_bytes: d.total_bytes,
            total_pages: d.total_pages,
            coalesce_count: d.coalesce_count,
            total_allocs: d.total_allocs.load(Ordering::Relaxed),
        }
    } else {
        let d = NON_PAGED_POOL.lock();
        PoolStats {
            total_bytes: d.total_bytes,
            total_pages: d.total_pages,
            coalesce_count: d.coalesce_count,
            total_allocs: d.total_allocs.load(Ordering::Relaxed),
        }
    }
}

/// Deprecated: prefer [`get_stats`] which returns the full
/// `PoolStats` snapshot. This stub returns
/// `(total_bytes, total_pages, coalesce_count)` for the
/// non-paged pool so existing call sites still compile.
#[deprecated(
    since = "0.1.0",
    note = "Use get_stats(pool_type) -> PoolStats instead"
)]
pub fn get_pool_stats() -> (u64, u64, u64) {
    let s = get_stats(PoolType::NonPaged);
    (s.total_bytes, s.total_pages, s.coalesce_count)
}

/// Initialize the pool allocator.
pub fn init() {
    let _l1 = LookasideList::new(64, tags::PROCESS);
    let _l2 = LookasideList::new(128, tags::THREAD);
}

// =============================================================================
// Free List Management (for coalescing)
// =============================================================================

/// Free block entry in the free list
#[repr(C)]
pub struct FreeBlock {
    /// Size of this free block (including header)
    pub size: usize,
    /// Pool type. Stored as `u8` so the `PoolHeader` freed flag at the next
    /// byte is not overwritten by free-list metadata.
    pub pool_type: u8,
}

impl FreeBlock {
    pub fn new(size: usize, pool_type: PoolType) -> Self {
        Self {
            size,
            pool_type: pool_type as u8,
        }
    }
}

/// Pool state with free lists.
///
/// Statistics (total_allocated / total_freed / coalesce_count) used
/// to live here but they were tracked in two places — here and on
/// `PoolDescriptor` — and the two numbers drifted. They are now
/// owned exclusively by `PoolDescriptor`; this struct only holds
/// the actual free-list bookkeeping.
pub struct PoolState {
    /// Free list for non-paged pool
    pub nonpaged_freelist: Vec<*mut FreeBlock>,
    /// Free list for paged pool
    pub paged_freelist: Vec<*mut FreeBlock>,
    /// Pool initialized flag
    pub initialized: bool,
}

impl PoolState {
    pub fn new() -> Self {
        Self {
            nonpaged_freelist: Vec::new(),
            paged_freelist: Vec::new(),
            initialized: false,
        }
    }
}

impl Default for PoolState {
    fn default() -> Self {
        Self::new()
    }
}

/// Pool state with free lists (lazily initialized)
static POOL_STATE: Spinlock<Option<PoolState>> = Spinlock::new(None);

/// internal helper to ensure pool state is initialized.
/// Must be called without holding any locks to avoid deadlock.
fn ensure_pool_state_initialized() {
    // Check without lock first (fast path)
    {
        let guard = POOL_STATE.lock();
        if guard.is_some() {
            return;
        }
    }

    // Slow path: acquire lock and init if needed
    let mut guard = POOL_STATE.lock();
    if guard.is_none() {
        *guard = Some(PoolState::new());
    }
    // guard dropped here, state remains initialized
}

/// Get mutable pool state reference - ensures initialization before returning
/// NOTE: Caller must not hold any spinlocks to avoid deadlock!
fn with_pool_state_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut PoolState) -> R,
{
    // Ensure initialization first (no locks held)
    ensure_pool_state_initialized();

    // Acquire lock and call closure
    let mut guard = POOL_STATE.lock();
    // State is guaranteed to exist now
    let result = f(unsafe { guard.as_mut().unwrap_unchecked() });
    drop(guard);
    result
}

/// Minimum allocation size for free list entries
const MIN_FREE_BLOCK_SIZE: usize = 32;

/// Try to allocate from free list
/// Returns Some(ptr) if a suitable block is found, None otherwise
pub fn allocate_from_freelist(pool_type: PoolType, size: usize) -> Option<*mut u8> {
    ensure_pool_state_initialized();
    with_pool_state_mut(|state| {
        let freelist = if pool_type.is_paged() {
            &mut state.paged_freelist
        } else {
            &mut state.nonpaged_freelist
        };

        // If freelist is empty (initial state), skip the search
        if freelist.is_empty() {
            return None;
        }

        // Find a block large enough to satisfy `size`. We try to keep
        // a leftover free block when it still meets MIN_FREE_BLOCK_SIZE
        // (so it can be reused later); otherwise we hand the whole
        // block to the caller rather than wasting it.
        for i in 0..freelist.len() {
            let block_ptr = freelist[i];
            if block_ptr.is_null() {
                continue;
            }
            unsafe {
                let block = &*block_ptr;
                if block.size < size {
                    continue;
                }

                let remaining_size = block.size - size;

                if remaining_size >= MIN_FREE_BLOCK_SIZE {
                    // Split: create new free block for remainder
                    let new_block_ptr = block_ptr.add(size);
                    (*new_block_ptr) = FreeBlock::new(remaining_size, pool_type);
                    freelist[i] = new_block_ptr;
                } else {
                    // Remainder too small to track — give the whole
                    // block to the caller rather than split it.
                    freelist[i] = core::ptr::null_mut();
                }

                // Initialize PoolHeader so callers can safely call
                // `free()` on this block. Previously the old FreeBlock
                // data was left in place, causing stale/uninitialized
                // header fields and false-positive double-free detection.
                let block_start = block_ptr as *mut u8;
                let total_alloc_size = size; // includes HEADER_SIZE
                let header = block_start as *mut PoolHeader;
                (*header).block_size = total_alloc_size as u32;
                (*header).pool_type = pool_type as u8;
                (*header).flags = PoolHeader::BLOCK_VALID;
                core::ptr::write_bytes(
                    block_start.add(PoolHeader::HEADER_SIZE),
                    0,
                    total_alloc_size.saturating_sub(PoolHeader::HEADER_SIZE),
                );
                return Some(block_start.add(PoolHeader::HEADER_SIZE));
            }
        }
        None
    })
}

/// Add a freed block to the free list for future allocation
/// Implements coalescing: merges with adjacent free blocks
pub fn free_to_freelist(ptr: *mut u8, total_size: usize, pool_type: PoolType) {
    ensure_pool_state_initialized();
    with_pool_state_mut(|state| {
        // create a free block from the freed memory
        let block_ptr = ptr as *mut FreeBlock;
        unsafe {
            (*block_ptr) = FreeBlock::new(total_size, pool_type);
        }

        let freelist = if pool_type.is_paged() {
            &mut state.paged_freelist
        } else {
            &mut state.nonpaged_freelist
        };

        // Get block boundaries for coalescing
        let block_start = ptr as usize;
        let block_end = block_start + total_size;

        // Find position to insert (keep list sorted by address)
        // and coalesce with adjacent blocks. Coalesce count is
        // recorded on the PoolDescriptor (the single source of
        // truth) rather than on PoolState.
        let mut insert_pos = freelist.len();
        let mut i = 0;
        while i < freelist.len() {
            let existing_ptr = freelist[i];
            if existing_ptr.is_null() {
                i += 1;
                continue;
            }
            unsafe {
                let existing_start = existing_ptr as usize;
                let existing_end = existing_start + (*existing_ptr).size;

                // Check if blocks are adjacent and can be merged
                if existing_end == block_start {
                    // existing block is directly before our block
                    // Merge: extend existing block
                    (*existing_ptr).size += total_size;
                    bump_coalesce_count(pool_type);
                    // [DISABLED] // // kprintln!(
                    // // // [DISABLED]                         level: crate::rtl::logging::LogLevel::Debug,
                    // // // [DISABLED]                         subsystem: "POOL",
                    // // // [DISABLED]                         "Coalesced: block before + our block, new_size={}",
                    // // // [DISABLED]                         (*existing_ptr).size
                    // // // [DISABLED]                     );
                    return;
                } else if block_end == existing_start {
                    // existing block is directly after our block
                    // Merge: extend our block and replace existing
                    (*block_ptr).size += (*existing_ptr).size;
                    freelist[i] = block_ptr;
                    bump_coalesce_count(pool_type);
                    // [DISABLED] // // kprintln!(
                    // // // [DISABLED]                         level: crate::rtl::logging::LogLevel::Debug,
                    // // // [DISABLED]                         subsystem: "POOL",
                    // // // [DISABLED]                         "Coalesced: our block + block after, new_size={}",
                    // // // [DISABLED]                         (*block_ptr).size
                    // // // [DISABLED]                     );

                    // Remove the old entry (already replaced)
                    // and return since we're done
                    return;
                } else if existing_start > block_start && insert_pos == freelist.len() {
                    // Insert before this block (sorted order)
                    insert_pos = i;
                }
            }
            i += 1;
        }

        // Insert the block into the free list
        if insert_pos >= freelist.len() {
            freelist.push(block_ptr);
        } else {
            freelist.insert(insert_pos, block_ptr);
        }

        // [DISABLED] // // kprintln!(
        // // // [DISABLED]             level: crate::rtl::logging::LogLevel::Debug,
        // // // [DISABLED]             subsystem: "POOL",
        // // // [DISABLED]             "free_to_freelist: inserted block size={} at position {}",
        // // // [DISABLED]             total_size, insert_pos
        // // // [DISABLED]         );
    });
}

/// Increment the coalesce count on the PoolDescriptor for the
/// given pool type. PoolState no longer owns this counter.
fn bump_coalesce_count(pool_type: PoolType) {
    let descriptor = if pool_type.is_paged() {
        &PAGED_POOL
    } else {
        &NON_PAGED_POOL
    };
    let mut d = descriptor.lock();
    d.coalesce_count += 1;
}

/// Get pool statistics (deprecated — see get_stats above).
const _POOL_STATS_PLACEHOLDER: () = ();

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_test_heap() {
        if crate::mm::heap::KERNEL_HEAP.configured_region().is_some() {
            return;
        }

        const TEST_HEAP_LEN: usize = 4 * 1024 * 1024;
        static mut TEST_HEAP: [u8; TEST_HEAP_LEN] = [0u8; TEST_HEAP_LEN];
        let len = TEST_HEAP_LEN;
        crate::mm::heap::KERNEL_HEAP.configure(core::ptr::addr_of_mut!(TEST_HEAP) as *mut u8, len);
    }

    #[test]
    #[should_panic(expected = "bugcheck 0x000000C2 p1=0x2")]
    fn double_free_bugs_check() {
        ensure_test_heap();
        let ptr = allocate_tagged(PoolType::NonPaged, 32, tags::MM);
        assert!(!ptr.is_null());
        unsafe {
            free(ptr);
        }
        unsafe {
            free(ptr);
        }
    }

    #[test]
    #[should_panic(expected = "bugcheck 0x000000C2 p1=0x9")]
    fn mismatched_pool_tag_bugs_check() {
        ensure_test_heap();
        let ptr = allocate_tagged(PoolType::NonPaged, 32, tags::PROCESS);
        assert!(!ptr.is_null());
        unsafe {
            free_with_tag(ptr, tags::THREAD);
        }
    }
}
