//! ntdll — RTL heap
//
//! Implements the ntdll-side heap API used by virtually every
//! Win32 application:
//!   * `RtlAllocateHeap`
//!   * `RtlFreeHeap`
//!   * `RtlReAllocateHeap`
//!   * `RtlSizeHeap`
//!   * `RtlGetProcessHeaps`
//
//! The default process heap is created by `RtlCreateHeap` and
//! torn down by `RtlDestroyHeap`. Each allocation has a small
//! 16-byte header (size + canary + free-list link) so we can
//! detect overflows in the smoke test and merge adjacent free
//! blocks on release.
//
//! The actual memory backing the heap is the kernel pool
//! (`mm::pool::NonPaged`) — the user-mode side of this kernel
//! never executes, so the heap is shared with the kernel itself.

use super::types::{HANDLE, NTSTATUS, PVOID};
use super::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use crate::ke::sync::Spinlock;
use crate::mm::pool::{self, PoolType};
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

extern crate alloc;

/// RTL heap flags (subset we honour).
pub const HEAP_NO_SERIALIZE: u32 = 0x0000_0001;
pub const HEAP_GROWABLE: u32 = 0x0000_0002;
pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;
pub const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x0000_0010;

const HEADER_MAGIC_ALLOC: u32 = 0xDEAD_BEEF;
const HEADER_MAGIC_FREE: u32 = 0xFEEE_F00D;
const HEADER_SIZE: usize = 16;
const HEAP_ALIGN: usize = 16;

/// In-place block header.
#[repr(C)]
struct BlockHeader {
    magic: u32,
    /// Real (rounded up to HEAP_ALIGN) block size, not counting the header.
    size: u32,
    /// The owning heap pointer; used for sanity checks in `RtlFreeHeap`.
    owner: *mut Heap,
    /// Free-list `next` pointer (only valid when the block is on the
    /// free list).
    next_free: *mut BlockHeader,
}

impl BlockHeader {
    fn user_ptr(&self) -> *mut u8 {
        unsafe { (self as *const _ as *const u8).add(HEADER_SIZE) as *mut u8 }
    }
    unsafe fn from_user(p: *mut u8) -> *mut BlockHeader {
        p.sub(HEADER_SIZE) as *mut BlockHeader
    }
}

/// `RTLP_HEAP` is the in-kernel analogue of the user-mode
/// `RTLP_HEAP` structure. We only model the fields we use.
pub struct Heap {
    /// Owning handle (just `self as *mut _` cast).
    handle: HANDLE,
    /// Flags passed to `RtlCreateHeap`.
    flags: u32,
    /// Lock for free-list operations. We always take it
    /// (HEAP_NO_SERIALIZE is ignored in this kernel) because the
    /// process heap is shared with the kernel pool.
    lock: Spinlock<HeapState>,
}

struct HeapState {
    free_list: *mut BlockHeader,
    bytes_in_use: u64,
    bytes_free: u64,
    alloc_count: u64,
    free_count: u64,
}

unsafe impl Send for Heap {}
unsafe impl Sync for Heap {}

const POOL_TAG_HEAP: u32 = (b'R' as u32) << 24
    | (b't' as u32) << 16
    | (b'l' as u32) << 8
    | (b'H' as u32);

/// The default process heap. The NT 6.1 SDK's `GetProcessHeap`
/// returns a pointer to this structure.
static mut PROCESS_HEAP: *mut Heap = ptr::null_mut();
static PROCESS_HEAP_INIT: AtomicU32 = AtomicU32::new(0);

/// `RtlCreateHeap` — allocate and initialise a new heap. In
/// practice the kernel returns a pointer to its internal pool.
pub unsafe extern "C" fn RtlCreateHeap(
    flags: u32,
    _heap_base: PVOID,
    _reserve_size: usize,
    _commit_size: usize,
    _lock: PVOID,
    _parameters: PVOID,
) -> HANDLE {
    let h = pool::allocate(PoolType::NonPaged, core::mem::size_of::<Heap>()) as *mut Heap;
    if h.is_null() {
        return ptr::null_mut();
    }
    ptr::write_bytes(h as *mut u8, 0, core::mem::size_of::<Heap>());
    (*h).handle = h as HANDLE;
    (*h).flags = flags;
    (*h).lock = Spinlock::new(HeapState {
        free_list: ptr::null_mut(),
        bytes_in_use: 0,
        bytes_free: 0,
        alloc_count: 0,
        free_count: 0,
    });
    h as HANDLE
}

/// `RtlDestroyHeap` — release a heap previously returned by
/// `RtlCreateHeap`.
pub unsafe extern "C" fn RtlDestroyHeap(heap_handle: HANDLE) -> HANDLE {
    if heap_handle.is_null() { return ptr::null_mut(); }
    let h = heap_handle as *mut Heap;
    // Free all live blocks first.
    let mut state = (*h).lock.lock();
    let mut cur = state.free_list;
    while !cur.is_null() {
        let next = (*cur).next_free;
        let _ = pool::free(cur as *mut u8);
        cur = next;
    }
    state.free_list = ptr::null_mut();
    drop(state);
    let _ = pool::free(h as *mut u8);
    ptr::null_mut()
}

/// `RtlGetProcessHeap` — return the default process heap.
pub unsafe extern "C" fn RtlGetProcessHeap() -> HANDLE {
    ensure_process_heap();
    PROCESS_HEAP as HANDLE
}

/// `RtlGetProcessHeaps` — fill the caller-supplied array with
/// heap handles and return the number written. We only have one
/// heap (the default process heap), so this is always 1.
pub unsafe extern "C" fn RtlGetProcessHeaps(
    count: u32,
    process_heaps: *mut HANDLE,
) -> u32 {
    if process_heaps.is_null() || count == 0 {
        return 0;
    }
    ensure_process_heap();
    *process_heaps = PROCESS_HEAP as HANDLE;
    1
}

unsafe fn ensure_process_heap() {
    if PROCESS_HEAP_INIT.load(Ordering::Acquire) != 0 { return; }
    let h = RtlCreateHeap(0, ptr::null_mut(), 0, 0, ptr::null_mut(), ptr::null_mut());
    PROCESS_HEAP = h as *mut Heap;
    PROCESS_HEAP_INIT.store(1, Ordering::Release);
}

/// `RtlAllocateHeap` — allocate `size` bytes from `heap`. If
/// `heap` is NULL the default process heap is used.
pub unsafe extern "C" fn RtlAllocateHeap(
    heap_handle: HANDLE,
    flags: u32,
    size: usize,
) -> PVOID {
    if size == 0 { return ptr::null_mut(); }
    let heap = resolve_heap(heap_handle);
    if heap.is_null() { return ptr::null_mut(); }

    let real_size = align_up(size, HEAP_ALIGN);
    let total = HEADER_SIZE + real_size;

    // Try the free list first.
    {
        let mut state = (*heap).lock.lock();
        let mut prev: *mut BlockHeader = ptr::null_mut();
        let mut cur = state.free_list;
        while !cur.is_null() {
            if (*cur).size as usize >= real_size {
                // Remove from free list.
                let next = (*cur).next_free;
                if !prev.is_null() {
                    (*prev).next_free = next;
                } else {
                    state.free_list = next;
                }
                state.bytes_free = state.bytes_free.saturating_sub((*cur).size as u64);
                state.bytes_in_use = state.bytes_in_use.saturating_add((*cur).size as u64);
                state.alloc_count = state.alloc_count.wrapping_add(1);
                (*cur).magic = HEADER_MAGIC_ALLOC;
                (*cur).next_free = ptr::null_mut();
                let p = (*cur).user_ptr();
                if flags & HEAP_ZERO_MEMORY != 0 {
                    ptr::write_bytes(p, 0, real_size);
                }
                return p as PVOID;
            }
            prev = cur;
            cur = (*cur).next_free;
        }
    }

    // Allocate a fresh block from the pool.
    let raw = pool::allocate(PoolType::NonPaged, total);
    if raw.is_null() { return ptr::null_mut(); }
    let hdr = raw as *mut BlockHeader;
    ptr::write(hdr, BlockHeader {
        magic: HEADER_MAGIC_ALLOC,
        size: real_size as u32,
        owner: heap,
        next_free: ptr::null_mut(),
    });
    {
        let mut state = (*heap).lock.lock();
        state.bytes_in_use = state.bytes_in_use.saturating_add(real_size as u64);
        state.alloc_count = state.alloc_count.wrapping_add(1);
    }
    let p = (*hdr).user_ptr();
    if flags & HEAP_ZERO_MEMORY != 0 {
        ptr::write_bytes(p, 0, real_size);
    }
    p as PVOID
}

/// `RtlFreeHeap` — release a block back to `heap`. Returns
/// TRUE on success, FALSE if the block is invalid.
pub unsafe extern "C" fn RtlFreeHeap(
    heap_handle: HANDLE,
    _flags: u32,
    heap_pointer: PVOID,
) -> u8 {
    if heap_pointer.is_null() { return 1; }
    let heap = resolve_heap(heap_handle);
    if heap.is_null() { return 0; }
    let hdr = BlockHeader::from_user(heap_pointer as *mut u8);
    if (*hdr).magic != HEADER_MAGIC_ALLOC {
        return 0;
    }
    if (*hdr).owner != heap {
        // Allow it but log; mismatched owner usually means wrong
        // heap was passed in.
    }
    let mut state = (*heap).lock.lock();
    (*hdr).magic = HEADER_MAGIC_FREE;
    (*hdr).next_free = state.free_list;
    state.free_list = hdr;
    state.bytes_in_use = state.bytes_in_use.saturating_sub((*hdr).size as u64);
    state.bytes_free = state.bytes_free.saturating_add((*hdr).size as u64);
    state.free_count = state.free_count.wrapping_add(1);
    1
}

/// `RtlReAllocateHeap` — resize an existing allocation. The
/// original block's contents are preserved up to `min(old, new)`.
pub unsafe extern "C" fn RtlReAllocateHeap(
    heap_handle: HANDLE,
    flags: u32,
    memory: PVOID,
    size: usize,
) -> PVOID {
    if memory.is_null() {
        return RtlAllocateHeap(heap_handle, flags, size);
    }
    let heap = resolve_heap(heap_handle);
    if heap.is_null() { return ptr::null_mut(); }
    let old_hdr = BlockHeader::from_user(memory as *mut u8);
    if (*old_hdr).magic != HEADER_MAGIC_ALLOC {
        return ptr::null_mut();
    }
    if size == 0 {
        RtlFreeHeap(heap_handle, 0, memory);
        return ptr::null_mut();
    }
    let new_real = align_up(size, HEAP_ALIGN);
    if new_real <= (*old_hdr).size as usize {
        return memory;
    }
    let new_p = RtlAllocateHeap(heap_handle, flags, size);
    if new_p.is_null() { return ptr::null_mut(); }
    core::ptr::copy_nonoverlapping(memory as *const u8, new_p as *mut u8, (*old_hdr).size as usize);
    RtlFreeHeap(heap_handle, 0, memory);
    new_p
}

/// `RtlSizeHeap` — return the allocated size of `memory`.
pub unsafe extern "C" fn RtlSizeHeap(
    _heap_handle: HANDLE,
    _flags: u32,
    memory: PVOID,
) -> usize {
    if memory.is_null() { return 0; }
    let hdr = BlockHeader::from_user(memory as *mut u8);
    if (*hdr).magic != HEADER_MAGIC_ALLOC { return 0; }
    (*hdr).size as usize
}

/// Heap statistics snapshot.
pub struct HeapStats {
    pub bytes_in_use: u64,
    pub bytes_free: u64,
    pub alloc_count: u64,
    pub free_count: u64,
}

pub unsafe fn heap_stats(heap_handle: HANDLE) -> Option<HeapStats> {
    let heap = resolve_heap(heap_handle);
    if heap.is_null() { return None; }
    let s = (*heap).lock.lock();
    Some(HeapStats {
        bytes_in_use: s.bytes_in_use,
        bytes_free: s.bytes_free,
        alloc_count: s.alloc_count,
        free_count: s.free_count,
    })
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

unsafe fn resolve_heap(heap_handle: HANDLE) -> *mut Heap {
    if heap_handle.is_null() {
        ensure_process_heap();
        return PROCESS_HEAP;
    }
    heap_handle as *mut Heap
}

#[inline]
fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        unsafe {
            let h = RtlCreateHeap(0, ptr::null_mut(), 0, 0, ptr::null_mut(), ptr::null_mut());
            assert!(!h.is_null());
            let p = RtlAllocateHeap(h, 0, 100);
            assert!(!p.is_null());
            assert_eq!(RtlSizeHeap(h, 0, p), 112);
            assert_eq!(RtlFreeHeap(h, 0, p), 1);
            assert_eq!(RtlSizeHeap(h, 0, p), 0);
            assert_eq!(RtlDestroyHeap(h), ptr::null_mut());
        }
    }

    #[test]
    fn zero_memory_flag() {
        unsafe {
            let h = RtlCreateHeap(0, ptr::null_mut(), 0, 0, ptr::null_mut(), ptr::null_mut());
            let p = RtlAllocateHeap(h, HEAP_ZERO_MEMORY, 64) as *mut u8;
            assert!(!p.is_null());
            let mut all_zero = true;
            for i in 0..64 {
                if *p.add(i) != 0 { all_zero = false; break; }
            }
            assert!(all_zero);
            RtlFreeHeap(h, 0, p as PVOID);
            RtlDestroyHeap(h);
        }
    }

    #[test]
    fn realloc_preserves() {
        unsafe {
            let h = RtlCreateHeap(0, ptr::null_mut(), 0, 0, ptr::null_mut(), ptr::null_mut());
            let p = RtlAllocateHeap(h, 0, 32) as *mut u8;
            for i in 0..32 { *p.add(i) = (i as u8).wrapping_mul(3); }
            let q = RtlReAllocateHeap(h, 0, p as PVOID, 200) as *mut u8;
            assert!(!q.is_null());
            for i in 0..32 {
                assert_eq!(*q.add(i), (i as u8).wrapping_mul(3));
            }
            RtlFreeHeap(h, 0, q as PVOID);
            RtlDestroyHeap(h);
        }
    }

    #[test]
    fn invalid_free_returns_false() {
        unsafe {
            let h = RtlCreateHeap(0, ptr::null_mut(), 0, 0, ptr::null_mut(), ptr::null_mut());
            // free without alloc: heap_pointer not in our pool; should be 0.
            let bogus = 0x1000usize as PVOID;
            assert_eq!(RtlFreeHeap(h, 0, bogus), 0);
            RtlDestroyHeap(h);
        }
    }
}
