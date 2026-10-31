//! Kernel Heap
//
//! Dynamic memory allocation for the kernel.
//
//! This module does two things:
//!   1. It defines a bump allocator with a free list for memory reuse and
//!      registers it as the kernel's `#[global_allocator]`. The
//!      previous implementation returned null for every alloc, which
//!      made `alloc::vec::Vec` / `String` immediately explode as soon
//!      as the loader tried to format a path.
//!   2. It exposes the NT-style `HeapControl` block to the rest of the
//!      kernel so that `heap::init` and `pool::init` can be called
//!      from the kernel-main boot sequence.
//
//! ## Memory Management
//
//! This heap implements a bump allocator with free list support:
//! - `alloc()` first checks the free list for reusable blocks
//! - If no suitable block is found, uses the bump pointer for new allocation
//! - `dealloc()` adds blocks to the free list for future reuse
//! - Adjacent free blocks are coalesced to prevent fragmentation

use crate::ke::sync::Spinlock;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Free block header stored at the beginning of each freed block.
///
/// We use an **intrusive** singly-linked list of raw pointers so the
/// free list itself never needs to allocate — fixing the recursion
/// problem the old `Vec<*mut FreeBlock>` had (the Vec's grow path
/// called back into `GlobalAlloc::alloc`, causing UB).
#[repr(C)]
struct FreeBlock {
    /// Size of this free block (including header)
    size: usize,
    /// Pointer to next free block in the list
    next: *mut FreeBlock,
}

impl FreeBlock {
    /// create a new free block at the given address.
    ///
    /// # Safety
    /// Caller must ensure `addr` points to writable memory of at
    /// least `core::mem::size_of::<FreeBlock>()` bytes.
    unsafe fn new(addr: *mut u8, size: usize) -> *mut FreeBlock {
        let block = addr as *mut FreeBlock;
        (*block).size = size;
        (*block).next = ptr::null_mut();
        block
    }
}

/// Metadata stored immediately before the user-visible allocation.
///
/// The free-list header is overwritten while a block is allocated, so
/// it cannot be used to recover the allocation size on `dealloc()`.
/// Keeping an independent header makes every free block self-describing
/// and allows allocations smaller than `size_of::<FreeBlock>()`.
#[repr(C)]
struct AllocationHeader {
    /// Magic value used to detect invalid or corrupted frees.
    magic: usize,
    /// Size of the allocation block, excluding alignment padding that
    /// may precede this header but including the header itself.
    block_size: usize,
}

impl AllocationHeader {
    const MAGIC: usize = 0x4e_54_36_31_48_45_41_50;
    const SIZE: usize = core::mem::size_of::<AllocationHeader>();
}

/// NT-style kernel heap control block. The fields mirror what
/// `nt!_HEAP` looks like in 7-era NT, but the actual layout is far
/// larger in NT. We only keep the parts that are useful for
/// diagnostics here.
#[repr(C)]
pub struct HeapControl {
    pub base_address: *mut u8,
    pub reserve_size: usize,
    pub commit_size: usize,
    pub allocation_algorithm: u32,
    pub flags: u32,
    pub next_free: *mut u8,
}

unsafe impl Send for HeapControl {}
unsafe impl Sync for HeapControl {}

impl HeapControl {
    pub const fn new() -> Self {
        HeapControl {
            base_address: core::ptr::null_mut(),
            reserve_size: 0,
            commit_size: 0,
            allocation_algorithm: 0,
            flags: 0,
            next_free: core::ptr::null_mut(),
        }
    }
}

impl Default for HeapControl {
    fn default() -> Self {
        Self::new()
    }
}

/// A bump allocator with free list support for memory reuse.
/// The base and size are configured by `init()`. Freed blocks
/// are added to a free list and reused for future allocations.
///
/// This implementation provides:
/// 1. A free list to track deallocated blocks (intrusive linked list)
/// 2. Coalescing of adjacent free blocks
/// 3. Linear search for best-fit block on allocation
///
/// # Concurrency
///
/// All fields are accessed only while holding the heap's internal
/// lock (taken via `kernel_lock()`). The lock is implicit — every
/// `add_to_free_list` / `alloc_from_free_list` / `alloc` /
/// `dealloc` path enters through `with_heap_lock`. Atomic
/// counters (e.g. `allocated`, `next`) are still used because
/// `configure()` is called from `init()` before any lock is set up.
pub struct KernelHeap {
    pub base: AtomicUsize,
    pub size: AtomicUsize,
    pub next: AtomicUsize,
    initialized: AtomicBool,
    control: UnsafeCell<HeapControl>,
    allocated: AtomicUsize,
    /// Statistics for debugging and future improvements
    stats: UnsafeCell<HeapStats>,
    /// Head pointer to an intrusive singly-linked list of free blocks
    /// (see `FreeBlock`). All operations on this list must hold
    /// `heap_lock`. Using raw pointers avoids any callback into
    /// `GlobalAlloc::alloc`, which would otherwise recurse.
    free_list_head: UnsafeCell<*mut FreeBlock>,
    /// Heap-wide spinlock. All operations that touch the free list
    /// or the bump pointer must hold this lock.
    heap_lock: UnsafeCell<Spinlock<()>>,
}

/// Heap statistics for debugging and future improvements
#[repr(C)]
pub struct HeapStats {
    pub total_allocations: u64,
    pub total_frees: u64,
    pub current_allocated: usize,
    pub peak_allocated: usize,
    pub failed_allocations: u64,
    /// Number of allocations served from the free list (reused).
    pub free_list_hits: u64,
    /// Number of times the free list was searched but no suitable
    /// block was found and we fell back to the bump allocator.
    pub free_list_misses: u64,
    /// Number of times the free list could have served the request
    /// (a block big enough existed) but the caller requested an
    /// alignment we could not satisfy without splitting.
    pub free_list_split: u64,
}

impl HeapStats {
    pub const fn new() -> Self {
        Self {
            total_allocations: 0,
            total_frees: 0,
            current_allocated: 0,
            peak_allocated: 0,
            failed_allocations: 0,
            free_list_hits: 0,
            free_list_misses: 0,
            free_list_split: 0,
        }
    }
}

impl Default for HeapStats {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl Send for KernelHeap {}
unsafe impl Sync for KernelHeap {}

impl KernelHeap {
    pub const fn new() -> Self {
        Self {
            base: AtomicUsize::new(0),
            size: AtomicUsize::new(0),
            next: AtomicUsize::new(0),
            initialized: AtomicBool::new(false),
            control: UnsafeCell::new(HeapControl::new()),
            allocated: AtomicUsize::new(0),
            stats: UnsafeCell::new(HeapStats::new()),
            free_list_head: UnsafeCell::new(ptr::null_mut()),
            heap_lock: UnsafeCell::new(Spinlock::new(())),
        }
    }

    /// Configure the heap with a contiguous virtual region.
    pub fn configure(&self, base: *mut u8, size: usize) {
        self.base.store(base as usize, Ordering::SeqCst);
        self.size.store(size, Ordering::SeqCst);
        self.next.store(base as usize, Ordering::SeqCst);
        self.initialized.store(true, Ordering::SeqCst);

        // SAFETY: We just stored the base; nothing else has had time to
        // touch `control` yet because the atomic store is a release
        // barrier.
        unsafe {
            let c = &mut *self.control.get();
            c.base_address = base;
            c.reserve_size = size;
            c.commit_size = size;
            c.next_free = base;
        }
    }

    fn align_up(val: usize, align: usize) -> usize {
        (val + align - 1) & !(align - 1)
    }

    /// Return the current heap region as `(base, size)`, or `None`
    /// if the heap has not been initialised. Used by `mm::init` to
    /// identity-map the heap range on non-x86_64 architectures
    /// before the pool subsystem touches it.
    pub fn configured_region(&self) -> Option<(*mut u8, usize)> {
        if !self.initialized.load(Ordering::Acquire) {
            return None;
        }
        let base = self.base.load(Ordering::Relaxed) as *mut u8;
        let size = self.size.load(Ordering::Relaxed);
        if base.is_null() || size == 0 {
            return None;
        }
        Some((base, size))
    }

    /// Check if a pointer and size fall within the heap range.
    fn is_in_heap_range(&self, ptr: *mut u8, size: usize) -> bool {
        let base = self.base.load(Ordering::Relaxed);
        let heap_end = base + self.size.load(Ordering::Relaxed);
        let ptr_addr = ptr as usize;
        ptr_addr >= base && ptr_addr + size <= heap_end
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Add a freed block to the free list with coalescing.
    ///
    /// Walk the intrusive linked list, merge with adjacent blocks
    /// when possible, otherwise prepend the new block.
    unsafe fn add_to_free_list(&self, block_ptr: *mut FreeBlock, size: usize) {
        let block_addr = block_ptr as usize;
        let _base = self.base.load(Ordering::Relaxed);

        let head_ref: &mut *mut FreeBlock = &mut *self.free_list_head.get();
        let mut merged_addr = block_addr;
        let mut merged_size = size;

        // Merge with every adjacent free block, not merely the first one.
        // The free list is address-independent, so repeatedly restart the
        // scan until a full pass makes no progress.
        loop {
            let mut merged = false;
            let mut prev: *mut FreeBlock = ptr::null_mut();
            let mut cur: *mut FreeBlock = *head_ref;

            while !cur.is_null() {
                let cur_addr = cur as usize;
                let cur_size = (*cur).size;
                let cur_next = (*cur).next;

                if cur_addr + cur_size == merged_addr {
                    merged_addr = cur_addr;
                    merged_size += cur_size;
                    merged = true;
                } else if merged_addr + merged_size == cur_addr {
                    merged_size += cur_size;
                    merged = true;
                }

                if merged {
                    if prev.is_null() {
                        *head_ref = cur_next;
                    } else {
                        (*prev).next = cur_next;
                    }
                    break;
                }

                prev = cur;
                cur = cur_next;
            }

            if !merged {
                break;
            }
        }

        // Merge with the bump-pointer region when the freed block
        // sits exactly at the current bump pointer — effectively
        // returning the memory to the bump allocator.
        let next = self.next.load(Ordering::SeqCst);
        if merged_addr + merged_size == next {
            self.next.store(merged_addr, Ordering::SeqCst);
            return;
        }

        // Initialize the free block header only after all adjacent blocks
        // have been absorbed; those blocks' storage is part of the merged
        // region and may contain the final header.
        let new_block = FreeBlock::new(merged_addr as *mut u8, merged_size);
        (*new_block).next = ptr::null_mut();

        // Prepend the (possibly grown) new block to the list.
        (*new_block).next = *head_ref;
        *head_ref = new_block;
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Try to allocate from the free list.
    /// Returns Some(ptr) if a suitable block is found, None otherwise.
    unsafe fn alloc_from_free_list(&self, layout: Layout) -> Option<*mut u8> {
        let head_ref: &mut *mut FreeBlock = &mut *self.free_list_head.get();
        let allocation_size = Self::align_up(layout.size(), 8);
        let alignment = layout.align().max(8);
        // `align_up()` can add up to `alignment - 1` bytes before the
        // allocation header. Reserve that worst case up front so every
        // block selected by best-fit is guaranteed to be large enough.
        let needed_size = AllocationHeader::SIZE + allocation_size + alignment.saturating_sub(1);

        // Best-fit: walk the intrusive list, find the smallest
        // block that still satisfies the request.
        let mut best_prev: *mut FreeBlock = ptr::null_mut();
        let mut best: *mut FreeBlock = ptr::null_mut();
        let mut best_size: usize = usize::MAX;

        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut cur: *mut FreeBlock = *head_ref;
        while !cur.is_null() {
            let cur_size = (*cur).size;
            if cur_size >= needed_size && cur_size < best_size {
                best = cur;
                best_prev = prev;
                best_size = cur_size;
            }
            prev = cur;
            cur = (*cur).next;
        }

        if best.is_null() {
            return None;
        }

        // Unlink `best` from the list.
        let best_next = (*best).next;
        if best_prev.is_null() {
            *head_ref = best_next;
        } else {
            (*best_prev).next = best_next;
        }

        let block_addr = best as usize;
        let block_size = best_size;
        let aligned_addr = Self::align_up(block_addr + AllocationHeader::SIZE, alignment);
        let header_addr = aligned_addr - AllocationHeader::SIZE;
        let block_end = block_addr + block_size;

        // If there is enough leading padding, return it to the free
        // list. Smaller gaps are intentionally abandoned; they cannot
        // hold a free-list header without overlapping the allocation.
        let leftover = header_addr - block_addr;
        if leftover >= core::mem::size_of::<FreeBlock>() {
            let new_free_addr = block_addr;
            let new_free_size = leftover;
            // SAFETY: caller of alloc_from_free_list already holds
            // heap_lock so re-entrant add_to_free_list is safe.
            self.add_to_free_list(new_free_addr as *mut FreeBlock, new_free_size);
        }

        let used_size = aligned_addr + allocation_size - header_addr;
        let remaining = block_end - (header_addr + used_size);
        if remaining >= core::mem::size_of::<FreeBlock>() {
            let remaining_addr = Self::align_up(aligned_addr + allocation_size, 8);
            let remaining_size = block_end - remaining_addr;
            if remaining_size >= core::mem::size_of::<FreeBlock>() {
                self.add_to_free_list(remaining_addr as *mut FreeBlock, remaining_size);
            }
        }

        let header = header_addr as *mut AllocationHeader;
        (*header).magic = AllocationHeader::MAGIC;
        (*header).block_size = used_size;
        Some(aligned_addr as *mut u8)
    }
}

impl Default for KernelHeap {
    fn default() -> Self {
        Self::new()
    }
}

/// Global heap instance.
pub static KERNEL_HEAP: KernelHeap = KernelHeap::new();

/// Allocator handle that forwards to the single kernel heap instance.
///
/// Binaries must declare their own global allocator static, but that
/// declaration must not create a second heap. This wrapper keeps the
/// configured `KERNEL_HEAP` as the sole storage.
pub struct KernelHeapAllocator;

unsafe impl GlobalAlloc for KernelHeapAllocator {
    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        KERNEL_HEAP.alloc(layout)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        KERNEL_HEAP.dealloc(ptr, layout)
    }
}

unsafe impl GlobalAlloc for KernelHeap {
    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.initialized.load(Ordering::Acquire) {
            return core::ptr::null_mut();
        }
        let base = self.base.load(Ordering::Relaxed);
        let size = self.size.load(Ordering::Relaxed);
        if base == 0 || size == 0 {
            return core::ptr::null_mut();
        }

        // Acquire the heap lock once for the entire alloc path so
        // the free list, bump pointer and stats are updated atomically.
        let lock_ref = &*self.heap_lock.get();
        let _guard = lock_ref.lock();
        // 1) Try the free list first — frees are accumulated into
        //    the intrusive list in `dealloc()`, so this is where
        //    previously-returned memory is recycled.
        if let Some(ptr) = self.alloc_from_free_list(layout) {
            let stats = &mut *self.stats.get();
            stats.total_allocations += 1;
            stats.free_list_hits += 1;
            stats.current_allocated += layout.size();
            if stats.current_allocated > stats.peak_allocated {
                stats.peak_allocated = stats.current_allocated;
            }
            return ptr;
        }

        // 2) Free list had no suitable block — fall back to the
        //    CAS-loop bump allocator for new allocations.
        let stats = &mut *self.stats.get();
        stats.free_list_misses += 1;
        let mut iters = 0;
        loop {
            let cur = self.next.load(Ordering::Relaxed);
            let aligned = Self::align_up(cur + AllocationHeader::SIZE, layout.align().max(8));
            let allocation_size = Self::align_up(layout.size(), 8);
            let new_next = Self::align_up(aligned + allocation_size, 8);
            if new_next > base + size {
                stats.failed_allocations += 1;
                return core::ptr::null_mut();
            }
            if self
                .next
                .compare_exchange(cur, new_next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.allocated.fetch_add(layout.size(), Ordering::Relaxed);
                stats.total_allocations += 1;
                stats.current_allocated += layout.size();
                if stats.current_allocated > stats.peak_allocated {
                    stats.peak_allocated = stats.current_allocated;
                }
                let header = (aligned - AllocationHeader::SIZE) as *mut AllocationHeader;
                (*header).magic = AllocationHeader::MAGIC;
                (*header).block_size = new_next - (aligned - AllocationHeader::SIZE);
                return aligned as *mut u8;
            }
            iters += 1;
            if iters > 1000000 {
                stats.failed_allocations += 1;
                crate::boot_print_always!("TRACE-HEAP: CAS retry exhausted\r\n");
                return core::ptr::null_mut();
            }
        }
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !ptr.is_null() && ptr as usize >= AllocationHeader::SIZE {
            let header = (ptr as usize - AllocationHeader::SIZE) as *mut AllocationHeader;
            let magic = (*header).magic;
            let block_size = (*header).block_size;
            let block_ptr = header as *mut FreeBlock;
            if magic != AllocationHeader::MAGIC
                || block_size < core::mem::size_of::<FreeBlock>()
                || !self.is_in_heap_range(block_ptr as *mut u8, block_size)
            {
                return;
            }
            let lock_ref = &*self.heap_lock.get();
            let _guard = lock_ref.lock();
            self.add_to_free_list(block_ptr, block_size);
            let stats = &mut *self.stats.get();
            stats.total_frees += 1;
            stats.current_allocated = stats.current_allocated.saturating_sub(layout.size());
        }
    }
}

/// Initialize the kernel heap with a runtime-allocated region.
///
/// We do not rely on a static BSS region for the heap. The
/// hand-rolled `linker.ld` for the UEFI target describes only
/// `.text` and `.data`, so a standalone `.bss` output section is
/// not emitted, and EDK2 rejects a PE section whose VirtualSize is
/// non-zero but whose PointerToRawData is zero. BSS statics are now
/// merged into `.data` by `linker.ld` and `linker-rv64.ld`, which
/// is what the frame and PFN table statics depend on; the heap
/// itself still comes from the frame allocator so its size is not
/// fixed at link time.
///
/// Instead, we ask the buddy frame allocator for a 4 MiB region at
/// runtime. The buddy allocator hands out physical addresses, and
/// the kernel's identity-mapped page tables (still in place from
/// the UEFI stub) make the physical address a valid virtual
/// address for early-boot allocations. Once the kernel heap is
/// configured, the rest of the subsystem (pool, working set,
/// ...) can proceed as before.
pub fn init() {
    use crate::mm::frame;

    // Try 64 MiB first; fall back to 32 MiB then 16 MiB if the
    // buddy allocator can't satisfy the larger request. The system
    // image loader (`system_image::build_all`) builds ~30 PE files
    // in memory (each a few KiB plus alignment), the loader's import
    // database needs a few hundred KiB more.  With a 64 MiB buddy
    // region, a 64 MiB heap gives comfortable headroom for the two
    // ~23 MiB system images (ntoskrnl.exe + hal.dll) that
    // `load_system_files()` must read from disk into the kernel heap.
    const HEAP_PAGES_LARGE: u64 = (256 * 1024 * 1024) / 4096;
    const HEAP_PAGES_MEDIUM: u64 = (32 * 1024 * 1024) / 4096;
    const HEAP_PAGES_SMALL: u64 = (16 * 1024 * 1024) / 4096;

    let (phys, pages) = match frame::allocate_pages(HEAP_PAGES_LARGE) {
        Some(p) => {
            crate::hal::serial::write_string_always("[heap] allocated 64MB at phys=");
            crate::hal::serial::write_hex_u64(p);
            crate::hal::serial::write_string("\r\n");
            (p, HEAP_PAGES_LARGE)
        }
        None => {
            crate::hal::serial::write_string_always("[heap] 64MB FAILED, trying 32MB\r\n");
            match frame::allocate_pages(HEAP_PAGES_MEDIUM) {
                Some(p) => {
                    crate::hal::serial::write_string_always("[heap] allocated 32MB at phys=");
                    crate::hal::serial::write_hex_u64(p);
                    crate::hal::serial::write_string("\r\n");
                    (p, HEAP_PAGES_MEDIUM)
                }
                None => {
                    crate::hal::serial::write_string_always("[heap] 32MB FAILED, trying 16MB\r\n");
                    match frame::allocate_pages(HEAP_PAGES_SMALL) {
                        Some(p) => {
                            crate::hal::serial::write_string_always(
                                "[heap] allocated 16MB at phys=",
                            );
                            crate::hal::serial::write_hex_u64(p);
                            crate::hal::serial::write_string("\r\n");
                            (p, HEAP_PAGES_SMALL)
                        }
                        None => {
                            crate::hal::serial::write_string(
                                "[heap] FATAL: 16MB allocation failed\r\n",
                            );
                            return;
                        }
                    }
                }
            }
        }
    };

    let base = phys as *mut u8;
    let size = (pages * 4096) as usize;
    crate::hal::serial::write_string_always("[heap] about to configure base=");
    crate::hal::serial::write_hex_u64(base as u64);
    crate::hal::serial::write_string(" size=");
    crate::hal::serial::write_hex_u64(size as u64);
    crate::hal::serial::write_string("\r\n");
    KERNEL_HEAP.configure(base, size);
    crate::hal::serial::write_string_always("[heap] configure done, checking...\r\n");
    let region = crate::mm::heap::KERNEL_HEAP.configured_region();
    crate::mm::init_state::verify_region(region, "heap::init");
    crate::hal::serial::write_string_always("[heap] configure VERIFIED OK\r\n");
}

/// Maximum heap size, used when the buddy allocator cannot
/// satisfy the full 4 MiB request: we keep retrying at this size
/// so that the smoke test always gets a heap region even on
/// memory-constrained configurations. The actual allocated size
/// is whatever the buddy allocator could find.///
/// Number of bytes currently handed out by the bump allocator.
pub fn get_allocated() -> usize {
    KERNEL_HEAP.allocated.load(Ordering::Relaxed)
}

/// Number of bytes still available.
pub fn get_free() -> usize {
    let base = KERNEL_HEAP.base.load(Ordering::Relaxed);
    let next = KERNEL_HEAP.next.load(Ordering::Relaxed);
    let size = KERNEL_HEAP.size.load(Ordering::Relaxed);
    size.saturating_sub(next.saturating_sub(base))
}
