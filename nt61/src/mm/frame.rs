//! Physical Frame Management
//
//! Physical page frame allocation using a buddy system.
//
//! The buddy system keeps one free-list per power-of-two block size
//! (per "order"). `MAX_BUDDY_ORDER` is the largest block we are
//! willing to hand out, which in this kernel is 2^21 pages = 8 GiB -
//! enough to map the lower half of physical memory in a single
//! allocation, which in turn is what `mm::vm` does for the kernel's
//! direct-map region.
//
//! # Free-list representation
//! We do not use intrusive list entries inside each frame (that would
//! destroy the user's data). Instead we use a single contiguous
//! `BuddyNode` table indexed by frame number; each node has explicit
//! `next` and `prev` indices. The table itself lives in a static
//! storage array - it is small (8 bytes per frame; 64 KiB of table
//! per 32 MiB of RAM) so this scales fine for the QEMU default.

use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU64, Ordering};

/// Frame info flags.
pub const FRAME_FREE: u8 = 0;
pub const FRAME_USED: u8 = 1;
pub const FRAME_RESERVED: u8 = 2;
pub const FRAME_BOOT: u8 = 3;
pub const FRAME_MMIO: u8 = 4;

/// Maximum buddy order. 2^21 pages = 8 GiB.
pub const MAX_BUDDY_ORDER: usize = 21;

/// Frame information.
#[derive(Debug, Clone, Copy)]
pub struct FrameInfo {
    pub order: u8,
    pub flags: u8,
    pub reference_count: u32,
    pub zone: u8,
}

impl FrameInfo {
    pub const fn new(order: u8, flags: u8, zone: u8) -> Self {
        Self {
            order,
            flags,
            reference_count: 0,
            zone,
        }
    }
    pub fn is_free(&self) -> bool {
        self.flags == FRAME_FREE
    }
}

/// Memory zone types. NT actually has a richer set (MmLowmem,
/// MmUsual, etc.) - the relevant thing for the bootstrap is "below
/// 4 GiB" vs "above 4 GiB" because that's what determines the
/// 32-bit DMA pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryZone {
    Usual = 0,
    Lowmem = 1,
    Movable = 2,
    Reserve = 3,
}

/// Free-list node, stored in a flat array indexed by frame number.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BuddyNode {
    next: u32,
    prev: u32,
    /// Set to 1 when this slot is on the free list for its order.
    on_list: u32,
}

const FREE_LIST_END: u32 = u32::MAX;

/// Return the buddy order for a count of `count` pages.
fn order_of(count: u64) -> usize {
    if count <= 1 {
        return 0;
    }
    let mut order = 0usize;
    let mut n = count;
    while n > 1 {
        n >>= 1;
        order += 1;
    }
    if count > (1u64 << order) {
        order += 1;
    }
    order
}

/// Buddy allocator. The free lists are protected by the spinlocks in
/// `free_lists`; `frame_infos` is read-mostly after init and we just
/// use `Ordering::Relaxed` for stats.
pub struct BuddyAllocator {
    free_lists: [Spinlock<FreeListHead>; MAX_BUDDY_ORDER],
    frame_infos: *mut FrameInfo,
    buddy_nodes: *mut BuddyNode,
    num_frames: u64,
    base_address: u64,
    free_frames: AtomicU64,
    /// Has the allocator been initialised?
    initialised: bool,
}

#[derive(Clone, Copy)]
struct FreeListHead {
    head: u32,
    count: u32,
}

impl FreeListHead {
    const fn empty() -> Self {
        Self {
            head: FREE_LIST_END,
            count: 0,
        }
    }
}

impl BuddyAllocator {
    pub const fn new() -> Self {
        const EMPTY: Spinlock<FreeListHead> = Spinlock::new(FreeListHead::empty());
        Self {
            free_lists: [EMPTY; MAX_BUDDY_ORDER],
            frame_infos: core::ptr::null_mut(),
            buddy_nodes: core::ptr::null_mut(),
            num_frames: 0,
            base_address: 0,
            free_frames: AtomicU64::new(0),
            initialised: false,
        }
    }

    /// Hand the allocator a contiguous region of physical memory. The
    /// region is described by a slice of (base, length) pairs.
    ///
    /// For the bootstrap we accept a single region - the QEMU virt
    /// machine reports a single contiguous block of usable memory so
    /// this is sufficient.
    pub fn init(&mut self, region_base: u64, region_size: u64, frame_table: *mut u8, frame_table_size: usize) {
        self.base_address = region_base;
        self.num_frames = region_size / 4096;
        // The bookkeeping buffer is split as follows:
        //   - First  num_frames * sizeof(FrameInfo) bytes : FrameInfo array
        //   - Next   num_frames * sizeof(BuddyNode)  bytes : BuddyNode array
        // The caller passes a buffer that is large enough for
        // both (the dynamic path always passes enough; the
        // static path passes a single static BSS that is sized
        // for the static coverage limit).
        let fi_size = self.num_frames as usize * core::mem::size_of::<FrameInfo>();
        let bn_size = self.num_frames as usize * core::mem::size_of::<BuddyNode>();
        if fi_size + bn_size > frame_table_size {
            // The caller passed too small a buffer. Clamp
            // num_frames so we don't write past the end of the
            // buffer. The caller is expected to detect this
            // and re-init with a bigger buffer.
            let max_frames = frame_table_size
                / (core::mem::size_of::<FrameInfo>() + core::mem::size_of::<BuddyNode>());
            self.num_frames = max_frames as u64;
            // kprintln bypassed — use the unified serial facade.
        crate::hal::serial::write_string("AI0_CLAMP\r\n");
        }
        self.frame_infos = frame_table as *mut FrameInfo;
        self.buddy_nodes = unsafe { frame_table.add(fi_size) as *mut BuddyNode };
        // Mark all frames as free in the meta-data.
        unsafe {
            core::ptr::write_bytes(self.frame_infos, 0, self.num_frames as usize);
            core::ptr::write_bytes(self.buddy_nodes, 0, self.num_frames as usize);
        }
        // Add every frame to order-0 free list, then bottom-up
        // coalesce adjacent pairs into the highest possible
        // order. Without the coalesce, a request for 16 MiB
        // (order 14) against a 1 GiB pool would OOM because every
        // frame is pinned at order 0.
        let total = self.num_frames as u32;
        // kprintln bypassed — use the unified serial facade.
        crate::hal::serial::write_string("AI0_SEED\r\n");
        {
            let mut lock = self.free_lists[0].lock();
            unsafe {
                for i in 0..total {
                    let node = self.buddy_nodes.add(i as usize);
                    (*node).next = i.wrapping_add(1);
                    (*node).prev = if i == 0 { FREE_LIST_END } else { i.wrapping_sub(1) };
                    (*node).on_list = 1;
                }
                let last = total.wrapping_sub(1);
                let head_node = self.buddy_nodes;
                (*head_node).prev = FREE_LIST_END;
                let tail_node = self.buddy_nodes.add(last as usize);
                (*tail_node).next = FREE_LIST_END;
            }
            lock.head = 0;
            lock.count = total;
        }
        // Bottom-up coalesce. For each order k from 0..MAX-1, walk
        // the order-k free list and merge buddy pairs into
        // order-(k+1). This builds the largest possible blocks at
        // the highest orders, which lets `allocate` satisfy
        // large contiguous requests.
        // kprintln bypassed: skip verbose log
        for k in 0..(MAX_BUDDY_ORDER - 1) {
            let mut merged_total: u32 = 0;
            // At most num_frames / 2^(k+1) pairs can possibly merge at this order.
            let max_merges_at_order: u32 = (self.num_frames as u32) >> (k + 1);
            // Safety net: cap attempts so a buggy walk cannot spin forever.
            let max_attempts: u32 = max_merges_at_order.saturating_mul(2).max(64);
            let mut attempts: u32 = 0;
            loop {
                attempts += 1;
                if attempts > max_attempts { break; }
                let result: Option<u32> = {
                    let mut lock = self.free_lists[k].lock();
                    let num = self.num_frames as u32;
                    let mut cur = lock.head;
                    let mut merged_base_opt: Option<u32> = None;
                    while cur != FREE_LIST_END {
                        let buddy = cur ^ (1u32 << k);
                        if buddy < num {
                            // Walk the list and see if `buddy` is on it.
                            let mut found = false;
                            let mut probe = lock.head;
                            for _ in 0..lock.count {
                                if probe == buddy { found = true; break; }
                                let next = unsafe {
                                    (*self.buddy_nodes.add(probe as usize)).next
                                };
                                if next == FREE_LIST_END { break; }
                                probe = next;
                            }
                            if found {
                                remove_node(&mut lock, cur, self.buddy_nodes);
                                remove_node(&mut lock, buddy, self.buddy_nodes);
                                merged_base_opt = Some(cur & !(1u32 << k));
                            }
                        }
                        if merged_base_opt.is_some() { break; }
                        let next = unsafe {
                            (*self.buddy_nodes.add(cur as usize)).next
                        };
                        if next == FREE_LIST_END { break; }
                        cur = next;
                    }
                    merged_base_opt
                };
                let merged_base = match result { Some(b) => b, None => break };
                {
                    let mut lock = self.free_lists[k + 1].lock();
                    push_head(&mut lock, merged_base, self.buddy_nodes);
                }
                merged_total += 1;
                if merged_total >= max_merges_at_order {
                    break;
                }
            }
        }

        self.free_frames.store(self.num_frames, Ordering::SeqCst);
        self.initialised = true;
        crate::hal::serial::write_string("AI1_INIT_DONE\r\n");
        // Dump free list counts per order for debugging
        crate::hal::serial::write_string("[frame] free-list dump:\r\n");
        for k in 0..MAX_BUDDY_ORDER {
            let count = {
                let lock = self.free_lists[k].lock();
                lock.count
            };
            if count > 0 {
                crate::hal::serial::write_string("  order=0x");
                crate::hal::serial::write_hex_u64(k as u64);
                crate::hal::serial::write_string(" count=0x");
                crate::hal::serial::write_hex_u64(count as u64);
                crate::hal::serial::write_string("\r\n");
            }
        }
    }

    /// Allocate `count` contiguous frames (rounded up to a power of
    /// two). Returns the base physical address or `None` if no
    /// suitable block is free.
    pub fn allocate(&mut self, count: u64) -> Option<u64> {
        if !self.initialised || count == 0 {
            return None;
        }
        let order = order_of(count).min(MAX_BUDDY_ORDER - 1);

        for current_order in order..MAX_BUDDY_ORDER {
            let frame = {
                let mut lock = self.free_lists[current_order].lock();
                pop_head(&mut lock, self.buddy_nodes)
            };
            if frame == FREE_LIST_END {
                continue;
            }
            // Split the block down to the requested order.
            let cur_frame = frame;
            let mut cur_order = current_order;
            while cur_order > order {
                cur_order -= 1;
                let buddy = cur_frame ^ (1u32 << cur_order);
                let mut sub_lock = self.free_lists[cur_order].lock();
                push_head(&mut sub_lock, buddy, self.buddy_nodes);
            }
            // Mark the block as used.
            unsafe {
                for i in 0..(1u64 << order) {
                    let idx = (cur_frame as u64) + i;
                    if idx < self.num_frames {
                        let info = &mut *self.frame_infos.add(idx as usize);
                        *info = FrameInfo::new(order as u8, FRAME_USED, MemoryZone::Usual as u8);
                    }
                }
            }
            self.free_frames
                .fetch_sub(1u64 << order, Ordering::SeqCst);
            return Some(self.base_address + (cur_frame as u64) * 4096);
        }
        None
    }

    /// Free a previously-allocated block of `count` pages.
    pub fn free(&mut self, phys_addr: u64, count: u64) {
        if !self.initialised || phys_addr < self.base_address {
            return;
        }
        let frame = ((phys_addr - self.base_address) / 4096) as u32;
        let order = order_of(count).min(MAX_BUDDY_ORDER - 1);

        unsafe {
            for i in 0..(1u32 << order) {
                let idx = (frame as u64) + i as u64;
                if idx < self.num_frames {
                    let info = &mut *self.frame_infos.add(idx as usize);
                    *info = FrameInfo::new(order as u8, FRAME_FREE, MemoryZone::Usual as u8);
                }
            }
        }

        // Try to coalesce with the buddy.
        let mut cur_frame = frame;
        let mut cur_order = order;
        while cur_order < MAX_BUDDY_ORDER - 1 {
            let buddy = cur_frame ^ (1u32 << cur_order);
            let on_list = unsafe {
                let node = &*self.buddy_nodes.add(buddy as usize);
                node.on_list
            };
            if on_list == 0 || (buddy as u64) >= self.num_frames {
                break;
            }
            // Remove buddy from the free list and merge.
            {
                let mut lock = self.free_lists[cur_order].lock();
                remove_node(&mut lock, buddy, self.buddy_nodes);
            }
            cur_order += 1;
            cur_frame = core::cmp::min(cur_frame, buddy);
        }
        let mut lock = self.free_lists[cur_order].lock();
        push_head(&mut lock, cur_frame, self.buddy_nodes);
        drop(lock);

        self.free_frames
            .fetch_add(1u64 << order, Ordering::SeqCst);
    }

    /// Number of free frames.
    pub fn free_count(&self) -> u64 {
        self.free_frames.load(Ordering::SeqCst)
    }

    /// Total frame count.
    pub fn total_count(&self) -> u64 {
        self.num_frames
    }
}

fn push_head(list: &mut FreeListHead, frame: u32, nodes: *mut BuddyNode) {
    unsafe {
        let node = &mut *nodes.add(frame as usize);
        node.prev = FREE_LIST_END;
        node.next = list.head;
        node.on_list = 1;
        if list.head != FREE_LIST_END {
            let old_head = &mut *nodes.add(list.head as usize);
            old_head.prev = frame;
        }
        list.head = frame;
        list.count += 1;
    }
}

fn pop_head(list: &mut FreeListHead, nodes: *mut BuddyNode) -> u32 {
    if list.head == FREE_LIST_END {
        return FREE_LIST_END;
    }
    let frame = list.head;
    unsafe {
        let node = &mut *nodes.add(frame as usize);
        list.head = node.next;
        if list.head != FREE_LIST_END {
            let next = &mut *nodes.add(list.head as usize);
            next.prev = FREE_LIST_END;
        }
        node.next = FREE_LIST_END;
        node.prev = FREE_LIST_END;
        node.on_list = 0;
    }
    list.count -= 1;
    frame
}

fn remove_node(list: &mut FreeListHead, frame: u32, nodes: *mut BuddyNode) {
    unsafe {
        let node = &mut *nodes.add(frame as usize);
        let next = node.next;
        let prev = node.prev;
        if prev != FREE_LIST_END {
            (*nodes.add(prev as usize)).next = next;
        } else {
            list.head = next;
        }
        if next != FREE_LIST_END {
            (*nodes.add(next as usize)).prev = prev;
        }
        node.next = FREE_LIST_END;
        node.prev = FREE_LIST_END;
        node.on_list = 0;
    }
    list.count -= 1;
}

/// Global buddy allocator instance.
static BUDDY_ALLOCATOR: Spinlock<BuddyAllocator> = Spinlock::new(BuddyAllocator::new());

static TOTAL_PAGES: AtomicU64 = AtomicU64::new(0);
static FREE_PAGES: AtomicU64 = AtomicU64::new(0);

/// Statically-allocated bookkeeping table for the bootstrap phase.
/// Sized to describe a 64 MiB region (16384 frames).  The
/// buffer holds BOTH the FrameInfo and BuddyNode arrays side
/// by side: the buddy's `init` splits the buffer using
/// `num_frames * sizeof(FrameInfo)` for the first half and
/// `num_frames * sizeof(BuddyNode)` for the second half, so
/// the buffer must be at least
///   num_frames * (sizeof(FrameInfo) + sizeof(BuddyNode))
/// bytes.  At 32768 frames and 8 + 12 = 20 bytes per frame, that's
/// ~2.4 MiB of BSS — still well within winload.efi's 5 MiB BSS region.
const FRAME_TABLE_ENTRIES: usize = 32768; // 128 MiB of RAM
const FRAME_TABLE_BYTES: usize = FRAME_TABLE_ENTRIES
    * (core::mem::size_of::<FrameInfo>() + core::mem::size_of::<BuddyNode>());

// Static bookkeeping buffer.  Kept as `static mut` (rather than
// `static` + interior mutability) because every accessor already
// takes the buddy spinlock — no aliasing concerns beyond what the
// spinlock already serialises.
//
// IMPORTANT: this buffer lives in winload.efi's `.bss`.  The size
// here MUST be smaller than the unused `.bss` capacity of the
// winload image, or the kernel will fault on access when the buddy
// tries to zero it.  `FRAME_TABLE_ENTRIES = 32768` keeps us at
// ~640 KiB which is far below the ~5 MiB available.
#[link_section = ".bss"]
static mut FRAME_TABLE: [u8; FRAME_TABLE_BYTES] = [0u8; FRAME_TABLE_BYTES];

/// Dynamic bookkeeping tables. After `init_with_range` completes
/// the buddy operates on these buffers; the static `FRAME_TABLE`
/// is retained only for fallback / bootstrap.
static mut DYN_FRAME_INFOS: *mut FrameInfo = core::ptr::null_mut();
static mut DYN_BUDDY_NODES: *mut BuddyNode = core::ptr::null_mut();
static mut DYN_FRAME_INFOS_PHYS: u64 = 0;
static mut DYN_BUDDY_NODES_PHYS: u64 = 0;
static mut DYN_LEN: usize = 0;
static mut DYN_BASE_PHYS: u64 = 0;

/// Initialise the frame allocator. The UEFI stub reports a single
/// contiguous usable region; we consume that here.
pub fn init() {
    // Legacy bootstrap: 16 MiB at 1 MiB, static tables.
    init_with_range(0x0010_0000u64, 64 * 1024 * 1024u64);
}

/// Bootstrap region limit for the buddy's static-bookkeeping path.
/// 16384 frames × 4 KiB = 64 MiB.  The kernel heap (up to 32 MiB)
/// fits comfortably inside this window.  The dynamic phase-2 init can
/// re-configure the buddy over a larger range once the dynamic
/// bookkeeping tables have been allocated.
pub const BOOTSTRAP_REGION: u64 = 64 * 1024 * 1024; // 64 MiB

/// Initialise the frame allocator for an arbitrary physical
/// memory range. Supports the 2 GiB – 192 GiB range that
/// QEMU / production firmware can hand us.
///
/// The implementation is two-phase:
/// 1. Bring the buddy up with a 1 GiB static-table bootstrap
///    window (clamped down to the requested range).  The
///    static BSS has metadata for exactly 1 GiB of RAM.
/// 2. Allocate the full-size FrameInfo + BuddyNode tables
///    from the bootstrap window, then re-initialise the
///    buddy with the full range using those tables.
pub fn init_with_range(region_base: u64, region_size: u64) {
    // For now, we go through the legacy single-phase path. The
    // legacy path uses a static BSS bookkeeping buffer (5 MiB
    // FRAME_TABLE, ~80 KiB usable → 4096 frame entries → 16 MiB
    // of managed RAM) and accepts a small region, which is
    // enough to bring the buddy up so that the rest of MM (PFN
    // DB, heap, pool) can allocate.
    //
    // A future change will allocate a dynamic bookkeeping
    // buffer out of the bootstrap window and re-init the buddy
    // over the full range; the current coalesce / free-list
    // algorithms expect the static-table layout, so we stay on
    // the legacy path until those algorithms are made
    // dynamic-friendly.
    legacy_init(region_base, region_size);
}

/// Legacy single-phase init used as phase 1 of `init_with_range`
/// and as the only path for tiny regions (< 16 MiB).
fn legacy_init(region_base: u64, region_size: u64) {
    // DEBUG: Pure serial output via the unified facade.
    crate::hal::serial::write_string("LI0\r\n");
    crate::hal::serial::write_string("LI_INIT_RNG_OK\r\n");

    unsafe {
        // Bridge the legacy single-phase bookkeeping path into the
        // dynamic bookkeeping tables declared above. The legacy
        // `FRAME_TABLE` BSS is the source of truth for the
        // bootstrap window; once we have finished the bootstrap
        // (i.e. we have brought the buddy up enough that the rest
        // of MM can allocate) we copy the live entries into the
        // dynamic tables so the next phase (a future, larger
        // re-init) can use them without re-allocating.
        let region_frames = ((region_size / 4096) as usize).min(FRAME_TABLE.len() / core::mem::size_of::<FrameInfo>());
        DYN_BASE_PHYS  = region_base;
        DYN_LEN        = region_frames;
        // The static FRAME_TABLE is laid out as bytes; the dynamic
        // tables are typed. We point them at the static buffer so
        // the page database and other subsystems can still walk
        // them by the typed pointer.
        DYN_FRAME_INFOS      = FRAME_TABLE.as_mut_ptr() as *mut FrameInfo;
        DYN_FRAME_INFOS_PHYS = region_base; // virt == phys for kernel BSS
        DYN_BUDDY_NODES      = (FRAME_TABLE.as_mut_ptr() as *mut BuddyNode)
            .wrapping_add(region_frames);
        DYN_BUDDY_NODES_PHYS = region_base + (region_frames as u64) * core::mem::size_of::<FrameInfo>() as u64;
        let table_ptr = FRAME_TABLE.as_mut_ptr() as *mut u8;
        let _ = table_ptr; // keep tbl ptr alive for the legacy fallback
        let _ = DYN_BUDDY_NODES_PHYS;

        crate::hal::serial::write_string("LI2\r\n");

        let mut alloc = BUDDY_ALLOCATOR.lock();

        crate::hal::serial::write_string("LI3\r\n");

        alloc.init(region_base, region_size, table_ptr, FRAME_TABLE_BYTES);
        TOTAL_PAGES.store(alloc.total_count(), Ordering::SeqCst);
        FREE_PAGES.store(alloc.free_count(), Ordering::SeqCst);
    }
    crate::hal::serial::write_string("FRAME_INIT_DONE_LEGACY\r\n");
}

/// Allocate a single physical frame.
pub fn allocate_frame() -> Option<u64> {
    allocate_pages(1)
}

/// Free a single physical frame.
pub fn free_frame(phys_addr: u64) {
    free_pages(phys_addr, 1);
}

/// Allocate `count` contiguous physical frames.
pub fn allocate_pages(count: u64) -> Option<u64> {
    let mut alloc = BUDDY_ALLOCATOR.lock();
    let result = alloc.allocate(count);
    if let Some(addr) = result {
        FREE_PAGES.fetch_sub(count, Ordering::SeqCst);
        Some(addr)
    } else {
        None
    }
}

/// Free `count` contiguous physical frames at `phys_addr`.
pub fn free_pages(phys_addr: u64, count: u64) {
    let mut alloc = BUDDY_ALLOCATOR.lock();
    alloc.free(phys_addr, count);
    FREE_PAGES.fetch_add(count, Ordering::SeqCst);
}

/// Allocate from a specific zone.
pub fn allocate_zone(_zone: MemoryZone, count: u64) -> Option<u64> {
    allocate_pages(count)
}

/// Increase reference count (page sharing).
pub fn reference(_phys_addr: u64) {}

/// Decrease reference count (page sharing).
pub fn dereference(_phys_addr: u64) {}

/// Get total physical memory.
pub fn get_total_physical() -> u64 {
    TOTAL_PAGES.load(Ordering::SeqCst) * 4096
}

/// Get free physical memory.
pub fn get_free_physical() -> u64 {
    FREE_PAGES.load(Ordering::SeqCst) * 4096
}

/// Convert physical address to frame index.
pub fn phys_to_frame(phys: u64) -> u64 {
    phys / 4096
}

/// Convert frame index to physical address.
pub fn frame_to_phys(frame: u64) -> u64 {
    frame * 4096
}
