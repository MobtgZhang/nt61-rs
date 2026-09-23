use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, AtomicI32, AtomicI64, AtomicPtr, Ordering};

use core::sync::atomic::{AtomicU64, AtomicUsize, AtomicPtr, Ordering};

const FRAME_TABLE_BYTES: usize = 1024 * 1024; // 1 MB

struct FrameAllocator {
    frame_table: [u8; FRAME_TABLE_BYTES],
    dyn_frame_infos: AtomicPtr<u8>,
    dyn_buddy_nodes: AtomicPtr<u8>,
    dyn_frame_infos_phys: AtomicU64,
    dyn_buddy_nodes_phys: AtomicU64,
    dyn_len: AtomicUsize,
    dyn_base_phys: AtomicU64,
}

impl FrameAllocator {
    const fn new() -> Self {
        Self {
            frame_table: [0; FRAME_TABLE_BYTES],
            dyn_frame_infos: AtomicPtr::new(core::ptr::null_mut()),
            dyn_buddy_nodes: AtomicPtr::new(core::ptr::null_mut()),
            dyn_frame_infos_phys: AtomicU64::new(0),
            dyn_buddy_nodes_phys: AtomicU64::new(0),
            dyn_len: AtomicUsize::new(0),
            dyn_base_phys: AtomicU64::new(0),
        }
    }
}

static FRAME_ALLOCATOR: Lazy<Mutex<FrameAllocator>> = Lazy::new(|| {
    Mutex::new(FrameAllocator::new())
});

pub fn init_dyn_allocator(
    frame_infos: *mut u8,
    buddy_nodes: *mut u8,
    frame_infos_phys: u64,
    buddy_nodes_phys: u64,
    len: usize,
    base_phys: u64,
) {
    let alloc = FRAME_ALLOCATOR.lock();
    alloc.dyn_frame_infos.store(frame_infos, Ordering::Release);
    alloc.dyn_buddy_nodes.store(buddy_nodes, Ordering::Release);
    alloc.dyn_frame_infos_phys.store(frame_infos_phys, Ordering::Release);
    alloc.dyn_buddy_nodes_phys.store(buddy_nodes_phys, Ordering::Release);
    alloc.dyn_len.store(len, Ordering::Release);
    alloc.dyn_base_phys.store(base_phys, Ordering::Release);
}

pub fn with_frame_table<F, R>(f: F) -> R
where
    F: FnOnce(&[u8; FRAME_TABLE_BYTES]) -> R,
{
    let alloc = FRAME_ALLOCATOR.lock();
    f(&alloc.frame_table)
}

pub fn get_dyn_frame_infos() -> *mut u8 {
    let alloc = FRAME_ALLOCATOR.lock();
    alloc.dyn_frame_infos.load(Ordering::Acquire)
}

pub fn get_dyn_len() -> usize {
    let alloc = FRAME_ALLOCATOR.lock();
    alloc.dyn_len.load(Ordering::Acquire)
}
