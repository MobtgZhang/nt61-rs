use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, AtomicI32, AtomicI64, AtomicPtr, Ordering};

use core::sync::atomic::{AtomicU64, AtomicUsize, AtomicPtr, Ordering};

const PFN_BOOTSTRAP_SIZE: usize = 2 * 1024 * 1024;

struct PfnStorage {
    bootstrap: [u8; PFN_BOOTSTRAP_SIZE],
    ptr: AtomicPtr<u8>,
    phys: AtomicU64,
    used: AtomicUsize,
    capacity: AtomicUsize,
}

impl PfnStorage {
    const fn new() -> Self {
        Self {
            bootstrap: [0; PFN_BOOTSTRAP_SIZE],
            ptr: AtomicPtr::new(core::ptr::null_mut()),
            phys: AtomicU64::new(0),
            used: AtomicUsize::new(0),
            capacity: AtomicUsize::new(0),
        }
    }

    fn get_ptr(&self) -> *mut u8 {
        self.ptr.load(Ordering::Acquire)
    }

    fn set_ptr(&self, ptr: *mut u8) {
        self.ptr.store(ptr, Ordering::Release);
    }

    fn get_phys(&self) -> u64 {
        self.phys.load(Ordering::Acquire)
    }

    fn set_phys(&self, phys: u64) {
        self.phys.store(phys, Ordering::Release);
    }

    fn get_used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    fn add_used(&self, delta: usize) -> usize {
        self.used.fetch_add(delta, Ordering::AcqRel)
    }

    fn get_capacity(&self) -> usize {
        self.capacity.load(Ordering::Acquire)
    }

    fn set_capacity(&self, cap: usize) {
        self.capacity.store(cap, Ordering::Release);
    }
}

static PFN_STORAGE: Lazy<Mutex<PfnStorage>> = Lazy::new(|| {
    Mutex::new(PfnStorage::new())
});

static PFN_COUNT: AtomicU64 = AtomicU64::new(0);
static PFN_BASE: AtomicU64 = AtomicU64::new(0);

pub fn get_pfn_count() -> u64 {
    PFN_COUNT.load(Ordering::Acquire)
}

pub fn set_pfn_count(count: u64) {
    PFN_COUNT.store(count, Ordering::Release);
}

pub fn get_pfn_base() -> u64 {
    PFN_BASE.load(Ordering::Acquire)
}

pub fn set_pfn_base(base: u64) {
    PFN_BASE.store(base, Ordering::Release);
}

pub fn init_pfn_storage(ptr: *mut u8, phys: u64, capacity: usize) {
    let storage = PFN_STORAGE.lock();
    storage.set_ptr(ptr);
    storage.set_phys(phys);
    storage.set_capacity(capacity);
}

pub fn alloc_pfn_storage(size: usize) -> Option<*mut u8> {
    let storage = PFN_STORAGE.lock();
    let used = storage.get_used();
    let capacity = storage.get_capacity();

    if used + size > capacity {
        return None;
    }

    let ptr = storage.get_ptr();
    if ptr.is_null() {
        return None;
    }

    let result = unsafe { ptr.add(used) };
    storage.add_used(size);
    Some(result)
}
