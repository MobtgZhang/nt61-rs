use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU8};

#[derive(Debug)]
pub struct CrtStats {
    malloc_count: AtomicU64,
    free_count: AtomicU64,
    realloc_count: AtomicU64,
}

impl CrtStats {
    pub const fn new() -> Self {
        Self {
            malloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            realloc_count: AtomicU64::new(0),
        }
    }

    pub fn inc_malloc(&self) {
        self.malloc_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_free(&self) {
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_realloc(&self) {
        self.realloc_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_malloc_count(&self) -> u64 {
        self.malloc_count.load(Ordering::Relaxed)
    }

    pub fn get_free_count(&self) -> u64 {
        self.free_count.load(Ordering::Relaxed)
    }

    pub fn get_realloc_count(&self) -> u64 {
        self.realloc_count.load(Ordering::Relaxed)
    }
}

pub static CRT_STATS: CrtStats = CrtStats::new();

#[cfg_attr(not(test), no_mangle)]
pub static __security_cookie: AtomicUsize = AtomicUsize::new(0xBB40E64E);
#[cfg_attr(not(test), no_mangle)]
pub static __security_cookie_complement: AtomicUsize = AtomicUsize::new(!0xBB40E64E);

pub fn init_security_cookie() {
    // In a real implementation, this would use hardware RNG
    let cookie = 0xBB40E64E ^ (crate::ke::time::get_system_time() as usize);
    __security_cookie.store(cookie, Ordering::Relaxed);
    __security_cookie_complement.store(!cookie, Ordering::Relaxed);
}

pub fn check_security_cookie(cookie: usize) -> bool {
    cookie == __security_cookie.load(Ordering::Relaxed)
}
