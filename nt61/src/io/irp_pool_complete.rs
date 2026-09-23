//! I/O Manager - Dynamic IRP Pool Implementation
//!
//! Scalable IRP pool with automatic growth and shrinking

use alloc::vec::Vec;
use crate::ke::sync::Spinlock;
use crate::mm::pool;

#[repr(C)]
pub struct Irp {
    pub flags: u32,
    pub io_status: IoStatusBlock,
    pub user_buffer: *mut u8,
    pub system_buffer: *mut u8,
    pub tail: IrpTail,
}

#[repr(C)]
pub struct IoStatusBlock {
    pub status: i32,
    pub information: usize,
}

#[repr(C)]
pub struct IrpTail {
    pub overlay: IrpOverlay,
}

#[repr(C)]
pub struct IrpOverlay {
    pub device_queue_entry: *mut u8,
    pub thread: *mut u8,
}

impl Irp {
    pub fn init(&mut self) {
        self.flags = 0;
        self.io_status.status = 0;
        self.io_status.information = 0;
        self.user_buffer = core::ptr::null_mut();
        self.system_buffer = core::ptr::null_mut();
    }

    pub fn reset(&mut self) {
        self.init();
    }
}

pub struct DynamicIrpPool {
    free_list: Vec<*mut Irp>,
    allocated_count: usize,
    peak_usage: usize,
    initial_size: usize,
    max_size: usize,
    grow_increment: usize,
    stats: IrpPoolStats,
}

#[derive(Debug, Clone, Copy)]
pub struct IrpPoolStats {
    pub total_allocations: u64,
    pub total_frees: u64,
    pub current_allocated: usize,
    pub peak_allocated: usize,
    pub grow_operations: u32,
    pub allocation_failures: u32,
}

impl DynamicIrpPool {
    pub fn new(initial_size: usize, max_size: usize) -> Self {
        let grow_increment = initial_size / 4;

        let mut pool = Self {
            free_list: Vec::with_capacity(initial_size),
            allocated_count: 0,
            peak_usage: 0,
            initial_size,
            max_size,
            grow_increment,
            stats: IrpPoolStats {
                total_allocations: 0,
                total_frees: 0,
                current_allocated: 0,
                peak_allocated: 0,
                grow_operations: 0,
                allocation_failures: 0,
            },
        };

        pool.grow(initial_size);

        pool
    }

    pub fn allocate(&mut self) -> Option<*mut Irp> {
        if let Some(irp) = self.free_list.pop() {
            self.allocated_count += 1;
            self.peak_usage = self.peak_usage.max(self.allocated_count);

            self.stats.total_allocations += 1;
            self.stats.current_allocated = self.allocated_count;
            self.stats.peak_allocated = self.stats.peak_allocated.max(self.allocated_count);

            return Some(irp);
        }

        if self.allocated_count < self.max_size {
            let grow_size = (self.grow_increment).min(self.max_size - self.allocated_count);
            if self.grow(grow_size) > 0 {
                self.stats.grow_operations += 1;
                return self.free_list.pop().map(|irp| {
                    self.allocated_count += 1;
                    self.stats.total_allocations += 1;
                    self.stats.current_allocated = self.allocated_count;
                    irp
                });
            }
        }

        self.stats.allocation_failures += 1;
        None
    }

    pub fn free(&mut self, irp: *mut Irp) {
        if irp.is_null() {
            return;
        }

        unsafe {
            (*irp).reset();
        }

        self.free_list.push(irp);
        self.allocated_count = self.allocated_count.saturating_sub(1);

        self.stats.total_frees += 1;
        self.stats.current_allocated = self.allocated_count;
    }

    fn grow(&mut self, count: usize) -> usize {
        let mut allocated = 0;

        for _ in 0..count {
            unsafe {
                let ptr = pool::alloc(core::mem::size_of::<Irp>(), b"Irp ");
                if !ptr.is_null() {
                    let irp = ptr as *mut Irp;
                    (*irp).init();
                    self.free_list.push(irp);
                    allocated += 1;
                } else {
                    break;
                }
            }
        }

        allocated
    }

    /// Shrink the pool (free unused IRPs)
    pub fn shrink(&mut self, target_free: usize) -> usize {
        let mut freed = 0;

        while self.free_list.len() > target_free {
            if let Some(irp) = self.free_list.pop() {
                unsafe {
                    pool::free(irp as *mut u8);
                }
                freed += 1;
            }
        }

        freed
    }

    pub fn get_stats(&self) -> IrpPoolStats {
        self.stats
    }

    pub fn usage_percent(&self) -> f32 {
        (self.allocated_count as f32 / self.max_size as f32) * 100.0
    }
}

static IRP_POOL: Spinlock<Option<DynamicIrpPool>> = Spinlock::new(None);

pub fn init_irp_pool(initial_size: usize, max_size: usize) {
    let mut pool = IRP_POOL.lock();
    *pool = Some(DynamicIrpPool::new(initial_size, max_size));
}

pub fn allocate_irp() -> Option<*mut Irp> {
    let mut pool = IRP_POOL.lock();
    pool.as_mut()?.allocate()
}

pub fn free_irp(irp: *mut Irp) {
    let mut pool = IRP_POOL.lock();
    if let Some(p) = pool.as_mut() {
        p.free(irp);
    }
}

pub fn get_irp_pool_stats() -> Option<IrpPoolStats> {
    let pool = IRP_POOL.lock();
    pool.as_ref().map(|p| p.get_stats())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irp_allocation() {
        let mut pool = DynamicIrpPool::new(10, 100);

        let irp = pool.allocate();
        assert!(irp.is_some());
        assert_eq!(pool.stats.current_allocated, 1);

        pool.free(irp.unwrap());
        assert_eq!(pool.stats.current_allocated, 0);
    }

    #[test]
    fn test_pool_growth() {
        let mut pool = DynamicIrpPool::new(2, 100);

        let irp1 = pool.allocate().unwrap();
        let irp2 = pool.allocate().unwrap();

        let irp3 = pool.allocate();
        assert!(irp3.is_some());
        assert!(pool.stats.grow_operations > 0);

        pool.free(irp1);
        pool.free(irp2);
        pool.free(irp3.unwrap());
    }

    #[test]
    fn test_max_size_limit() {
        let mut pool = DynamicIrpPool::new(2, 5);

        let mut irps = Vec::new();

        for _ in 0..10 {
            if let Some(irp) = pool.allocate() {
                irps.push(irp);
            }
        }

        assert!(irps.len() <= 5);
        assert!(pool.stats.allocation_failures > 0);

        for irp in irps {
            pool.free(irp);
        }
    }
}
