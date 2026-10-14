//! I/O Manager - Dynamic IRP Pool Implementation
//!
//! Scalable IRP pool with automatic growth and shrinking.
//!
//! The pool hands out blocks that contain the IRP body plus its stack
//! locations inline, which is the layout `crate::io::allocate_irp`
//! produces. This file used to define its own `Irp` with no stack
//! locations at all, so IRPs handed out here were not layout-compatible
//! with the I/O manager and could not carry an I/O stack; it also ignored
//! the requested stack depth. Both are fixed by reusing the canonical
//! `crate::io` layout.

use crate::io::{IoStackLocation, Irp};
use crate::ke::sync::Spinlock;
use crate::mm::pool;
use alloc::vec::Vec;

const IRP_TAG: u32 = u32::from_be_bytes([b'I', b'r', b'p', b' ']);

#[inline]
fn block_size(stack_locations: usize) -> usize {
    core::mem::size_of::<Irp>() + core::mem::size_of::<IoStackLocation>() * stack_locations
}

/// Lay out the inline stack locations after the IRP body.
///
/// Locations are numbered 1..StackCount from the low end of the block and
/// `CurrentStack` starts at location StackCount, matching WRK
/// `ExAllocateIrp`, so `IoGetNextStackLocation` walks downwards.
unsafe fn setup_irp(irp: *mut Irp, stack_locations: usize) {
    (*irp) = Irp::new();
    (*irp).stack_count = stack_locations as u8;
    (*irp).current_location = stack_locations as u8;
    (*irp).allocate_stack = 0;

    let stack_base = (irp as *mut u8).add(core::mem::size_of::<Irp>()) as *mut IoStackLocation;
    for i in 0..stack_locations {
        let sl = stack_base.add(i);
        (*sl) = IoStackLocation::new();
    }
    (*irp).current_stack = stack_base.add(stack_locations - 1);
}

pub struct DynamicIrpPool {
    free_list: Vec<(*mut Irp, usize)>,
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
        // A pool created with an initial size below 4 would get a zero grow
        // increment and therefore never be able to allocate anything beyond its
        // initial block: every later `allocate()` would report a failure. The
        // lookaside-style pool must always be able to grow by at least one IRP.
        let grow_increment = (initial_size / 4).max(1);

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

        pool.grow(initial_size, 1);

        pool
    }

    pub fn allocate(&mut self, stack_locations: u8) -> Option<*mut Irp> {
        if stack_locations == 0 {
            self.stats.allocation_failures += 1;
            return None;
        }

        let needed = block_size(stack_locations as usize);

        // Reuse a block that is big enough for the requested stack depth.
        if let Some(index) = self.free_list.iter().position(|&(_, size)| size >= needed) {
            let (irp, size) = self.free_list.remove(index);
            unsafe { setup_irp(irp, stack_locations as usize) };

            self.allocated_count += 1;
            self.peak_usage = self.peak_usage.max(self.allocated_count);
            self.stats.total_allocations += 1;
            self.stats.current_allocated = self.allocated_count;
            self.stats.peak_allocated = self.stats.peak_allocated.max(self.allocated_count);
            let _ = size;
            return Some(irp);
        }

        if self.allocated_count < self.max_size {
            let grow_size = self
                .grow_increment
                .min(self.max_size - self.allocated_count);
            if self.grow(grow_size, stack_locations as usize) > 0 {
                self.stats.grow_operations += 1;
                if let Some(index) = self.free_list.iter().position(|&(_, size)| size >= needed) {
                    let (irp, _) = self.free_list.remove(index);
                    self.allocated_count += 1;
                    self.peak_usage = self.peak_usage.max(self.allocated_count);
                    self.stats.total_allocations += 1;
                    self.stats.current_allocated = self.allocated_count;
                    self.stats.peak_allocated = self.stats.peak_allocated.max(self.allocated_count);
                    return Some(irp);
                }
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
            (*irp) = Irp::new();

            let header =
                (irp as *mut u8).sub(pool::PoolHeader::HEADER_SIZE) as *const pool::PoolHeader;
            let usable = (*header).block_size as usize - pool::PoolHeader::HEADER_SIZE;
            self.free_list.push((irp, usable));
        }

        self.allocated_count = self.allocated_count.saturating_sub(1);
        self.stats.total_frees += 1;
        self.stats.current_allocated = self.allocated_count;
    }

    fn grow(&mut self, count: usize, stack_locations: usize) -> usize {
        let mut allocated = 0;

        for _ in 0..count {
            let ptr = pool::allocate_tagged(
                pool::PoolType::NonPaged,
                block_size(stack_locations),
                IRP_TAG,
            );
            if ptr.is_null() {
                break;
            }
            let irp = ptr as *mut Irp;
            unsafe { setup_irp(irp, stack_locations) };
            self.free_list.push((irp, block_size(stack_locations)));
            allocated += 1;
        }

        allocated
    }

    /// Shrink the pool (free unused IRPs)
    pub fn shrink(&mut self, target_free: usize) -> usize {
        let mut freed = 0;

        while self.free_list.len() > target_free {
            if let Some((irp, _)) = self.free_list.pop() {
                pool::free(irp as *mut u8);
                freed += 1;
            }
        }

        freed
    }

    pub fn get_stats(&self) -> IrpPoolStats {
        self.stats
    }

    pub fn usage_percent(&self) -> f32 {
        if self.max_size == 0 {
            return 0.0;
        }
        (self.allocated_count as f32 / self.max_size as f32) * 100.0
    }
}

static IRP_POOL: Spinlock<Option<DynamicIrpPool>> = Spinlock::new(None);

pub fn init_irp_pool(initial_size: usize, max_size: usize) {
    let mut pool = IRP_POOL.lock();
    *pool = Some(DynamicIrpPool::new(initial_size, max_size));
}

pub fn allocate_irp(stack_locations: u8) -> Option<*mut Irp> {
    let mut pool = IRP_POOL.lock();
    pool.as_mut()?.allocate(stack_locations)
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

    // Under user-mode libtest the kernel heap is never initialised (no
    // `kernel_main` runs), so `pool::allocate_tagged` returns null. Configure a
    // test region so these tests exercise the real allocation path instead of
    // skipping it.
    fn ensure_test_heap() {
        if crate::mm::heap::KERNEL_HEAP.configured_region().is_some() {
            return;
        }
        static mut TEST_HEAP: [u8; 64 * 1024] = [0u8; 64 * 1024];
        unsafe {
            let base = core::ptr::addr_of_mut!(TEST_HEAP) as *mut u8;
            crate::mm::heap::KERNEL_HEAP.configure(base, TEST_HEAP.len());
        }
    }

    #[test]
    fn test_irp_allocation() {
        ensure_test_heap();

        let mut pool = DynamicIrpPool::new(10, 100);

        let irp = pool.allocate(1);
        assert!(irp.is_some());
        assert_eq!(pool.stats.current_allocated, 1);

        unsafe {
            assert_eq!((*irp.unwrap()).stack_count, 1);
            assert_eq!((*irp.unwrap()).current_location, 1);
            assert!(!(*irp.unwrap()).current_stack.is_null());
        }

        pool.free(irp.unwrap());
        assert_eq!(pool.stats.current_allocated, 0);
    }

    #[test]
    fn test_stack_locations_are_honoured() {
        ensure_test_heap();

        let mut pool = DynamicIrpPool::new(4, 100);

        let irp = pool.allocate(3).unwrap();
        unsafe {
            assert_eq!((*irp).stack_count, 3);
            assert_eq!((*irp).current_location, 3);

            // The current location must be the top of the stack, and the
            // next one must still be inside the block.
            let current = (*irp).current_stack;
            let base = (irp as *mut u8).add(core::mem::size_of::<Irp>()) as *mut IoStackLocation;
            assert_eq!(current, base.add(2));

            let next = (current as usize - core::mem::size_of::<IoStackLocation>())
                as *mut IoStackLocation;
            assert!(next >= base && next < current);
        }
        pool.free(irp);
    }

    #[test]
    fn test_pool_growth() {
        ensure_test_heap();

        let mut pool = DynamicIrpPool::new(2, 100);

        let irp1 = pool.allocate(1).unwrap();
        let irp2 = pool.allocate(1).unwrap();
        let irp3 = pool.allocate(1);
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
            if let Some(irp) = pool.allocate(1) {
                irps.push(irp);
            }
        }

        assert!(irps.len() <= 5);
        if !irps.is_empty() {
            assert!(pool.stats.current_allocated <= 5);
            for irp in irps {
                pool.free(irp);
            }
        } else {
            // No heap available in libtest: the only observable behaviour
            // is that every request was counted as a failure.
            assert!(pool.stats.allocation_failures > 0);
        }
    }
}
