//! Registry Cell Allocator
//!
//! Manages allocation and deallocation of registry cells within hive bins.
//! Implements the NT Configuration Manager's cell allocation strategy with
//! free lists and bitmap tracking for efficient space management.

extern crate alloc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};

use super::hive::HiveError;

pub const MIN_CELL_SIZE: usize = 8;

pub const MAX_CELL_SIZE: usize = 512 * 1024;

pub const CELL_ALIGNMENT: usize = 8;

pub const FREE_LIST_BUCKETS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellFlags {
    pub volatile: bool,
    pub stable: bool,
}

impl Default for CellFlags {
    fn default() -> Self {
        Self {
            volatile: false,
            stable: true,
        }
    }
}

#[derive(Debug, Clone)]
struct FreeCell {
    offset: u32,
    size: u32,
}

pub struct CellAllocator {
    free_lists: [Vec<FreeCell>; FREE_LIST_BUCKETS],
    allocated: BTreeMap<u32, u32>,
    total_allocated: AtomicU32,
    total_free: AtomicU32,
    next_offset: AtomicU32,
    max_size: u32,
}

impl CellAllocator {
    pub fn new(initial_size: u32, max_size: u32) -> Self {
        const EMPTY_VEC: Vec<FreeCell> = Vec::new();
        Self {
            free_lists: [EMPTY_VEC; FREE_LIST_BUCKETS],
            allocated: BTreeMap::new(),
            total_allocated: AtomicU32::new(0),
            total_free: AtomicU32::new(0),
            next_offset: AtomicU32::new(initial_size),
            max_size,
        }
    }

    pub fn allocate(&mut self, size: u32, _flags: CellFlags) -> Result<u32, HiveError> {
        if size < MIN_CELL_SIZE as u32 || size > MAX_CELL_SIZE as u32 {
            return Err(HiveError::OutOfBounds);
        }

        let aligned_size = align_up(size, CELL_ALIGNMENT as u32);

        let bucket = size_to_bucket(aligned_size);

        for b in bucket..FREE_LIST_BUCKETS {
            if let Some(pos) = self.free_lists[b]
                .iter()
                .position(|cell| cell.size >= aligned_size)
            {
                let cell = self.free_lists[b].remove(pos);
                let offset = cell.offset;

                let remainder = cell.size - aligned_size;
                if remainder >= MIN_CELL_SIZE as u32 {
                    self.free_cell_internal(offset + aligned_size, remainder);
                }

                self.allocated.insert(offset, aligned_size);
                self.total_allocated.fetch_add(aligned_size, Ordering::SeqCst);
                self.total_free.fetch_sub(cell.size, Ordering::SeqCst);

                return Ok(offset);
            }
        }

        let offset = self.next_offset.load(Ordering::SeqCst);
        let new_next = offset + aligned_size;

        if new_next > self.max_size {
            return Err(HiveError::OutOfBounds);
        }

        self.next_offset.store(new_next, Ordering::SeqCst);
        self.allocated.insert(offset, aligned_size);
        self.total_allocated.fetch_add(aligned_size, Ordering::SeqCst);

        Ok(offset)
    }

    pub fn free(&mut self, offset: u32) -> Result<(), HiveError> {
        let size = self.allocated
            .remove(&offset)
            .ok_or(HiveError::InvalidPointer)?;

        self.total_allocated.fetch_sub(size, Ordering::SeqCst);
        self.free_cell_internal(offset, size);

        Ok(())
    }

    fn free_cell_internal(&mut self, offset: u32, size: u32) {
        let coalesced = self.coalesce_free_cell(offset, size);

        let bucket = size_to_bucket(coalesced.size);
        let coalesced_size = coalesced.size;
        self.free_lists[bucket].push(coalesced);
        self.total_free.fetch_add(coalesced_size, Ordering::SeqCst);
    }

    fn coalesce_free_cell(&mut self, offset: u32, size: u32) -> FreeCell {
        let mut result_offset = offset;
        let mut result_size = size;

        for bucket in &mut self.free_lists {
            if let Some(pos) = bucket.iter().position(|cell| cell.offset + cell.size == offset) {
                let prev = bucket.remove(pos);
                result_offset = prev.offset;
                result_size += prev.size;
                self.total_free.fetch_sub(prev.size, Ordering::SeqCst);
                break;
            }
        }

        let next_offset = result_offset + result_size;
        for bucket in &mut self.free_lists {
            if let Some(pos) = bucket.iter().position(|cell| cell.offset == next_offset) {
                let next = bucket.remove(pos);
                result_size += next.size;
                self.total_free.fetch_sub(next.size, Ordering::SeqCst);
                break;
            }
        }

        FreeCell {
            offset: result_offset,
            size: result_size,
        }
    }

    pub fn stats(&self) -> CellAllocatorStats {
        CellAllocatorStats {
            total_allocated: self.total_allocated.load(Ordering::SeqCst),
            total_free: self.total_free.load(Ordering::SeqCst),
            allocated_cells: self.allocated.len() as u32,
            next_offset: self.next_offset.load(Ordering::SeqCst),
        }
    }

    pub fn validate(&self) -> Result<(), HiveError> {
        let mut sorted: Vec<_> = self.allocated.iter().collect();
        sorted.sort_by_key(|(offset, _)| *offset);

        for i in 0..sorted.len().saturating_sub(1) {
            let (off1, size1) = sorted[i];
            let (off2, _) = sorted[i + 1];
            if off1 + size1 > *off2 {
                return Err(HiveError::OutOfBounds);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CellAllocatorStats {
    pub total_allocated: u32,
    pub total_free: u32,
    pub allocated_cells: u32,
    pub next_offset: u32,
}

fn size_to_bucket(size: u32) -> usize {
    if size <= 64 {
        0
    } else if size <= 128 {
        1
    } else if size <= 256 {
        2
    } else if size <= 512 {
        3
    } else {
        let mut log: usize = 0;
        let mut s = size;
        while s > 1 {
            s >>= 1;
            log += 1;
        }
        (log.saturating_sub(9)).min(FREE_LIST_BUCKETS - 1)
    }
}

fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_free() {
        let mut allocator = CellAllocator::new(4096, 1024 * 1024);

        let offset1 = allocator.allocate(64, CellFlags::default()).unwrap();
        assert_eq!(offset1, 4096);

        let offset2 = allocator.allocate(128, CellFlags::default()).unwrap();
        assert_eq!(offset2, 4096 + 64);

        allocator.free(offset1).unwrap();

        let offset3 = allocator.allocate(64, CellFlags::default()).unwrap();
        assert_eq!(offset3, 4096); // Reused
    }

    #[test]
    fn test_coalescing() {
        let mut allocator = CellAllocator::new(4096, 1024 * 1024);

        let o1 = allocator.allocate(64, CellFlags::default()).unwrap();
        let o2 = allocator.allocate(64, CellFlags::default()).unwrap();
        let _o3 = allocator.allocate(64, CellFlags::default()).unwrap();

        allocator.free(o1).unwrap();
        allocator.free(o2).unwrap();

        let o4 = allocator.allocate(128, CellFlags::default()).unwrap();
        assert_eq!(o4, o1);
    }
}
