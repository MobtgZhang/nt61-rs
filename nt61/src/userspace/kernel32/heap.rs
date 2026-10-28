//! Per-process Windows heap backing user-mode allocations.

extern crate alloc;

use crate::ke::sync::Spinlock;
use crate::mm::pte;
use crate::mm::vas;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::mem::size_of;
use core::ptr;

#[cfg(target_arch = "riscv64")]
pub const HEAP_BASE: u64 = 0x0000_003F_C000_0000;

#[cfg(not(target_arch = "riscv64"))]
pub const HEAP_BASE: u64 = 0x0000_7FFF_C000_0000;
pub const HEAP_PAGE_BUDGET: u64 = 0x0040_0000;
const BLOCK_MAGIC: u32 = 0x4B4F_4C42;
const HEADER_SIZE: usize = size_of::<BlockHeader>();
const MIN_BLOCK_SIZE: usize = 32;
const ALIGNMENT: usize = 16;

#[repr(C)]
struct BlockHeader {
    magic: u32,
    flags: u32,
    size: usize,
    next: *mut BlockHeader,
}

/// One process's heap state. Heap metadata lives in the process's own
/// address space at `HEAP_BASE`, so two processes must never share a
/// free list: sharing corrupts both heaps when either allocates.
#[derive(Clone, Copy)]
struct ProcessHeap {
    base: u64,
    free_head: *mut BlockHeader,
}

struct HeapTableEntry {
    pml4: u64,
    heap: ProcessHeap,
}

/// Upper bound on concurrently tracked process heaps. The boot-time
/// process count is small; when the table is full `init_user_heap`
/// fails closed (allocations return null) instead of sharing a heap.
const HEAP_TABLE_MAX: usize = 32;

static HEAPS: Spinlock<alloc::vec::Vec<HeapTableEntry>> = Spinlock::new(alloc::vec::Vec::new());

/// PML4 of the process whose address space is currently active, or 0
/// when no user process is running (heap ops then fail closed).
fn current_process_pml4() -> u64 {
    let ethread = crate::ps::thread::get_current_ethread();
    if ethread.is_null() {
        return 0;
    }
    unsafe { (*(*ethread).kthread.process).page_table_pml4 }
}

pub struct UserHeapAllocator;

pub fn init_user_heap(pml4: u64) -> u64 {
    if pml4 == 0 {
        return 0;
    }

    let mut table = HEAPS.lock();
    if let Some(entry) = table.iter().find(|e| e.pml4 == pml4) {
        let base = entry.heap.base;
        return base;
    }
    if table.len() >= HEAP_TABLE_MAX {
        return 0;
    }

    let status = vas::map_user_pages(pml4, HEAP_BASE, HEAP_PAGE_BUDGET, pte::PTE_RW | pte::PTE_US);
    if status != vas::MmStatus::Ok {
        return 0;
    }

    // Page-table setup must happen on the system root. Attach only after
    // all user pages exist, so the heap can be initialized through user VAs.
    vas::refresh_kernel_mappings(pml4);
    let previous_root = vas::attach_process(pml4);

    let base = HEAP_BASE;
    let first_block = (base + HEADER_SIZE as u64) as *mut BlockHeader;
    let first_size = HEAP_PAGE_BUDGET as usize - HEADER_SIZE;
    unsafe {
        for offset in 0..HEAP_PAGE_BUDGET as usize {
            core::ptr::write_volatile((base + offset as u64) as *mut u8, 0u8);
        }
        ptr::write(
            first_block,
            BlockHeader {
                magic: BLOCK_MAGIC,
                flags: 0,
                size: first_size,
                next: ptr::null_mut(),
            },
        );
    }
    vas::detach_process(previous_root);

    // Insert the heap only after returning to the system root. `Vec::push`
    // can allocate, and kernel allocations may touch PFN metadata by
    // physical address; performing that work under a process root would
    // depend on an identity mapping that is not guaranteed on every target.
    table.push(HeapTableEntry {
        pml4,
        heap: ProcessHeap {
            base,
            free_head: first_block,
        },
    });
    base
}

fn align_up(value: usize) -> usize {
    (value + ALIGNMENT - 1) & !(ALIGNMENT - 1)
}

pub fn alloc_bytes(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }

    let requested = align_up(size + HEADER_SIZE);
    let mut table = HEAPS.lock();
    let heap = match table
        .iter_mut()
        .find(|e| e.pml4 == current_process_pml4())
    {
        Some(entry) => &mut entry.heap,
        None => return ptr::null_mut(),
    };

    let mut previous: *mut BlockHeader = ptr::null_mut();
    let mut current = heap.free_head;
    while !current.is_null() {
        unsafe {
            let block = &mut *current;
            if block.magic != BLOCK_MAGIC {
                return ptr::null_mut();
            }
            if block.size >= requested {
                let remaining = block.size - requested;
                if remaining >= MIN_BLOCK_SIZE + HEADER_SIZE {
                    let split = current as usize + requested;
                    let split_block = split as *mut BlockHeader;
                    ptr::write(
                        split_block,
                        BlockHeader {
                            magic: BLOCK_MAGIC,
                            flags: 0,
                            size: remaining,
                            next: block.next,
                        },
                    );
                    block.next = split_block;
                    block.size = requested;
                }
                if previous.is_null() {
                    heap.free_head = block.next;
                } else {
                    (*previous).next = block.next;
                }

                block.flags = 1;
                let data = (current as usize + HEADER_SIZE) as *mut u8;
                return data;
            }

            previous = current;
            current = block.next;
        }
    }

    ptr::null_mut()
}

pub fn free_bytes(pointer: *mut u8) {
    if pointer.is_null() {
        return;
    }

    let mut table = HEAPS.lock();
    let heap = match table
        .iter_mut()
        .find(|e| e.pml4 == current_process_pml4())
    {
        Some(entry) => &mut entry.heap,
        None => {
            return;
        }
    };

    let block = unsafe { pointer.sub(HEADER_SIZE) as *mut BlockHeader };
    unsafe {
        if (*block).magic != BLOCK_MAGIC || (*block).flags != 1 {
            return;
        }

        (*block).flags = 0;
        let mut previous: *mut BlockHeader = ptr::null_mut();
        let mut current = heap.free_head;
        while !current.is_null() && (current as usize) < block as usize {
            previous = current;
            current = (*current).next;
        }

        if previous.is_null() {
            (*block).next = heap.free_head;
            heap.free_head = block;
        } else {
            (*block).next = (*previous).next;
            (*previous).next = block;
        }

        if !(*block).next.is_null() && block as usize + (*block).size == (*block).next as usize {
            (*block).size += (*(*block).next).size + HEADER_SIZE;
            (*block).next = (*(*block).next).next;
        }

        if !previous.is_null() && previous as usize + (*previous).size == block as usize {
            (*previous).size += (*block).size + HEADER_SIZE;
            (*previous).next = (*block).next;
        }
    }
}

unsafe impl GlobalAlloc for UserHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        alloc_bytes(layout.size())
    }

    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        free_bytes(pointer)
    }
}
