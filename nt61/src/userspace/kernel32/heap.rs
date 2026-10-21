//! Per-process Windows heap backing user-mode allocations.

extern crate alloc;

use crate::ke::sync::Spinlock;
use crate::mm::pte;
use crate::mm::vas;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::mem::size_of;
use core::ptr;

pub const HEAP_BASE: u64 = 0x0000_7FFF_C000_0000;
pub const HEAP_PAGE_BUDGET: u64 = 0x0200_0000;
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

#[derive(Clone, Copy)]
struct HeapState {
    base: u64,
    free_head: *mut BlockHeader,
    initialized: bool,
}

static HEAP: Spinlock<HeapState> = Spinlock::new(HeapState {
    base: 0,
    free_head: ptr::null_mut(),
    initialized: false,
});

pub struct UserHeapAllocator;

pub fn init_user_heap(pml4: u64) -> u64 {
    crate::boot_println!("[USERHEAP] init enter pml4=0x{:x}", pml4);
    if pml4 == 0 {
        return 0;
    }

    let mut state = HEAP.lock();
    crate::boot_println!("[USERHEAP] locked initialized={}", state.initialized);
    if state.initialized {
        return state.base;
    }

    let status = vas::map_user_pages(pml4, HEAP_BASE, HEAP_PAGE_BUDGET, pte::PTE_RW | pte::PTE_US);
    if status != vas::MmStatus::Ok {
        crate::boot_println!("[USERHEAP] map failed status={:?}", status);
        return 0;
    }
    crate::boot_println!(
        "[USERHEAP] map complete pages={}",
        HEAP_PAGE_BUDGET / 0x1000
    );

    // Page-table setup must happen on the system root. Attach only after
    // all user pages exist, so the heap can be initialized through user VAs.
    vas::refresh_kernel_mappings(pml4);
    crate::boot_println!("[USERHEAP] kernel mappings refreshed");
    let previous_root = vas::attach_process(pml4);
    crate::boot_println!("[USERHEAP] process attached");

    let base = HEAP_BASE;
    let first_block = (base + HEADER_SIZE as u64) as *mut BlockHeader;
    let first_size = HEAP_PAGE_BUDGET as usize - HEADER_SIZE;
    unsafe {
        core::ptr::write_bytes(base as *mut u8, 0, HEAP_PAGE_BUDGET as usize);
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
    crate::boot_println!("[USERHEAP] heap zeroed");

    *state = HeapState {
        base,
        free_head: first_block,
        initialized: true,
    };
    vas::detach_process(previous_root);
    crate::boot_println!("[USERHEAP] process detached");
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
    let mut state = HEAP.lock();
    if !state.initialized {
        return ptr::null_mut();
    }

    let mut previous: *mut BlockHeader = ptr::null_mut();
    let mut current = state.free_head;
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
                    state.free_head = block.next;
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

    let mut state = HEAP.lock();
    if !state.initialized {
        return;
    }

    let block = unsafe { pointer.sub(HEADER_SIZE) as *mut BlockHeader };
    unsafe {
        if (*block).magic != BLOCK_MAGIC || (*block).flags != 1 {
            return;
        }

        (*block).flags = 0;
        let mut previous: *mut BlockHeader = ptr::null_mut();
        let mut current = state.free_head;
        while !current.is_null() && (current as usize) < block as usize {
            previous = current;
            current = (*current).next;
        }

        if previous.is_null() {
            (*block).next = state.free_head;
            state.free_head = block;
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
