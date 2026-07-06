//! Heap allocator backing user-mode `Vec` / `String`.
//!
//! Phase 1 implements a tiny bump allocator over user-mode virtual
//! pages; Phase 3 will replace it with the full RtlHeap engine.

#![allow(dead_code)]

extern crate alloc;
use core::alloc::Layout;
use core::ptr;

use crate::mm::pte;
use crate::mm::vas;

/// Process-local heap.
pub struct UserHeap {
    pub base: u64,
    pub cursor: u64,
    pub brk: u64,
    pub pages: u32,
}

impl UserHeap {
    pub const fn new() -> Self {
        Self { base: 0, cursor: 0, brk: 0, pages: 0 }
    }
}

static mut HEAP: UserHeap = UserHeap::new();

/// Heap base — well below the user stack, just above the loader's
/// 2 MiB reserved region.
pub const HEAP_BASE: u64 = 0x0000_0000_0100_0000;
pub const HEAP_PAGE_BUDGET: u64 = 0x0200_0000; // 32 MiB

/// Establish the per-process heap if it has not been created yet.
pub fn init_user_heap(pml4: u64) -> u64 {
    unsafe {
        if HEAP.base != 0 { return HEAP.base; }
        let r = vas::map_user_pages(pml4, HEAP_BASE, HEAP_PAGE_BUDGET, pte::PTE_RW | pte::PTE_US);
        if r != vas::MmStatus::Ok { return 0; }
        HEAP.base = HEAP_BASE;
        HEAP.cursor = HEAP_BASE + 0x1000;
        HEAP.brk = HEAP_BASE + HEAP_PAGE_BUDGET;
        HEAP.base
    }
}

pub fn alloc_bytes(n: usize) -> *mut u8 {
    let aligned = (n + 15) & !15;
    unsafe {
        if HEAP.cursor + aligned as u64 > HEAP.brk { return ptr::null_mut(); }
        let p = HEAP.cursor as *mut u8;
        HEAP.cursor += aligned as u64;
        p
    }
}

pub fn free_bytes(_p: *mut u8) { /* Phase 1: bump allocator; no free. */ }

/// Vector backed by the user heap.
pub struct HeapVec<T> {
    ptr: *mut T,
    len: usize,
    cap: usize,
    _marker: core::marker::PhantomData<T>,
}

impl<T> HeapVec<T> {
    pub const fn new() -> Self {
        Self { ptr: ptr::null_mut(), len: 0, cap: 0, _marker: core::marker::PhantomData }
    }

    /// Pre-allocate capacity for `cap` items. Mirrors `Vec::with_capacity`.
    pub fn with_capacity(cap: usize) -> Self {
        if cap == 0 {
            return Self::new();
        }
        let layout = Layout::array::<T>(cap).unwrap();
        let p = alloc_bytes(layout.size()) as *mut T;
        Self { ptr: p, len: 0, cap, _marker: core::marker::PhantomData }
    }

    pub fn push(&mut self, val: T) {
        if self.len == self.cap {
            // Phase 1 doubles capacity.
            let new_cap = if self.cap == 0 { 4 } else { self.cap * 2 };
            let old_layout = if self.cap == 0 {
                Layout::from_size_align(0, 1).unwrap()
            } else {
                Layout::array::<T>(self.cap).unwrap()
            };
            let new_layout = Layout::array::<T>(new_cap).unwrap();
            unsafe {
                let new_ptr = alloc_bytes(new_layout.size()) as *mut T;
                if new_ptr.is_null() { return; }
                if !self.ptr.is_null() && self.len > 0 {
                    ptr::copy_nonoverlapping(self.ptr, new_ptr, self.len);
                    if old_layout.size() > 0 {
                        let _ = alloc::alloc::dealloc(self.ptr as *mut u8, old_layout);
                    }
                }
                self.ptr = new_ptr;
                self.cap = new_cap;
            }
        }
        unsafe {
            ptr::write(self.ptr.add(self.len), val);
            self.len += 1;
        }
    }
    pub fn len(&self) -> usize { self.len }
    pub fn as_ptr(&self) -> *const T { self.ptr }
}
