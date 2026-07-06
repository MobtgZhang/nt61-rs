//! riscv64 paging implementation — provides PagingArch trait for the
//! canonical paging interface in `arch::common::paging`.
//
//! Uses Sv39 3-level page tables with satp as root.

#![allow(dead_code)]

use crate::arch::common::paging::{PageFlags, PagingArch};

impl PagingArch for () {
    fn map_page(va: u64, pa: u64, flags: PageFlags) -> bool {
        crate::arch::riscv64::paging::map_page(va, pa, flags.bits())
    }
    fn unmap_page(va: u64) -> Option<u64> {
        crate::arch::riscv64::paging::unmap_page(va)
    }
    fn translate_virt(va: u64) -> Option<u64> {
        crate::arch::riscv64::paging::translate_virt(va)
    }
    fn invalidate_tlb(va: u64) {
        crate::arch::riscv64::paging::invalidate_tlb(va)
    }
    fn flush_tlb() {
        crate::arch::riscv64::paging::flush_tlb()
    }
    unsafe fn load_page_root(root_pfn: u64) {
        crate::arch::riscv64::paging::load_page_root(root_pfn)
    }
    fn read_page_root_pfn() -> u64 {
        crate::arch::riscv64::paging::read_page_root_pfn()
    }
}

/// Architecture init hook for paging. Phase 1 leaves satp in bare
/// mode; Phase 2 will install a real Sv39 (or Sv48) page table.
///
/// Provided so callers (`mm::init`, `kernel_main`) can call a
/// uniform `arch::riscv64::paging_impl::init` regardless of
/// whether the boot phase has the pool allocator ready.
pub fn init() {
    // No-op at Phase 1. The real Sv39 install is performed by
    // [`crate::arch::riscv64::paging::map_page`] via
    // `mm::vas::init`.
}
