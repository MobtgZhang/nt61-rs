//! x86_64 paging implementation — provides PagingArch trait for the
//! canonical paging interface in `arch::common::paging`.
//
//! Uses 4-level PML4 page tables with CR3 as root.

#![allow(dead_code)]

use crate::arch::common::paging::{PageFlags, PagingArch};

/// Paging implementation for x86_64.
impl PagingArch for () {
    fn map_page(va: u64, pa: u64, flags: PageFlags) -> bool {
#[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::paging::map_page(va, pa, flags.bits())
    }

    fn unmap_page(va: u64) -> Option<u64> {
#[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::paging::unmap_page(va)
    }

    fn translate_virt(va: u64) -> Option<u64> {
#[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::paging::translate_virt(va)
    }

    fn invalidate_tlb(va: u64) {
#[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::paging::invalidate_tlb(va)
    }

    fn flush_tlb() {
#[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::paging::flush_tlb()
    }

    unsafe fn load_page_root(root_pfn: u64) {
#[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::paging::load_page_root(root_pfn)
    }

    fn read_page_root_pfn() -> u64 {
#[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::paging::read_page_root_pfn()
    }
}
