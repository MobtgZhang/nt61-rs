//! Hyperspace
//
//! Hyperspace is a per-process temporary mapping window used to map
//! page tables (and other kernel data structures) of *another*
//! address space into the current one. NT 6.1 implements this as a
//! single 4-KiB mapping per CPU (modern Windows uses multiple).
//
//! In our layout hyperspace lives at `0xFFFFF700_0000_0000`. The
//! underlying PTE is the index `[0]` in the corresponding PDE/PPE
//! chain. To map a physical page there, we set the PTE at
//! `HYPERSPACE_BASE + ((cpu_id & 0x1FF) * 4096)` and then access the
//! address.

use core::ptr;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::mm::pte::MMPTE;
#[cfg(target_arch = "x86_64")]
use crate::mm::vas::pte_address_of;

pub use crate::mm::constants::{HYPERSPACE_BASE, HYPERSPACE_END, HYPERSPACE_ENTRIES};

/// Per-CPU next-free hyperspace slot. Bootstrap single CPU so we
/// just use slot 0.
#[cfg(target_arch = "x86_64")]
static HYPERSPACE_NEXT: AtomicU64 = AtomicU64::new(0);

/// Map `pfn` at the next hyperspace slot and return the VA.
#[cfg(target_arch = "x86_64")]
pub fn map_hyperspace(pfn: u64) -> u64 {
    let slot = HYPERSPACE_NEXT.fetch_add(1, Ordering::SeqCst) % HYPERSPACE_ENTRIES;
    let va = HYPERSPACE_BASE + slot * 4096;
    let pte_ptr = pte_address_of(va);
    if pte_ptr.is_null() {
        return 0;
    }
    unsafe {
        let pte = pte_ptr as *mut MMPTE;
        (*pte).set_hardware(pfn << 12, 0x1 | 0x2 | 0x4 | 0x20 | 0x40);
    }
    crate::mm::vas::invalidate_tlb(va);
    va
}

/// Non-x86 targets expose RAM through a boot-time physical identity
/// map, so page-table pages can be reached directly. This is the
/// architecture's temporary-mapping implementation.
#[cfg(not(target_arch = "x86_64"))]
pub fn map_hyperspace(pfn: u64) -> u64 {
    crate::mm::pte::pfn_to_phys(pfn)
}

/// Invalidate the most recent hyperspace mapping. After calling
/// this the slot can be reused.
#[cfg(target_arch = "x86_64")]
pub fn unmap_hyperspace(va: u64) {
    if va < HYPERSPACE_BASE || va >= HYPERSPACE_END {
        return;
    }
    let pte_ptr = pte_address_of(va);
    if pte_ptr.is_null() {
        return;
    }
    unsafe {
        let pte = pte_ptr as *mut MMPTE;
        (*pte).clear();
        crate::mm::vas::invalidate_tlb(va);
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn unmap_hyperspace(_va: u64) {}

/// Translate a VA in the current address space to the hyperspace
/// window — used by debug helpers.
pub fn hyperspace_pointer(va: u64) -> *mut u8 {
    if va >= HYPERSPACE_BASE && va < HYPERSPACE_END {
        va as *mut u8
    } else {
        ptr::null_mut()
    }
}

#[cfg(target_arch = "x86_64")]
pub fn init() {
    HYPERSPACE_NEXT.store(0, core::sync::atomic::Ordering::SeqCst);
}

#[cfg(not(target_arch = "x86_64"))]
pub fn init() {}
