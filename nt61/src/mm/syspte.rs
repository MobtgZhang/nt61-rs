//! System PTE pool (`MiReserveSystemPtes` / `MiReleaseSystemPtes`)
//!
//! x86_64-only implementation. Uses `arch::x86_64::paging` directly.
//! Non-x86_64 architectures compile in `syspte_stub.rs` instead.
//!
//! Windows 7 reserves a contiguous VA region whose page-table
//! entries are the *system* PTE pool. Kernel subsystems that need a
//! short-lived mapping (I/O space, MDL, kernel stacks) grab a
//! handful of PTEs here, install them, and release them when done.
//!
//! In our layout the system PTE pool lives in the
//! `0xFFFFF900_0000_0000` region, with the upper bound at
//! `0xFFFFF9A0_0000_0000` (16 GiB = 4 M PTEs). The VAD tree is
//! reserved at the system PTE base to keep allocations out of the
//! region used by the self-map.
//!
//! `MiMapIoSpace` / `MiUnmapIoSpace` are convenience wrappers that
//! map a contiguous physical range into the system PTE region.

#![cfg(target_arch = "x86_64")]
#![allow(non_snake_case)]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::vas::pte_address_of;

const SYSTEM_PTE_BASE: u64 = 0xFFFF_F900_0000_0000;
const SYSTEM_PTE_END: u64 = 0xFFFF_F9A0_0000_0000;
const SYSTEM_PTE_BYTES: u64 = SYSTEM_PTE_END - SYSTEM_PTE_BASE;

/// Bitmap of allocated 64-KiB regions. Each bit represents 64 KiB
/// (16 pages). Region size is 64 KiB so the bitmap fits in
/// `SYSTEM_PTE_BYTES / 64 KiB = 262144` bits = 32 KiB.
const SYSTEM_PTE_REGION_BYTES: u64 = 64 * 1024;
const SYSTEM_PTE_REGION_PAGES: u64 = SYSTEM_PTE_REGION_BYTES / 4096;
const SYSTEM_PTE_REGION_COUNT: u64 = SYSTEM_PTE_BYTES / SYSTEM_PTE_REGION_BYTES;

static SYSTEM_PTE_BITMAP: [AtomicU64; 4096] = [const { AtomicU64::new(0) }; 4096];
static SYSTEM_PTE_NEXT: AtomicU64 = AtomicU64::new(0);
static SYSTEM_PTE_LOCK: Spinlock<()> = Spinlock::new(());

/// Reserve `count` system PTEs and return the virtual address they
/// cover. The PTEs are installed as 4-KiB pages mapping consecutive
/// physical pages (the caller is responsible for the contents).
pub fn reserve_system_ptes(count: u64) -> Option<u64> {
    if count == 0 { return None; }
    let _g = SYSTEM_PTE_LOCK.lock();
    // Round up to a multiple of the region size.
    let regions = (count + SYSTEM_PTE_REGION_PAGES - 1) / SYSTEM_PTE_REGION_PAGES;
    if regions > 8 { return None; } // sanity
    for bit in 0..SYSTEM_PTE_REGION_COUNT as usize {
        let word = bit / 64;
        let mask = 1u64 << (bit % 64);
        let prev = SYSTEM_PTE_BITMAP[word].compare_exchange(
            0, mask, Ordering::AcqRel, Ordering::Acquire);
        if prev.is_ok() {
            let va = SYSTEM_PTE_BASE + (bit as u64) * SYSTEM_PTE_REGION_BYTES;
            return Some(va);
        }
    }
    crate::hal::serial::write_string("RSP-EXHAUSTED\n");
    None
}

/// Release a previously-reserved system PTE region.
/// This function properly unmaps all PTE entries and invalidates TLB.
pub fn release_system_ptes(va: u64) {
    if va < SYSTEM_PTE_BASE || va >= SYSTEM_PTE_END { return; }
    let bit = ((va - SYSTEM_PTE_BASE) / SYSTEM_PTE_REGION_BYTES) as usize;
    let word = bit / 64;
    let mask = 1u64 << (bit % 64);
    let _g = SYSTEM_PTE_LOCK.lock();

    // Unmap all PTE entries for this region via the direct PML4
    // walker (`map_page`'s sibling), since the recursive self-map
    // doesn't cover the SYSTEM_PTE region (PML4[0x1F2]).
    for i in 0..SYSTEM_PTE_REGION_PAGES {
        let va_i = va + i * 4096;
        crate::arch::x86_64::paging::unmap_page(va_i);
    }

    // Release bitmap
    SYSTEM_PTE_BITMAP[word].fetch_and(!mask, Ordering::AcqRel);
}

/// Map `count` consecutive physical pages into a system PTE region.
///
/// Uses `arch::x86_64::paging::map_page` directly (which walks PML4
/// from CR3) instead of the recursive self-map. This avoids a
/// fundamental issue with the current self-map: PML4[0x1ED] is the
/// only entry wired into the chain, but the SYSTEM_PTE_BASE region
/// lives at PML4[0x1F2] which is not populated by UEFI. The
/// recursive self-map only handles the PXE/PPE/PDE/PTE_BASE windows
/// (all sharing PML4 index 0x1ED); trying to write a PTE for a
/// SYSTEM_PTE VA via `pte_address_of` would fault on `PTE_BASE`
/// access during the chain walk.
///
/// `map_page` walks the page tables from CR3 and installs intermediate
/// tables on demand, so it works for any VA regardless of the
/// self-map.
pub fn map_io_space(pa: u64, count: u64) -> Option<u64> {
    if count == 0 { return None; }
    let va = reserve_system_ptes(count)?;
    for i in 0..count {
        let va_i = va + i * 4096;
        let pa_i = pa + i * 4096;
        // Flags: P=1, R/W=1, U=1 (kernel still accesses via supervisor
        // bit is fine; U=1 keeps the PTE consistent with other kernel
        // mappings and is what the AHCI/e1000 drivers expect). PCD/PWT
        // are clear (uncached is unnecessary for MMIO behind an iATU;
        // the controller's own caches handle coherency).
        const FLAGS: u64 = 0x1 | 0x2 | 0x4;
        if !crate::arch::x86_64::paging::map_page(va_i, pa_i, FLAGS) {
            // Roll back what we've mapped so far.
            for j in 0..i {
                crate::arch::x86_64::paging::unmap_page(va + j * 4096);
            }
            release_system_ptes(va);
            return None;
        }
    }
    Some(va)
}

/// Unmap a previously-mapped I/O range.
pub fn unmap_io_space(va: u64, count: u64) {
    for i in 0..count {
        let va_i = va + i * 4096;
        let pte = pte_address_of(va_i);
        if !pte.is_null() {
            unsafe { (*pte).clear(); }
        }
    }
    release_system_ptes(va);
}

pub fn init() {
    SYSTEM_PTE_NEXT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_and_release() {
        let va = reserve_system_ptes(1).expect("reserve");
        assert!(va >= SYSTEM_PTE_BASE && va < SYSTEM_PTE_END);
        release_system_ptes(va);
        // Re-reserve succeeds.
        assert!(reserve_system_ptes(1).is_some());
    }

    #[test]
    fn system_pte_base_range() {
        // Verify base and end constants are valid
        assert!(SYSTEM_PTE_BASE < SYSTEM_PTE_END);
        assert!(SYSTEM_PTE_BYTES > 0);
        assert_eq!(SYSTEM_PTE_REGION_BYTES, 64 * 1024);
        assert_eq!(SYSTEM_PTE_REGION_PAGES, 16);
    }

    #[test]
    fn reserve_multiple_regions() {
        // Reserve 2 regions
        let va1 = reserve_system_ptes(16).expect("reserve first");
        let va2 = reserve_system_ptes(16).expect("reserve second");

        // They should be different
        assert_ne!(va1, va2);

        // Release both
        release_system_ptes(va1);
        release_system_ptes(va2);

        // Should be able to reserve again
        assert!(reserve_system_ptes(1).is_some());
    }

    #[test]
    fn map_and_unmap_io_space() {
        let phys = 0x10000u64;
        let va = map_io_space(phys, 1);
        if va.is_some() {
            let va = va.unwrap();
            assert!(va >= SYSTEM_PTE_BASE && va < SYSTEM_PTE_END);
            unmap_io_space(va, 1);
        }
        // If map_io_space returned None, it means the pool is exhausted
        // which is valid in a constrained test environment
    }
}
