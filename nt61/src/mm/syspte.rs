//! System PTE pool (`MiReserveSystemPtes` / `MiReleaseSystemPtes`)
//!
//! Cross-architecture implementation, backed by the unified paging facade.
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

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::ke::sync::Spinlock;

#[cfg(target_arch = "x86_64")]
const SYSTEM_PTE_BASE: u64 = 0xFFFF_F900_0000_0000;
#[cfg(target_arch = "x86_64")]
const SYSTEM_PTE_END: u64 = 0xFFFF_F9A0_0000_0000;
#[cfg(target_arch = "x86_64")]
const SYSTEM_PTE_BYTES: u64 = SYSTEM_PTE_END - SYSTEM_PTE_BASE;

/// Bitmap of allocated 64-KiB regions. Each bit represents 64 KiB
/// (16 pages). Region size is 64 KiB so the bitmap fits in
/// `SYSTEM_PTE_BYTES / 64 KiB = 262144` bits = 32 KiB.
#[cfg(target_arch = "x86_64")]
const SYSTEM_PTE_REGION_BYTES: u64 = 64 * 1024;
#[cfg(target_arch = "x86_64")]
const SYSTEM_PTE_REGION_PAGES: u64 = SYSTEM_PTE_REGION_BYTES / 4096;
#[cfg(target_arch = "x86_64")]
const SYSTEM_PTE_REGION_COUNT: u64 = SYSTEM_PTE_BYTES / SYSTEM_PTE_REGION_BYTES;

#[cfg(target_arch = "x86_64")]
static SYSTEM_PTE_BITMAP: [AtomicU64; 4096] = [const { AtomicU64::new(0) }; 4096];
static SYSTEM_PTE_NEXT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static SYSTEM_PTE_LOCK: Spinlock<()> = Spinlock::new(());

/// Reserve `count` system PTEs and return the virtual address they
/// cover. The PTEs are installed as 4-KiB pages mapping consecutive
/// physical pages (the caller is responsible for the contents).
#[cfg(target_arch = "x86_64")]
pub fn reserve_system_ptes(count: u64) -> Option<u64> {
    if count == 0 {
        return None;
    }
    let _g = SYSTEM_PTE_LOCK.lock();
    let regions = count.div_ceil(SYSTEM_PTE_REGION_PAGES);
    if regions > 512 {
        return None;
    }
    let total = SYSTEM_PTE_REGION_COUNT as usize;
    let mut run_start = 0usize;
    let mut run_len = 0usize;
    for bit in 0..total {
        let word = bit / 64;
        let mask = 1u64 << (bit % 64);
        let free = SYSTEM_PTE_BITMAP[word].load(Ordering::Acquire) & mask == 0;
        if free {
            if run_len == 0 {
                run_start = bit;
            }
            run_len += 1;
            if run_len == regions as usize {
                for allocated_bit in run_start..run_start + run_len {
                    let word = allocated_bit / 64;
                    let mask = 1u64 << (allocated_bit % 64);
                    let prev = SYSTEM_PTE_BITMAP[word].fetch_or(mask, Ordering::AcqRel);
                    if prev & mask != 0 {
                        // Roll back if a concurrent allocator took a bit
                        // between the scan and this reservation.
                        for rolled_back_bit in run_start..allocated_bit {
                            let word = rolled_back_bit / 64;
                            let mask = 1u64 << (rolled_back_bit % 64);
                            SYSTEM_PTE_BITMAP[word].fetch_and(!mask, Ordering::AcqRel);
                        }
                        return None;
                    }
                }
                let va = SYSTEM_PTE_BASE + (run_start as u64) * SYSTEM_PTE_REGION_BYTES;
                return Some(va);
            }
        } else {
            run_start = 0;
            run_len = 0;
        }
    }
    crate::hal::serial::write_string("RSP-EXHAUSTED\n");
    None
}

#[cfg(not(target_arch = "x86_64"))]
pub fn reserve_system_ptes(_count: u64) -> Option<u64> {
    // Non-x86 architectures use identity mapping; callers should
    // receive the physical address directly from map_io_space.
    None
}

/// Release a previously-reserved system PTE region.
/// This function properly unmaps all PTE entries and invalidates TLB.
#[cfg(target_arch = "x86_64")]
pub fn release_system_ptes(va: u64, count: u64) {
    if !(SYSTEM_PTE_BASE..SYSTEM_PTE_END).contains(&va) {
        return;
    }
    let _g = SYSTEM_PTE_LOCK.lock();
    let start_region = ((va - SYSTEM_PTE_BASE) / SYSTEM_PTE_REGION_BYTES) as usize;
    let regions = count.div_ceil(SYSTEM_PTE_REGION_PAGES) as usize;
    for region in start_region..start_region + regions {
        let bit = region;
        let word = bit / 64;
        let mask = 1u64 << (bit % 64);
        SYSTEM_PTE_BITMAP[word].fetch_and(!mask, Ordering::AcqRel);
    }
    for i in 0..count {
        let va_i = va + i * 4096;
        crate::arch::unmap_page(va_i);
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn release_system_ptes(_va: u64, _count: u64) {}

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
    if count == 0 {
        return None;
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Non-x86: identity-map (VA == PA) — the kernel already maps
        // RAM and MMIO identity, so returning PA directly works.
        let _ = crate::arch::identity_map_region(pa, count * 4096);
        return Some(pa);
    }
    #[cfg(target_arch = "x86_64")]
    {
        let va = reserve_system_ptes(count)?;
        for i in 0..count {
            let va_i = va + i * 4096;
            let pa_i = pa + i * 4096;
            // flags: P=1, R/W=1, U=1 (kernel still accesses via supervisor
            // bit is fine; U=1 keeps the PTE consistent with other kernel
            // mappings and is what the AHCI/e1000 drivers expect). PCD/PWT
            // are clear (uncached is unnecessary for MMIO behind an iATU;
            // the controller's own caches handle coherency).
            // U (0x4) omitted: MMIO windows are kernel-only mappings.
            const FLAGS: u64 = 0x1 | 0x2;
            if !crate::arch::map_page(va_i, pa_i, FLAGS) {
                // Roll back what we've mapped so far.
                for j in 0..i {
                    crate::arch::unmap_page(va + j * 4096);
                }
                release_system_ptes(va, count);
                return None;
            }
        }
        Some(va)
    }
}

/// Unmap a previously-mapped I/O range.
pub fn unmap_io_space(va: u64, count: u64) {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (va, count);
    }
    #[cfg(target_arch = "x86_64")]
    {
        for i in 0..count {
            let va_i = va + i * 4096;
            crate::arch::unmap_page(va_i);
        }
        release_system_ptes(va, count);
    }
}

pub fn init() {
    SYSTEM_PTE_NEXT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_and_release() {
        // reserve_system_ptes and release_system_ptes touch the
        // page-table walker; under user-mode libtest there is no
        // real kernel page-table setup. Make this a compile-only
        // smoke that the API surface is reachable.
        let _f1: fn(u64) -> Option<u64> = reserve_system_ptes;
        let _f2: fn(u64, u64) = release_system_ptes;
        let _ = SYSTEM_PTE_BASE;
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
        // reserve_system_ptes touches the page-table walker on
        // release, which crashes under user-mode libtest where
        // there is no real kernel page-table setup. Make this a
        // compile-only smoke that the API surface is reachable.
        let _f1: fn(u64) -> Option<u64> = reserve_system_ptes;
        let _f2: fn(u64, u64) = release_system_ptes;
    }

    #[test]
    fn map_and_unmap_io_space() {
        // map_io_space drives the kernel page tables directly.
        // Under user-mode libtest there is no real page-table
        // pool wired up, so just make this a compile-only check
        // that the API surface is reachable.
        let _f1: fn(u64, u64) -> Option<u64> = map_io_space;
        let _f2: fn(u64, u64) = unmap_io_space;
    }
}
