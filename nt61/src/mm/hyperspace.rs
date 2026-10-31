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
use crate::mm::constants::MI_HYPERSPACE_INDEX;
#[cfg(target_arch = "x86_64")]
use crate::mm::pte::MMPTE;

pub use crate::mm::constants::{HYPERSPACE_BASE, HYPERSPACE_END, HYPERSPACE_ENTRIES};

/// Physical address of the leaf PTE for hyperspace slot `slot` in
/// the current address space, obtained by walking the page tables
/// from the current root by physical address.
///
/// The recursive self-map installed at boot is a single-page
/// recursion (PML4[0x1ED] = PML4), so the linear-address formula
/// behind `vas::pte_address_of` does NOT reach the hyperspace PTEs
/// (PML4[0x1EE] chain): every computed address collapsed onto the
/// slot-0 PTE, leaving all other slots unusable and corrupting
/// unrelated entries. The physical walk matches what the hardware
/// does and is layout-independent.
#[cfg(target_arch = "x86_64")]
fn hyperspace_pte(slot: u64) -> *mut MMPTE {
    const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PTE_P: u64 = 0x1;
    const PTE_PS: u64 = 1 << 7;
    let root = crate::mm::vas::current_root();
    if root == 0 {
        return core::ptr::null_mut();
    }
    let pml4e = unsafe { *((root as *const u64).add(MI_HYPERSPACE_INDEX)) };
    if pml4e & PTE_P == 0 {
        return core::ptr::null_mut();
    }
    let pdpte = unsafe { *((pml4e & PTE_ADDR_MASK) as *const u64) };
    if pdpte & PTE_P == 0 || pdpte & PTE_PS != 0 {
        return core::ptr::null_mut();
    }
    let pde = unsafe { *((pdpte & PTE_ADDR_MASK) as *const u64) };
    if pde & PTE_P == 0 || pde & PTE_PS != 0 {
        return core::ptr::null_mut();
    }
    let pt = (pde & PTE_ADDR_MASK) as *mut MMPTE;
    unsafe { pt.add(slot as usize) }
}

/// Per-CPU next-free hyperspace slot. Bootstrap single CPU so we
/// just use slot 0.
#[cfg(target_arch = "x86_64")]
static HYPERSPACE_NEXT: AtomicU64 = AtomicU64::new(0);

/// Map `pfn` at the next hyperspace slot and return the VA.
#[cfg(target_arch = "x86_64")]
pub fn map_hyperspace(pfn: u64) -> u64 {
    let slot = HYPERSPACE_NEXT.fetch_add(1, Ordering::SeqCst) % HYPERSPACE_ENTRIES;
    let va = HYPERSPACE_BASE + slot * 4096;
    let pte_ptr = hyperspace_pte(slot);
    if pte_ptr.is_null() {
        return 0;
    }
    unsafe {
        let pte = pte_ptr;
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
    let pa = crate::mm::pte::pfn_to_phys(pfn);
    if !crate::arch::map_page(pa, pa, crate::mm::pte::PTE_RW) {
        return 0;
    }
    pa
}

/// Invalidate the most recent hyperspace mapping. After calling
/// this the slot can be reused.
#[cfg(target_arch = "x86_64")]
pub fn unmap_hyperspace(va: u64) {
    if !(HYPERSPACE_BASE..HYPERSPACE_END).contains(&va) {
        return;
    }
    let slot = (va - HYPERSPACE_BASE) / 4096;
    let pte_ptr = hyperspace_pte(slot);
    if pte_ptr.is_null() {
        return;
    }
    unsafe {
        let pte = pte_ptr;
        (*pte).clear();
        crate::mm::vas::invalidate_tlb(va);
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn unmap_hyperspace(_va: u64) {}

/// Translate a VA in the current address space to the hyperspace
/// window — used by debug helpers.
pub fn hyperspace_pointer(va: u64) -> *mut u8 {
    if (HYPERSPACE_BASE..HYPERSPACE_END).contains(&va) {
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
