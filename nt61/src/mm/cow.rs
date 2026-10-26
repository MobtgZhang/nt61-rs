//! Copy-on-write (COW)
//
//! NT-style COW for sections and forked pages. The flow:
//
//! 1. A process tries to write to a page that is marked copy-on-write
//!    (the hardware PTE is `P=1, R/W=0, software-bit-9=1`).
//! 2. The CPU traps into `MmAccessFault` with the access type `write`.
//! 3. We allocate a fresh page (zeroed, if possible), copy the
//!    original contents into it, rewrite the PTE to point at the new
//!    page, and clear the COW software bit.
//! 4. If the original page was the only one referencing the
//!    physical memory, the share count drops to zero and the page is
//!    freed. Otherwise the share count decrements.
//
//! The prototype PTE for a section is the canonical source of truth;
//! per-process PTEs are checked against it.

use crate::mm::pfn;
use crate::mm::pte::MMPTE;
use crate::mm::vas::current_root;

/// Walk the page table to get a PTE pointer for `va`. Works for both
/// user and kernel addresses.
///
/// On x86_64 the walk goes through the recursive self-map, so no
/// identity mapping of the page-table pages is required: the
/// historical "physical address == pointer" dereferences only worked
/// while every allocated frame was 1:1 mapped, which COW in process
/// context cannot rely on. On other architectures the page-table
/// pages are kept identity-mapped by the kernel's bootstrap mapping
/// (`identity_map_region`), so the direct-physical walk remains the
/// supported path there.
fn get_pte_ptr(va: u64) -> Option<*mut MMPTE> {
    #[cfg(target_arch = "x86_64")]
    {
        use core::ptr::read_volatile;

        let pml4e = unsafe { read_volatile(crate::mm::vas::pxe_address_of(va)) };
        if !pml4e.is_hardware() {
            return None;
        }
        let pdpte = unsafe { read_volatile(crate::mm::vas::ppe_address_of(va)) };
        if !pdpte.is_hardware() || pdpte.large() {
            return None;
        }
        let pde = unsafe { read_volatile(crate::mm::vas::pde_address_of(va)) };
        if !pde.is_hardware() || pde.large() {
            return None;
        }
        return Some(crate::mm::vas::pte_address_of(va));
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        walk_pte_direct_physical(va)
    }
}

/// Direct-physical page-table walk (identity-mapped targets only).
#[cfg(not(target_arch = "x86_64"))]
fn walk_pte_direct_physical(va: u64) -> Option<*mut MMPTE> {
    let pml4_phys = current_root();
    if pml4_phys == 0 {
        return None;
    }
    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx = ((va >> 21) & 0x1FF) as usize;
    let pt_idx = ((va >> 12) & 0x1FF) as usize;

    let pml4e = unsafe { *((pml4_phys as *const MMPTE).add(pml4_idx)) };
    if !pml4e.is_hardware() {
        return None;
    }
    let pdpt_phys = pml4e.hardware_page_frame();
    let pdpte = unsafe { *((pdpt_phys as *const MMPTE).add(pdpt_idx)) };
    if !pdpte.is_hardware() || pdpte.large() {
        return None;
    }
    let pd_phys = pdpte.hardware_page_frame();
    let pde = unsafe { *((pd_phys as *const MMPTE).add(pd_idx)) };
    if !pde.is_hardware() || pde.large() {
        return None;
    }
    let pt_phys = pde.hardware_page_frame();
    let pte_ptr = unsafe { (pt_phys as *mut MMPTE).add(pt_idx) };
    Some(pte_ptr)
}

/// Perform a COW copy on `va`. Returns true on success.
///
/// Assumes the caller has determined via the PTE that COW is
/// required and the access is otherwise valid.
pub fn perform_cow(va: u64) -> Result<(), u64> {
    // Resolve PTE via direct physical walk.
    let pte_ptr = match get_pte_ptr(va) {
        Some(p) => p,
        None => {
            // // kprintln!("[COW] get_pte_ptr returned None for va=0x{:x}", va);
            return Err(0xC0000005);
        }
    };
    // // kprintln!("[COW] pte_ptr=0x{:x}", pte_ptr as u64);
    let original = unsafe { *pte_ptr };
    // // kprintln!("[COW] original PTE=0x{:016x} is_hw={} is_cow={}",
    // //               original.raw(), original.is_hardware(), original.is_copy_on_write());
    if !original.is_hardware() {
        // // kprintln!("[COW] not hardware PTE");
        return Err(0xC0000005);
    }
    if !original.is_copy_on_write() {
        // // kprintln!("[COW] not COW PTE");
        return Err(0xC0000005);
    }
    let old_pa = original.hardware_page_frame();
    // // kprintln!("[COW] old_pa=0x{:x}", old_pa);

    // Allocate a new PFN.
    let new_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => return Err(0xC0000017), /* STATUS_NO_MEMORY */
    };
    let new_pa = pfn::pfn_to_phys_va(new_pfn);
    // // kprintln!("[COW] new_pa=0x{:x} (new_pfn={})", new_pa, new_pfn);

    // Perform the actual page copy through the kernel temporary
    // mapping window. Treating the physical addresses directly as
    // pointers only works while a 1:1 low-memory mapping exists;
    // COW runs in process context where that assumption is not
    // guaranteed, so map both pages explicitly.
    const PAGE_SIZE: usize = 4096;
    let src_va = match crate::mm::vm::direct_map_phys(old_pa, PAGE_SIZE as u64) {
        Ok(va) => va,
        Err(()) => return Err(0xC0000017), /* STATUS_NO_MEMORY */
    };
    let dst_va = match crate::mm::vm::direct_map_phys(new_pa, PAGE_SIZE as u64) {
        Ok(va) => va,
        Err(()) => {
            crate::mm::vm::direct_unmap_va(src_va, PAGE_SIZE as u64);
            return Err(0xC0000017); /* STATUS_NO_MEMORY */
        }
    };

    // Copy the page. We have exclusive access to both pages (old page's
    // share_count > 0, new page is freshly allocated), so
    // copy_nonoverlapping is appropriate here.
    // SAFETY: Exclusive access to both source and destination is guaranteed
    // by the caller (share_count > 0 for source, freshly allocated dest).
    unsafe {
        core::ptr::copy_nonoverlapping(src_va as *const u8, dst_va as *mut u8, PAGE_SIZE);
    }
    crate::mm::vm::direct_unmap_va(src_va, PAGE_SIZE as u64);
    crate::mm::vm::direct_unmap_va(dst_va, PAGE_SIZE as u64);
    // // kprintln!("[COW] copied {} bytes from 0x{:x} to 0x{:x}", PAGE_SIZE, old_pa, new_pa);

    // Re-write the PTE to point at the new page with R/W=1 and no COW flag.
    let new_pte_bits = original.hardware_flags() | 0x2 /* R/W */;
    // // kprintln!("[COW] writing new PTE: pa=0x{:x} bits=0x{:x}", new_pa, new_pte_bits & !0x200);
    unsafe {
        (*pte_ptr).set_hardware(new_pa, new_pte_bits & !0x200);
        (*pte_ptr).clear_copy_on_write();
        (*pte_ptr).set_dirty(true);
    }
    let _pte_after = unsafe { (*pte_ptr).raw() };
    // _pte_after is intentionally unused - reserved for future debugging
    // // kprintln!("[COW] PTE after write=0x{:016x}", _pte_after);

    // TLB shootdown - the PTE was rewritten (writable COW page ->
    // private copy), so every CPU holding a stale writable
    // translation of `va` must drop it before the old page is reused.
    // A local invalidate alone leaves the other cores free to keep
    // writing through the old mapping.
    crate::ke::tlb_shootdown::invalidate_va_all_cpus(va);

    // Update PFN database: decrement old page reference, increment new page reference
    let mut db = pfn::PFN_DB.lock();
    let old_pfn = pfn::phys_to_pfn(old_pa);

    // Decrement old page's share count
    if let Some(entry) = db.entry(old_pfn) {
        unsafe {
            if (*entry).share_count <= 1 {
                // No more references, free the old page
                (*entry).share_count = 0;
                (*entry).reference_count = 0;
                db.add_to_free(old_pfn);
                // // kprintln!("[COW] old page PFN {} freed (was only reference)", old_pfn);
            } else {
                (*entry).share_count -= 1;
                (*entry).reference_count = (*entry).reference_count.saturating_sub(1);
                // // kprintln!("[COW] old page PFN {} share_count now {}", old_pfn, (*entry).share_count);
            }
        }
    }

    // Initialize new page's share count
    if let Some(new_entry) = db.entry(new_pfn) {
        unsafe {
            (*new_entry).share_count = 1;
            (*new_entry).reference_count = 1;
            // // kprintln!("[COW] new page PFN {} initialized with share_count=1", new_pfn);
        }
    }

    Ok(())
}
