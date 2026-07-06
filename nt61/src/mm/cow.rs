//! Copy-on-Write (COW)
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

#![allow(non_snake_case)]

use crate::mm::pfn;
use crate::mm::pte::MMPTE;
use crate::mm::vas::current_root;

/// Walk the page table using direct physical access to get a PTE pointer.
/// Works for both user and kernel addresses.
fn get_pte_ptr(va: u64) -> Option<*mut MMPTE> {
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
    let Pt_phys = pde.hardware_page_frame();
    let pte_ptr = unsafe { (Pt_phys as *mut MMPTE).add(pt_idx) };
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
            // // kprintln!("[COW] get_pte_ptr returned None for va=0x{:x}", va)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return Err(0xC0000005);
        }
    };
    // // kprintln!("[COW] pte_ptr=0x{:x}", pte_ptr as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    let original = unsafe { *pte_ptr };
    // // kprintln!("[COW] original PTE=0x{:016x} is_hw={} is_cow={}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //               original.raw(), original.is_hardware(), original.is_copy_on_write());
    if !original.is_hardware() {
        // // kprintln!("[COW] not hardware PTE")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return Err(0xC0000005);
    }
    if !original.is_copy_on_write() {
        // // kprintln!("[COW] not COW PTE")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return Err(0xC0000005);
    }
    let old_pa = original.hardware_page_frame();
    // // kprintln!("[COW] old_pa=0x{:x}", old_pa)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Allocate a new PFN.
    let new_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => return Err(0xC0000017), /* STATUS_NO_MEMORY */
    };
    let new_pa = pfn::pfn_to_phys_va(new_pfn);
    // // kprintln!("[COW] new_pa=0x{:x} (new_pfn={})", new_pa, new_pfn)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Perform the actual page copy using identity mapping.
    // In UEFI boot environment, kernel page tables are typically identity-mapped,
    // so we can directly access physical memory as virtual addresses.
    const PAGE_SIZE: usize = 4096;
    let src_ptr = old_pa as *const u8;
    let dst_ptr = new_pa as *mut u8;

    // Copy the page. We have exclusive access to both pages (old page's
    // share_count > 0, new page is freshly allocated), so
    // copy_nonoverlapping is appropriate here.
    // SAFETY: Exclusive access to both source and destination is guaranteed
    // by the caller (share_count > 0 for source, freshly allocated dest).
    unsafe {
        core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, PAGE_SIZE);
    }
    // // kprintln!("[COW] copied {} bytes from 0x{:x} to 0x{:x}", PAGE_SIZE, old_pa, new_pa)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Re-write the PTE to point at the new page with R/W=1 and no COW flag.
    let new_pte_bits = original.hardware_flags() | 0x2 /* R/W */;
    // // kprintln!("[COW] writing new PTE: pa=0x{:x} bits=0x{:x}", new_pa, new_pte_bits & !0x200)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    unsafe {
        (*pte_ptr).set_hardware(new_pa, new_pte_bits & !0x200);
        (*pte_ptr).clear_copy_on_write();
        (*pte_ptr).set_dirty(true);
    }
    let _pte_after = unsafe { (*pte_ptr).raw() };
    // _pte_after is intentionally unused - reserved for future debugging
    // // kprintln!("[COW] PTE after write=0x{:016x}", _pte_after)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // TLB shootdown - invalidate the TLB entry for this virtual address
    crate::mm::vas::invalidate_tlb(va);

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
                // // kprintln!("[COW] old page PFN {} freed (was only reference)", old_pfn)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            } else {
                (*entry).share_count -= 1;
                (*entry).reference_count = (*entry).reference_count.saturating_sub(1);
                // // kprintln!("[COW] old page PFN {} share_count now {}", old_pfn, (*entry).share_count)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
        }
    }

    // Initialize new page's share count
    if let Some(new_entry) = db.entry(new_pfn) {
        unsafe {
            (*new_entry).share_count = 1;
            (*new_entry).reference_count = 1;
            // // kprintln!("[COW] new page PFN {} initialized with share_count=1", new_pfn)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        }
    }

    Ok(())
}
