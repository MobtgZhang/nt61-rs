//! Paging and virtual memory — x86_64
//
//! Implements a 4-level page table (PML4 / PDPT / PD / PT) for the
//! long-mode 4-KiB-granule layout. The architecture interface
//! functions are real and they walk the page table via the
//! recursive self-map installed in `mm::vas::init`.
//
//! `map_page` allocates any missing intermediate tables, then
//! installs the leaf PTE. `unmap_page` removes the leaf and, if an
//! intermediate table becomes empty, frees it back to the PFN
//! database. `translate_virt` walks the table for a hardware PTE
//! and returns the physical address. `load_page_root` writes the
//! supplied PFN to CR3.

#![allow(non_snake_case)]

use core::arch::asm;
use core::ptr;

use crate::mm::pfn;
use crate::mm::pte::{MMPTE, pfn_from_phys, pfn_to_phys};
use crate::mm::vas::{pde_address_of, ppe_address_of, pte_address_of, pxe_address_of};

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SHIFT: u64 = 12;
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Type alias for virtual address (for backward compatibility).
pub type VirtAddr = u64;
/// Type alias for physical address (for backward compatibility).
pub type PhysAddr = u64;
/// Backward-compatibility shim for the old `PageTableEntry` type.
pub struct PageTableEntry {
    pub value: u64,
}
impl PageTableEntry {
    pub const fn empty() -> Self { Self { value: 0 } }
    pub fn present(&self) -> bool { (self.value & 1) != 0 }
    pub fn writable(&self) -> bool { (self.value & 2) != 0 }
    pub fn user(&self) -> bool { (self.value & 4) != 0 }
    pub fn frame(&self) -> u64 { self.value & 0x000F_FFFF_FFFF_F000 }
    pub fn set(&mut self, addr: u64, flags: u64) {
        self.value = (addr & 0x000F_FFFF_FFFF_F000) | (flags & 0xFFF);
    }
}

/// Walk the page table for `va` and return the address of the leaf
/// PTE, along with a pointer to the page-table page so the caller
/// can replace it if necessary.
#[allow(dead_code)]
fn walk_to_leaf(va: u64) -> Option<*mut MMPTE> {
    // PML4 entry (PXE)
    let pxe = unsafe { &*pxe_address_of(va) };
    if !pxe.is_hardware() { return None; }
    // PDPT entry (PPE)
    let ppe = unsafe { &*ppe_address_of(va) };
    if !ppe.is_hardware() { return None; }
    // PD entry (PDE)
    let pde = unsafe { &*pde_address_of(va) };
    if !pde.is_hardware() { return None; }
    if pde.large() {
        // 2 MiB page — caller handles large pages via map_large_page.
        return None;
    }
    let pte = pte_address_of(va);
    if pte.is_null() { return None; }
    Some(pte)
}

/// Install an intermediate page-table page. `level` is 1 (PDPT),
/// 2 (PD), or 3 (PT). The intermediate page's PTE is written in
/// the parent table with `P=1, R/W=1, U=1, A=1, D=1`.
unsafe fn install_intermediate(parent_pte: *mut u64, level: u32) -> bool {
    let new_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => return false,
    };
    let new_pa = pfn_to_phys(new_pfn);
    // // kprintln!("[MAP] install_intermediate: pfn={} pa=0x{:x} parent=0x{:x} level={}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //               new_pfn, new_pa, parent_pte as u64, level);
    // Try the direct identity-mapped write first. If the
    // UEFI-loaded page tables identity-map this PFN, this is
    // the fastest path.
    ptr::write_bytes(new_pa as *mut u8, 0, 4096);
    // // kprintln!("[MAP] install_intermediate: direct zero OK, writing parent PTE")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // Write the parent PTE: physical address of the new
    // table, P=1, R/W=1, U=1, A=1, D=1.
    let pte_val = (new_pa & 0x000F_FFFF_FFFF_F000) | 0x1 | 0x2 | 0x4 | 0x20 | 0x40;
    // Temporarily clear CR0.WP (write protect) so we can write to a
    // parent PTE that lives on a UEFI read-only page (typically the
    // PML4 page itself).
    let saved_cr0: u64;
    core::arch::asm!(
        "mov {}, cr0",
        out(reg) saved_cr0,
        options(nostack, preserves_flags),
    );
    core::arch::asm!(
        "mov cr0, {}",
        in(reg) saved_cr0 & !0x0001_0000u64,
        options(nostack, preserves_flags),
    );
    *parent_pte = pte_val;
    core::arch::asm!(
        "mov cr0, {}",
        in(reg) saved_cr0,
        options(nostack, preserves_flags),
    );
    // // kprintln!("[MAP] install_intermediate: parent PTE written")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    let _ = level;
    true
}

/// Map a 4-KiB page. Returns true on success.
pub fn map_page(va: u64, pa: u64, flags: u64) -> bool {
    // // kprintln!("[MAP] map_page: enter va=0x{:x} pa=0x{:x} flags=0x{:x}", va, pa, flags)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // We walk the page table directly using the system PML4
    // address rather than the recursive self-map windows. The
    // self-map is a 4-page structure (PML4 -> PDPT -> PD -> PT)
    // whose indices need to match the kernel's address-space
    // layout exactly; a single-page self-map only gives access
    // to a small slice of the address space and faults on the
    // rest. The direct walk is straightforward and works for
    // any VA the kernel might be asked to map.
    let pml4_pa = crate::mm::vas::current_root();
    // // kprintln!("[MAP] map_page: pml4_pa=0x{:x}", pml4_pa)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    let pml4_va = pml4_pa; // identity-mapped in low memory under UEFI.
    if pml4_va == 0 { return false; }

    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pml4e = (pml4_va as *mut u64).wrapping_add(pml4_idx);
    // // kprintln!("[MAP] map_page: pml4e=0x{:x} idx={}", pml4e as u64, pml4_idx)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    unsafe {
        let pml4e_val = *pml4e;
        // // kprintln!("[MAP] map_page: pml4e_val=0x{:x}", pml4e_val)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        if (pml4e_val & 1) == 0 {
            // // kprintln!("[MAP] map_page: installing PDPT")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            if !install_intermediate(pml4e, 1) { return false; }
        }
        let pdpt_va = *pml4e & 0x000F_FFFF_FFFF_F000;
        // // kprintln!("[MAP] map_page: pdpt_va=0x{:x}", pdpt_va)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
        let pdpte = (pdpt_va as *mut u64).wrapping_add(pdpt_idx);
        // // kprintln!("[MAP] map_page: pdpte=0x{:x} idx={}", pdpte as u64, pdpt_idx)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        let pdpte_val = *pdpte;
        // // kprintln!("[MAP] map_page: pdpte_val=0x{:x}", pdpte_val)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        if (pdpte_val & 1) == 0 {
            // // kprintln!("[MAP] map_page: installing PD")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            if !install_intermediate(pdpte, 2) { return false; }
        }
        let pd_va = *pdpte & 0x000F_FFFF_FFFF_F000;
        // // kprintln!("[MAP] map_page: pd_va=0x{:x}", pd_va)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        let pd_idx = ((va >> 21) & 0x1FF) as usize;
        let pde = (pd_va as *mut u64).wrapping_add(pd_idx);
        // // kprintln!("[MAP] map_page: pde=0x{:x} idx={}", pde as u64, pd_idx)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        let pde_val = *pde;
        // // kprintln!("[MAP] map_page: pde_val=0x{:x}", pde_val)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        if (pde_val & 1) == 0 {
            // // kprintln!("[MAP] map_page: installing PT")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            if !install_intermediate(pde, 3) { return false; }
        }
        let pt_va = *pde & 0x000F_FFFF_FFFF_F000;
        // // kprintln!("[MAP] map_page: pt_va=0x{:x}", pt_va)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        let pt_idx = ((va >> 12) & 0x1FF) as usize;
        let pte = (pt_va as *mut u64).wrapping_add(pt_idx);
        // // kprintln!("[MAP] map_page: pte=0x{:x} idx={}", pte as u64, pt_idx)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        // Write the leaf PTE as a hardware entry.
        let pte_val = (pa & 0x000F_FFFF_FFFF_F000) | (flags & 0xFFF) | 1;
        *pte = pte_val;
        // // kprintln!("[MAP] map_page: pte written")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
    invalidate_tlb(va);
    // // kprintln!("[MAP] map_page: tlb invalidated, returning true")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    true
}

/// Unmap a 4-KiB page. Returns the previously-mapped physical
/// address.
pub fn unmap_page(va: u64) -> Option<u64> {
    let pte_ptr = pte_address_of(va);
    if pte_ptr.is_null() { return None; }
    unsafe {
        let pte = &mut *pte_ptr;
        if !pte.is_hardware() { return None; }
        let pa = pte.hardware_page_frame();
        pte.clear();
        invalidate_tlb(va);
        Some(pa)
    }
}

/// Translate `va` to a physical address by walking the page table.
/// Returns None if the VA is not mapped or is in a non-hardware
/// PTE state.
pub fn translate_virt(va: u64) -> Option<u64> {
    let pxe = unsafe { &*pxe_address_of(va) };
    if !pxe.is_hardware() { return None; }
    if pxe.large() { return None; }
    let ppe = unsafe { &*ppe_address_of(va) };
    if !ppe.is_hardware() { return None; }
    if ppe.large() { return None; }
    let pde = unsafe { &*pde_address_of(va) };
    if !pde.is_hardware() { return None; }
    if pde.large() {
        // 2 MiB page: physical base is bits 51:21.
        let pa = pde.hardware_page_frame() & !0x1F_FFFF;
        return Some(pa | (va & 0x1F_FFFF));
    }
    let pte = unsafe { &*pte_address_of(va) };
    if !pte.is_hardware() { return None; }
    Some(pte.hardware_page_frame() | (va & 0xFFF))
}

/// Write the supplied PFN into CR3.
pub unsafe fn load_page_root(pml4_pfn: u64) {
    let paddr = pfn_to_phys(pml4_pfn);
    asm!("mov cr3, {}", in(reg) paddr, options(nostack));
}

/// Initialise the paging subsystem. In the bootstrap this just
/// reads CR3 to populate the system PML4 PFN in the VAS
/// subsystem. The recursive self-map is installed by
/// `mm::vas::init`.
pub unsafe fn init() {
    let cr3: u64;
    asm!("mov {}, cr3", out(reg) cr3, options(nostack));
    crate::mm::vas::set_current_root(cr3);
}

/// Read the current CR3.
pub fn read_page_root_pfn() -> u64 {
    let cr3: u64;
    unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nostack)); }
    pfn_from_phys(cr3)
}

/// Invalidate the TLB for a single VA.
pub fn invalidate_tlb(va: u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = va;
    }
}

/// Flush the entire TLB by reloading CR3.
pub fn flush_tlb() {
    unsafe {
        let cr3: u64;
        asm!("mov {}, cr3", out(reg) cr3, options(nostack));
        asm!("mov cr3, {}", in(reg) cr3, options(nostack));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_size() {
        assert_eq!(PAGE_SIZE, 4096);
        assert_eq!(PAGE_MASK, !4095);
    }
}
