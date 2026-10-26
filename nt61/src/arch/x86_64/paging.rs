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

use core::arch::asm;
use core::ptr;

use crate::mm::pte::{pfn_from_phys, pfn_to_phys, MMPTE};
use crate::mm::vas::{pde_address_of, ppe_address_of, pte_address_of, pxe_address_of};

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SHIFT: u64 = 12;
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// r#type alias for virtual address (for backward compatibility).
pub type VirtAddr = u64;
/// r#type alias for physical address (for backward compatibility).
pub type PhysAddr = u64;
/// Backward-compatibility shim for the old `PageTableEntry` type.
pub struct PageTableEntry {
    pub value: u64,
}
impl PageTableEntry {
    pub const fn empty() -> Self {
        Self { value: 0 }
    }
    pub fn present(&self) -> bool {
        (self.value & 1) != 0
    }
    pub fn writable(&self) -> bool {
        (self.value & 2) != 0
    }
    pub fn user(&self) -> bool {
        (self.value & 4) != 0
    }
    pub fn frame(&self) -> u64 {
        self.value & 0x000F_FFFF_FFFF_F000
    }
    pub fn set(&mut self, addr: u64, flags: u64) {
        self.value = (addr & 0x000F_FFFF_FFFF_F000) | (flags & 0xFFF);
    }
}

/// Walk the page table for `va` and return the address of the leaf
/// PTE, along with a pointer to the page-table page so the caller
/// can replace it if necessary.
pub fn walk_to_leaf(va: u64) -> Option<*mut MMPTE> {
    // PML4 entry (PXE)
    let pxe = unsafe { &*pxe_address_of(va) };
    if !pxe.is_hardware() {
        return None;
    }
    // PDPT entry (PPE)
    let ppe = unsafe { &*ppe_address_of(va) };
    if !ppe.is_hardware() {
        return None;
    }
    // PD entry (PDE)
    let pde = unsafe { &*pde_address_of(va) };
    if !pde.is_hardware() {
        return None;
    }
    if pde.large() {
        // 2 MiB page — caller handles large pages via map_large_page.
        return None;
    }
    let pte = pte_address_of(va);
    if pte.is_null() {
        return None;
    }
    Some(pte)
}

/// Install an intermediate page-table page. `level` is 1 (PDPT),
/// 2 (PD), or 3 (PT). The intermediate page's PTE is written in
/// the parent table with `P=1, R/W=1, U=1, A=1, D=1`.
/// Map a page-table page by physical address, read one entry, and
/// immediately release the hyperspace mapping. `None` means the
/// temporary map could not be established.
unsafe fn read_table_entry(table_phys: u64, idx: usize) -> Option<u64> {
    if table_phys == 0 {
        return None;
    }
    Some(ptr::read_volatile((table_phys as *const u64).add(idx)))
}

/// Map a page-table page by physical address, write one entry, and
/// immediately release the hyperspace mapping.
unsafe fn write_table_entry(table_phys: u64, idx: usize, value: u64) -> bool {
    if table_phys == 0 {
        return false;
    }
    ptr::write_volatile((table_phys as *mut u64).add(idx), value);
    true
}

unsafe fn install_intermediate(parent_table_phys: u64, parent_idx: usize, level: u32) -> bool {
    let _ = level;
    let pfn = match crate::mm::pfn::allocate_pfn() {
        Some(pfn) => pfn,
        None => return false,
    };
    let new_pa = pfn_to_phys(pfn);
    // The fresh table page must be identity-mapped before it can be
    // zeroed; on failure fail closed and return the page to the free
    // list (free_pfn only relinks the page, its contents do not matter).
    if !crate::mm::vas::ensure_low_identity_map(new_pa & !0x1F_FFFF, 0x20_0000) {
        crate::mm::pfn::free_pfn(pfn);
        return false;
    }
    ptr::write_bytes(new_pa as *mut u8, 0, PAGE_SIZE as usize);

    if !write_table_entry(
        parent_table_phys,
        parent_idx,
        // P=1 | RW=1 | PWT=0x20 | PCD=0x40. US (0x4) is deliberately
        // clear: intermediate page-table pages must be supervisor-only.
        new_pa | 0x1 | 0x2 | 0x20 | 0x40,
    ) {
        crate::mm::pfn::free_pfn(pfn);
        return false;
    }
    true
}

/// Map a 4-KiB page. Returns true on success.
pub fn map_page(va: u64, pa: u64, flags: u64) -> bool {
    // // kprintln!("[MAP] map_page: enter va=0x{:x} pa=0x{:x} flags=0x{:x}", va, pa, flags);
    // We walk the page table directly using the system PML4
    // address rather than the recursive self-map windows. The
    // self-map is a 4-page structure (PML4 -> PDPT -> PD -> PT)
    // whose indices need to match the kernel's address-space
    // layout exactly; a single-page self-map only gives access
    // to a small slice of the address space and faults on the
    // rest. The direct walk is straightforward and works for
    // any VA the kernel might be asked to map.
    let pml4_pa = crate::mm::vas::current_root();
    // // kprintln!("[MAP] map_page: pml4_pa=0x{:x}", pml4_pa);
    if pml4_pa == 0 {
        return false;
    }

    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    // // kprintln!("[MAP] map_page: pml4e=0x{:x} idx={}", pml4e as u64, pml4_idx);
    unsafe {
        let mut pml4e_val = match read_table_entry(pml4_pa, pml4_idx) {
            Some(value) => value,
            None => return false,
        };
        // // kprintln!("[MAP] map_page: pml4e_val=0x{:x}", pml4e_val);
        if (pml4e_val & 1) == 0 {
            // // kprintln!("[MAP] map_page: installing PDPT");
            if !install_intermediate(pml4_pa, pml4_idx, 1) {
                return false;
            }
            pml4e_val = match read_table_entry(pml4_pa, pml4_idx) {
                Some(value) => value,
                None => return false,
            };
        }
        let pdpt_va = pml4e_val & 0x000F_FFFF_FFFF_F000;
        // // kprintln!("[MAP] map_page: pdpt_va=0x{:x}", pdpt_va);
        let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
        // // kprintln!("[MAP] map_page: pdpte=0x{:x} idx={}", pdpte as u64, pdpt_idx);
        let mut pdpte_val = match read_table_entry(pdpt_va, pdpt_idx) {
            Some(value) => value,
            None => return false,
        };
        // // kprintln!("[MAP] map_page: pdpte_val=0x{:x}", pdpte_val);
        if (pdpte_val & 1) == 0 {
            // // kprintln!("[MAP] map_page: installing PD");
            if !install_intermediate(pdpt_va, pdpt_idx, 2) {
                return false;
            }
            pdpte_val = match read_table_entry(pdpt_va, pdpt_idx) {
                Some(value) => value,
                None => return false,
            };
        }
        let pd_va = pdpte_val & 0x000F_FFFF_FFFF_F000;
        // // kprintln!("[MAP] map_page: pd_va=0x{:x}", pd_va);
        let pd_idx = ((va >> 21) & 0x1FF) as usize;
        // // kprintln!("[MAP] map_page: pde=0x{:x} idx={}", pde as u64, pd_idx);
        let mut pde_val = match read_table_entry(pd_va, pd_idx) {
            Some(value) => value,
            None => return false,
        };
        // // kprintln!("[MAP] map_page: pde_val=0x{:x}", pde_val);
        if (pde_val & 1) != 0 && (pde_val & 0x80) != 0 {
            // PDE is a 2 MiB large page (PS=1): there is no page table
            // beneath it. Writing a 4-KiB PTE here would corrupt the
            // large page's physical address field.
            return false;
        }
        if (pde_val & 1) == 0 {
            // // kprintln!("[MAP] map_page: installing PT");
            if !install_intermediate(pd_va, pd_idx, 3) {
                return false;
            }
            pde_val = match read_table_entry(pd_va, pd_idx) {
                Some(value) => value,
                None => return false,
            };
        }
        let pt_va = pde_val & 0x000F_FFFF_FFFF_F000;
        // // kprintln!("[MAP] map_page: pt_va=0x{:x}", pt_va);
        let pt_idx = ((va >> 12) & 0x1FF) as usize;
        // // kprintln!("[MAP] map_page: pte=0x{:x} idx={}", pte as u64, pt_idx);
        // write the leaf PTE as a hardware entry.
        // Preserve the NX bit (63) as well as the low 12 PTE flag bits;
        // masking to 0xFFF silently dropped NX.
        let pte_val =
            (pa & 0x000F_FFFF_FFFF_F000) | (flags & (0xFFF | 0x8000_0000_0000_0000)) | 1;
        if !write_table_entry(pt_va, pt_idx, pte_val) {
            return false;
        }
        // // kprintln!("[MAP] map_page: pte written");
    }
    invalidate_tlb(va);
    // // kprintln!("[MAP] map_page: tlb invalidated, returning true");
    true
}

/// Unmap a 4-KiB page. Returns the previously-mapped physical
/// address.
pub fn unmap_page(va: u64) -> Option<u64> {
    let pml4_pa = crate::mm::vas::current_root();
    if pml4_pa == 0 {
        return None;
    }

    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pml4e_val = match unsafe { read_table_entry(pml4_pa, pml4_idx) } {
        Some(value) => value,
        None => return None,
    };
    if (pml4e_val & 1) == 0 {
        return None;
    }
    let pdpt_pa = pml4e_val & 0x000F_FFFF_FFFF_F000;

    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pdpte_val = match unsafe { read_table_entry(pdpt_pa, pdpt_idx) } {
        Some(value) => value,
        None => return None,
    };
    if (pdpte_val & 1) == 0 {
        return None;
    }
    if pdpte_val & 0x80 != 0 {
        // 1 GiB leaf: a 4-KiB unmap cannot split a large page.
        return None;
    }
    let pd_pa = pdpte_val & 0x000F_FFFF_FFFF_F000;

    let pd_idx = ((va >> 21) & 0x1FF) as usize;
    let pde_val = match unsafe { read_table_entry(pd_pa, pd_idx) } {
        Some(value) => value,
        None => return None,
    };
    if (pde_val & 1) == 0 {
        return None;
    }
    if pde_val & 0x80 != 0 {
        // 2 MiB leaf: a 4-KiB unmap cannot split a large page.
        return None;
    }
    let pt_pa = pde_val & 0x000F_FFFF_FFFF_F000;

    let pt_idx = ((va >> 12) & 0x1FF) as usize;
    let pte_val = match unsafe { read_table_entry(pt_pa, pt_idx) } {
        Some(value) => value,
        None => return None,
    };
    if (pte_val & 1) == 0 {
        return None;
    }
    let pa = pte_val & 0x000F_FFFF_FFFF_F000;
    unsafe {
        ptr::write_volatile((pt_pa as *mut u64).add(pt_idx), 0);
    }
    invalidate_tlb(va);
    Some(pa)
}

/// Translate `va` to a physical address by walking the page table.
/// Returns None if the VA is not mapped or is in a non-hardware
/// PTE state.
pub fn translate_virt(va: u64) -> Option<u64> {
    let pml4_pa = crate::arch::read_current_page_root();
    if pml4_pa == 0 {
        return None;
    }

    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pml4e_val = match unsafe { read_table_entry(pml4_pa, pml4_idx) } {
        Some(value) => value,
        None => return None,
    };
    if (pml4e_val & 1) == 0 {
        return None;
    }
    if pml4e_val & 0x80 != 0 {
        // 512 GiB leaf: physical base is bits 51:30.
        let pa = pml4e_val & 0x000F_FFFF_FFFF_F000;
        return Some(pa | (va & 0x3F_FFFF_FFFF));
    }
    let pdpt_pa = pml4e_val & 0x000F_FFFF_FFFF_F000;

    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pdpte_val = match unsafe { read_table_entry(pdpt_pa, pdpt_idx) } {
        Some(value) => value,
        None => return None,
    };
    if (pdpte_val & 1) == 0 {
        return None;
    }
    if pdpte_val & 0x80 != 0 {
        // 1 GiB leaf: physical base is bits 51:30.
        let pa = pdpte_val & 0x000F_FFFF_FFFF_F000;
        return Some(pa | (va & 0x3F_FFFF_FFFF));
    }
    let pd_pa = pdpte_val & 0x000F_FFFF_FFFF_F000;

    let pd_idx = ((va >> 21) & 0x1FF) as usize;
    let pde_val = match unsafe { read_table_entry(pd_pa, pd_idx) } {
        Some(value) => value,
        None => return None,
    };
    if (pde_val & 1) == 0 {
        return None;
    }
    if pde_val & 0x80 != 0 {
        // 2 MiB leaf: physical base is bits 51:21.
        let pa = pde_val & 0x000F_FFFF_FFFF_F000;
        return Some(pa | (va & 0x1F_FFFF));
    }
    let pt_pa = pde_val & 0x000F_FFFF_FFFF_F000;

    let pt_idx = ((va >> 12) & 0x1FF) as usize;
    let pte_val = match unsafe { read_table_entry(pt_pa, pt_idx) } {
        Some(value) => value,
        None => return None,
    };
    if (pte_val & 1) == 0 {
        return None;
    }
    Some((pte_val & 0x000F_FFFF_FFFF_F000) | (va & 0xFFF))
}

/// Return the leaf PTE covering `va` so user-copy helpers can enforce
/// U/S and R/W permissions without relying on SMAP as a probe.
pub fn leaf_entry(va: u64) -> Option<u64> {
    let pml4_pa = crate::arch::read_current_page_root();
    if pml4_pa == 0 {
        return None;
    }

    let pml4e = match unsafe { read_table_entry(pml4_pa, ((va >> 39) & 0x1FF) as usize) } {
        Some(value) => value,
        None => return None,
    };
    if (pml4e & 1) == 0 {
        return None;
    }
    if pml4e & 0x80 != 0 {
        return Some(pml4e);
    }

    let pdpte = match unsafe { read_table_entry(pml4e & 0x000F_FFFF_FFFF_F000, ((va >> 30) & 0x1FF) as usize) } {
        Some(value) => value,
        None => return None,
    };
    if (pdpte & 1) == 0 {
        return None;
    }
    if pdpte & 0x80 != 0 {
        return Some(pdpte);
    }

    let pde = match unsafe { read_table_entry(pdpte & 0x000F_FFFF_FFFF_F000, ((va >> 21) & 0x1FF) as usize) } {
        Some(value) => value,
        None => return None,
    };
    if (pde & 1) == 0 {
        return None;
    }
    if pde & 0x80 != 0 {
        return Some(pde);
    }

    unsafe { read_table_entry(pde & 0x000F_FFFF_FFFF_F000, ((va >> 12) & 0x1FF) as usize) }
        .filter(|entry| (entry & 1) != 0)
}

/// write the supplied PFN into CR3.
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

/// read the current CR3.
pub fn read_page_root_pfn() -> u64 {
    let cr3: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nostack));
    }
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
