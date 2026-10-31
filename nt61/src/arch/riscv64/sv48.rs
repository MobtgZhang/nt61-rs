//! RISC-V 64 Sv48 large-address paging support.
//!
//! Sv48 is the 48-bit virtual address space extension of Sv39. It
//! adds a fourth level of page-table walk, allowing VAs in the
//! range `0x0000_8000_0000_0000 .. 0xFFFF_8000_0000_0000` to be
//! translated.
//!
//! Phase 2 implements the Sv48 `map_page` / `unmap_page` /
//! `translate_virt` paths as alternatives to the Sv39 code in
//! [`super::paging`]. The choice between Sv39 and Sv48 is made
//! once at boot from [`crate::arch::riscv64::soc::current_soc`]
//! — boards with `phys_addr_bits >= 40` typically default to Sv48.
//!
//! ## Memory layout
//!
//! ```text
//!   VA[47:39]  L0 (PXE)  —  512 GiB per entry
//!   VA[38:30]  L1 (PPE)  —    1 GiB per entry
//!   VA[29:21]  L2 (PDE)  —    2 MiB per entry (megapage)
//!   VA[20:12]  L3 (PTE)  —    4 KiB per entry (page)
//!   VA[11:0]   page offset
//! ```
//!
//! The PTE format is identical to Sv39, but the PPN field widens
//! to 44 bits (vs 44 bits in Sv39; the layout stays the same in
//! practice because the encoding is a superset).
//!
//! References:
//! * RISC-V Privileged Specification §4.4 (Sv48).
//! * Linux arch/riscv/mm/pgtable.c / __pgtable_l4_enabled.

use core::arch::asm;

use crate::mm::pfn;
use crate::mm::pte::{pfn_to_phys, MMPTE};

/// Sv48 satp mode (8 = Sv39, 9 = Sv48).
pub const SATP_MODE_SV48: u64 = 9u64 << 60;

/// Number of page-table levels for Sv48 (vs 3 for Sv39).
pub const SV48_LEVELS: usize = 4;

/// PTE flag bits — same as Sv39.
const PTE_V: u64 = 1 << 0;
const PTE_R: u64 = 1 << 1;
const PTE_W: u64 = 1 << 2;
const PTE_X: u64 = 1 << 3;
fn make_pte(pa: u64, flags: u64) -> u64 {
    ((pa >> 12) << 10) | (flags & 0xFF) | PTE_V
}

fn is_valid(e: u64) -> bool {
    (e & PTE_V) != 0
}
fn is_leaf(e: u64) -> bool {
    (e & (PTE_R | PTE_W | PTE_X)) != 0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Install an intermediate page table at `parent` if absent.
unsafe fn install_intermediate_riscv(parent: *mut MMPTE) -> bool {
    let new_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => return false,
    };
    let new_pa = pfn_to_phys(new_pfn);
    core::ptr::write_bytes(new_pa as *mut u8, 0, 4096);
    *parent = MMPTE::from_raw(make_pte(new_pa, 0));
    true
}

/// Return the physical address of the table referenced by a valid,
/// non-leaf Sv48 entry.
fn referenced_table_pa(entry: u64) -> Option<u64> {
    if !is_valid(entry) || is_leaf(entry) {
        return None;
    }
    Some(((entry & 0x000F_FFFF_FFFF_FC00) >> 10) << 12)
}

/// Return a mutable pointer to the Sv48 PTE at `table_pa[index]`.
fn slot_at(table_pa: u64, index: usize) -> *mut u64 {
    unsafe { (table_pa as *mut u64).add(index) }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Map a virtual page using a 4-level Sv48 page table. The
/// `root_pa` parameter is the physical address of the L0 table;
/// the implementation walks it directly and allocates missing
/// intermediates as needed.
///
/// Returns `false` on allocator failure.
pub unsafe fn map_page_sv48(root_pa: u64, va: u64, pa: u64, flags: u64) -> bool {
    unsafe {
        let l0 = ((va >> 39) & 0x1FF) as usize;
        let l1 = ((va >> 30) & 0x1FF) as usize;
        let l2 = ((va >> 21) & 0x1FF) as usize;
        let l3 = ((va >> 12) & 0x1FF) as usize;

        let pxe_ptr = slot_at(root_pa, l0);
        let pxe = *pxe_ptr;
        let ppe_table_pa = if is_valid(pxe) && !is_leaf(pxe) {
            match referenced_table_pa(pxe) {
                Some(table) => table,
                None => return false,
            }
        } else if !is_valid(pxe) {
            install_intermediate_riscv(pxe_ptr as *mut MMPTE);
            match referenced_table_pa(*pxe_ptr) {
                Some(table) => table,
                None => return false,
            }
        } else {
            return false;
        };

        let ppe_ptr = slot_at(ppe_table_pa, l1);
        let ppe = *ppe_ptr;
        let pde_table_pa = if is_valid(ppe) && !is_leaf(ppe) {
            match referenced_table_pa(ppe) {
                Some(table) => table,
                None => return false,
            }
        } else if !is_valid(ppe) {
            install_intermediate_riscv(ppe_ptr as *mut MMPTE);
            match referenced_table_pa(*ppe_ptr) {
                Some(table) => table,
                None => return false,
            }
        } else {
            return false;
        };

        let pde_ptr = slot_at(pde_table_pa, l2);
        let pde = *pde_ptr;
        let pte_table_pa = if is_valid(pde) && !is_leaf(pde) {
            match referenced_table_pa(pde) {
                Some(table) => table,
                None => return false,
            }
        } else if !is_valid(pde) {
            install_intermediate_riscv(pde_ptr as *mut MMPTE);
            match referenced_table_pa(*pde_ptr) {
                Some(table) => table,
                None => return false,
            }
        } else {
            return false;
        };

        let pte_ptr = slot_at(pte_table_pa, l3);
        *pte_ptr = make_pte(pa, flags) | PTE_V;
        asm!("sfence.vma {}, zero", in(reg) va, options(nostack));
    }
    true
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Unmap a virtual page in Sv48 mode.
pub unsafe fn unmap_page_sv48(va: u64) -> Option<u64> {
    unsafe {
        let root_pa = crate::arch::riscv64::paging::root_phys();
        let mut table_pa = root_pa;
        let mut level = 0usize;
        while level < SV48_LEVELS {
            let shift = 39 - level * 9;
            let index = ((va >> shift) & 0x1FF) as usize;
            let entry = *slot_at(table_pa, index);
            if !is_valid(entry) {
                return None;
            }
            if level == SV48_LEVELS - 1 || is_leaf(entry) {
                if level != SV48_LEVELS - 1 {
                    return None;
                }
                let pa = (entry & 0x000F_FFFF_FFFF_FC00) >> 10 << 12;
                *slot_at(table_pa, index) = 0;
                asm!("sfence.vma {}, zero", in(reg) va, options(nostack));
                return Some(pa);
            }
            table_pa = referenced_table_pa(entry)?;
            level += 1;
        }
        None
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Translate a virtual address in Sv48 mode.
pub unsafe fn translate_virt_sv48(va: u64) -> Option<u64> {
    unsafe {
        let root_pa = crate::arch::riscv64::paging::root_phys();
        let mut table_pa = root_pa;
        for level in 0..SV48_LEVELS {
            let shift = 39 - level * 9;
            let index = ((va >> shift) & 0x1FF) as usize;
            let entry = *slot_at(table_pa, index);
            if !is_valid(entry) {
                return None;
            }
            if level == SV48_LEVELS - 1 || is_leaf(entry) {
                if level != SV48_LEVELS - 1 {
                    return None;
                }
                let pa = ((entry & 0x000F_FFFF_FFFF_FC00) >> 10) << 12;
                return Some(pa | (va & 0xFFF));
            }
            table_pa = referenced_table_pa(entry)?;
        }
        None
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Load the Sv48 page-table root into `satp`.
///
/// `pml4_pfn` is the PFN of the L0 (PXE) table; we shift it into
/// the PPN field and OR in the Sv48 mode bits.
pub unsafe fn load_page_root_sv48(pml4_pfn: u64) {
    let pa = pfn_to_phys(pml4_pfn);
    let satp: u64 = SATP_MODE_SV48 | (pa >> 12);
    asm!("csrw satp, {}", in(reg) satp, options(nostack));
    asm!("sfence.vma", options(nostack));
}

/// TLB flush helpers — forwarded to the parent module via local
/// re-exports for callers that prefer the Sv48 namespace.
pub use crate::arch::riscv64::paging::flush_tlb as flush_tlb_sv48;

/// Choose between Sv39 and Sv48 at boot time. Defaults to Sv48
/// if the SoC reports `phys_addr_bits >= 40` (most server-class
/// parts) and Sv39 otherwise.
pub fn choose_mode() -> u64 {
    use crate::arch::riscv64::soc;
    if soc::phys_addr_bits() >= 40 {
        SATP_MODE_SV48
    } else {
        8u64 << 60 // MODE_SV39
    }
}

/// Smoke test: verify Sv48 mode bits.
pub fn smoke_test() -> bool {
    SATP_MODE_SV48 == (9u64 << 60) && SV48_LEVELS == 4
}
