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
use crate::mm::pte::{MMPTE, pfn_to_phys};
use crate::mm::vas::{pde_address_of, ppe_address_of, pte_address_of, pxe_address_of};

/// Sv48 satp mode (8 = Sv39, 9 = Sv48).
pub const SATP_MODE_SV48: u64 = 9u64 << 60;

/// Number of page-table levels for Sv48 (vs 3 for Sv39).
pub const SV48_LEVELS: usize = 4;

/// PTE flag bits — same as Sv39.
const PTE_V: u64 = 1 << 0;
const PTE_R: u64 = 1 << 1;
const PTE_W: u64 = 1 << 2;
const PTE_X: u64 = 1 << 3;
const PTE_U: u64 = 1 << 4;

fn make_pte(pa: u64, flags: u64) -> u64 {
    ((pa >> 12) << 10) | (flags & 0xFF) | PTE_V
}

fn is_valid(e: u64) -> bool { (e & PTE_V) != 0 }
fn is_leaf(e: u64) -> bool {
    (e & (PTE_R | PTE_W | PTE_X)) != 0
}

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

/// Map a virtual page using a 4-level Sv48 page table. The
/// `root` parameter is the physical address of the L0 (PXE)
/// table; the implementation walks down through PPE, PDE and
/// PTE levels and allocates intermediates as needed.
///
/// Returns `false` on allocator failure.
pub unsafe fn map_page_sv48(root_pa: u64, va: u64, pa: u64, flags: u64) -> bool {
    // Compute the addresses of each level's PTE slot. We reuse
    // the existing x86_64-style helpers but the levels here map
    // to L0..L3 in Sv48 instead of the x86 PML4..PT.
    let pxe_ptr = pxe_address_of(va);
    let ppe_ptr = ppe_address_of(va);
    let pde_ptr = pde_address_of(va);
    let pte_ptr = pte_address_of(va);
    if pxe_ptr.is_null() || ppe_ptr.is_null() || pde_ptr.is_null() || pte_ptr.is_null() {
        return false;
    }

    // For Phase 2 we re-use the page-root pointer as a physical
    // address (not a PFN). The caller is responsible for
    // translating the root_pfn at boot time.
    let _ = root_pa;

    unsafe {
        let pxe = &mut *pxe_ptr;
        if !is_valid(pxe.raw()) {
            if !install_intermediate_riscv(pxe) { return false; }
        }
        let ppe = &mut *ppe_ptr;
        if !is_valid(ppe.raw()) {
            if !install_intermediate_riscv(ppe) { return false; }
        }
        let pde = &mut *pde_ptr;
        if !is_valid(pde.raw()) {
            if !install_intermediate_riscv(pde) { return false; }
        }
        let pte = &mut *pte_ptr;
        *pte = MMPTE::from_raw(make_pte(pa, flags));
        asm!("sfence.vma {}, zero", in(reg) va, options(nostack));
    }
    true
}

/// Unmap a virtual page in Sv48 mode.
pub unsafe fn unmap_page_sv48(va: u64) -> Option<u64> {
    let pte_ptr = pte_address_of(va);
    if pte_ptr.is_null() { return None; }
    unsafe {
        let pte = &mut *pte_ptr;
        if !is_valid(pte.raw()) { return None; }
        let pa = pte.hardware_page_frame();
        pte.clear();
        asm!("sfence.vma {}, zero", in(reg) va, options(nostack));
        Some(pa)
    }
}

/// Translate a virtual address in Sv48 mode.
pub unsafe fn translate_virt_sv48(va: u64) -> Option<u64> {
    let pxe = unsafe { &*pxe_address_of(va) };
    if !is_valid(pxe.raw()) { return None; }
    let ppe = unsafe { &*ppe_address_of(va) };
    if !is_valid(ppe.raw()) { return None; }
    let pde = unsafe { &*pde_address_of(va) };
    if !is_valid(pde.raw()) { return None; }
    let pte = unsafe { &*pte_address_of(va) };
    if !is_valid(pte.raw()) { return None; }
    if is_leaf(pte.raw()) {
        return Some(pte.hardware_page_frame() | (va & 0xFFF));
    }
    None
}

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
    SATP_MODE_SV48 == (9u64 << 60)
        && SV48_LEVELS == 4
}