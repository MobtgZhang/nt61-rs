//! RISC-V 64 paging
//
//! Sv39 layout: a 3-level page table. We walk it by *physical*
//! address using the page-root PA stored in `satp`. We cannot rely
//! on the NT 6.1 self-map windows (`PXE_BASE` / `PPE_BASE` / ...)
//! because `mm::vas::init` is a no-op on non-x86_64 architectures
//! and those VAs are unmapped. See the long comment in
//! `arch::aarch64::paging` for the reasoning.
//
//! PTE format (Sv39):
//
//! * bit 0: V (valid)
//! * bit 1: R (read)
//! * bit 2: W (write)
//! * bit 3: X (execute)
//! * bit 4: U (user)
//! * bit 5: G (global)
//! * bit 6: A (accessed)
//! * bit 7: D (dirty)
//! * bits [9:8]: RSW (reserved for software)
//! * bits [53:10]: physical page number (the PPN field, shifted)

#![allow(non_snake_case)]

use core::arch::asm;
use core::ptr;

use crate::mm::pfn;
use crate::mm::pte::pfn_to_phys;

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SHIFT: u64 = 12;
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

pub type VirtAddr = u64;
pub type PhysAddr = u64;

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

/// Read the page-root PA out of `satp`. Sv39 packs the PPN into
/// bits [43:0]; we shift left by 12 to recover a physical address
/// aligned to a page boundary.
#[inline]
fn root_phys() -> u64 {
    let satp: u64;
    unsafe { asm!("csrr {}, satp", out(reg) satp, options(nostack)); }
    (satp & 0x000F_FFFF_FFFF_F000) as u64
}

/// Walk the Sv39 page tables for `va` and return a writable pointer
/// to the leaf PTE. Allocates any missing intermediate along the
/// way.
unsafe fn leaf_pte_for(va: u64) -> *mut u64 {
    let l0_phys = root_phys();
    let l0_idx = ((va >> 30) & 0x1FF) as usize;
    let l1_idx = ((va >> 21) & 0x1FF) as usize;
    let l2_idx = ((va >> 12) & 0x1FF) as usize;

    let l0 = l0_phys as *mut u64;
    let l0e = core::ptr::read_volatile(l0.add(l0_idx));
    let l1_phys = if (l0e & PTE_V) != 0 {
        (l0e >> 10) & 0x000F_FFFF_FFFF_F000
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_pte(new_phys, 0);
        core::ptr::write_volatile(l0.add(l0_idx), new_desc);
        new_phys
    };

    let l1 = l1_phys as *mut u64;
    let l1e = core::ptr::read_volatile(l1.add(l1_idx));
    let l2_phys = if (l1e & PTE_V) != 0 {
        (l1e >> 10) & 0x000F_FFFF_FFFF_F000
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_pte(new_phys, 0);
        core::ptr::write_volatile(l1.add(l1_idx), new_desc);
        new_phys
    };

    let l2 = l2_phys as *mut u64;
    l2.add(l2_idx)
}

pub fn map_page(va: u64, pa: u64, flags: u64) -> bool {
    let l2_pte = unsafe { leaf_pte_for(va) };
    if l2_pte.is_null() { return false; }
    unsafe {
        core::ptr::write_volatile(l2_pte, make_pte(pa, flags));
        asm!("sfence.vma {}, zero", in(reg) va, options(nostack));
    }
    true
}

pub fn unmap_page(va: u64) -> Option<u64> {
    let l2_pte = unsafe { leaf_pte_for(va) };
    if l2_pte.is_null() { return None; }
    unsafe {
        let pte = core::ptr::read_volatile(l2_pte);
        if !is_valid(pte) { return None; }
        let pa = ((pte >> 10) & 0x000F_FFFF_FFFF_F000)
            | (va & 0xFFF);
        core::ptr::write_volatile(l2_pte, 0);
        asm!("sfence.vma {}, zero", in(reg) va, options(nostack));
        Some(pa)
    }
}

pub fn translate_virt(va: u64) -> Option<u64> {
    unsafe {
        let l0_phys = root_phys();
        let l0_idx = ((va >> 30) & 0x1FF) as usize;
        let l1_idx = ((va >> 21) & 0x1FF) as usize;
        let l2_idx = ((va >> 12) & 0x1FF) as usize;
        let l0 = l0_phys as *const u64;
        let l0e = core::ptr::read_volatile(l0.add(l0_idx));
        if !is_valid(l0e) { return None; }
        let l1_phys = ((l0e >> 10) & 0x000F_FFFF_FFFF_F000) as u64;
        let l1 = l1_phys as *const u64;
        let l1e = core::ptr::read_volatile(l1.add(l1_idx));
        if !is_valid(l1e) { return None; }
        let l2_phys = ((l1e >> 10) & 0x000F_FFFF_FFFF_F000) as u64;
        let l2 = l2_phys as *const u64;
        let l2e = core::ptr::read_volatile(l2.add(l2_idx));
        if !is_valid(l2e) { return None; }
        if !is_leaf(l2e) { return None; }
        Some(((l2e >> 10) & 0x000F_FFFF_FFFF_F000) | (va & 0xFFF))
    }
}

pub unsafe fn load_page_root(pml4_pfn: u64) {
    let pa = pfn_to_phys(pml4_pfn);
    // satp = MODE (8 = Sv39) << 60 | ASID (0) << 44 | PPN
    let satp: u64 = (8u64 << 60) | (pa >> 12);
    asm!("csrw satp, {}", in(reg) satp, options(nostack));
    asm!("sfence.vma", options(nostack));
}

pub fn read_page_root_pfn() -> u64 {
    let satp: u64;
    unsafe { asm!("csrr {}, satp", out(reg) satp, options(nostack)); }
    (satp & 0x000F_FFFF_FFFF_F000) >> 12
}

/// Invalidate a single TLB entry for the given virtual address.
/// Uses `sfence.vma` with rs1=zero (all ASIDs, single VA).
pub fn invalidate_tlb(va: u64) {
    unsafe {
        // sfence.vma rs1=zero, rs2=zero invalidates all entries matching rs1 (all).
        // For a specific VA, use sfence.vma with the VA in rs1.
        asm!("sfence.vma {}", in(reg) va, options(nostack));
    }
}

/// Flush the entire TLB (all entries and all ASIDs).
pub fn flush_tlb() {
    unsafe {
        asm!("sfence.vma", options(nostack));
    }
}

/// Identity-map `[pa, pa + size)` into the kernel's Sv39 translation
/// tables. Mirrors the aarch64 helper of the same name. Used by
/// the kernel heap init flow to make sure `GlobalAlloc::alloc`
/// returns pointers that resolve under the kernel's `satp`.
///
/// `pa` must be page-aligned; `size` is rounded up to the next
/// page boundary. Returns `true` on success, `false` if any
/// `map_page` call in the range failed.
pub fn identity_map_region(pa: u64, size: u64) -> bool {
    const PAGE_SIZE: u64 = 4096;
    const HEAP_FLAGS: u64 = PTE_R | PTE_W; // read-write, no execute (NX)
    let pa_aligned = pa & !(PAGE_SIZE - 1);
    let end = pa.saturating_add(size);
    let mut cur = pa_aligned;
    while cur < end {
        if !map_page(cur, cur, HEAP_FLAGS) {
            return false;
        }
        cur = cur.saturating_add(PAGE_SIZE);
    }
    flush_tlb();
    true
}

/// Architecture init hook for paging. Phase 1 leaves `satp` in
/// bare mode; Phase 2 installs a real Sv39 (or Sv48) page table.
///
/// `mm::vm::init` calls this via the `paging_impl::init` alias.
pub fn init() {
    // No-op at Phase 1. The real Sv39 install happens during
    // `mm::vas::init`.
}
