//! LoongArch 64 paging
//
//! 4-level page table pointed at by `PGDH` (the kernel half is
//! PGDH, the user half is PGD). PTE format:
//
//! * bit 0: V (valid)
//! * bit 1: D (dirty)
//! * bit 2: W (writable)
//! * bit 3: PLV (privilege level bits 1:0 — these are bits 4:3
//!   in the encoding)
//! * bit 4: PLV bit 0
//! * bit 5: MAT (memory access type)
//! * bit 6: G (global)
//! * bit 7: P (huge page)
//! * bit 8: W1
//! * bit 9: NR (not read)
//! * bit 10: NX (no execute)
//! * bits [47:12]: physical page number
//
//! The PGDH register is at CSR 0x19.

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
const PTE_D: u64 = 1 << 1;
const PTE_W: u64 = 1 << 2;
const PTE_PLV_USER: u64 = 3 << 3; // PLV 3
const PTE_G: u64 = 1 << 6;
const PTE_NX: u64 = 1 << 10;

fn make_pte_loong(pa: u64, flags: u64) -> u64 {
    let pte = ((pa & 0x0000_FFFF_FFFF_F000) >> 0)
        | PTE_V
        | if flags & 0x2 != 0 { PTE_W } else { 0 }
        | if flags & 0x4 != 0 { PTE_PLV_USER } else { 0 }
        | PTE_G
        | if flags & (1u64 << 63) != 0 { PTE_NX } else { 0 };
    pte
}
fn is_valid_loong(e: u64) -> bool { (e & PTE_V) != 0 }
fn is_table_loong(e: u64) -> bool {
    is_valid_loong(e) && (e & (1u64 << 1)) == 0
}

/// Read the page-root PA out of the `PGDH` CSR (0x19). On
/// LoongArch64 the kernel half is configured to use PGDH (high
/// half, kernel VAs); we keep using that root here.
#[inline]
fn root_phys() -> u64 {
    let pa: u64;
    unsafe { asm!("csrrd {}, 0x19", out(reg) pa, options(nostack)); }
    pa & 0x0000_FFFF_FFFF_F000
}

/// Walk the LoongArch 4-level page tables for `va` and return a
/// writable pointer to the leaf PTE.
unsafe fn leaf_pte_for(va: u64) -> *mut u64 {
    let l0_phys = root_phys();
    let l0_idx = ((va >> 48) & 0x1FF) as usize;
    let l1_idx = ((va >> 39) & 0x1FF) as usize;
    let l2_idx = ((va >> 30) & 0x1FF) as usize;
    let l3_idx = ((va >> 21) & 0x1FF) as usize;

    let l0 = l0_phys as *mut u64;
    let l0e = core::ptr::read_volatile(l0.add(l0_idx));
    let l1_phys = if is_table_loong(l0e) {
        l0e & 0x000F_FFFF_FFFF_F000
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_pte_loong(new_phys, 0) & !PTE_NX;
        core::ptr::write_volatile(l0.add(l0_idx), new_desc);
        new_phys
    };

    let l1 = l1_phys as *mut u64;
    let l1e = core::ptr::read_volatile(l1.add(l1_idx));
    let l2_phys = if is_table_loong(l1e) {
        l1e & 0x000F_FFFF_FFFF_F000
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_pte_loong(new_phys, 0) & !PTE_NX;
        core::ptr::write_volatile(l1.add(l1_idx), new_desc);
        new_phys
    };

    let l2 = l2_phys as *mut u64;
    let l2e = core::ptr::read_volatile(l2.add(l2_idx));
    let l3_phys = if is_table_loong(l2e) {
        l2e & 0x000F_FFFF_FFFF_F000
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_pte_loong(new_phys, 0) & !PTE_NX;
        core::ptr::write_volatile(l2.add(l2_idx), new_desc);
        new_phys
    };

    let l3 = l3_phys as *mut u64;
    let l3e = core::ptr::read_volatile(l3.add(l3_idx));
    // LoongArch uses bits 1:0 = 0b11 for valid table, 0b01 for
    // leaf. We allow either as a "table" predecessor and always
    // reuse l3_phys for the leaf write.
    let _ = l3e;
    let phys_pte_idx = ((va >> 12) & 0x1FF) as usize;
    (l3_phys as *mut u64).add(phys_pte_idx)
}

pub fn map_page(va: u64, pa: u64, flags: u64) -> bool {
    let l3_pte = unsafe { leaf_pte_for(va) };
    if l3_pte.is_null() { return false; }
    unsafe {
        core::ptr::write_volatile(l3_pte, make_pte_loong(pa, flags));
        asm!("invtlb 0, $r0, {0}", in(reg) va, options(nostack));
    }
    true
}

pub fn unmap_page(va: u64) -> Option<u64> {
    let l3_pte = unsafe { leaf_pte_for(va) };
    if l3_pte.is_null() { return None; }
    unsafe {
        let pte = core::ptr::read_volatile(l3_pte);
        if !is_valid_loong(pte) { return None; }
        let pa = pte & 0x000F_FFFF_FFFF_F000;
        core::ptr::write_volatile(l3_pte, 0);
        asm!("invtlb 0, $r0, {0}", in(reg) va, options(nostack));
        Some(pa)
    }
}

pub fn translate_virt(va: u64) -> Option<u64> {
    unsafe {
        let l0_phys = root_phys();
        let l0_idx = ((va >> 48) & 0x1FF) as usize;
        let l1_idx = ((va >> 39) & 0x1FF) as usize;
        let l2_idx = ((va >> 30) & 0x1FF) as usize;
        let l3_idx = ((va >> 21) & 0x1FF) as usize;
        let l0 = l0_phys as *const u64;
        let l0e = core::ptr::read_volatile(l0.add(l0_idx));
        if !is_table_loong(l0e) { return None; }
        let l1_phys = l0e & 0x000F_FFFF_FFFF_F000;
        let l1 = l1_phys as *const u64;
        let l1e = core::ptr::read_volatile(l1.add(l1_idx));
        if !is_table_loong(l1e) { return None; }
        let l2_phys = l1e & 0x000F_FFFF_FFFF_F000;
        let l2 = l2_phys as *const u64;
        let l2e = core::ptr::read_volatile(l2.add(l2_idx));
        if !is_table_loong(l2e) { return None; }
        let l3_phys = l2e & 0x000F_FFFF_FFFF_F000;
        let l3 = l3_phys as *const u64;
        let l3e = core::ptr::read_volatile(l3.add(l3_idx));
        if !is_valid_loong(l3e) { return None; }
        Some((l3e & 0x000F_FFFF_FFFF_F000) | (va & 0xFFF))
    }
}

pub unsafe fn load_page_root(pml4_pfn: u64) {
    let pa = pfn_to_phys(pml4_pfn);
    asm!("csrwr {0}, 0x19", in(reg) pa, options(nostack));
    asm!("invtlb 0, $r0, $r0", options(nostack));
    // Paging may still be off (CRMD.PG = 0) if `arch::init` was
    // bypassed and the firmware-style "kernel_main → mm::init"
    // flow ran without ever flipping it back on. Make sure the
    // new page tables are actually consulted from this point
    // on by clearing the PG bit, since enabling paging on
    // LoongArch requires a deliberate `csrwr` to CRMD after the
    // root has been installed.
    let mut crmd: u64;
    asm!("csrrd {}, 0x0", out(reg) crmd, options(nostack));
    crmd |= 1u64 << 4; // set PG
    asm!("csrwr {}, 0x0", in(reg) crmd, options(nostack));
}

pub fn read_page_root_pfn() -> u64 {
    let pa: u64;
    unsafe { asm!("csrrd {}, 0x19", out(reg) pa, options(nostack)); }
    pa >> 12
}

/// Invalidate a single TLB entry for the given virtual address.
pub fn invalidate_tlb(va: u64) {
    unsafe {
        asm!("invtlb 0, $r0, {0}", in(reg) va, options(nostack));
    }
}

/// Flush the entire TLB (all entries).
pub fn flush_tlb() {
    unsafe {
        // invtlb with rs=0, vpn=0 invalidates all TLB entries
        asm!("invtlb 0, $r0, $r0", options(nostack));
    }
}

/// Identity-map `[pa, pa + size)` into the kernel's translation
/// tables. Mirrors the aarch64 helper of the same name. Used by
/// the kernel heap init flow to make sure `GlobalAlloc::alloc`
/// returns pointers that resolve under the kernel's `PGDH`.
///
/// `pa` must be page-aligned; `size` is rounded up to the next
/// page boundary. Returns `true` on success, `false` if any
/// `map_page` call in the range failed.
pub fn identity_map_region(pa: u64, size: u64) -> bool {
    const PAGE_SIZE: u64 = 4096;
    // Read-write (kernel PLV), no execute (NX). bit 2 = W in the
    // unified flags convention used by `make_pte_loong`.
    const HEAP_FLAGS: u64 = 0x2;
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

/// Architecture-required initialisation hook called by `mm::vm::init`.
///
/// On LoongArch64 the page-table walker is configured by `arch::init`
/// (PWCL/PWCH + STLBPS); here we just publish the kernel root PGDH
/// if not already done. Safe to call repeatedly.
pub fn init() {
    // No-op for now: the page-walker is brought up in `arch::loongarch64::init`
    // before `mm::init` runs, so by the time we get here PGDL/PGDH already
    // hold valid roots for the kernel half of the address space.
}
