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

use core::arch::asm;
use core::ptr;

use crate::mm::frame;
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

const PTE_V: u64 = 1 << 0;
const PTE_R: u64 = 1 << 1;
const PTE_W: u64 = 1 << 2;
const PTE_X: u64 = 1 << 3;
const PTE_A: u64 = 1 << 6;
const PTE_D: u64 = 1 << 7;

/// Sv39 stores the 44-bit PPN in PTE bits [53:10]. Recover the aligned
/// physical address by shifting the PPN back into bits [55:12].
const PTE_PPN_MASK: u64 = 0x000F_FFFF_FFFF_FC00;
fn pte_pa(entry: u64) -> u64 {
    ((entry & PTE_PPN_MASK) >> 10) << 12
}

/// Bootstrap root page table. It lives in the kernel image so it is
/// valid before the PFN database is online; `paging::init()` installs
/// it as the current root and later mappings build on it.
static mut ROOT_TABLE: [u64; 512] = [0; 512];
static mut ROOT_PHYS: u64 = 0;

/// Read the active root-table physical address from the satp CSR.
///
/// The UEFI firmware (and OpenSBI) may already be running with Sv39
/// enabled before the kernel's own paging subsystem is initialized.
/// Reading satp is the authoritative answer -- exactly like reading
/// CR3 on x86_64 or TTBR1 on aarch64 -- and must be used whenever the
/// software mirror (ROOT_PHYS) has not been published yet.
fn current_satp_root_phys() -> u64 {
    let satp: u64;
    unsafe {
        asm!("csrr {}, satp", out(reg) satp, options(nostack));
    }
    // satp.MODE (bits [63:60]): 0 = bare, 8 = Sv39, 9 = Sv48. The
    // PPN field is bits [43:0] for both supported modes and the
    // physical address of the root table is PPN << 12.
    let mode = satp >> 60;
    if mode == 0 {
        return 0;
    }
    (satp & 0x0000_0FFF_FFFF_FFFF) << 12
}

pub fn root_phys() -> u64 {
    let mirrored = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ROOT_PHYS)) };
    if mirrored != 0 {
        return mirrored;
    }
    // Early boot (before paging::init()): the MMU may already be
    // translating through a firmware-installed root table. Fall back
    // to it so that early identity mappings land in the table that is
    // actually in use, instead of dereferencing a null root.
    current_satp_root_phys()
}

pub fn read_page_root_phys() -> u64 {
    root_phys()
}

/// Allocate a page-table page. The PFN database is not available while
/// the bootstrap heap is being mapped, so fall back to the frame
/// allocator until it comes online.
fn alloc_page_table() -> Option<u64> {
    if let Some(pfn) = pfn::allocate_pfn() {
        return Some(pfn_to_phys(pfn));
    }
    frame::allocate_pages(1)
}
fn make_pte(pa: u64, flags: u64) -> u64 {
    // Sv39 requires the A bit for every referenced page and the D bit
    // for every stored page. The kernel bootstrap has no PTE update
    // path in the page fault handler, so these bits are installed
    // eagerly. This is safe for MMIO and kernel mappings and also
    // avoids surprising faults in Ring 3.
    let dirty = if (flags & PTE_W) != 0 { PTE_D } else { 0 };
    ((pa >> 12) << 10) | (flags & 0xFF) | PTE_V | PTE_A | dirty
}
fn is_valid(e: u64) -> bool {
    (e & PTE_V) != 0
}
fn is_leaf(e: u64) -> bool {
    (e & (PTE_R | PTE_W | PTE_X)) != 0
}

/// Walk the Sv39 page tables for `va` and return a writable pointer
/// to the leaf PTE. Allocates any missing intermediate along the
/// way.
/// Walk a specific Sv39 root table and return the leaf PTE pointer.
///
/// `root_phys` is the physical address of the root table. The caller
/// may be operating on a non-current process root, so this function
/// never switches `satp`; it writes directly through the kernel's
/// identity mapping.
unsafe fn leaf_pte_for_at(root_phys: u64, va: u64) -> *mut u64 {
    let l0_phys = root_phys;
    let l0_idx = ((va >> 30) & 0x1FF) as usize;
    let l1_idx = ((va >> 21) & 0x1FF) as usize;
    let l2_idx = ((va >> 12) & 0x1FF) as usize;

    let l0 = l0_phys as *mut u64;
    let l0e = core::ptr::read_volatile(l0.add(l0_idx));
    let l1_phys = if (l0e & PTE_V) != 0 {
        pte_pa(l0e)
    } else {
        let new_phys = match alloc_page_table() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_pte(new_phys, 0);
        core::ptr::write_volatile(l0.add(l0_idx), new_desc);
        new_phys
    };

    let l1 = l1_phys as *mut u64;
    let l1e = core::ptr::read_volatile(l1.add(l1_idx));
    let l2_phys = if (l1e & PTE_V) != 0 {
        pte_pa(l1e)
    } else {
        let new_phys = match alloc_page_table() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_pte(new_phys, 0);
        core::ptr::write_volatile(l1.add(l1_idx), new_desc);
        new_phys
    };

    let l2 = l2_phys as *mut u64;
    l2.add(l2_idx)
}

/// Walk the current root table for `va`.
unsafe fn leaf_pte_for(va: u64) -> *mut u64 {
    leaf_pte_for_at(root_phys(), va)
}

pub fn map_page(va: u64, pa: u64, flags: u64) -> bool {
    let mut root = root_phys();
    if root == 0 {
        // Bare mode with no firmware root: initialize our bootstrap
        // table first so the mapping has somewhere to live.
        init();
        root = root_phys();
    }
    let l2_pte = unsafe { leaf_pte_for_at(root, va) };
    if l2_pte.is_null() {
        return false;
    }
    unsafe {
        core::ptr::write_volatile(l2_pte, make_pte(pa, flags));
        asm!("sfence.vma {}, zero", in(reg) va, options(nostack));
    }
    true
}

/// Map a page into a non-current Sv39 root without switching `satp`.
pub fn map_page_in_root(root_pfn: u64, va: u64, pa: u64, flags: u64) -> bool {
    let root_phys = pfn_to_phys(root_pfn);
    let l2_pte = unsafe { leaf_pte_for_at(root_phys, va) };
    if l2_pte.is_null() {
        return false;
    }
    unsafe {
        core::ptr::write_volatile(l2_pte, make_pte(pa, flags));
        asm!("sfence.vma {}, zero", in(reg) va, options(nostack));
    }
    true
}

pub fn unmap_page(va: u64) -> Option<u64> {
    let l2_pte = unsafe { leaf_pte_for(va) };
    if l2_pte.is_null() {
        return None;
    }
    unsafe {
        let pte = core::ptr::read_volatile(l2_pte);
        if !is_valid(pte) {
            return None;
        }
        let pa = pte_pa(pte) | (va & 0xFFF);
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
        if !is_valid(l0e) {
            return None;
        }
        let l1_phys = pte_pa(l0e);
        let l1 = l1_phys as *const u64;
        let l1e = core::ptr::read_volatile(l1.add(l1_idx));
        if !is_valid(l1e) {
            return None;
        }
        let l2_phys = pte_pa(l1e);
        let l2 = l2_phys as *const u64;
        let l2e = core::ptr::read_volatile(l2.add(l2_idx));
        if !is_valid(l2e) {
            return None;
        }
        if !is_leaf(l2e) {
            return None;
        }
        Some(pte_pa(l2e) | (va & 0xFFF))
    }
}

pub unsafe fn load_page_root(pml4_pfn: u64) {
    let pa = pfn_to_phys(pml4_pfn);
    // satp = MODE (8 = Sv39) << 60 | ASID (0) << 44 | PPN
    let satp: u64 = (8u64 << 60) | (pa >> 12);
    asm!("csrw satp, {}", in(reg) satp, options(nostack));
    asm!("sfence.vma", options(nostack));
    core::ptr::write_volatile(core::ptr::addr_of_mut!(ROOT_PHYS), pa);
}

pub fn read_page_root_pfn() -> u64 {
    root_phys() >> 12
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
/// the kernel heap init flow to make sure `global_alloc::alloc`
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
    unsafe {
        // If the MMU is already translating (firmware Sv39), adopt the
        // active root table instead of replacing it. Wiping it would
        // discard every mapping the firmware and early boot built --
        // including the identity mappings created before this hook
        // runs -- and would fault immediately. This mirrors aarch64,
        // which adopts TTBR1 rather than rebuilding the tables.
        let active = current_satp_root_phys();
        if active != 0 {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(ROOT_PHYS), active);
            return;
        }
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!(ROOT_TABLE) as *mut u8,
            0,
            core::mem::size_of::<[u64; 512]>(),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ROOT_PHYS),
            core::ptr::addr_of!(ROOT_TABLE) as u64,
        );
    }
}
