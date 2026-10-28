//! LoongArch 64 paging
//
//! Five-level page table. Kernel VAs live in the low half (VA63 ==
//! 0) and are walked through PGDL (CSR 0x15); `enter_first_user_thread`
//! switches PGDL to the user root, so PGDL — not PGDH — is always the
//! operative root. The TLB-refill stub reads the active root from
//! PGDL (CSR 0x19), which `load_page_root`, `init` and
//! `enter_first_user_thread` switch. PTE format
//! (hardware TLBENTRY, per QEMU `target/loongarch/cpu-csr.h`):
//
//! * bit 0: V (valid)
//! * bit 1: D (dirty)
//! * bits 2:3: PLV (privilege level)
//! * bits 4:5: MAT (memory access type)
//! * bit 6: G (global)
//! * bit 7: P (huge page)
//! * bit 8: W (writable)
//! * bits [47:12]: physical page number
//
//! Bit 61: NR (not readable), bit 62: NX (not executable), bit 63:
//! RPLV (restricted privilege). Bits 9:11 are software-reserved and
//! stripped by the hardware refill path. PGDH is at CSR 0x1a and
//! covers only the high half, which this kernel does not use.

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::pfn;
use crate::mm::pte::pfn_to_phys;

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SHIFT: u64 = 12;
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Watchpoint state: physical frame of the leaf table that owns the
/// exception-vector page. vector_page_check resolves and records it;
/// every PTE write into this frame is logged so the code path that
/// corrupts the vector mapping (PTE observed flipping to 0x5D3, i.e.
/// pa=0) can be identified from the serial timeline.
static LEAF_WATCH_FRAME: AtomicU64 = AtomicU64::new(0);
static LEAF_WATCH_HITS: AtomicU64 = AtomicU64::new(0);
static ZERO_PA_HITS: AtomicU64 = AtomicU64::new(0);
static VECW_HITS: AtomicU64 = AtomicU64::new(0);

/// Log a PTE write if it targets the watched leaf frame, and log any
/// map of pa=0 into a non-null va (make_pte_loong(0, writable) is
/// exactly 0x5D3, the value observed corrupting the vector page).
fn watch_pte_write(op: &str, va: u64, pa: u64, flags: u64, pte_ptr: u64) {
    // VA-based watch: fire on ANY map of the vector page regardless of
    // which leaf frame hosts it or when the watch frame was armed.
    let vec_va = crate::arch::loongarch64::idt::vector_page_va() & PAGE_MASK;
    if (va & PAGE_MASK) == vec_va {
        let n = VECW_HITS.fetch_add(1, Ordering::Relaxed);
        if n < 24 {
            crate::hal::serial::write_string_always("[VECW] ");
            crate::hal::serial::write_string_always(op);
            crate::hal::serial::write_string_always(" va=");
            crate::hal::serial::write_hex_u64_always(va);
            crate::hal::serial::write_string_always(" pa=");
            crate::hal::serial::write_hex_u64_always(pa);
            crate::hal::serial::write_string_always(" fl=");
            crate::hal::serial::write_hex_u64_always(flags);
            crate::hal::serial::write_string_always(" pte_ptr=");
            crate::hal::serial::write_hex_u64_always(pte_ptr);
            crate::hal::serial::write_string_always("\r\n");
        }
    }
    let frame = LEAF_WATCH_FRAME.load(Ordering::Relaxed);
    if frame != 0 && (pte_ptr & PAGE_MASK) == frame {
        let n = LEAF_WATCH_HITS.fetch_add(1, Ordering::Relaxed);
        if n < 24 {
            crate::hal::serial::write_string_always("[LEAFW] ");
            crate::hal::serial::write_string_always(op);
            crate::hal::serial::write_string_always(" va=");
            crate::hal::serial::write_hex_u64_always(va);
            crate::hal::serial::write_string_always(" pa=");
            crate::hal::serial::write_hex_u64_always(pa);
            crate::hal::serial::write_string_always(" fl=");
            crate::hal::serial::write_hex_u64_always(flags);
            crate::hal::serial::write_string_always(" pte_ptr=");
            crate::hal::serial::write_hex_u64_always(pte_ptr);
            crate::hal::serial::write_string_always("\r\n");
        }
    }
    if (pa & PAGE_MASK) == 0 && va != 0 {
        let n = ZERO_PA_HITS.fetch_add(1, Ordering::Relaxed);
        if n < 12 {
            crate::hal::serial::write_string_always("[PTE0] ");
            crate::hal::serial::write_string_always(op);
            crate::hal::serial::write_string_always(" va=");
            crate::hal::serial::write_hex_u64_always(va);
            crate::hal::serial::write_string_always(" flags=");
            crate::hal::serial::write_hex_u64_always(flags);
            crate::hal::serial::write_string_always("\r\n");
        }
    }
}

/// Log the zeroing of a newly allocated page-table frame if it is the
/// watched live leaf frame (PFN allocator re-issuing a live frame).
fn watch_leaf_zero(new_phys: u64) {
    let frame = LEAF_WATCH_FRAME.load(Ordering::Relaxed);
    if frame != 0 && (new_phys & PAGE_MASK) == frame {
        crate::hal::serial::write_string_always("[LEAFW] ZERO new-table pa=");
        crate::hal::serial::write_hex_u64_always(new_phys);
        crate::hal::serial::write_string_always(" (live vector-page leaf frame re-issued!)\r\n");
    }
}

/// Hook for the PFN allocator: report re-allocation of the watched
/// live leaf-table frame (cfg-gated call site lives in mm/pfn.rs).
pub fn watch_pfn_alloc(pfn: u64) {
    let frame = LEAF_WATCH_FRAME.load(Ordering::Relaxed);
    if frame != 0 && frame >> PAGE_SHIFT == pfn {
        crate::hal::serial::write_string_always("[PFNWATCH] frame re-allocated pfn=");
        crate::hal::serial::write_hex_u64_always(pfn);
        crate::hal::serial::write_string_always("\r\n");
    }
}

/// LoongArch direct address translation window 0.
///
/// Linux and QEMU reserve VA segment 0x8000_0000_0000_0000 for
/// strongly-ordered uncached MMIO. Keeping MMIO in this window lets
/// the kernel keep its low-half code/data VAs in the mapped page
/// tables while still touching firmware and platform devices after
/// CRMD.PG is enabled. Only PLV0 may use the window, so Ring-3
/// mappings cannot accidentally reach device memory through it.
/// The QEMU/EDK2 LoongArch64 loader keeps the kernel in the VSEG-0xA
/// identity window.  This must be DMW0 because QEMU only honors the first
/// direct window reliably; DMW1 is used for MMIO.
pub const DMW0_IO_VIRT_BASE: u64 = 0x8000_0000_0000_0000;
/// Direct window covering the kernel's identity-mapped low physical
/// addresses (`0xA000_0000_0000_0000..=0xAFFF...`).  QEMU/EDK2 loads this
/// kernel in that VSEG; enabling CRMD.PG without a matching DMW makes even
/// the exception vector unmapped, so the first TLB refill cannot execute.
pub const DMW1_KERNEL_VIRT_BASE: u64 = 0xA000_0000_0000_0000;
pub const CSR_DMW0_PLV0: u64 = 1;

/// Value that enables DMW0 for supervisor-mode MMIO.
pub const CSR_DMW0_INIT: u64 = DMW0_IO_VIRT_BASE | CSR_DMW0_PLV0;

pub type VirtAddr = u64;
pub type PhysAddr = u64;

#[repr(C, align(4096))]
pub struct PageAlignedTable(pub [u64; 512]);

const PAGE_TABLE_ENTRIES: usize = 512;
const MAX_LEAF_TABLES: usize = 512;
const BOOTSTRAP_TABLE_COUNT: usize = 3 + MAX_LEAF_TABLES;

#[repr(C, align(4096))]
pub struct BootstrapPageTables(pub [u64; 512 * BOOTSTRAP_TABLE_COUNT]);

#[derive(Clone, Copy)]
struct LeafTableKey {
    l2_index: usize,
    l3_index: usize,
}

struct PagingState {
    root: PageAlignedTable,
    bootstrap: BootstrapPageTables,
    leaf_keys: [Option<LeafTableKey>; MAX_LEAF_TABLES],
}

impl PagingState {
    const fn new() -> Self {
        Self {
            root: PageAlignedTable([0; 512]),
            bootstrap: BootstrapPageTables([0; 512 * BOOTSTRAP_TABLE_COUNT]),
            leaf_keys: [None; MAX_LEAF_TABLES],
        }
    }
}

static PAGING_STATE: Spinlock<PagingState> = Spinlock::new(PagingState::new());

unsafe fn leaf_table_for(
    state: &mut PagingState,
    key: LeafTableKey,
) -> Option<*mut u64> {
    for (index, slot) in state.leaf_keys.iter().enumerate() {
        let existing = slot.unwrap_or(LeafTableKey {
            l2_index: usize::MAX,
            l3_index: usize::MAX,
        });
        if existing.l2_index == key.l2_index && existing.l3_index == key.l3_index {
            return Some((core::ptr::addr_of_mut!(state.bootstrap.0) as *mut u64)
                .add((3 + index) * PAGE_TABLE_ENTRIES));
        }
    }

    for (index, slot) in state.leaf_keys.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(key);
            let table = (core::ptr::addr_of_mut!(state.bootstrap.0) as *mut u64)
                .add((3 + index) * PAGE_TABLE_ENTRIES);
            core::ptr::write_bytes(table as *mut u8, 0, PAGE_SIZE as usize);
            return Some(table);
        }
    }

    None
}

/// Page tables used before the PFN database is available. The first
/// three tables are L1, L2, and DIR1 for the bootstrap identity map;
/// the remaining tables are 2 MiB leaf tables. The pool covers the
/// 256 MiB low-RAM window plus the QEMU LoongArch MMIO windows.
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
const PTE_D: u64 = 1 << 1;
const PTE_PLV_USER: u64 = 3 << 2;
const PTE_CACHE_CC: u64 = 1 << 4;
const PTE_G: u64 = 1 << 6;
const PTE_PRESENT: u64 = 1 << 7;
const PTE_W: u64 = 1 << 8;
const PTE_MODIFIED: u64 = 1 << 10;
/// LoongArch hardware no-execute bit (leaf PTE bit 62). Bits 9:11 are
/// software-reserved and stripped by the TLB-refill hardware, so
/// executability can only be controlled through bit 62.
const PTE_NX_LOONG: u64 = 1 << 62;
const PTE_PFN_SHIFT: u64 = PAGE_SHIFT - 12 + 12;
const PTE_PFN_END_SHIFT: u64 = 48;
const PTE_PFN_MASK: u64 = (!0u64 << PTE_PFN_SHIFT) & ((1u64 << PTE_PFN_END_SHIFT) - 1);

fn make_pte_loong(pa: u64, flags: u64) -> u64 {
    let pfn = (pa & PAGE_MASK) >> PAGE_SHIFT;
    // Portable callers pass x86-style PTE bits.  Do not let native LoongArch
    // permission bit values alias into PLV or PAGE flags; translate them here
    // in one place.
    let writable = flags & crate::mm::pte::PTE_RW != 0;
    let user = flags & (crate::mm::pte::PTE_US | crate::arch::common::paging::PageFlags::USER.bits()) != 0;
    let not_executable = flags & (crate::mm::pte::PTE_NX | crate::arch::common::paging::PageFlags::NO_EXECUTE.bits()) != 0;
    let pte = ((pfn << PTE_PFN_SHIFT) & PTE_PFN_MASK)
        | PTE_V
        | PTE_D
        | PTE_CACHE_CC
        | PTE_G
        | PTE_PRESENT
        | if writable { PTE_W | PTE_MODIFIED } else { 0 }
        | if not_executable { PTE_NX_LOONG } else { 0 }
        | if user { PTE_PLV_USER } else { 0 };
    pte
}
fn is_valid_loong(e: u64) -> bool {
    (e & PTE_V) != 0
}
fn is_table_loong(e: u64) -> bool {
    e != 0
}

fn make_table_desc_loong(pa: u64) -> u64 {
    let pfn = (pa & PAGE_MASK) >> PAGE_SHIFT;
    // Directory entries must be the bare 4K-aligned physical address.
    // The hardware (and QEMU helper_lddir) computes the next-level
    // address as base | index * 8 while masking only the physical
    // range, so flag bits such as V would corrupt the table address
    // and break the TLB refill walk.
    (pfn << PTE_PFN_SHIFT) & PTE_PFN_MASK
}

fn table_pa_loong(e: u64) -> u64 {
    let pfn = (e & PTE_PFN_MASK) >> PTE_PFN_SHIFT;
    pfn << PAGE_SHIFT
}

/// Convert an x86-format root entry into a LoongArch directory descriptor.
pub fn translate_x86_root_entry(entry: u64) -> u64 {
    if entry & crate::mm::pte::PTE_P == 0 {
        return 0;
    }
    make_table_desc_loong(entry & 0x000F_FFFF_FFFF_F000)
}

/// Read the page-root PA out of the `PGDL` CSR (0x19). Kernel VAs
/// live in the low half (VA63 == 0) and user VAs share that half, so
/// PGDL — which `enter_first_user_thread` switches to the user root —
/// is the operative root for both the refill walk (CSR_PGD) and the
/// software walk below.
#[inline]
fn root_phys() -> u64 {
    let pa: u64;
    unsafe {
        asm!("csrrd {}, 0x19", out(reg) pa, options(nostack));
    }
    pa & 0x0000_FFFF_FFFF_F000
}

/// Walk the LoongArch 4-level page tables for `va` and return a
/// writable pointer to the leaf PTE.
unsafe fn leaf_pte_for_at(root_pa: u64, va: u64) -> *mut u64 {
    let l0_phys = root_pa;
    let l0_idx = ((va >> 48) & 0x1FF) as usize;
    let l1_idx = ((va >> 39) & 0x1FF) as usize;
    let l2_idx = ((va >> 30) & 0x1FF) as usize;
    let l3_idx = ((va >> 21) & 0x1FF) as usize;

    let l0 = l0_phys as *mut u64;
    let l0e = core::ptr::read_volatile(l0.add(l0_idx));
    let l1_phys = if is_table_loong(l0e) {
        table_pa_loong(l0e)
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        watch_leaf_zero(new_phys);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_table_desc_loong(new_phys);
        core::ptr::write_volatile(l0.add(l0_idx), new_desc);
        new_phys
    };

    let l1 = l1_phys as *mut u64;
    let l1e = core::ptr::read_volatile(l1.add(l1_idx));
    let l2_phys = if is_table_loong(l1e) {
        table_pa_loong(l1e)
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        watch_leaf_zero(new_phys);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_table_desc_loong(new_phys);
        core::ptr::write_volatile(l1.add(l1_idx), new_desc);
        new_phys
    };

    let l2 = l2_phys as *mut u64;
    let l2e = core::ptr::read_volatile(l2.add(l2_idx));
    let dir1_phys = if is_table_loong(l2e) {
        table_pa_loong(l2e)
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        watch_leaf_zero(new_phys);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_table_desc_loong(new_phys);
        core::ptr::write_volatile(l2.add(l2_idx), new_desc);
        new_phys
    };

    let dir1 = dir1_phys as *mut u64;
    let dir1e = core::ptr::read_volatile(dir1.add(l3_idx));
    let leaf_phys = if is_table_loong(dir1e) {
        table_pa_loong(dir1e)
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        watch_leaf_zero(new_phys);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_table_desc_loong(new_phys);
        core::ptr::write_volatile(dir1.add(l3_idx), new_desc);
        new_phys
    };

    let leaf_table = leaf_phys as *mut u64;
    let phys_pte_idx = ((va >> 12) & 0x1FF) as usize;
    leaf_table.add(phys_pte_idx)
}

unsafe fn leaf_pte_for(va: u64) -> *mut u64 {
    leaf_pte_for_at(root_phys(), va)
}

pub fn map_page(va: u64, pa: u64, flags: u64) -> bool {
    let _state = PAGING_STATE.lock();
    let l3_pte = unsafe { leaf_pte_for(va) };
    if l3_pte.is_null() {
        return false;
    }
    watch_pte_write("map", va, pa, flags, l3_pte as u64);
    unsafe {
        core::ptr::write_volatile(l3_pte, make_pte_loong(pa, flags));
        if paging_enabled() {
            crate::arch::loongarch64::tlb::flush_page(va & PAGE_MASK);
        }
    }
    true
}

/// Map one page into a non-current root without switching hardware context.
pub fn map_page_in_root(root_pfn: u64, va: u64, pa: u64, flags: u64) -> bool {
    let _state = PAGING_STATE.lock();
    let root_pa = pfn_to_phys(root_pfn);
    let leaf_pte = unsafe { leaf_pte_for_at(root_pa, va) };
    if leaf_pte.is_null() {
        return false;
    }
    watch_pte_write("maproot", va, pa, flags, leaf_pte as u64);
    unsafe {
        core::ptr::write_volatile(leaf_pte, make_pte_loong(pa, flags));
    }
    if paging_enabled() {
        crate::arch::loongarch64::tlb::flush_page(va & PAGE_MASK);
    }
    true
}

pub fn unmap_page(va: u64) -> Option<u64> {
    let _state = PAGING_STATE.lock();
    let l3_pte = unsafe { leaf_pte_for(va) };
    if l3_pte.is_null() {
        return None;
    }
    unsafe {
        let pte = core::ptr::read_volatile(l3_pte);
        if !is_valid_loong(pte) {
            return None;
        }
        let pa = pte & 0x000F_FFFF_FFFF_F000;
        watch_pte_write("unmap", va, pa, 0, l3_pte as u64);
        core::ptr::write_volatile(l3_pte, 0);
        if paging_enabled() {
            crate::arch::loongarch64::tlb::flush_page(va & PAGE_MASK);
        }
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
        if !is_table_loong(l0e) {
            return None;
        }
        let l1_phys = table_pa_loong(l0e);
        let l1 = l1_phys as *const u64;
        let l1e = core::ptr::read_volatile(l1.add(l1_idx));
        if !is_table_loong(l1e) {
            return None;
        }
        let l2_phys = table_pa_loong(l1e);
        let l2 = l2_phys as *const u64;
        let l2e = core::ptr::read_volatile(l2.add(l2_idx));
        if !is_table_loong(l2e) {
            return None;
        }
        let dir1_phys = table_pa_loong(l2e);
        let dir1 = dir1_phys as *const u64;
        let dir1e = core::ptr::read_volatile(dir1.add(l3_idx));
        if !is_table_loong(dir1e) {
            return None;
        }
        let leaf_phys = table_pa_loong(dir1e);
        let leaf_table = leaf_phys as *const u64;
        let pte_idx = ((va >> 12) & 0x1FF) as usize;
        let pte = core::ptr::read_volatile(leaf_table.add(pte_idx));
        if !is_valid_loong(pte) {
            return None;
        }
        Some((pte & 0x000F_FFFF_FFFF_F000) | (va & 0xFFF))
    }
}

/// Return the LoongArch leaf PTE covering `va`.
pub fn leaf_entry(va: u64) -> Option<u64> {
    unsafe {
        let root = root_phys() as *const u64;
        let l0e = core::ptr::read_volatile(root.add(((va >> 48) & 0x1FF) as usize));
        if !is_table_loong(l0e) {
            return None;
        }
        let l1e = core::ptr::read_volatile(table_pa_loong(l0e) as *const u64);
        if !is_table_loong(l1e) {
            return None;
        }
        let l2e = core::ptr::read_volatile(table_pa_loong(l1e) as *const u64);
        if !is_table_loong(l2e) {
            return None;
        }
        let dir1e = core::ptr::read_volatile(table_pa_loong(l2e) as *const u64);
        if !is_table_loong(dir1e) {
            return None;
        }
        let entry = core::ptr::read_volatile(table_pa_loong(dir1e) as *const u64);
        if is_valid_loong(entry) {
            Some(entry)
        } else {
            None
        }
    }
}

/// Walk a non-current LoongArch root without switching CSR context.
pub fn page_is_mapped_in_root(root_pfn: u64, va: u64) -> bool {
    let root_pa = pfn_to_phys(root_pfn);
    let root = root_pa as *const u64;
    let l0_idx = ((va >> 48) & 0x1FF) as usize;
    let l1_idx = ((va >> 39) & 0x1FF) as usize;
    let l2_idx = ((va >> 30) & 0x1FF) as usize;
    let l3_idx = ((va >> 21) & 0x1FF) as usize;
    let pte_idx = ((va >> 12) & 0x1FF) as usize;
    unsafe {
        let l0e = core::ptr::read_volatile(root.add(l0_idx));
        if !is_table_loong(l0e) {
            return false;
        }
        let l1 = table_pa_loong(l0e) as *const u64;
        let l1e = core::ptr::read_volatile(l1.add(l1_idx));
        if !is_table_loong(l1e) {
            return false;
        }
        let l2 = table_pa_loong(l1e) as *const u64;
        let l2e = core::ptr::read_volatile(l2.add(l2_idx));
        if !is_table_loong(l2e) {
            return false;
        }
        let dir1 = table_pa_loong(l2e) as *const u64;
        let dir1e = core::ptr::read_volatile(dir1.add(l3_idx));
        if !is_table_loong(dir1e) {
            return false;
        }
        let leaf = table_pa_loong(dir1e) as *const u64;
        is_valid_loong(core::ptr::read_volatile(leaf.add(pte_idx)))
    }
}

pub unsafe fn load_page_root(pml4_pfn: u64) {
    let pa = pfn_to_phys(pml4_pfn);
    let is_system_root = {
        let system = crate::mm::vas::MM_SYSTEM_VAS.lock();
        system.pml4_phys == pa
    };
    crate::hal::serial::write_string_always("[PGDL] target=");
    crate::hal::serial::write_hex_u64_always(pa);
    crate::hal::serial::write_string_always(if is_system_root {
        " system\r\n"
    } else {
        " process\r\n"
    });
    // Keep the same switch-time guards as RISC-V so the system root can
    // always reach the active image, stack, heap, and serial device.
    crate::hal::serial::write_string_always("[LAPG] prepare enter\r\n");
    prepare_switch_mappings(pml4_pfn);
    crate::hal::serial::write_string_always("[LAPG] prepare done\r\n");
    let switch_pa = pa;
        asm!("csrwr {0}, 0x1a", inout(reg) switch_pa => _, options(nostack));
    let switch_pa2 = pa;
    // The kernel image and all kernel VAs live in the *low* half
    // (VA63 == 0), which is walked through PGDL (CSR 0x19), not
    // PGDH. Both half-roots must therefore point at the same root
    // table, otherwise low-half translations (including the
    // identity map and the loaded kernel image) are invalid.
        asm!("csrwr {0}, 0x19", inout(reg) switch_pa2 => _, options(nostack));
    asm!("invtlb 0, $r0, $r0", options(nostack));
    crate::hal::serial::write_string_always("[LAPG] flushed\r\n");
    // Clear DA and set PG so the new page tables are consulted.
    let mut crmd: u64;
    asm!("csrrd {}, 0x0", out(reg) crmd, options(nostack));
    crmd &= !(1u64 << 3); // clear DA (mutually exclusive with PG)
    crmd |= 1u64 << 4; // set PG
    crate::hal::serial::write_string_always("[LAPG] enabling\r\n");
    asm!("csrwr {}, 0x0", in(reg) crmd, options(nostack));
    crate::hal::serial::write_string_always("[LAPG] enabled\r\n");
}

/// Install the running image and current stack in the destination root.
///
/// LoongArch changes translation when PGDL is written.  A process root is a
/// private view, so merely sharing root-level descriptors is insufficient;
/// the kernel image and switch-time stack must be present before the switch.
fn prepare_switch_mappings(root_pfn: u64) {
    const KERNEL_CODE: u64 = crate::mm::pte::PTE_P | crate::mm::pte::PTE_RW;

    let return_address: u64;
    unsafe {
        asm!("move {}, $ra", out(reg) return_address, options(nostack));
    }
    let image_start = return_address & !(16 * 1024 * 1024 - 1);
    let image_end = image_start + 18 * 1024 * 1024;
    crate::hal::serial::write_string_always("[LAPGROOT] ra=");
    crate::hal::serial::write_hex_u64_always(return_address);
    crate::hal::serial::write_string_always(" start=");
    crate::hal::serial::write_hex_u64_always(image_start);
    crate::hal::serial::write_string_always("\r\n");
    for page in (image_start..image_end).step_by(PAGE_SIZE as usize) {
        let pa = if paging_enabled() {
            match translate_virt(page) {
                Some(pa) => pa & PAGE_MASK,
                None => page,
            }
        } else {
            page
        };
        if !map_page_in_root(root_pfn, page, pa, KERNEL_CODE) {
            crate::hal::serial::write_string_always(&alloc::format!(
                "[LAPGROOT] kernel map failed at {:x}\r\n",
                page
            ));
        }
    }
    // Vector-page integrity probe: the exception vectors live in the
    // image identity range; verify the destination root really covers
    // the EENTRY page before switching.
    let vec_va = crate::arch::loongarch64::idt::vector_page_va();
    crate::hal::serial::write_string_always("[VECPG] prepare va=");
    crate::hal::serial::write_hex_u64_always(vec_va);
    crate::hal::serial::write_string_always(" mapped=");
    crate::mm::write_decimal_u64(
        page_is_mapped_in_root(root_pfn, vec_va) as u64,
    );
    crate::hal::serial::write_string_always("\r\n");
    // Arm the LEAFW watchpoint on the destination root as early as
    // possible so PTE writes into the vector-page leaf table are
    // logged even before the first vector_page_check runs.
    if let Some(leaf_pa) = leaf_pa_in_root(pfn_to_phys(root_pfn), vec_va) {
        LEAF_WATCH_FRAME.store(leaf_pa, Ordering::Relaxed);
    }
    crate::hal::serial::write_string_always("[LAPGROOT] pc mapped=");
    crate::mm::write_decimal_u64(page_is_mapped_in_root(root_pfn, return_address) as u64);
    crate::hal::serial::write_string_always("\r\n");
    let refill_page = (return_address + 0x418) & PAGE_MASK;
    crate::hal::serial::write_string_always("[LAPGDUMPPAGE] refill_mapped=");
    crate::mm::write_decimal_u64(
        page_is_mapped_in_root(root_pfn, refill_page) as u64,
    );
    crate::hal::serial::write_string_always(" page=");
    crate::hal::serial::write_hex_u64_always(refill_page);
    crate::hal::serial::write_string_always("\r\n");
    let root_pa = pfn_to_phys(root_pfn);
    let root_entry = unsafe { core::ptr::read_volatile(root_pa as *const u64) };
    let l1_pa = table_pa_loong(root_entry);
    let l1_entry = unsafe {
        core::ptr::read_volatile((l1_pa + (((return_address >> 39) & 0x1ff) * 8)) as *const u64)
    };
    let l2_pa = table_pa_loong(l1_entry);
    let l2_entry = unsafe {
        core::ptr::read_volatile((l2_pa + (((return_address >> 30) & 0x1ff) * 8)) as *const u64)
    };
    let dir1_pa = table_pa_loong(l2_entry);
    let dir1_entry = unsafe {
        core::ptr::read_volatile((dir1_pa + (((return_address >> 21) & 0x1ff) * 8)) as *const u64)
    };
    let leaf_pa = table_pa_loong(dir1_entry);
    let leaf_entry = unsafe {
        core::ptr::read_volatile((leaf_pa + (((return_address >> 12) & 0x1ff) * 8)) as *const u64)
    };
    let pwcl: u64;
    let pwch: u64;
    let pgdl: u64;
    unsafe {
        asm!("csrrd {}, 0x1c", out(reg) pwcl, options(nostack));
        asm!("csrrd {}, 0x1d", out(reg) pwch, options(nostack));
        asm!("csrrd {}, 0x19", out(reg) pgdl, options(nostack));
    }
    crate::hal::serial::write_string_always("[LAPGDUMP] root=");
    crate::hal::serial::write_hex_u64_always(root_entry);
    crate::hal::serial::write_string_always(" l1=");
    crate::hal::serial::write_hex_u64_always(l1_entry);
    crate::hal::serial::write_string_always(" l2=");
    crate::hal::serial::write_hex_u64_always(l2_entry);
    crate::hal::serial::write_string_always(" dir1=");
    crate::hal::serial::write_hex_u64_always(dir1_entry);
    crate::hal::serial::write_string_always(" pte=");
    crate::hal::serial::write_hex_u64_always(leaf_entry);
    crate::hal::serial::write_string_always(" pwcl=");
    crate::hal::serial::write_hex_u64_always(pwcl);
    crate::hal::serial::write_string_always(" pwch=");
    crate::hal::serial::write_hex_u64_always(pwch);
    crate::hal::serial::write_string_always(" pgdl=");
    crate::hal::serial::write_hex_u64_always(pgdl);
    crate::hal::serial::write_string_always("\r\n");

    let mut stack_pointer = 0u64;
    unsafe {
        asm!("move {}, $sp", out(reg) stack_pointer, options(nostack));
    }
    for index in 0..512u64 {
        let page = (stack_pointer - index * PAGE_SIZE) & PAGE_MASK;
        let pa = if paging_enabled() {
            match translate_virt(page) {
                Some(pa) => pa & PAGE_MASK,
                None => page,
            }
        } else {
            page
        };
        map_page_in_root(root_pfn, page, pa, KERNEL_CODE);
    }
    for index in 1..512u64 {
        let page = (stack_pointer.wrapping_add(index * PAGE_SIZE)) & PAGE_MASK;
        let pa = if paging_enabled() {
            match translate_virt(page) {
                Some(pa) => pa & PAGE_MASK,
                None => page,
            }
        } else {
            page
        };
        map_page_in_root(root_pfn, page, pa, KERNEL_CODE);
    }

    // Keep the kernel heap visible in every process context.  The heap
    // allocator hands out identity-mapped physical addresses, so re-encode
    // only those native mappings here rather than copying x86 table forms.
    if let Some((heap_base, heap_size)) = crate::mm::heap::KERNEL_HEAP.configured_region() {
        let heap_start = heap_base as u64 & PAGE_MASK;
        let heap_end = heap_start
            .checked_add(heap_size as u64)
            .unwrap_or(heap_start)
            .min(0x0000_FFFF_FFFF_FFFF);
        let mut page = heap_start;
        while page < heap_end {
            let pa = if paging_enabled() {
                match translate_virt(page) {
                    Some(pa) => pa & PAGE_MASK,
                    None => page,
                }
            } else {
                page
            };
            if !map_page_in_root(root_pfn, page, pa, KERNEL_CODE) {
                crate::hal::serial::write_string_always(&alloc::format!(
                    "[LAPGROOT] kernel heap map failed at {:x}\r\n",
                    page
                ));
            }
            page += PAGE_SIZE;
        }
    }

    let fb = crate::hal::common::framebuffer::info();
    if fb.address != 0 && fb.pitch != 0 {
        let fb_size = (fb.pitch as u64) * (fb.height as u64);
        let mut page = fb.address & PAGE_MASK;
        let fb_end = fb.address + fb_size;
        while page < fb_end {
            let pa = if paging_enabled() {
                match translate_virt(page) {
                    Some(pa) => pa & PAGE_MASK,
                    None => page,
                }
            } else {
                page
            };
            map_page_in_root(root_pfn, page, pa, KERNEL_CODE);
            page += PAGE_SIZE;
        }
    }
}

/// Map an MMIO physical address into the DMW0 direct window.
///
/// Callers must only use the result after paging is enabled. Before
/// CRMD.PG is set, LoongArch addresses translate directly, so early
/// boot code keeps using the physical address.
pub fn mmio_virt(pa: u64) -> u64 {
    DMW0_IO_VIRT_BASE | pa
}

/// Verify (and if necessary install) the exception-vector page
/// mapping in the currently active root.  The vector page is part of
/// the kernel image identity map, but frame reuse has been observed
/// to wipe it; taking an exception then re-faults on the vector
/// itself (PIF at ERA=EENTRY) and hangs the CPU.
pub fn ensure_vector_page_mapped() -> bool {
    let va = crate::arch::loongarch64::idt::vector_page_va();
    if page_is_mapped_in_root(read_page_root_pfn(), va) {
        return true;
    }
    let pa = if paging_enabled() {
        match translate_virt(va) {
            Some(pa) => pa & PAGE_MASK,
            None => va,
        }
    } else {
        va
    };
    const VEC_FLAGS: u64 = crate::mm::pte::PTE_P | crate::mm::pte::PTE_RW;
    map_page(va, pa, VEC_FLAGS)
}

/// Serial diagnostic: mapping state of the vector page in the
/// currently active root.
pub fn vector_page_check(tag: &str) {
    let va = crate::arch::loongarch64::idt::vector_page_va();
    let mapped = page_is_mapped_in_root(read_page_root_pfn(), va);
    let pte = leaf_entry(va);
    if let Some(leaf_pa) = leaf_pa_in_root(root_phys(), va) {
        LEAF_WATCH_FRAME.store(leaf_pa, Ordering::Relaxed);
    }
    crate::hal::serial::write_string_always("[VECPG] ");
    crate::hal::serial::write_string_always(tag);
    crate::hal::serial::write_string_always(" va=");
    crate::hal::serial::write_hex_u64_always(va);
    crate::hal::serial::write_string_always(" mapped=");
    crate::mm::write_decimal_u64(mapped as u64);
    if let Some(e) = pte {
        crate::hal::serial::write_string_always(" pte=");
        crate::hal::serial::write_hex_u64_always(e);
    }
    // Report the leaf table frame that owns this VA so a later
    // checkpoint can reveal the frame being reused.
    let root = root_phys() as *const u64;
    let l0e = unsafe { core::ptr::read_volatile(root.add(((va >> 48) & 0x1FF) as usize)) };
    if is_table_loong(l0e) {
        let l1e = unsafe { core::ptr::read_volatile((table_pa_loong(l0e) as *const u64).add(((va >> 39) & 0x1FF) as usize)) };
        if is_table_loong(l1e) {
            let l2e = unsafe { core::ptr::read_volatile((table_pa_loong(l1e) as *const u64).add(((va >> 30) & 0x1FF) as usize)) };
            if is_table_loong(l2e) {
                let dir1e = unsafe { core::ptr::read_volatile((table_pa_loong(l2e) as *const u64).add(((va >> 21) & 0x1FF) as usize)) };
                if is_table_loong(dir1e) {
                    let leaf_pa = table_pa_loong(dir1e);
                    LEAF_WATCH_FRAME.store(leaf_pa, Ordering::Relaxed);
                    crate::hal::serial::write_string_always(" leaf_pa=");
                    crate::hal::serial::write_hex_u64_always(leaf_pa);
                }
            }
        }
    }
    crate::hal::serial::write_string_always("\r\n");
}

/// Pure-read walk of a page-table root for the leaf-table frame that
/// owns va. Returns None if any level is unmapped. Used to arm the
/// LEAFW watchpoint for roots other than the active one.
fn leaf_pa_in_root(root_pa: u64, va: u64) -> Option<u64> {
    let root = root_pa as *const u64;
    let l0e = unsafe { core::ptr::read_volatile(root.add(((va >> 48) & 0x1FF) as usize)) };
    if !is_table_loong(l0e) {
        return None;
    }
    let l1e = unsafe {
        core::ptr::read_volatile((table_pa_loong(l0e) as *const u64).add(((va >> 39) & 0x1FF) as usize))
    };
    if !is_table_loong(l1e) {
        return None;
    }
    let l2e = unsafe {
        core::ptr::read_volatile((table_pa_loong(l1e) as *const u64).add(((va >> 30) & 0x1FF) as usize))
    };
    if !is_table_loong(l2e) {
        return None;
    }
    let dir1e = unsafe {
        core::ptr::read_volatile((table_pa_loong(l2e) as *const u64).add(((va >> 21) & 0x1FF) as usize))
    };
    if !is_table_loong(dir1e) {
        return None;
    }
    Some(table_pa_loong(dir1e))
}

pub fn paging_enabled() -> bool {
    let crmd: u64;
    unsafe {
        asm!("csrrd {}, 0x0", out(reg) crmd, options(nostack));
    }
    (crmd & (1 << 4)) != 0
}

pub fn read_page_root_pfn() -> u64 {
    let pa: u64;
    unsafe {
        asm!("csrrd {}, 0x19", out(reg) pa, options(nostack));
    }
    pa >> 12
}

/// Invalidate a single TLB entry for the given virtual address.
pub fn invalidate_tlb(va: u64) {
    if paging_enabled() {
        crate::arch::loongarch64::tlb::flush_page(va & PAGE_MASK);
    }
}

/// Flush the entire TLB (all entries).
pub fn flush_tlb() {
    unsafe {
        crate::boot_debug_println!("[LA-FLUSH] enter");
        let enabled = paging_enabled();
        let crmd: u64;
        asm!("csrrd {}, 0x0", out(reg) crmd, options(nostack));
        crate::boot_debug_println!("[LA-FLUSH] crmd=0x{:x} pg={}", crmd, enabled);
        if enabled {
            asm!("invtlb 0, $r0, $r0", options(nostack));
            crate::boot_debug_println!("[LA-FLUSH] invtlb done");
        }
    }
}

/// Identity-map `[pa, pa + size)` into the kernel's translation
/// tables. Mirrors the aarch64 helper of the same name. Used by
/// the kernel heap init flow to make sure `global_alloc::alloc`
/// returns pointers that resolve under the kernel's `PGDH`.
///
/// `pa` must be page-aligned; `size` is rounded up to the next
/// page boundary. Returns `true` on success, `false` if any
/// `map_page` call in the range failed.
pub fn identity_map_region(pa: u64, size: u64) -> bool {
    const HEAP_FLAGS: u64 = 0x2;
    let pa_aligned = pa & !(PAGE_SIZE - 1);
    let end = pa.saturating_add(size);
    if !crate::mm::pfn::is_initialized() {
        let mut state = PAGING_STATE.lock();
        unsafe {
            let root_pa = if paging_enabled() {
                root_phys()
            } else {
                (&state.root as *const PageAlignedTable) as u64
            };
            let root_entries = root_pa as *mut u64;
            let tables = (&state.bootstrap as *const BootstrapPageTables) as u64;
            let l1_pa = tables;
            let l2_pa = tables + PAGE_SIZE;
            let dir1_pa = tables + 2 * PAGE_SIZE;
            let mut cur = pa_aligned;
            while cur < end {
                let l0_idx = ((cur >> 48) & 0x1FF) as usize;
                let l1_idx = ((cur >> 39) & 0x1FF) as usize;
                let l2_idx = ((cur >> 30) & 0x1FF) as usize;
                let l3_idx = ((cur >> 21) & 0x1FF) as usize;
                let page_index = ((cur >> 12) & 0x1FF) as usize;
                let Some(l3_table) = leaf_table_for(
                    &mut state,
                    LeafTableKey {
                        l2_index: l2_idx,
                        l3_index: l3_idx,
                    },
                ) else {
                    return false;
                };
                let root_entry = root_entries.add(l0_idx);
                let root_e = core::ptr::read_volatile(root_entry);
                let l1_pa_used = if is_table_loong(root_e) {
                    table_pa_loong(root_e)
                } else {
                    core::ptr::write_volatile(root_entry, make_table_desc_loong(l1_pa));
                    l1_pa
                };
                let l1 = l1_pa_used as *mut u64;
                let l1e = core::ptr::read_volatile(l1.add(l1_idx));
                let l2_pa_used = if is_table_loong(l1e) {
                    table_pa_loong(l1e)
                } else {
                    core::ptr::write_volatile(l1.add(l1_idx), make_table_desc_loong(l2_pa));
                    l2_pa
                };
                let l2 = l2_pa_used as *mut u64;
                let l2e = core::ptr::read_volatile(l2.add(l2_idx));
                if !is_table_loong(l2e) {
                    core::ptr::write_volatile(l2.add(l2_idx), make_table_desc_loong(dir1_pa));
                }

                let dir1 = dir1_pa as *mut u64;
                let dir1e = core::ptr::read_volatile(dir1.add(l3_idx));
                if !is_table_loong(dir1e) {
                    core::ptr::write_volatile(
                        dir1.add(l3_idx),
                        make_table_desc_loong(l3_table as u64),
                    );
                }
                core::ptr::write_volatile(
                    l3_table.add(page_index),
                    make_pte_loong(cur, HEAP_FLAGS),
                );
                cur = cur.saturating_add(PAGE_SIZE);
            }
            return true;
        }
    }

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
/// On LoongArch64 the page-table walker is configured by
/// `arch::init_page_walk` (PWCL/PWCH + STLBPS); here we just publish
/// the kernel root into PGDH (0x1a) and PGDL (0x19)
/// if not already done. Safe to call repeatedly.
pub fn init() {
    let mut state = PAGING_STATE.lock();
    let root_pa = core::ptr::addr_of!(state.root.0) as u64;
    debug_assert_eq!(root_pa & (PAGE_SIZE - 1), 0);
    unsafe {
        state.root.0 = [0u64; 512];
        asm!("csrwr {0}, 0x1a", inout(reg) root_pa => _, options(nostack));
        let root_pa2 = core::ptr::addr_of!(state.root.0) as u64;
        asm!("csrwr {0}, 0x19", inout(reg) root_pa2 => _, options(nostack));
    }
}
