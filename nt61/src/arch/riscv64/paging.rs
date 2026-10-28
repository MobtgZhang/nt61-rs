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
const PTE_U: u64 = 1 << 4;
const PTE_G: u64 = 1 << 5;
const PTE_A: u64 = 1 << 6;
const PTE_D: u64 = 1 << 7;

/// Sv39 stores the 44-bit PPN in PTE bits [53:10]. Recover the aligned
/// physical address by shifting the PPN back into bits [55:12].
const PTE_PPN_MASK: u64 = 0x000F_FFFF_FFFF_FC00;
fn pte_pa(entry: u64) -> u64 {
    ((entry & PTE_PPN_MASK) >> 10) << 12
}

/// Bootstrap page-table pages used only while building the Sv39
/// identity map. They live in the kernel image, so they are valid
/// before the PFN allocator is online and before any dynamic page
/// table page has been mapped.
///
/// Sv39 needs one L1 table per 1 GiB identity window and one L2
/// table per 2 MiB window. 256 pages therefore cover a 256 MiB
/// RAM window plus a small amount of MMIO without taking pages from
/// the PFN allocator.
const IDENTITY_PT_POOL_PAGES: usize = 4096;
static mut IDENTITY_PT_POOL: [[u64; 512]; IDENTITY_PT_POOL_PAGES] =
    [[0; 512]; IDENTITY_PT_POOL_PAGES];
static mut IDENTITY_PT_USED: usize = 0;
static mut IDENTITY_PT_ALLOCATED: usize = 0;

const MAX_IDENTITY_RANGES: usize = 128;
static IDENTITY_MAPPED_RANGES: crate::ke::sync::Spinlock<(
    usize,
    [(u64, u64); MAX_IDENTITY_RANGES],
)> = crate::ke::sync::Spinlock::new((
    0,
    [(0, 0); MAX_IDENTITY_RANGES],
));

/// Reset the bootstrap identity-map pool.
///
/// The kernel PE loader does not currently guarantee a zeroed BSS for
/// every target. These counters and the 1 MiB pool therefore must be
/// initialized explicitly before the first kernel-side identity map.
pub fn reset_bootstrap_identity_pool() {
    unsafe {
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!(IDENTITY_PT_POOL) as *mut u8,
            0,
            core::mem::size_of::<[[u64; 512]; IDENTITY_PT_POOL_PAGES]>(),
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!(IDENTITY_PT_USED), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(IDENTITY_PT_ALLOCATED), 0);
    }
}

fn alloc_identity_pt() -> Option<u64> {
    let used = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IDENTITY_PT_USED)) };
    if used >= IDENTITY_PT_POOL_PAGES {
        crate::hal::serial::write_string_always("[RVIPT] pool exhausted used=");
        crate::hal::serial::write_hex_u64_always(used as u64);
        crate::hal::serial::write_string_always("\r\n");
        // Once the PFN database is online, the full RAM identity
        // window has already been installed. Dynamic page-table pages
        // are therefore safely writable while their own descriptor is
        // being created.
        let pfn = pfn::allocate_pfn()?;
        let pa = pfn_to_phys(pfn);
        unsafe {
            core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE as usize);
        }
        return Some(pa);
    }
    let pool_base = core::ptr::addr_of!(IDENTITY_PT_POOL) as u64;
    let pa = pool_base + (used as u64) * PAGE_SIZE;
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(IDENTITY_PT_USED), used + 1);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(IDENTITY_PT_ALLOCATED), used + 1);
        core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE as usize);
    }
    Some(pa)
}

fn record_identity_range(start: u64, end: u64) {
    let mut ranges = IDENTITY_MAPPED_RANGES.lock();
    let (count, entries) = &mut *ranges;
    if entries[..*count].iter().any(|&(base, range_end)| {
        base <= start && end <= range_end
    }) {
        return;
    }
    if *count < entries.len() {
        entries[*count] = (start, end);
        *count += 1;
    }
}

fn identity_ranges_mapped_in_root(root_pfn: u64) -> bool {
    let ranges = IDENTITY_MAPPED_RANGES.lock();
    let (count, entries) = &*ranges;
    entries[..*count].iter().all(|&(start, end)| {
        let aligned = start & PAGE_MASK;
        let mut page = aligned;
        while page < end {
            if !page_is_mapped_in_root(root_pfn, page) {
                return false;
            }
            page += PAGE_SIZE;
        }
        true
    })
}

/// Sv39 walk used exclusively by `identity_map_region`.
///
/// New intermediate pages are allocated from the bootstrap pool. This
/// is required because a dynamic page-table page is not necessarily
/// identity mapped at the exact moment its own parent table is being
/// created.
unsafe fn identity_l1_pte_for_at(root_phys: u64, va: u64) -> *mut u64 {
    let l0_idx = ((va >> 30) & 0x1FF) as usize;
    let l1_idx = ((va >> 21) & 0x1FF) as usize;

    let root = root_phys as *mut u64;
    let l0e = core::ptr::read_volatile(root.add(l0_idx));
    let l1_phys = if (l0e & PTE_V) != 0 {
        pte_pa(l0e)
    } else {
        let new_phys = match alloc_identity_pt() {
            Some(pa) => pa,
            None => return core::ptr::null_mut(),
        };
        let descriptor = make_nonleaf_pte(new_phys);
        core::ptr::write_volatile(root.add(l0_idx), descriptor);
        new_phys
    };

    (l1_phys as *mut u64).add(l1_idx)
}

/// Sv39 walk used exclusively by `identity_map_region`.
///
/// New intermediate pages are allocated from the bootstrap pool. This
/// is required because a dynamic page-table page is not necessarily
/// identity mapped at the exact moment its own parent table is being
/// created.
unsafe fn identity_leaf_pte_for_at(root_phys: u64, va: u64) -> *mut u64 {
    let l1_idx = ((va >> 21) & 0x1FF) as usize;
    let l2_idx = ((va >> 12) & 0x1FF) as usize;
    let l1 = identity_l1_pte_for_at(root_phys, va);
    if l1.is_null() {
        return core::ptr::null_mut();
    }
    let l1e = core::ptr::read_volatile(l1);
    // A superpage L1 entry is a leaf, not a pointer to an L2 table.
    // When the region is not 2 MiB aligned we must split the superpage
    // into 4 KiB entries in a fresh L2 table, so treat a leaf L1
    // descriptor the same as an empty slot (replace it with a new L2
    // table pointer).
    let l2_phys = if (l1e & PTE_V) != 0 && !is_leaf(l1e) {
        pte_pa(l1e)
    } else {
        let new_phys = match alloc_identity_pt() {
            Some(pa) => pa,
            None => return core::ptr::null_mut(),
        };
        let descriptor = make_nonleaf_pte(new_phys);
        core::ptr::write_volatile(l1.add(l1_idx), descriptor);
        new_phys
    };

    let l2 = l2_phys as *mut u64;
    l2.add(l2_idx)
}

/// Bootstrap root page table. It lives in the kernel image so it is
/// valid before the PFN database is online; `paging::init()` installs
/// it as the current root and later mappings build on it.
///
/// Sv39 requires the root table itself to be aligned to a 4-KiB
/// physical page. An ordinary `[u64; 512]` only guarantees 8-byte
/// alignment, so `satp` would silently drop the low address bits and
/// point at the wrong page.
#[repr(C, align(4096))]
#[derive(Clone, Copy)]
struct PageAlignedTable([u64; 512]);

static mut ROOT_TABLE: PageAlignedTable = PageAlignedTable([0; 512]);
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

/// Publish the hardware root PA to the fast software mirror.
///
/// The noreturn Ring-3 entry path bypasses `load_page_root`, so it must
/// update this cache explicitly before the SATP write. Otherwise trap
/// diagnostics report the stale system root.
pub fn publish_root_phys(pa: u64) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ROOT_PHYS), pa);
    }
}

pub fn read_page_root_phys() -> u64 {
    root_phys()
}

/// Allocate a page-table page. The PFN database is not available while
/// the bootstrap heap is being mapped, so fall back to the frame
/// allocator until it comes online.
fn alloc_page_table() -> Option<u64> {
    // Bootstrap page-table pages are part of the kernel image and are
    // deliberately excluded from the PFN allocator. Use them first so
    // early mappings cannot collide with a page that `allocate_pfn()`
    // later hands out again. The pool falls back to PFN pages only after
    // the PFN database has been initialized.
    alloc_identity_pt()
}
fn make_pte(pa: u64, flags: u64) -> u64 {
    // Callers use x86-style PTE flags (and a few portable PageFlags
    // bits). Translate them to the disjoint Sv39 permission bits. On
    // x86, an NX-cleared page is readable and executable, so preserve
    // those permissions here. A/D are always installed eagerly because
    // the bootstrap mapper has no page-fault update path.
    let x86_rw = crate::mm::pte::PTE_RW;
    let x86_user = crate::mm::pte::PTE_US | crate::arch::common::paging::PageFlags::USER.bits();
    let x86_nx = crate::mm::pte::PTE_NX | crate::arch::common::paging::PageFlags::NO_EXECUTE.bits();
    let writable = (flags & x86_rw) != 0;
    let readable = true;
    let executable = (flags & x86_nx) == 0;
    let dirty = if writable { PTE_D } else { 0 };
    let mut pte_flags = PTE_V | PTE_A | dirty;
    if readable {
        pte_flags |= PTE_R;
    }
    if writable {
        pte_flags |= PTE_W;
    }
    if executable {
        pte_flags |= PTE_X;
    }
    if (flags & x86_user) != 0 {
        pte_flags |= PTE_U;
    }
    ((pa >> 12) << 10) | pte_flags
}

fn make_nonleaf_pte(pa: u64) -> u64 {
    ((pa >> 12) << 10) | PTE_V
}

/// Map a 1-GiB identity superpage into a non-current root table.
///
/// Used during bare-mode → Sv39 root switches to guarantee that every
/// physical address the kernel already touched remains reachable.  A
/// 1-GiB superpage needs no intermediate tables: the root entry itself
/// is a leaf, which keeps the switch guard to at most eight writes for
/// the full 8 GiB QEMU virt RAM window.
fn map_gib_superpage_in_root(root_pfn: u64, gpa: u64) -> bool {
    let root_phys = pfn_to_phys(root_pfn);
    let root = root_phys as *mut u64;
    let idx = ((gpa >> 30) & 0x1FF) as usize;
    // Sv39 1-GiB leaf: PPN[2] = gpa[55:30], PPN[1:0] = 0 (guaranteed by
    // 1-GiB alignment).  R|W|X makes it a leaf; A|D avoid first-touch
    // traps in supervisor mode; U is clear so user code cannot read
    // kernel RAM through this window.
    let flags = PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D;
    // Sv39 stores PPN at bits 53:10; PPN = gpa >> 12.  For a 1-GiB
    // aligned address this is exactly (gpa >> 30) << 28.
    let entry = ((gpa >> 12) << 10) | flags;
    unsafe {
        let existing = core::ptr::read_volatile(root.add(idx));
        if !is_valid(existing) {
            core::ptr::write_volatile(root.add(idx), entry);
            asm!("sfence.vma", options(nostack));
        }
    }
    true
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
    let l1_phys = if (l0e & PTE_V) != 0 && is_leaf(l0e) {
        // A 1-GiB superpage is a leaf at level 0.  Split only the requested
        // 1-GiB window into 2-MiB leaves so a process root can still mix
        // firmware superpages with normal 4-KiB mappings.
        let new_phys = match alloc_page_table() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let base = pte_pa(l0e);
        let flags = l0e & 0xFFF;
        let table = new_phys as *mut u64;
        for index in 0..512usize {
            let pa = base + (index as u64) * (2 * 1024 * 1024);
            core::ptr::write_volatile(table.add(index), pa | flags);
        }
        let descriptor = make_nonleaf_pte(new_phys);
        core::ptr::write_volatile(l0.add(l0_idx), descriptor);
        new_phys
    } else if (l0e & PTE_V) != 0 {
        pte_pa(l0e)
    } else {
        let new_phys = match alloc_page_table() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_nonleaf_pte(new_phys);
        core::ptr::write_volatile(l0.add(l0_idx), new_desc);
        new_phys
    };

    let l1 = l1_phys as *mut u64;
    let l1e = core::ptr::read_volatile(l1.add(l1_idx));
    let l2_phys = if (l1e & PTE_V) != 0 && is_leaf(l1e) {
        // A 2-MiB superpage is a leaf at level 1.  Split it into 4-KiB
        // entries before writing the requested leaf PTE.
        let new_phys = match alloc_page_table() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let base = pte_pa(l1e);
        let flags = l1e & 0xFFF;
        let table = new_phys as *mut u64;
        for index in 0..512usize {
            let pa = base + (index as u64) * PAGE_SIZE;
            core::ptr::write_volatile(table.add(index), pa | flags);
        }
        let descriptor = make_nonleaf_pte(new_phys);
        core::ptr::write_volatile(l1.add(l1_idx), descriptor);
        new_phys
    } else if (l1e & PTE_V) != 0 {
        pte_pa(l1e)
    } else {
        let new_phys = match alloc_page_table() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = make_nonleaf_pte(new_phys);
        core::ptr::write_volatile(l1.add(l1_idx), new_desc);
        new_phys
    };

    let l2 = l2_phys as *mut u64;
    let l2_pte = l2.add(l2_idx);
    l2_pte
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
    map_page_in_root_impl(root_pfn, va, pa, flags, true)
}

/// Same mapping without the per-page serial trace.  Used by the
/// switch-time guard loops, which may map hundreds of pages and would
/// otherwise flood the serial log.
fn map_page_in_root_quiet(root_pfn: u64, va: u64, pa: u64, flags: u64) -> bool {
    map_page_in_root_impl(root_pfn, va, pa, flags, false)
}

fn map_page_in_root_impl(root_pfn: u64, va: u64, pa: u64, flags: u64, verbose: bool) -> bool {
    let root_phys = pfn_to_phys(root_pfn);
    let _ = verbose;
    let l2_pte = unsafe { leaf_pte_for_at(root_phys, va) };
    if va == 0x0000_003F_C000_0000 && !l2_pte.is_null() {
        unsafe {
            core::ptr::write_volatile(l2_pte, make_pte(pa, flags));
            asm!("sfence.vma {}, zero", in(reg) va, options(nostack));
        }
        return true;
    }
    if l2_pte.is_null() {
        crate::hal::serial::write_string_always("[RVPGROOT] fail root_pfn=");
        crate::hal::serial::write_hex_u64_always(root_pfn);
        crate::hal::serial::write_string_always(" root=");
        crate::hal::serial::write_hex_u64_always(root_phys);
        crate::hal::serial::write_string_always(" va=");
        crate::hal::serial::write_hex_u64_always(va);
        crate::hal::serial::write_string_always(" pa=");
        crate::hal::serial::write_hex_u64_always(pa);
        crate::hal::serial::write_string_always("\r\n");
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
        if is_leaf(l0e) {
            return Some(pte_pa(l0e) | (va & ((1 << 30) - 1)));
        }
        let l1_phys = pte_pa(l0e);
        let l1 = l1_phys as *const u64;
        let l1e = core::ptr::read_volatile(l1.add(l1_idx));
        if !is_valid(l1e) {
            return None;
        }
        if is_leaf(l1e) {
            return Some(pte_pa(l1e) | (va & ((1 << 21) - 1)));
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

/// Return the Sv39 leaf PTE covering `va`.
pub fn leaf_entry(va: u64) -> Option<u64> {
    unsafe {
        let root = root_phys() as *const u64;
        let l0e = core::ptr::read_volatile(root.add(((va >> 30) & 0x1FF) as usize));
        if !is_valid(l0e) {
            return None;
        }
        if is_leaf(l0e) {
            return Some(l0e);
        }
        let l1 = pte_pa(l0e) as *const u64;
        let l1e = core::ptr::read_volatile(l1.add(((va >> 21) & 0x1FF) as usize));
        if !is_valid(l1e) {
            return None;
        }
        if is_leaf(l1e) {
            return Some(l1e);
        }
        let l2 = pte_pa(l1e) as *const u64;
        let l2e = core::ptr::read_volatile(l2.add(((va >> 12) & 0x1FF) as usize));
        if is_valid(l2e) && is_leaf(l2e) {
            return Some(l2e);
        }
        None
    }
}

/// Walk a non-current Sv39 root without switching `satp`.
pub fn page_is_mapped_in_root(root_pfn: u64, va: u64) -> bool {
    let root_pa = pfn_to_phys(root_pfn);
    let root = root_pa as *const u64;
    let l0_idx = ((va >> 30) & 0x1FF) as usize;
    let l1_idx = ((va >> 21) & 0x1FF) as usize;
    let l2_idx = ((va >> 12) & 0x1FF) as usize;
    unsafe {
        let l0e = core::ptr::read_volatile(root.add(l0_idx));
        if !is_valid(l0e) || is_leaf(l0e) {
            return is_valid(l0e) && is_leaf(l0e);
        }
        let l1 = pte_pa(l0e) as *const u64;
        let l1e = core::ptr::read_volatile(l1.add(l1_idx));
        if !is_valid(l1e) || is_leaf(l1e) {
            return is_valid(l1e) && is_leaf(l1e);
        }
        let l2 = pte_pa(l1e) as *const u64;
        let l2e = core::ptr::read_volatile(l2.add(l2_idx));
        is_valid(l2e) && is_leaf(l2e)
    }
}

/// Walk a non-current Sv39 root and return the raw leaf PTE covering
/// `va`, or `None` when no valid leaf exists. Diagnostic counterpart
/// to page_is_mapped_in_root: the boolean variant cannot report
/// whether an existing leaf carries execute permission or points at
/// the correct PA, both of which matter when a root switch faults on
/// fetch at an address whose mapped-check had passed.
pub fn leaf_entry_in_root(root_pfn: u64, va: u64) -> Option<u64> {
    let root_pa = pfn_to_phys(root_pfn);
    let root = root_pa as *const u64;
    let l0_idx = ((va >> 30) & 0x1FF) as usize;
    let l1_idx = ((va >> 21) & 0x1FF) as usize;
    let l2_idx = ((va >> 12) & 0x1FF) as usize;
    unsafe {
        let l0e = core::ptr::read_volatile(root.add(l0_idx));
        if !is_valid(l0e) {
            return None;
        }
        if is_leaf(l0e) {
            return Some(l0e);
        }
        let l1 = pte_pa(l0e) as *const u64;
        let l1e = core::ptr::read_volatile(l1.add(l1_idx));
        if !is_valid(l1e) {
            return None;
        }
        if is_leaf(l1e) {
            return Some(l1e);
        }
        let l2 = pte_pa(l1e) as *const u64;
        let l2e = core::ptr::read_volatile(l2.add(l2_idx));
        if is_valid(l2e) && is_leaf(l2e) {
            return Some(l2e);
        }
        None
    }
}

/// Walk an already-valid leaf entry in a non-current root and clear
/// privilege flags that would make S-mode instruction fetch fault.
///
/// Firmware-derived superpages can carry U|G into a copied system
/// root.  `page_is_mapped_in_root` correctly treats such an entry as
/// mapped, so the switch guard must still remove U (and G) before the
/// `satp` write; otherwise S-mode immediately takes an instruction
/// page fault on fetch from the new root.
fn sanitize_leaf_flags_in_root(root_pfn: u64, va: u64) -> bool {
    let root_pa = pfn_to_phys(root_pfn);
    let root = root_pa as *mut u64;
    let l0_idx = ((va >> 30) & 0x1FF) as usize;
    let l1_idx = ((va >> 21) & 0x1FF) as usize;
    let l2_idx = ((va >> 12) & 0x1FF) as usize;
    unsafe {
        let l0e = core::ptr::read_volatile(root.add(l0_idx));
        let pte = if !is_valid(l0e) {
            core::ptr::null_mut()
        } else if is_leaf(l0e) {
            root.add(l0_idx)
        } else {
            let l1 = pte_pa(l0e) as *mut u64;
            let l1e = core::ptr::read_volatile(l1.add(l1_idx));
            if !is_valid(l1e) {
                core::ptr::null_mut()
            } else if is_leaf(l1e) {
                l1.add(l1_idx)
            } else {
                let l2 = pte_pa(l1e) as *mut u64;
                let l2e = core::ptr::read_volatile(l2.add(l2_idx));
                if is_valid(l2e) && is_leaf(l2e) {
                    l2.add(l2_idx)
                } else {
                    core::ptr::null_mut()
                }
            }
        };
        if pte.is_null() {
            return false;
        }
        let old = core::ptr::read_volatile(pte);
        let cleaned = old & !(PTE_U | PTE_G);
        if cleaned == old {
            return false;
        }
        core::ptr::write_volatile(pte, cleaned);
        crate::hal::serial::write_string_always("[SATP] sanitize va=");
        crate::hal::serial::write_hex_u64_always(va);
        crate::hal::serial::write_string_always(" old=");
        crate::hal::serial::write_hex_u64_always(old);
        crate::hal::serial::write_string_always(" new=");
        crate::hal::serial::write_hex_u64_always(cleaned);
        crate::hal::serial::write_string_always("\r\n");
        true
    }
}

/// Map every page-table page of `dst_pfn`'s tree into the *current*
/// root (identity), so that destination-root walks never fault while
/// the current root is active.  All table walkers in this module use
/// identity pointers, so once paging is enabled every table page they
/// touch must be reachable through the running root.  Bare mode needs
/// nothing: identity accesses bypass the MMU entirely.
fn map_root_tables_into_current(dst_pfn: u64) {
    let host_phys = current_satp_root_phys();
    if host_phys == 0 {
        return;
    }
    let host_pfn = host_phys >> 12;
    if host_pfn == dst_pfn {
        return;
    }
    let flags = crate::mm::pte::PTE_P | crate::mm::pte::PTE_RW;
    let dst_pa = pfn_to_phys(dst_pfn);
    // The mappings below walk the host root itself; if the host
    // cannot reach its own tables this fault surfaces here with the
    // caller's diagnostics rather than deep inside the walk.
    if !page_is_mapped_in_root(host_pfn, dst_pa) {
        map_page_in_root_quiet(host_pfn, dst_pa, dst_pa, flags);
    }
    let dst = dst_pa as *const u64;
    unsafe {
        for i in 0..512usize {
            let e0 = core::ptr::read_volatile(dst.add(i));
            if !is_valid(e0) || is_leaf(e0) {
                continue;
            }
            let l1_pa = pte_pa(e0);
            if !page_is_mapped_in_root(host_pfn, l1_pa) {
                map_page_in_root_quiet(host_pfn, l1_pa, l1_pa, flags);
            }
            let l1 = l1_pa as *const u64;
            for j in 0..512usize {
                let e1 = core::ptr::read_volatile(l1.add(j));
                if !is_valid(e1) || is_leaf(e1) {
                    continue;
                }
                let l2_pa = pte_pa(e1);
                if !page_is_mapped_in_root(host_pfn, l2_pa) {
                    map_page_in_root_quiet(host_pfn, l2_pa, l2_pa, flags);
                }
            }
        }
    }
}

/// Map every page-table page of `dst_pfn`'s tree into the
/// destination root *itself* (identity), in addition to the current
/// root.  After the switch the kernel walks the active root through
/// identity pointers (`translate_virt`, `identity_map_region`,
/// `page_is_mapped_in_root`, smss's pml4 reads), so the root page
/// and every table page below it must resolve through the root they
/// describe.  The leaf writes are unconditional: a stale leaf whose
/// PA is wrong (or absent) at one of these positions is exactly the
/// observed post-switch LoadAccessFault on the root table's own
/// address, so an existing entry cannot be trusted here.  This
/// mirrors the aarch64 fix that identity-maps freshly allocated
/// table pages into the running root.
fn map_root_tables_into_self(dst_pfn: u64) {
    let dst_pa = pfn_to_phys(dst_pfn);
    let flags = crate::mm::pte::PTE_P | crate::mm::pte::PTE_RW;
    let mut mapped = 0u64;
    if map_page_in_root_quiet(dst_pfn, dst_pa, dst_pa, flags) {
        mapped += 1;
    }
    let dst = dst_pa as *const u64;
    unsafe {
        for i in 0..512usize {
            let e0 = core::ptr::read_volatile(dst.add(i));
            if !is_valid(e0) || is_leaf(e0) {
                continue;
            }
            let l1_pa = pte_pa(e0);
            if map_page_in_root_quiet(dst_pfn, l1_pa, l1_pa, flags) {
                mapped += 1;
            }
            let l1 = l1_pa as *const u64;
            for j in 0..512usize {
                let e1 = core::ptr::read_volatile(l1.add(j));
                if !is_valid(e1) || is_leaf(e1) {
                    continue;
                }
                let l2_pa = pte_pa(e1);
                if map_page_in_root_quiet(dst_pfn, l2_pa, l2_pa, flags) {
                    mapped += 1;
                }
            }
        }
    }
    let _ = mapped;
}

pub unsafe fn load_page_root(pml4_pfn: u64) {
    let pa = pfn_to_phys(pml4_pfn);
    crate::arch::riscv64::csr::sstatus::set(
        crate::arch::riscv64::csr::sstatus::SUM,
    );
    let is_system_root = {
        let system = crate::mm::vas::MM_SYSTEM_VAS.lock();
        system.pml4_phys == pa
    };
    let _ = is_system_root;
    // A non-x86 root copied from the system root often already contains
    // native superpages or lower-level descriptors for every switch-time
    // page.  Rebuilding those mappings would split a valid 1-GiB leaf and
    // can corrupt the destination root, so only run the explicit guard when
    // a critical page is actually missing.
    let code_page = (load_page_root as *const () as u64) & PAGE_MASK;
    let mut stack_pointer = 0u64;
    unsafe {
        asm!("mv {}, sp", out(reg) stack_pointer, options(nostack));
    }
    let stack_page = stack_pointer & PAGE_MASK;
    const UART_PAGE: u64 = 0x1000_0000;
    // Destination-root walks below read the destination table pages
    // through identity addresses, which under an active root
    // translate through the *current* root.  Make those pages
    // reachable before walking anything.
    map_root_tables_into_current(pml4_pfn);
    // The active root must also reach its own table tree once it
    // starts translating, or the first post-switch root walk faults
    // on the root table's own identity address.
    map_root_tables_into_self(pml4_pfn);
    for page in [code_page, stack_page, UART_PAGE] {
        sanitize_leaf_flags_in_root(pml4_pfn, page);
    }
    // Even when the three bootstrap pages are already present, other
    // kernel data reachable immediately after the switch (notably the
    // heap) can live behind a finer-grained root descriptor. The
    // existing guard only fills invalid windows, so run it on every
    // switch to fill those missing pages without replacing valid ones.
    prepare_switch_mappings(pml4_pfn);
    let switch_pa = pa;
    // satp = MODE (from sv48::choose_mode) << 60 | ASID (0) << 44 | PPN
    let mode = crate::arch::riscv64::sv48::choose_mode();
    let satp: u64 = mode | (switch_pa >> 12);
    let saved_sstatus: u64;
    asm!(
        "csrr {}, sstatus",
        "csrci sstatus, 2",
        out(reg) saved_sstatus,
        options(nostack)
    );
    asm!("csrw satp, {}", in(reg) satp, options(nostack));
    asm!("sfence.vma", options(nostack));
    core::ptr::write_volatile(core::ptr::addr_of_mut!(ROOT_PHYS), pa);
    if (saved_sstatus & 2) != 0 {
        asm!("csrsi sstatus, 2", options(nostack));
    }
}

/// Map the few pages required to survive a root-table switch.
///
/// Sv39 changes translation *immediately* when `satp` is written.  The
/// kernel must therefore guarantee that its own current code page,
/// current stack pages, and the diagnostic UART are reachable through the
/// destination root.  The generic VAS layer copies root descriptors, but
/// this explicit switch guard keeps the critical path working even when a
/// process root was built before every kernel mapping was refreshed.
pub fn prepare_switch_mappings_if_needed(root_pfn: u64) {
    let root_phys = pfn_to_phys(root_pfn);
    let code_page = (load_page_root as *const () as u64) & PAGE_MASK;
    let mut stack_pointer = 0u64;
    unsafe {
        asm!("mv {}, sp", out(reg) stack_pointer, options(nostack));
    }
    let stack_page = stack_pointer & PAGE_MASK;
    const UART_PAGE: u64 = 0x1000_0000;
    map_root_tables_into_current(root_pfn);
    let capture_ranges_mapped = [crate::fs::esp_capture_range(), crate::fs::sys_capture_range()]
        .into_iter()
        .all(|range| match range {
            None => true,
            Some((base, size)) => {
                let start = base as u64 & PAGE_MASK;
                let end = start
                    .checked_add(size as u64)
                    .unwrap_or(start);
                let mut page = start;
                while page < end {
                    if !page_is_mapped_in_root(root_pfn, page) {
                        return false;
                    }
                    page += PAGE_SIZE;
                }
                true
            }
        });
    if capture_ranges_mapped
        && identity_ranges_mapped_in_root(root_pfn)
        && page_is_mapped_in_root(root_pfn, code_page)
        && page_is_mapped_in_root(root_pfn, stack_page)
        && page_is_mapped_in_root(root_pfn, UART_PAGE)
    {
        return;
    }
    let _ = root_phys;
    prepare_switch_mappings(root_pfn);
}

fn prepare_switch_mappings(root_pfn: u64) {
    let map_switch_page = |va: u64, flags: u64| -> bool {
        if va == 0 || va & 0xfff != 0 {
            return false;
        }
        if current_satp_root_phys() == 0 {
            map_page_in_root(root_pfn, va, va, flags)
        } else {
            let Some(pa) = translate_virt(va) else {
                crate::hal::serial::write_string_always("[SATP] translate fail va=");
                crate::hal::serial::write_hex_u64_always(va);
                crate::hal::serial::write_string_always("\r\n");
                return false;
            };
            map_page_in_root(root_pfn, va, pa, flags)
        }
    };

    const KERNEL_DATA: u64 = crate::mm::pte::PTE_P | crate::mm::pte::PTE_RW;

    // Map 1-GiB identity superpages FIRST so that all kernel code,
    // stack, and heap addresses are already reachable through the
    // new root. This eliminates the need for page-by-page loops that
    // would emit tens of thousands of serial writes.
    map_gib_superpage_in_root(root_pfn, 0x8000_0000);
    map_gib_superpage_in_root(root_pfn, 0x1_0000_0000);
    map_gib_superpage_in_root(root_pfn, 0x2_0000_0000);
    map_gib_superpage_in_root(root_pfn, 0x2_4000_0000);

    // The 1-GiB superpages above only fill *invalid* root entries.
    // When a window's root entry already holds a non-leaf descriptor
    // the superpage is skipped (overwriting it would destroy the
    // finer-grained mappings it points to), so every page the
    // post-switch path depends on must be added page by page into the
    // existing sub-tables.  The page must be mapped unconditionally:
    // merely testing presence would trust an inherited leaf with the
    // wrong physical page or permissions and leave the kernel
    // unmapped immediately after the address-space switch.
    let map_guard_page = |page: u64, flags: u64| -> bool {
        if current_satp_root_phys() == 0 {
            map_page_in_root_quiet(root_pfn, page, page, flags)
        } else {
            match translate_virt(page) {
                Some(pa) => map_page_in_root_quiet(root_pfn, page, pa, flags),
                None => map_page_in_root_quiet(root_pfn, page, page, flags),
            }
        }
    };

    // Whole loaded image (winload + linked kernel lib): the trap
    // handler, the serial helpers, and every other function reached
    // right after `csrw satp` live here.  A single unmapped page turns
    // any post-switch fault into a recursive fault on the unmapped
    // `stvec` target, which is silent and unrecoverable.
    extern "C" {
        static __image_start: u8;
        static __image_end: u8;
    }
    let image_start = core::ptr::addr_of!(__image_start) as u64 & PAGE_MASK;
    let image_end = core::ptr::addr_of!(__image_end) as u64;
    let mut image_page = image_start;
    let mut image_map_failures = 0u64;
    while image_page < image_end {
        if !map_page_in_root_quiet(root_pfn, image_page, image_page, KERNEL_DATA) {
            image_map_failures += 1;
        }
        image_page += PAGE_SIZE;
    }
    if image_map_failures != 0 {
        crate::hal::serial::write_string_always("[SATP] image map failures=");
        crate::hal::serial::write_hex_u64_always(image_map_failures);
        crate::hal::serial::write_string_always("\r\n");
    }

    // Trap handler entry and the pages behind it.
    let trap_pc = crate::arch::riscv64::idt::trap_entry_addr();
    let trap_page = trap_pc & PAGE_MASK;
    for index in 0..4u64 {
        map_guard_page(trap_page + index * PAGE_SIZE, KERNEL_DATA);
    }

    // Current stack window: keep a generous guard around `sp` so that
    // trap frames and deep panic paths stay reachable.
    let mut stack_pointer = 0u64;
    unsafe {
        asm!("mv {}, sp", out(reg) stack_pointer, options(nostack));
    }
    for delta in 0..128u64 {
        map_guard_page(
            (stack_pointer.wrapping_sub(delta * PAGE_SIZE)) & PAGE_MASK,
            KERNEL_DATA,
        );
    }
    for delta in 1..128u64 {
        map_guard_page(
            (stack_pointer + delta * PAGE_SIZE) & PAGE_MASK,
            KERNEL_DATA,
        );
    }

    // Kernel heap: identity-mapped frames outside the superpage
    // windows are not covered by any leaf and must be mapped page by
    // page.
    if let Some((heap_base, heap_size)) = crate::mm::heap::KERNEL_HEAP.configured_region() {
        let heap_start = heap_base as u64 & PAGE_MASK;
        let heap_end = heap_start
            .checked_add(heap_size as u64)
            .unwrap_or(heap_start)
            .min(0x0000_FFFF_FFFF_FFFF);
        let mut heap_page = heap_start;
        while heap_page < heap_end {
            map_guard_page(heap_page, KERNEL_DATA);
            heap_page += PAGE_SIZE;
        }
    }

    for capture_range in [crate::fs::esp_capture_range(), crate::fs::sys_capture_range()] {
        let Some((base, size)) = capture_range else {
            continue;
        };
        let start = base as u64 & PAGE_MASK;
        let end = start
            .checked_add(size as u64)
            .unwrap_or(start);
        let mut page = start;
        while page < end {
            map_guard_page(page, KERNEL_DATA);
            page += PAGE_SIZE;
        }
    }

    let mapped_ranges = IDENTITY_MAPPED_RANGES.lock();
    let (range_count, mapped_regions) = &*mapped_ranges;
    for &(start, end) in mapped_regions[..*range_count].iter() {
        let aligned = start & PAGE_MASK;
        let mut page = aligned;
        while page < end {
            map_guard_page(page, KERNEL_DATA);
            page += PAGE_SIZE;
        }
    }
    drop(mapped_ranges);

    // Critical single pages, in case the image bounds above do not
    // cover them (e.g. a separately linked stage).
    let code_page = (load_page_root as *const () as u64) & PAGE_MASK;
    let stack_page = stack_pointer & PAGE_MASK;
    const UART_PAGE_FALLBACK: u64 = 0x1000_0000;
    for page in [code_page, stack_page, UART_PAGE_FALLBACK] {
        map_guard_page(page, KERNEL_DATA);
    }

    let fb = crate::hal::common::framebuffer::info();
    if fb.address != 0 && fb.pitch != 0 {
        let fb_size = (fb.pitch as u64) * (fb.height as u64);
        let fb_start = fb.address & PAGE_MASK;
        let fb_end = fb.address + fb_size;
        let mut page = fb_start;
        while page < fb_end {
            map_switch_page(page, KERNEL_DATA);
            page += PAGE_SIZE;
        }
    }

    const SYSTEM_TABLE_PHYS: u64 = 0x27FFF_E000;
    map_switch_page(SYSTEM_TABLE_PHYS & PAGE_MASK, KERNEL_DATA);

    const LOAD_PAGE_PHYS: u64 = 0x8350_7000;
    map_switch_page(LOAD_PAGE_PHYS, KERNEL_DATA);

    const UART_PHYS: u64 = 0x1000_0000;
    const UART_FLAGS: u64 = crate::mm::pte::PTE_P | crate::mm::pte::PTE_RW;
    map_page_in_root(
            root_pfn,
            UART_PHYS & PAGE_MASK,
            UART_PHYS & PAGE_MASK,
            UART_FLAGS,
        );
    map_page_in_root(
            root_pfn,
            (UART_PHYS + PAGE_SIZE) & PAGE_MASK,
            (UART_PHYS + PAGE_SIZE) & PAGE_MASK,
            UART_FLAGS,
        );

    const VIRTIO_MMIO_BASE: u64 = 0x1000_1000;
    const VIRTIO_MMIO_SLOTS: u64 = 8;
    for slot in 0..VIRTIO_MMIO_SLOTS {
        let pa = VIRTIO_MMIO_BASE + slot * PAGE_SIZE;
        map_page_in_root(root_pfn, pa, pa, UART_FLAGS);
    }

}

/// Convert an x86-format root entry into an Sv39 non-leaf descriptor.
///
/// The portable VAS layer stores x86-format PTEs, but Sv39 treats the
/// same bit layout as a completely different page-table format. Root
/// entries must therefore be re-encoded before switching to a copied
/// root.
pub fn translate_x86_root_entry(entry: u64) -> u64 {
    if entry & PTE_V == 0 {
        return 0;
    }

    // The portable VAS layer snapshots the system PML4 in x86 format.
    // Hardware requires Sv39 here, so preserve only the frame address
    // and the valid bit. Sv39 non-leaf entries carry no permission
    // bits; permissions are resolved by the child levels.
    let pa = entry & 0x000F_FFFF_FFFF_F000;
    let translated = ((pa >> 12) << 10) | PTE_V;
    translated
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
    const SUPERPAGE_SIZE: u64 = 2 * 1024 * 1024;
    const HEAP_FLAGS: u64 = PTE_R | PTE_W; // read-write, no execute (NX)
    let pa_aligned = pa & !(PAGE_SIZE - 1);
    let end = pa.saturating_add(size);
    if root_phys() == 0 {
        init();
    }
    let root = root_phys();
    let mut cur = pa_aligned;
    while cur < end {
        let aligned_2m = cur & !(SUPERPAGE_SIZE - 1);
        let can_use_superpage = cur == aligned_2m && end.saturating_sub(cur) >= SUPERPAGE_SIZE;
        let l1_pte = unsafe { identity_l1_pte_for_at(root, cur) };
        if l1_pte.is_null() {
            let used =
                unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IDENTITY_PT_ALLOCATED)) };
            crate::hal::serial::write_string_always("[RVPGT] identity l1 fail cur=");
            crate::hal::serial::write_hex_u64_always(cur);
            crate::hal::serial::write_string_always(" root=");
            crate::hal::serial::write_hex_u64_always(root);
            crate::hal::serial::write_string_always(" pool=");
            crate::hal::serial::write_hex_u64_always(used as u64);
            crate::hal::serial::write_string_always("\r\n");
            return false;
        }
        let l1e = unsafe { core::ptr::read_volatile(l1_pte) };
        if (l1e & PTE_V) != 0 && is_leaf(l1e) {
            cur = if can_use_superpage {
                cur.saturating_add(SUPERPAGE_SIZE)
            } else {
                cur.saturating_add(PAGE_SIZE)
            };
            continue;
        }
        if can_use_superpage && (l1e & PTE_V) == 0 {
            unsafe {
                core::ptr::write_volatile(l1_pte, make_pte(cur, HEAP_FLAGS));
                asm!("sfence.vma {}, zero", in(reg) cur, options(nostack));
            }
            cur = cur.saturating_add(SUPERPAGE_SIZE);
            continue;
        }

        let pte = unsafe { identity_leaf_pte_for_at(root, cur) };
        if pte.is_null() {
            let used =
                unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IDENTITY_PT_ALLOCATED)) };
            crate::hal::serial::write_string_always("[RVPGT] identity leaf fail cur=");
            crate::hal::serial::write_hex_u64_always(cur);
            crate::hal::serial::write_string_always(" root=");
            crate::hal::serial::write_hex_u64_always(root);
            crate::hal::serial::write_string_always(" pool=");
            crate::hal::serial::write_hex_u64_always(used as u64);
            crate::hal::serial::write_string_always("\r\n");
            return false;
        }
        unsafe {
            core::ptr::write_volatile(pte, make_pte(cur, HEAP_FLAGS));
            asm!("sfence.vma {}, zero", in(reg) cur, options(nostack));
        }
        cur = cur.saturating_add(PAGE_SIZE);
    }
    flush_tlb();
    record_identity_range(pa_aligned, end);
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
            core::mem::size_of::<PageAlignedTable>(),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ROOT_PHYS),
            core::ptr::addr_of!(ROOT_TABLE) as u64,
        );
    }
}
