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
    let root_phys = pfn_to_phys(root_pfn);
    if va == 0x0000_003F_C000_0000 {
        let root = root_phys as *const u64;
        let root_entry = unsafe { core::ptr::read_volatile(root.add(((va >> 30) & 0x1FF) as usize)) };
        crate::hal::serial::write_string_always(&alloc::format!(
            "[RVPGROOT] heap root={:x} root_entry={:x} pa={:x} flags={:x}\r\n",
            root_phys,
            root_entry,
            pa,
            flags
        ));
    }
    let l2_pte = unsafe { leaf_pte_for_at(root_phys, va) };
    if va == 0x0000_003F_C000_0000 && !l2_pte.is_null() {
        let leaf = unsafe { core::ptr::read_volatile(l2_pte) };
        crate::hal::serial::write_string_always(&alloc::format!(
            "[RVPGROOT] heap leaf_addr={:x} leaf={:x}\r\n",
            l2_pte as u64,
            leaf
        ));
    }
    if va == 0x0000_003F_C000_0000 && !l2_pte.is_null() {
        unsafe {
            core::ptr::write_volatile(l2_pte, make_pte(pa, flags));
            asm!("sfence.vma {}, zero", in(reg) va, options(nostack));
        }
        let leaf = unsafe { core::ptr::read_volatile(l2_pte) };
        crate::hal::serial::write_string_always("[RVPGROOT] heap written leaf=");
        crate::hal::serial::write_hex_u64_always(leaf);
        crate::hal::serial::write_string_always("\r\n");
        return true;
    }
    let l2_pte_addr = l2_pte as u64;
    if l2_pte.is_null() {
        crate::hal::serial::write_string_always(&alloc::format!(
            "[RVPGROOT] fail root_pfn={:x} root={:x} va={:x} pa={:x}\r\n",
            root_pfn,
            root_phys,
            va,
            pa
        ));
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

pub unsafe fn load_page_root(pml4_pfn: u64) {
    let pa = pfn_to_phys(pml4_pfn);
    crate::arch::riscv64::csr::sstatus::set(
        crate::arch::riscv64::csr::sstatus::SUM,
    );
    crate::hal::serial::write_string_always("[SATP] before\r\n");
    let is_system_root = {
        let system = crate::mm::vas::MM_SYSTEM_VAS.lock();
        system.pml4_phys == pa
    };
    if !is_system_root {
        prepare_switch_mappings(pml4_pfn);
    }
    crate::hal::serial::write_string_always("[SATP] prepared\r\n");
    // satp = MODE (8 = Sv39) << 60 | ASID (0) << 44 | PPN
    let satp: u64 = (8u64 << 60) | (pa >> 12);
    crate::hal::serial::write_string_always("[SATP] pre-csrw\r\n");
    // The first transition can trap while still executing kernel code.
    // In that case `sscratch` has never been primed with a kernel stack,
    // so the trap entry would otherwise save the entire frame at 0.
    let current_sp: u64;
    asm!("mv {}, sp", out(reg) current_sp, options(nostack));
    asm!("csrw sscratch, {}", in(reg) current_sp, options(nostack));
    asm!("csrw satp, {}", in(reg) satp, options(nostack));
    asm!("sfence.vma", options(nostack));
    crate::hal::serial::write_string_always("[SATP] written\r\n");
    crate::hal::serial::write_string_always("[SATP] fenced\r\n");
    core::ptr::write_volatile(core::ptr::addr_of_mut!(ROOT_PHYS), pa);
    crate::hal::serial::write_string_always("[SATP] cached\r\n");
}

/// Map the few pages required to survive a root-table switch.
///
/// Sv39 changes translation *immediately* when `satp` is written.  The
/// kernel must therefore guarantee that its own current code page,
/// current stack pages, and the diagnostic UART are reachable through the
/// destination root.  The generic VAS layer copies root descriptors, but
/// this explicit switch guard keeps the critical path working even when a
/// process root was built before every kernel mapping was refreshed.
fn prepare_switch_mappings(root_pfn: u64) {
    let map_switch_page = |va: u64, flags: u64| -> bool {
        if va == 0 || va & 0xfff != 0 {
            return false;
        }
        // The switch may happen before the MMU is enabled.  In that
        // case the static bootstrap root is not the active translation
        // and cannot be used to discover the physical backing of the
        // running image.  Bare mode guarantees VA == PA, so install the
        // same identity mapping in the destination root.
        if current_satp_root_phys() == 0 {
            unsafe { map_page_in_root(root_pfn, va, va, flags) }
        } else {
            let Some(pa) = translate_virt(va) else {
                crate::hal::serial::write_string_always("[SATP] translate fail va=");
                crate::hal::serial::write_hex_u64(va);
                crate::hal::serial::write_string_always(" root=");
                crate::hal::serial::write_hex_u64(root_phys());
                crate::hal::serial::write_string_always("\r\n");
                return false;
            };
            unsafe { map_page_in_root(root_pfn, va, pa, flags) }
        }
    };

    // `map_page_in_root()` expects the portable/x86-style flag inputs used
    // by `make_pte()`. Passing native Sv39 bits here would alias EXECUTE
    // into USER and make kernel trap code inaccessible in S-mode.
    const KERNEL_CODE: u64 = crate::mm::pte::PTE_P | crate::mm::pte::PTE_RW;
    const KERNEL_DATA: u64 = crate::mm::pte::PTE_P | crate::mm::pte::PTE_RW;

    // A process root must expose the entire running kernel image.  Copying
    // only the root-level descriptors from the system root is not enough:
    // mappings created after the snapshot can introduce new lower-level
    // tables that are invisible to a process root.  The Win10 ARM64 model
    // keeps kernel views coherent in the process context; for Sv39 we do
    // this explicitly by installing the kernel pages before `satp` changes.
    extern "C" {
        static __image_start: u8;
        static __image_end: u8;
    }
    let image_start = unsafe { core::ptr::addr_of!(__image_start) } as u64 & PAGE_MASK;
    let image_end = unsafe { core::ptr::addr_of!(__image_end) } as u64;
    for page in (image_start..image_end).step_by(PAGE_SIZE as usize) {
        if !map_switch_page(page, KERNEL_CODE) {
            crate::hal::serial::write_string_always("[SATP] kernel map failed at ");
            crate::hal::serial::write_hex_u64(page);
            crate::hal::serial::write_string_always("\r\n");
        }
    }

    // `write_string_always` and `load_page_root` may live on adjacent code
    // pages.  Map both pages for each function to tolerate page-boundary
    // calls.  The copy is normally inherited from the system root; these
    // mappings only patch a destination root with stale or missing entries.
    let load_pc = load_page_root as *const () as u64;
    let serial_pc = crate::hal::riscv64::serial::write_string_always as *const () as u64;
    let trap_pc = crate::arch::riscv64::idt::trap_entry_addr();
    let mut sp = 0u64;
    unsafe {
        asm!("mv {}, sp", out(reg) sp, options(nostack));
    }
    crate::hal::serial::write_string_always("[SATP] switch load_pc=");
    crate::hal::serial::write_hex_u64(load_pc);
    crate::hal::serial::write_string_always(" serial_pc=");
    crate::hal::serial::write_hex_u64(serial_pc);
    crate::hal::serial::write_string_always(" sp=");
    crate::hal::serial::write_hex_u64(sp);
    crate::hal::serial::write_string_always(" root=");
    crate::hal::serial::write_hex_u64(current_satp_root_phys());
    crate::hal::serial::write_string_always(" dest=");
    crate::hal::serial::write_hex_u64(pfn_to_phys(root_pfn));
    crate::hal::serial::write_string_always(" image=");
    crate::hal::serial::write_hex_u64(image_start);
    crate::hal::serial::write_string_always("..");
    crate::hal::serial::write_hex_u64(image_end);
    crate::hal::serial::write_string_always("\r\n");
    for pc in [load_pc, serial_pc] {
        let page = pc & PAGE_MASK;
        let next = page + PAGE_SIZE;
        map_switch_page(page, KERNEL_CODE);
        map_switch_page(next, KERNEL_CODE);
    }

    let trap_page = trap_pc & PAGE_MASK;
    for index in 0..4u64 {
        map_switch_page(trap_page + index * PAGE_SIZE, KERNEL_CODE);
    }

    for delta in 0..128u64 {
        let page = (sp - delta * PAGE_SIZE) & PAGE_MASK;
        map_switch_page(page, KERNEL_DATA);
    }
    for delta in 1..128u64 {
        let page = (sp + delta * PAGE_SIZE) & PAGE_MASK;
        map_switch_page(page, KERNEL_DATA);
    }

    // The kernel heap uses identity physical virtual addresses.  A process
    // root created after `heap::init()` does not inherit these pages unless
    // the system root is explicitly refreshed, and even then a stale root
    // can miss pages added by dynamic allocations.  Install the complete
    // configured heap region in the destination root so attach/detach and
    // syscalls can safely touch kernel pool objects.
    if let Some((heap_base, heap_size)) = crate::mm::heap::KERNEL_HEAP.configured_region() {
        let heap_start = heap_base as u64 & PAGE_MASK;
        let heap_end = heap_start
            .checked_add(heap_size as u64)
            .unwrap_or(heap_start)
            .min(0x0000_FFFF_FFFF_FFFF);
        let mut page = heap_start;
        while page < heap_end {
            let pa = if current_satp_root_phys() == 0 {
                page
            } else {
                match translate_virt(page) {
                    Some(pa) => pa & PAGE_MASK,
                    None => page,
                }
            };
            if !map_page_in_root(root_pfn, page, pa, KERNEL_DATA) {
                crate::hal::serial::write_string_always("[SATP] kernel heap map failed at ");
                crate::hal::serial::write_hex_u64(page);
                crate::hal::serial::write_string_always("\r\n");
            }
            page += PAGE_SIZE;
        }
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

    // The RISC-V serial backend addresses the UART by physical VA.
    // A stale current-root translation must never be copied here: doing so
    // silently retargets diagnostics to ordinary RAM and hides the next
    // boot trace.  QEMU virt exposes the NS16550A at this physical page.
    const UART_PHYS: u64 = 0x1000_0000;
    const UART_FLAGS: u64 = crate::mm::pte::PTE_P | crate::mm::pte::PTE_RW;
    unsafe {
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
    }
    crate::hal::serial::write_string_always("[SATP] uart guard done\r\n");
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
    ((pa >> 12) << 10) | PTE_V
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
            crate::hal::serial::write_string_always(&alloc::format!(
                "[RVPGT] identity l1 fail cur=0x{:x} root=0x{:x} pool={}\r\n",
                cur,
                root,
                used
            ));
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
            crate::hal::serial::write_string_always(&alloc::format!(
                "[RVPGT] identity leaf fail cur=0x{:x} root=0x{:x} pool={}\r\n",
                cur,
                root,
                used
            ));
            return false;
        }
        unsafe {
            core::ptr::write_volatile(pte, make_pte(cur, HEAP_FLAGS));
            asm!("sfence.vma {}, zero", in(reg) cur, options(nostack));
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
            core::mem::size_of::<PageAlignedTable>(),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ROOT_PHYS),
            core::ptr::addr_of!(ROOT_TABLE) as u64,
        );
    }
}
