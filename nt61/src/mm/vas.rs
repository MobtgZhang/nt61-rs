//! Virtual address space management and recursive self-map
//
//! Implements the NT 6.1 layout with the page-table self-map trick
//! (PML4 index 0x1ED points back at the PML4 itself). This gives us
//! a fixed virtual window from which we can read or write *any* PTE
//! in the system without having to keep intermediate tables
//! permanently mapped somewhere else.
//
//! Constants reproduced from `docs/mem1.md` / `docs/53d07021-...html`:
//
//! ```text
//! PXE_BASE = 0xFFFFF6FB7DBED000
//! PPE_BASE = 0xFFFFF6FB7DA00000
//! PDE_BASE = 0xFFFFF6FB40000000
//! PTE_BASE = 0xFFFFF68000000000
//! ```
//
//! The user PML4 entries 0..255 are the user half; entries 256..511
//! (0x100..0x1FF) are the kernel half. The system process has a PML4
//! that exposes *all* of those (system PML4 is shared, user processes
//! only have a copy of the kernel half + their own user half).
//
//! For processes that want their own PML4 we allocate a new page, copy
//! the kernel half of the system PML4 into it, and zero the user
//! half. The result is a PML4 with the same kernel mappings but a
//! private user space.

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::pfn;
use crate::mm::pte::{PfnNumber, MMPTE};
use crate::mm::vad::VadTree;

// Re-export all constants from the single source of truth.
// Locally-defined constants that duplicate these are removed below.
pub use crate::mm::constants::*;

/// Index into the PML4 for the self-map slot.
pub const MI_SELF_MAP_INDEX: usize = 0x1ED;

/// Self-map addresses (imported from `crate::mm::constants` via
/// `pub use crate::mm::constants::*`).///
/// Self-map derived addresses for a given virtual address.
///
/// The offset must preserve the complete 48-bit linear page number.
/// Masking each level independently collapses all pages that share the
/// same 9-bit sub-index and makes the upper PML4 regions unreachable.
const VIRTUAL_ADDRESS_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

#[inline]
pub fn pte_address_of(va: u64) -> *mut MMPTE {
    let linear_page = (va & VIRTUAL_ADDRESS_MASK) >> PAGE_SHIFT;
    (PTE_BASE + linear_page * 8) as *mut MMPTE
}
#[inline]
pub fn pde_address_of(va: u64) -> *mut MMPTE {
    // The PDE window addresses every page-table page in the address
    // space, so the index is the *full* PT-page number (VA >> 21),
    // not a 9-bit sub-index. The window between PDE_BASE and
    // PPE_BASE is exactly 2^27 * 8 bytes = 1 GiB, which only fits
    // the untruncated index. Masking to 9 bits aliased every page
    // table beyond the first 2 MiB onto the first 512.
    let linear_directory_page = (va & VIRTUAL_ADDRESS_MASK) >> (PAGE_SHIFT + 9);
    (PDE_BASE + linear_directory_page * 8) as *mut MMPTE
}
#[inline]
pub fn ppe_address_of(va: u64) -> *mut MMPTE {
    // Same reasoning: the PPE window (2 MiB) is indexed by the full
    // PD-page number (VA >> 30). A 9-bit mask aliased every page
    // directory beyond the first 1 GiB onto the first 512.
    let linear_pointer_page = (va & VIRTUAL_ADDRESS_MASK) >> (PAGE_SHIFT + 18);
    (PPE_BASE + linear_pointer_page * 8) as *mut MMPTE
}
#[inline]
pub fn pxe_address_of(va: u64) -> *mut MMPTE {
    let linear_root_page = (va >> (PAGE_SHIFT + 27)) & 0x1FF;
    (PXE_BASE + linear_root_page * 8) as *mut MMPTE
}

/// Invalidate a single TLB entry for the given virtual address.
/// Delegates to the architecture-specific TLB invalidation.
pub fn invalidate_tlb(addr: u64) {
    crate::arch::invalidate_tlb(addr);
}

// ---------------------------------------------------------------------------
// System address space
// ---------------------------------------------------------------------------

/// Global state for the system (kernel) address space. There is
/// exactly one of these and it is never freed.
pub struct MmSystemAddressSpace {
    /// Physical address of the system PML4.
    pub pml4_phys: u64,
    /// Virtual address of the PML4 (equal to its physical address on
    /// x86 with the identity map we set up at boot; with the self
    /// map in place we can always address it via `PXE_BASE`).
    pub pml4_virt: u64,
    /// Range of PFNs that the system PML4 kernel half references.
    pub initialized: bool,
}

impl MmSystemAddressSpace {
    pub const fn new() -> Self {
        Self {
            pml4_phys: 0,
            pml4_virt: 0,
            initialized: false,
        }
    }
}

impl Default for MmSystemAddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

pub static MM_SYSTEM_VAS: Spinlock<MmSystemAddressSpace> =
    Spinlock::new(MmSystemAddressSpace::new());

/// Return a virtual pointer to the system PML4.
///
/// # Note
///
/// The NT 6.1 self-map (see `install_self_map_with_identity_map`)
/// is a single-page recursive map whose "PXE_BASE" window points
/// at the **PDPT** that backs PML4[0x1ED], not at the PML4
/// itself. (Every self-map window — PXE_BASE, PPE_BASE, PDE_BASE,
/// PTE_BASE — closes the recursion at the same page.) Therefore
/// we cannot just cast `PXE_BASE` to a `*mut MMPTE` and expect to
/// read or write the PML4; that pointer addresses the PDPT, and
/// `PXE_BASE[0]` reads `PDPT[0]`, not `PML4[0]`.
///
/// We instead return the PML4's current *physical* address (read
/// from the arch-specific page root register). The PML4 page is
/// always identity-mapped in the low half of the address space
/// (the OVMF firmware and the kernel's own `vas::init` both ensure
/// this), so the physical address is also a valid virtual address
/// in the kernel half.
pub fn system_pml4_ptr() -> *const MMPTE {
    crate::arch::read_current_page_root() as *const MMPTE
}
/// Return a mutable virtual pointer to the system PML4.
/// See `system_pml4_ptr` for why we read the page root here.
pub fn system_pml4_mut() -> *mut MMPTE {
    crate::arch::read_current_page_root() as *mut MMPTE
}

// ---------------------------------------------------------------------------
// Per-process virtual address space
// ---------------------------------------------------------------------------

/// Per-process address space.
pub struct MmVirtualAddressSpace {
    /// Physical address of the process PML4.
    pub pml4_phys: u64,
    /// VAD tree for user mode.
    pub vad_root: VadTree,
    /// Commit charge, in pages.
    pub commit_charge: AtomicU64,
    /// Working set count.
    pub working_set_size: AtomicU64,
    /// Has this VAS been initialised.
    pub initialized: bool,
    /// Per-process user VA allocator
    pub user_va_allocator: Spinlock<UserVaAllocator>,
}

impl MmVirtualAddressSpace {
    pub const fn new() -> Self {
        Self {
            pml4_phys: 0,
            vad_root: VadTree::new(),
            commit_charge: AtomicU64::new(0),
            working_set_size: AtomicU64::new(0),
            initialized: false,
            user_va_allocator: Spinlock::new(UserVaAllocator::new()),
        }
    }

    pub fn commit(&self, n: u64) {
        self.commit_charge.fetch_add(n, Ordering::Relaxed);
    }
    pub fn uncommit(&self, n: u64) {
        self.commit_charge.fetch_sub(n, Ordering::Relaxed);
    }
    pub fn commit_count(&self) -> u64 {
        self.commit_charge.load(Ordering::Relaxed)
    }

    /// Allocate user-mode virtual address from this process's address space
    pub fn allocate_user_va(&self, desired_base: u64, size: u64, _protect: u32) -> Option<u64> {
        let mut allocator = self.user_va_allocator.lock();
        // _protect is intentionally unused - reserved for future use (protection flags)

        // Align size to page boundary
        let aligned_size = (size + 0xFFF) & !0xFFF;

        // Find a suitable VA
        let va = if desired_base == 0 {
            let mut candidate = allocator.next_va;
            loop {
                if candidate > allocator.end_va || aligned_size > allocator.end_va - candidate {
                    return None;
                }
                let end = candidate + aligned_size;
                if !allocator.is_overlapping(candidate, end) {
                    break;
                }
                candidate = (end + 0xFFF) & !0xFFF;
            }
            candidate
        } else {
            let base = desired_base & !0xFFF;
            let end = base.checked_add(aligned_size)?;
            if base >= 0x0000_7FFF_FFFF_FFFF
                || end > allocator.end_va
                || allocator.is_overlapping(base, end)
            {
                return None;
            }
            base
        };

        if allocator.record(va, va + aligned_size) {
            Some(va)
        } else {
            None
        }
    }

    /// Free a user-mode VA range previously returned by this allocator.
    pub fn free_user_va(&self, va: u64) -> bool {
        let mut allocator = self.user_va_allocator.lock();
        let index = allocator
            .allocations
            .iter()
            .position(|allocation| allocation.map(|region| region.start == va).unwrap_or(false));
        match index {
            Some(index) => {
                allocator.allocations[index] = None;
                true
            }
            None => false,
        }
    }

    /// Reset the user VA allocator to initial state
    pub fn reset_user_va_allocator(&self) {
        let mut allocator = self.user_va_allocator.lock();
        allocator.next_va = USER_BASE;
        allocator.end_va = 0x0000_7FFF_FFFF_F000; // Windows 7 x64 user limit
        allocator.allocations = [const { None }; MAX_USER_VA_ALLOCATIONS];
    }
}

impl Default for MmVirtualAddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Self-map installation
// ---------------------------------------------------------------------------

/// Walk the self-map and confirm it is in place. Returns the PML4's
/// PFN as recorded in the self-map slot, if valid.
pub fn verify_self_map() -> Option<PfnNumber> {
    let entry = unsafe { system_pml4_mut().add(MI_SELF_MAP_INDEX) };
    unsafe {
        let pte = *entry;
        if !pte.is_hardware() {
            return None;
        }
        Some(pte.hardware_page_frame() >> 12)
    }
}

/// Install the architecture's full recursive self-map.
pub fn install_self_map(pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    crate::arch::common::self_map::install_recursive(pml4_pfn)
}

/// Install the NT hyperspace temporary-mapping window.
pub fn install_hyperspace_tables(pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    crate::arch::common::self_map::install_hyperspace(pml4_pfn)
}

/// Install the single-level fallback self-map.
pub fn install_single_level_self_map(pml4_phys: u64) {
    crate::arch::common::self_map::install_single_level(pml4_phys)
}

/// Install a single-level self-map directly by physical address.
pub fn install_single_level_self_map_direct(pml4_phys: u64) {
    crate::arch::common::self_map::install_single_level_direct(pml4_phys);
}

/// Identity-map a low-memory region into the system page root.
pub fn ensure_low_identity_map(pa_base: u64, size: u64) -> bool {
    crate::arch::common::self_map::ensure_low_identity_map(pa_base, size)
}

/// Call `ensure_low_identity_map` and loudly report failures on the
/// boot serial log instead of silently continuing with an unmapped
/// region. Boot-critical callers use this so an OOM during page-table
/// setup cannot masquerade as success.
fn ensure_identity_or_log(pa_base: u64, size: u64, what: &str) {
    if !ensure_low_identity_map(pa_base, size) {
        crate::boot_println!(
            "[VAS] ERROR: identity-map failed for {} (pa=0x{:x} size=0x{:x})",
            what,
            pa_base,
            size
        );
    }
}

// ---------------------------------------------------------------------------
// Per-process address space creation
// ---------------------------------------------------------------------------

/// create a new user process address space. Allocates a new PML4 page
/// from the PFN database, copies the system PML4 into it, and
/// returns the physical address of the new PML4.
///
/// # Note on kernel-half layout
///
/// In this kernel the kernel image is *identity-mapped* in the low
/// half of the address space (PML4 indices 0..256), not in the
/// high half. The "kernel half" PML4 indices 256..512 are otherwise
/// empty (apart from the recursive self-map at index
/// `MI_SELF_MAP_INDEX = 0x1ED`).
///
/// If we only copied the high half into the new PML4, the user
/// process would have no mapping for the kernel image: as soon as
/// we switched CR3 to the new PML4, the very first instruction
/// executed by the kernel (e.g. the return address inside
/// `attach_process`) would page-fault.
///
/// On x86_64 the copy is split by ownership (see
/// `copy_system_root_for_process`): supervisor-only kernel entries
/// are carried over verbatim so the kernel stays reachable under a
/// process CR3, while the low-identity chain under PML4[0] is
/// deep-copied into freshly allocated tables so per-process user
/// mappings (ring-3 stub, user allocations in the low half) never
/// share page-table pages with the system root or with other
/// processes. Later kernel identity mappings installed in the
/// system chain are merged back into the private copy by
/// `refresh_kernel_mappings`.
pub fn create_user_address_space() -> Option<u64> {
    let pfn = pfn::allocate_pfn()?;
    crate::boot_debug_println!("[VAS] create_user_address_space: A: new pfn=0x{:x}", pfn);
    // The root page is handed out by the PFN allocator. On non-x86
    // targets the kernel does not necessarily map every physical
    // frame one-to-one, so install an explicit identity mapping before
    // using the PFN as a pointer. This keeps the root table address
    // used by the hardware root register identical to the address used
    // by Rust.
    let root_va = pfn << 12;
    if !crate::arch::identity_map_region(root_va, 4096) {
        crate::boot_debug_println!(
            "[VAS] create_user_address_space: ERROR: root identity map failed"
        );
        pfn::free_pfn(pfn);
        return None;
    }
    // Zero the new PML4.
    unsafe {
        let va = (pfn << 12) as *mut u8;
        ptr::write_bytes(va, 0, 4096);
    }
    let system = system_pml4_mut();
    let dst = (pfn << 12) as *mut MMPTE;
    #[cfg(target_arch = "x86_64")]
    {
        // x86_64: kernel identity/self-map entries must stay reachable
        // while the kernel executes under a process CR3, but the user
        // half must start clean. See copy_system_root_for_process.
        if !copy_system_root_for_process(dst, system) {
            crate::boot_debug_println!(
                "[VAS] create_user_address_space: ERROR: root copy failed (OOM)",
            );
            pfn::free_pfn(pfn);
            return None;
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        for i in 0..PT_ENTRIES {
            let src_entry = *system.add(i);
            *dst.add(i) = MMPTE {
                u_long: src_entry.raw(),
            };
        }
    }
    crate::boot_debug_println!("[VAS] create_user_address_space: B: copied system PML4",);
    // Install a self-map chain + identity map for this PML4. The
    // system PML4's identity-map entry points at the system PML4's
    // own physical address; the new user PML4 sits at a different
    // physical address, so the copy above inherits an identity map
    // that no longer resolves correctly. We re-install the chain
    // here so the kernel's PXE_BASE / PDE_BASE / PTE_BASE macros
    // (and any subsequent context switch to this PML4) can reach
    // the new page tables through the self-map.
    if crate::arch::common::self_map::install_with_identity_map(pfn).is_err() {
        // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] ERROR: create_user_address_space failed to install self-map");
        crate::boot_debug_println!("[VAS] create_user_address_space: ERROR: self-map failed");
        pfn::free_pfn(pfn);
        return None;
    }
    crate::boot_debug_println!("[VAS] create_user_address_space: D: self-map installed");
    if crate::arch::common::self_map::install_hyperspace(pfn).is_err() {
        crate::boot_debug_println!("[VAS] create_user_address_space: ERROR: hyperspace failed");
        pfn::free_pfn(pfn);
        return None;
    }
    // Force W=1 on every identity-map (low-half) entry in the new
    // PML4 so the kernel can write to page-table pages while running
    // with this user PML4 as CR3. Without this, a write to a PT/PD
    // page would trigger a kernel-mode protection-violation (#PF
    // with err=0x3) and a reboot. Boot-loader mappings are
    // intentionally R/O for some regions (e.g., MMIO for the EFI
    // framebuffer), so we must lift W=0 here.
    //
    // x86_64 only — on aarch64 / riscv64 / loongarch64 the PTEs are
    // constructed with the AP / W / K fields already set to permit
    // kernel writes, so no CR0.WP lift is required.
    unsafe {
        crate::arch::common::self_map::force_writable_identity_map(pfn);
        crate::arch::common::self_map::arm_write_watchpoint(pfn);
    }
    Some(pfn << 12)
}

/// Synchronize kernel-owned root entries into a process page root.
///
/// The process root is a snapshot of the system root. Kernel pool and
/// console allocations made after the snapshot install new mappings in
/// the system root; without this refresh, the first syscall executed
/// under the process CR3 can fault while writing to a kernel console
/// buffer. Kernel-half entries (indices 1..511, excluding the self-map
/// slot) are copied into absent process slots with the U bit cleared
/// so the mappings remain kernel-only. Index 0 holds a per-process
/// private copy of the low identity chain (see
/// `copy_system_root_for_process`), so it is merged at the chain
/// level: an absent process chain is deep-copied from the system
/// chain, an existing one is merged via `sync_identity_chain`.
pub fn refresh_kernel_mappings(pml4_phys: u64) {
    if pml4_phys == 0 {
        return;
    }
    let system_phys = MM_SYSTEM_VAS.lock().pml4_phys;
    if system_phys == 0 || system_phys == pml4_phys {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // The root tables live at arbitrary physical addresses. The
        // historical "physical address == pointer" shortcut only
        // worked while a full 1:1 identity map of every allocated
        // frame existed, which is not guaranteed in process context.
        // Map both tables explicitly through the hyperspace window.
        let system_guard = match crate::mm::vm::direct_map_guard(system_phys, 4096) {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let process_guard = match crate::mm::vm::direct_map_guard(pml4_phys, 4096) {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let system = system_guard.va() as *const MMPTE;
        let process = process_guard.va() as *mut MMPTE;
        unsafe {
            // PML4[0] is a per-process private deep copy of the low
            // identity chain (see `copy_system_root_for_process`), so
            // it cannot be merged entry-by-entry at the root level.
            // Merge at chain level instead: absent chains are copied
            // wholesale, present chains are merged recursively.
            let system_entry0 = core::ptr::read_volatile(system).raw();
            if system_entry0 & PTE_P != 0 {
                let sys_chain = system_entry0 & PTE_FRAME_MASK;
                let process_entry0 = core::ptr::read_volatile(process).raw();
                if process_entry0 & PTE_P == 0 {
                    if let Some(copied) = copy_identity_chain(sys_chain, 3) {
                        let new0 = (system_entry0 & !PTE_FRAME_MASK) | copied;
                        core::ptr::write_volatile(process, MMPTE { u_long: new0 });
                    }
                    // On OOM the process entry stays absent; the next
                    // refresh retries.
                } else {
                    let proc_chain = process_entry0 & PTE_FRAME_MASK;
                    sync_identity_chain(sys_chain, proc_chain, 3);
                }
            }
            for idx in 1..(PT_ENTRIES - 1) {
                if idx == MI_SELF_MAP_INDEX || idx == 255 {
                    continue;
                }
                let process_entry = core::ptr::read_volatile(process.add(idx)).raw();
                if process_entry & PTE_P != 0 {
                    continue;
                }
                let system_entry = core::ptr::read_volatile(system.add(idx)).raw();
                if system_entry & PTE_P == 0 {
                    continue;
                }
                let kernel_entry = crate::arch::translate_x86_root_entry(system_entry);
                core::ptr::write_volatile(
                    process.add(idx),
                    crate::mm::pte::MMPTE {
                        u_long: kernel_entry,
                    },
                );
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // The live system root is already in native MMU encoding on
        // non-x86 targets, so copy its descriptors verbatim.
        // As on x86_64, the root tables are reached through the
        // hyperspace direct-map window instead of assuming their
        // physical addresses are dereferenceable.
        let system_guard = match crate::mm::vm::direct_map_guard(system_phys, 4096) {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let process_guard = match crate::mm::vm::direct_map_guard(pml4_phys, 4096) {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let system = system_guard.va() as *const MMPTE;
        let process = process_guard.va() as *mut MMPTE;
        unsafe {
            for idx in 1..PT_ENTRIES {
                let process_entry = core::ptr::read_volatile(process.add(idx)).raw();
                if process_entry != 0 {
                    continue;
                }
                let system_entry = core::ptr::read_volatile(system.add(idx)).raw();
                if system_entry != 0 {
                    core::ptr::write_volatile(
                        process.add(idx),
                        crate::mm::pte::MMPTE {
                            u_long: system_entry,
                        },
                    );
                }
            }
        }
    }
}

/// Attach a process. Updates the per-CPU CR3 / TTBR1 etc. via the
/// arch-specific `load_page_root` helper. Returns the previous root.
pub fn attach_process(pml4_phys: u64) -> u64 {
    let prev = current_root();
    let root_pfn = pml4_phys >> 12;
    // The previous implementation traced the first PML4 entries of
    // the new root here by reading `pml4_phys` as a pointer. That
    // dereference silently relied on a 1:1 identity map of the root
    // page being present under the *old* root — an assumption that
    // does not hold in process context — and it spammed COM1 on every
    // context switch. Loading a root register does not need to read
    // the root's contents, so the trace is removed instead of
    // re-guarded.
    unsafe {
        crate::arch::load_page_root(root_pfn);
    }
    set_current_root(pml4_phys);
    crate::arch::common::percpu::set_address_space_roots(prev, pml4_phys);
    prev
}

/// Detach a process. Restores the system root.
pub fn detach_process(prev: u64) {
    let restored = if prev == 0 {
        MM_SYSTEM_VAS.lock().pml4_phys
    } else {
        prev
    };
    unsafe {
        crate::arch::load_page_root(restored >> 12);
    }
    set_current_root(restored);
    crate::arch::common::percpu::clear_user_address_space();
}

// ---------------------------------------------------------------------------
// Per-process page-table helpers (Phase 0 ring transition)
// ---------------------------------------------------------------------------
//
// `create_user_address_space` allocates a fresh PML4 that mirrors the
// kernel half of the system PML4 and zeroes the user half. The
// functions below populate the user half on demand.
//
// Important: The page-table pages we allocate via `pfn::allocate_pfn`
// live in physical memory. To write their PTEs we need a kernel
// virtual pointer to each page. On x86_64 the arch-specific
// `ensure_low_identity_map` walks PML4/PDPT/PD on demand and can map
// any physical address, so `alloc_zeroed_page` is safe for frames
// above 4 GiB as well. On AArch64/RISC-V/LoongArch the identity map
// is established during `vas::init` from the boot-info ranges.
//
// `ensure_low_identity_map` is called with boot-info-derived base
// and size by `fs::mount_esp_from_bootinfo` and by `mm::init`, so
// images loaded by winload above the default 4 GiB bootstrap window
// are mapped correctly on all four architectures.

/// Protection flags for `map_page_in_pml4`. The values are the raw
/// bits ORed into the leaf PTE. `R/W = 1<<1`, `U/S = 1<<2`, plus
/// `P = 1<<0` always.
///
/// All PTE_* constants and INT_PTE_BITS are now imported from
/// `crate::mm::constants` via `pub use crate::mm::constants::*`.///
/// Allocate a fresh page, zero it, and return its physical address.
fn alloc_zeroed_page() -> Option<u64> {
    let pfn = crate::mm::pfn::allocate_pfn()?;
    let pa = crate::mm::pte::pfn_to_phys(pfn);
    if !crate::arch::identity_map_region(pa & !0x1F_FFFF, 0x20_0000) {
        return None;
    }
    unsafe {
        core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE as usize);
    }
    Some(pa)
}

/// Public variant of `alloc_zeroed_page` for callers that want to
/// allocate a backing page outside of `map_user_pages` (e.g. when
/// they need to write into the page before mapping it).
pub fn alloc_zeroed_page_for_vas() -> Option<u64> {
    alloc_zeroed_page()
}

/// x86_64 page-size bit. In a PDE/PDPTE this is the PS (page size)
/// bit marking a 2 MiB / 1 GiB leaf; the same bit position is named
/// PAT in leaf PTEs, which never carry PS semantics.
#[cfg(target_arch = "x86_64")]
const PS_BIT: u64 = 1 << 7;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Deep-copy an x86_64 page-table subtree rooted at `table_phys`.
///
/// `level` is the level of the table itself: 3 = PDPT (direct child
/// of a PML4), 2 = PD, 1 = PT. Entries are classified per level:
///
/// * Leaves (level 1, or PS set at level 2/3) that carry the U bit
///   are user mappings and are dropped: user pages belong to the
///   process that mapped them, never to the shared system chain.
/// * Supervisor leaves (the kernel identity map uses 2 MiB PDEs
///   without U, see `ensure_low_identity_map`) are copied verbatim.
/// * Intermediate entries are recursed into; the copy references the
///   freshly allocated child tables, so the private chain shares no
///   page-table pages with the system root.
///
/// Returns the physical address of the new table. On OOM returns
/// `None`; pages allocated by already-completed sub-levels are then
/// unreachable and intentionally leaked rather than partially freed
/// (this runs during early boot where no safe teardown exists).
#[cfg(target_arch = "x86_64")]
unsafe fn copy_identity_chain(table_phys: u64, level: u8) -> Option<u64> {
    let new_table = alloc_zeroed_page()?;
    let src = table_phys as *const u64;
    let dst = new_table as *mut u64;
    for idx in 0..PT_ENTRIES {
        let entry = core::ptr::read_volatile(src.add(idx));
        if entry & PTE_P == 0 {
            continue;
        }
        let is_leaf = level == 1 || (entry & PS_BIT) != 0;
        if is_leaf {
            if entry & PTE_US != 0 {
                continue;
            }
            core::ptr::write_volatile(dst.add(idx), entry);
        } else {
            let child_phys = entry & PTE_FRAME_MASK;
            let copied = copy_identity_chain(child_phys, level - 1)?;
            let new_entry = (entry & !PTE_FRAME_MASK) | copied;
            core::ptr::write_volatile(dst.add(idx), new_entry);
        }
    }
    Some(new_table)
}

/// Copy the system PML4 into a freshly zeroed process PML4, splitting
/// the entries by ownership:
///
/// * PML4[0] holds the low identity chain that user mappings in the
///   low half (ring-3 stub, user allocator VAs) also live under. It
///   is deep-copied via `copy_identity_chain` so each process owns
///   its own chain and user mappings never leak between processes.
/// * Every other present entry is a supervisor-owned mapping and is
///   carried over with the U bit cleared (via
///   `translate_x86_root_entry`) so the kernel stays reachable under
///   a process CR3 while ring 3 cannot reach it.
///
/// Returns `false` on OOM, in which case the caller must consider the
/// destination PML4 invalid.
#[cfg(target_arch = "x86_64")]
fn copy_system_root_for_process(dst: *mut MMPTE, system: *const MMPTE) -> bool {
    unsafe {
        let src0 = core::ptr::read_volatile(system).raw();
        if src0 & PTE_P != 0 {
            let sys_chain = src0 & PTE_FRAME_MASK;
            match copy_identity_chain(sys_chain, 3) {
                Some(copied) => {
                    let new0 = (src0 & !PTE_FRAME_MASK) | copied;
                    core::ptr::write_volatile(dst, MMPTE { u_long: new0 });
                }
                None => return false,
            }
        }
        for idx in 1..PT_ENTRIES {
            let entry = core::ptr::read_volatile(system.add(idx)).raw();
            if entry & PTE_P == 0 {
                continue;
            }
            let kernel_entry = crate::arch::translate_x86_root_entry(entry);
            core::ptr::write_volatile(
                dst.add(idx),
                MMPTE {
                    u_long: kernel_entry,
                },
            );
        }
    }
    true
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Merge kernel mappings that were installed in the system's low
/// identity chain after a process PML4 snapshot into that process's
/// private copy of the chain.
///
/// `sys_phys` / `proc_phys` are the physical addresses of the two
/// tables at `level` (3 = PDPT, 2 = PD, 1 = PT). Semantics:
///
/// * Supervisor leaves (U clear) are merged into absent process
///   slots. Present slots are never overwritten: a process leaf at
///   the same position is either its own user mapping (user wins) or
///   a copy of an older kernel mapping (still valid).
/// * User leaves (U set) in the system chain are skipped: they
///   belong to whichever process mapped them, not to this process.
/// * Absent intermediates are deep-copied wholesale via
///   `copy_identity_chain`; present intermediates are merged
///   recursively.
///
/// Returns `false` on OOM (the caller may retry on the next refresh);
/// pages allocated by completed sub-levels are leaked, as in
/// `copy_identity_chain`.
#[cfg(target_arch = "x86_64")]
unsafe fn sync_identity_chain(sys_phys: u64, proc_phys: u64, level: u8) -> bool {
    let src = sys_phys as *const u64;
    let dst = proc_phys as *mut u64;
    for idx in 0..PT_ENTRIES {
        let sys_entry = core::ptr::read_volatile(src.add(idx));
        if sys_entry & PTE_P == 0 {
            continue;
        }
        let proc_entry = core::ptr::read_volatile(dst.add(idx));
        let is_leaf = level == 1 || (sys_entry & PS_BIT) != 0;
        if is_leaf {
            if proc_entry & PTE_P == 0 && sys_entry & PTE_US == 0 {
                core::ptr::write_volatile(dst.add(idx), sys_entry);
            }
        } else if proc_entry & PTE_P == 0 {
            let child = sys_entry & PTE_FRAME_MASK;
            if let Some(copied) = copy_identity_chain(child, level - 1) {
                let new_entry = (sys_entry & !PTE_FRAME_MASK) | copied;
                core::ptr::write_volatile(dst.add(idx), new_entry);
            } else {
                return false;
            }
        } else {
            let sys_child = sys_entry & PTE_FRAME_MASK;
            let proc_child = proc_entry & PTE_FRAME_MASK;
            if !sync_identity_chain(sys_child, proc_child, level - 1) {
                return false;
            }
        }
    }
    true
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Read a PTE from a table addressed by its physical address.
///
/// Per-process page-table pages are not guaranteed to be in the
/// bootstrap identity map. All physical page-table accesses must go
/// through the kernel direct map and release the system PTE afterwards.
#[inline]
unsafe fn pml4e(pml4_phys: u64, idx: usize) -> u64 {
    let mapped = crate::mm::vm::direct_map_phys(pml4_phys, 4096);
    let va = match mapped {
        Ok(va) => va,
        Err(_) => return 0,
    };
    let value = core::ptr::read_volatile((va as *const u64).add(idx));
    crate::mm::vm::direct_unmap_va(va, 4096);
    value
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Write a PTE in a user PML4 at the given PML4 index.
#[inline]
unsafe fn set_pml4e(pml4_phys: u64, idx: usize, val: u64) {
    let mapped = crate::mm::vm::direct_map_phys(pml4_phys, 4096);
    let va = match mapped {
        Ok(va) => va,
        Err(_) => return,
    };
    core::ptr::write_volatile((va as *mut u64).add(idx), val);
    crate::mm::vm::direct_unmap_va(va, 4096);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Read a PTE from an intermediate page table.
#[inline]
unsafe fn pte_read(table_phys: u64, idx: usize) -> u64 {
    let mapped = crate::mm::vm::direct_map_phys(table_phys, 4096);
    let va = match mapped {
        Ok(va) => va,
        Err(_) => return 0,
    };
    let value = core::ptr::read_volatile((va as *const u64).add(idx));
    crate::mm::vm::direct_unmap_va(va, 4096);
    value
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Write a PTE to an intermediate page table.
#[inline]
unsafe fn pte_write(table_phys: u64, idx: usize, val: u64) {
    let mapped = crate::mm::vm::direct_map_phys(table_phys, 4096);
    let va = match mapped {
        Ok(va) => va,
        Err(_) => return,
    };
    core::ptr::write_volatile((va as *mut u64).add(idx), val);
    crate::mm::vm::direct_unmap_va(va, 4096);
}

/// Result type for per-process mapping operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmStatus {
    Ok,
    OutOfMemory,
    InvalidAddress,
    AlreadyMapped,
}

/// Map a single 4-KiB page in a per-process PML4.
///
/// `pml4_phys` is the physical address of the PML4. `va` is the
/// user-mode virtual address. `pa` is the physical address of the
/// backing page. `flags` are the raw PTE bits to OR with `P=1` —
/// typically `PTE_RW | PTE_US` for user R/W, plus `PTE_NX` if you
/// want to disallow execute.
///
/// Allocates any missing PDPT/PD/PT pages, all of which are marked
/// user-accessible so that the Ring 3 code that walks the page
/// table is allowed to reach the leaf PTE.
pub fn map_page_in_pml4(pml4_phys: u64, va: u64, pa: u64, flags: u64) -> MmStatus {
    if pml4_phys == 0 || va & 0xFFF != 0 || pa & 0xFFF != 0 {
        return MmStatus::InvalidAddress;
    }
    if !crate::arch::common::self_map::current_recursive_self_map_is_supported() {
        return if unsafe {
            crate::arch::map_page_in_root(crate::mm::pfn::phys_to_pfn(pml4_phys), va, pa, flags)
        } {
            MmStatus::Ok
        } else {
            MmStatus::OutOfMemory
        };
    }
    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx = ((va >> 21) & 0x1FF) as usize;
    let pt_idx = ((va >> 12) & 0x1FF) as usize;

    unsafe {
        // PML4 -> PDPT
        let mut pml4e_val = pml4e(pml4_phys, pml4_idx);
        if (pml4e_val & PTE_P) == 0 {
            let new_pdpt = match alloc_zeroed_page() {
                Some(p) => p,
                None => return MmStatus::OutOfMemory,
            };
            pml4e_val = new_pdpt | INT_PTE_BITS;
            set_pml4e(pml4_phys, pml4_idx, pml4e_val);
        }
        let pdpt_phys = pml4e_val & 0x000F_FFFF_FFFF_F000;

        // PDPT -> PD
        let mut pdpte_val = pte_read(pdpt_phys, pdpt_idx);
        // A PDPT entry may already be a 1 GiB large page, typically
        // inherited from the boot identity map. Split that large page
        // into 2 MiB directory entries before trying to install a PT.
        // Without this, the code below would treat the large-page
        // physical address as another page table and read/write memory
        // outside the process page tables.
        if pdpte_val & PTE_P != 0 && pdpte_val & (1u64 << 7) != 0 {
            let Some(new_pd) = alloc_zeroed_page() else {
                return MmStatus::OutOfMemory;
            };
            let large_base = pdpte_val & 0x000F_FFFF_C000_0000;
            let large_flags = pdpte_val & !(1u64 << 7);
            for directory_index in 0..512usize {
                let directory_pa = large_base + (directory_index as u64) * 0x20_0000;
                let directory_entry = directory_pa | large_flags | PTE_A | PTE_D | (1u64 << 7);
                pte_write(new_pd, directory_index, directory_entry);
            }
            pdpte_val = new_pd | INT_PTE_BITS;
            pte_write(pdpt_phys, pdpt_idx, pdpte_val);
        }
        if (pdpte_val & PTE_P) == 0 {
            let new_pd = match alloc_zeroed_page() {
                Some(p) => p,
                None => return MmStatus::OutOfMemory,
            };
            pdpte_val = new_pd | INT_PTE_BITS;
            pte_write(pdpt_phys, pdpt_idx, pdpte_val);
        }
        let pd_phys = pdpte_val & 0x000F_FFFF_FFFF_F000;

        // PD -> PT
        let mut pde_val = pte_read(pd_phys, pd_idx);
        // If the existing PDE is a 2MB large page (PS=1), we cannot
        // mix it with 4KB PT entries — the CPU would still treat it
        // as a leaf mapping. Discard the large-page entry and
        // replace it with a freshly-allocated PT page. We do NOT
        // free the 2MB page's backing physical frame here because
        // that frame belongs to the UEFI/bootloader identity map,
        // not to our PFN allocator (freeing it would corrupt the
        // allocator's bookkeeping).
        if pde_val & PTE_P != 0 && pde_val & (1u64 << 7) != 0 {
            crate::boot_debug_println!(
                "[VAS] map_page_in_pml4: replacing 2MB large PDE at PD[{}] for va=0x{:x}",
                pd_idx,
                va
            );
            pde_val = 0;
        }
        if (pde_val & PTE_P) == 0 {
            let new_pt = match alloc_zeroed_page() {
                Some(p) => p,
                None => return MmStatus::OutOfMemory,
            };
            pde_val = new_pt | INT_PTE_BITS;
            pte_write(pd_phys, pd_idx, pde_val);
            crate::boot_debug_println!(
                "[VAS] map_page_in_pml4: PD[{}] <= 0x{:x} (for va=0x{:x})",
                pd_idx,
                pde_val,
                va
            );
        }
        let pt_phys = pde_val & 0x000F_FFFF_FFFF_F000;

        // Leaf PTE
        // The NX bit lives in bit 63, well above the 12-bit flags
        // window that holds the protection bits, so we OR it in
        // explicitly instead of relying on `flags & 0xFFF`.
        let leaf = (pa & 0x000F_FFFF_FFFF_F000)
            | (flags & 0xFFF)
            | PTE_P
            | PTE_A
            | PTE_D
            | (flags & PTE_NX);
        crate::boot_debug_println!(
            "[VAS] map_page_in_pml4: PT[{}] <= 0x{:x} (for va=0x{:x})",
            pt_idx,
            leaf,
            va
        );
        pte_write(pt_phys, pt_idx, leaf);
    }
    MmStatus::Ok
}

/// Walk a user range and report whether every page in `[va, va+size)`
/// currently has a present PTE. A 0-length range trivially returns
/// `true`. Returns `false` on the first page that is missing or that
/// cannot be reached because an intermediate table is absent.
pub fn is_user_range_mapped(pml4_phys: u64, va: u64, size: u64) -> bool {
    if size == 0 {
        return true;
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let root_pfn = pml4_phys >> 12;
        let mut cur = va & !0xFFFu64;
        let end = (va + size + 0xFFF) & !0xFFFu64;
        while cur < end {
            if !crate::arch::page_is_mapped_in_root(root_pfn, cur) {
                return false;
            }
            cur += 0x1000;
        }
        return true;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let mut cur = va & !0xFFFu64;
        let end = (va + size + 0xFFF) & !0xFFFu64;
        while cur < end {
            let pml4_idx = ((cur >> 39) & 0x1FF) as usize;
            let pdpt_idx = ((cur >> 30) & 0x1FF) as usize;
            let pd_idx = ((cur >> 21) & 0x1FF) as usize;
            let pt_idx = ((cur >> 12) & 0x1FF) as usize;
            unsafe {
                let pml4e_val = pml4e(pml4_phys, pml4_idx);
                if pml4e_val & PTE_P == 0 {
                    return false;
                }
                let pdpt_phys = pml4e_val & 0x000F_FFFF_FFFF_F000;
                let pdpte_val = pte_read(pdpt_phys, pdpt_idx);
                if pdpte_val & PTE_P == 0 {
                    return false;
                }
                let pd_phys = pdpte_val & 0x000F_FFFF_FFFF_F000;
                let pde_val = pte_read(pd_phys, pd_idx);
                if pde_val & PTE_P == 0 {
                    return false;
                }
                let pt_phys = pde_val & 0x000F_FFFF_FFFF_F000;
                let pte_val = pte_read(pt_phys, pt_idx);
                if pte_val & PTE_P == 0 {
                    return false;
                }
            }
            cur += 0x1000;
        }
        true
    }
}

/// Update the protection bits on an existing user range without
/// remapping the underlying pages. Each leaf PTE in `[va, va+size)` is
/// re-programmed so that bits other than `P`, `A`, `D`, and the
/// physical-address bits are taken from `new_protect` (a Win32
/// PAGE_* value).
///
/// The page must already be mapped; this routine will not allocate
/// new tables. Returns `InvalidAddress` if any page in the range is
/// not currently present.
pub fn protect_user_range(pml4_phys: u64, va: u64, size: u64, new_protect: u32) -> MmStatus {
    if size == 0 {
        return MmStatus::Ok;
    }
    let mut cur = va & !0xFFFu64;
    let end = (va + size + 0xFFF) & !0xFFFu64;
    while cur < end {
        let pml4_idx = ((cur >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((cur >> 30) & 0x1FF) as usize;
        let pd_idx = ((cur >> 21) & 0x1FF) as usize;
        let pt_idx = ((cur >> 12) & 0x1FF) as usize;
        unsafe {
            let pml4e_val = pml4e(pml4_phys, pml4_idx);
            if pml4e_val & PTE_P == 0 {
                return MmStatus::InvalidAddress;
            }
            let pdpt_phys = pml4e_val & 0x000F_FFFF_FFFF_F000;
            let pdpte_val = pte_read(pdpt_phys, pdpt_idx);
            if pdpte_val & PTE_P == 0 {
                return MmStatus::InvalidAddress;
            }
            let pd_phys = pdpte_val & 0x000F_FFFF_FFFF_F000;
            let pde_val = pte_read(pd_phys, pd_idx);
            if pde_val & PTE_P == 0 {
                return MmStatus::InvalidAddress;
            }
            let pt_phys = pde_val & 0x000F_FFFF_FFFF_F000;
            let pte_val = pte_read(pt_phys, pt_idx);
            if pte_val & PTE_P == 0 {
                return MmStatus::InvalidAddress;
            }
            // Preserve the physical-address bits and P/A/D; replace
            // protection, NX, user/kernel, etc. from new_protect.
            let pa_bits = pte_val & 0x000F_FFFF_FFFF_F000u64;
            // new_protect is a u32 PAGE_* value; combine with the
            // standard hardware PTE bits expected for user mappings.
            let mut new_pte = pa_bits | PTE_P | PTE_A | PTE_D | PTE_US;
            if new_protect & 0x04 != 0 {
                new_pte |= PTE_RW;
            } // PAGE_READWRITE
            if new_protect & 0x40 != 0 {
                new_pte |= PTE_RW;
            } // PAGE_EXECUTE_READWRITE
            if new_protect & 0xF0 == 0 {
                new_pte |= PTE_NX;
            } // non-executable by default
            pte_write(pt_phys, pt_idx, new_pte);
            // Protection changed on a mapping other CPUs may have in
            // their TLB. A downgrade (clearing the write bit) is only
            // safe once every core dropped the stale writable entry,
            // so this invalidation is cross-core.
            crate::ke::tlb_shootdown::invalidate_va_all_cpus(cur);
        }
        cur += 0x1000;
    }
    MmStatus::Ok
}

/// Map a contiguous range `[va, va+size)` of 4-KiB user pages,
/// allocating one physical frame per 4-KiB page and mapping it with
/// `flags`. Returns the first error encountered; partial progress is
/// not undone.
pub fn map_user_pages(pml4_phys: u64, va: u64, size: u64, flags: u64) -> MmStatus {
    if size == 0 {
        return MmStatus::Ok;
    }
    let mut cur = va & !0xFFFu64;
    let end = (va + size + 0xFFF) & !0xFFFu64;
    while cur < end {
        let pa = match alloc_zeroed_page() {
            Some(p) => p,
            None => return MmStatus::OutOfMemory,
        };
        let r = map_page_in_pml4(pml4_phys, cur, pa, flags);
        if r != MmStatus::Ok {
            return r;
        }
        cur += 0x1000;
    }
    MmStatus::Ok
}

/// Map a contiguous range of user pages but reuse `phys_base` as the
/// backing store. Useful for mapping a kernel-side buffer (e.g. a
/// loaded PE image) into a process.
pub fn map_user_phys_range(
    pml4_phys: u64,
    va: u64,
    phys_base: u64,
    size: u64,
    flags: u64,
) -> MmStatus {
    if size == 0 {
        return MmStatus::Ok;
    }
    let mut cur = va & !0xFFFu64;
    let mut pa = phys_base & !0xFFFu64;
    let end = (va + size + 0xFFF) & !0xFFFu64;
    while cur < end {
        let r = map_page_in_pml4(pml4_phys, cur, pa, flags);
        if r != MmStatus::Ok {
            return r;
        }
        cur += 0x1000;
        pa += 0x1000;
    }
    MmStatus::Ok
}

/// Unmap a user range and free the backing physical pages. PT/PD/PDPT
/// pages that become empty are also freed back to the PFN database.
pub fn unmap_user_pages(pml4_phys: u64, va: u64, size: u64) -> MmStatus {
    if size == 0 {
        return MmStatus::Ok;
    }
    let mut cur = va & !0xFFFu64;
    let end = (va + size + 0xFFF) & !0xFFFu64;
    while cur < end {
        let pml4_idx = ((cur >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((cur >> 30) & 0x1FF) as usize;
        let pd_idx = ((cur >> 21) & 0x1FF) as usize;
        let pt_idx = ((cur >> 12) & 0x1FF) as usize;
        unsafe {
            let pml4e_val = pml4e(pml4_phys, pml4_idx);
            if (pml4e_val & PTE_P) == 0 {
                cur += 0x1000;
                continue;
            }
            let pdpt_phys = pml4e_val & 0x000F_FFFF_FFFF_F000;
            let pdpte_val = pte_read(pdpt_phys, pdpt_idx);
            if (pdpte_val & PTE_P) == 0 {
                cur += 0x1000;
                continue;
            }
            let pd_phys = pdpte_val & 0x000F_FFFF_FFFF_F000;
            let pde_val = pte_read(pd_phys, pd_idx);
            if (pde_val & PTE_P) == 0 {
                cur += 0x1000;
                continue;
            }
            let pt_phys = pde_val & 0x000F_FFFF_FFFF_F000;
            let pte = pte_read(pt_phys, pt_idx);
            if (pte & PTE_P) != 0 {
                let pa = pte & 0x000F_FFFF_FFFF_F000;
                if pa != 0 {
                    pfn::free_pfn(pa >> 12);
                }
                pte_write(pt_phys, pt_idx, 0);
            }
        }
        cur += 0x1000;
    }
    MmStatus::Ok
}

// ---------------------------------------------------------------------------
// User VA allocation (for ntdll NT_ALLOCATE_VIRTUAL_MEMORY)
// ---------------------------------------------------------------------------

/// Global system VA allocator for early boot (before any process context exists).
///
/// This is NOT the primary allocator for user VA ranges — each process's
/// `MmVirtualAddressSpace` has its own `allocate_user_va()` which is the
/// correct, per-process path. This static is kept as a fallback for code
/// that runs before any process context has been set up (e.g., early boot
/// when no process EPROCESS has been created yet).
///
/// Renamed from `USER_VA_ALLOCATOR` to `SYSTEM_VA_ALLOCATOR` to clarify
/// its role and avoid confusion with the per-process allocator.
static SYSTEM_VA_ALLOCATOR: Spinlock<UserVaAllocator> = Spinlock::new(UserVaAllocator::new());

/// Per-process user VA allocator
pub struct UserVaAllocator {
    /// Next VA to allocate
    pub next_va: u64,
    /// End of user VA range
    pub end_va: u64,
    /// Active allocations, identified by their base address.
    pub allocations: [Option<VaAllocation>; MAX_USER_VA_ALLOCATIONS],
}

impl UserVaAllocator {
    pub const fn new() -> Self {
        Self {
            // Start above the x86 bootstrap VA == PA window. User VAs
            // must never overwrite physical-memory translations.
            next_va: USER_BASE,
            // Windows 7 x64 user mode limit is 0x00007FFFFFFFFFFF
            end_va: 0x0000_7FFF_FFFF_F000,
            allocations: [const { None }; MAX_USER_VA_ALLOCATIONS],
        }
    }

    fn is_overlapping(&self, start: u64, end: u64) -> bool {
        self.allocations.iter().any(|allocation| {
            allocation
                .map(|region| start < region.end && region.start < end)
                .unwrap_or(false)
        })
    }

    fn record(&mut self, start: u64, end: u64) -> bool {
        match self.allocations.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(VaAllocation { start, end });
                true
            }
            None => false,
        }
    }
}

impl Default for UserVaAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// A live user VA allocation.
#[derive(Clone, Copy)]
pub struct VaAllocation {
    pub start: u64,
    pub end: u64,
}

pub const MAX_USER_VA_ALLOCATIONS: usize = 256;

/// Allocate user-mode virtual address range.
///
/// This is the **global fallback** allocator used during early boot before
/// any process context exists. Normal per-process VA allocation should use
/// `MmVirtualAddressSpace::allocate_user_va()` instead.
pub fn allocate_user_va(desired_base: u64, size: u64, _protect: u32) -> Option<u64> {
    let mut alloc = SYSTEM_VA_ALLOCATOR.lock();

    // Align size to page boundary
    let aligned_size = (size + 0xFFF) & !0xFFF;

    // Find a suitable VA
    let va = if desired_base == 0 {
        let mut candidate = alloc.next_va;
        loop {
            if candidate > alloc.end_va || aligned_size > alloc.end_va - candidate {
                return None;
            }
            let end = candidate + aligned_size;
            if !alloc.is_overlapping(candidate, end) {
                break;
            }
            candidate = (end + 0xFFF) & !0xFFF;
        }
        candidate
    } else {
        let base = desired_base & !0xFFF;
        let end = base.checked_add(aligned_size)?;
        if base >= 0x0000_7FFF_FFFF_FFFF || end > alloc.end_va || alloc.is_overlapping(base, end) {
            return None;
        }
        base
    };

    if alloc.record(va, va + aligned_size) {
        Some(va)
    } else {
        None
    }
}

/// Free user-mode virtual address range.
pub fn free_user_va(va: u64) -> bool {
    let mut alloc = SYSTEM_VA_ALLOCATOR.lock();
    let index = alloc
        .allocations
        .iter()
        .position(|allocation| allocation.map(|region| region.start == va).unwrap_or(false));
    match index {
        Some(index) => {
            alloc.allocations[index] = None;
            true
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/// Self-test: create a user address space and verify that PML4[0] is
/// a private deep copy of the system's low identity chain (present,
/// but backed by its own freshly allocated page tables) rather than a
/// shared reference to the system root.
pub fn self_test_user_address_space() -> bool {
    let system = system_pml4_mut();
    let kernel_entry_0 = unsafe { (*system.add(0)).raw() };

    let new_pml4_phys = match create_user_address_space() {
        Some(p) => p,
        None => {
            // [DISABLED-KPRINTLN]             // // kprintln!("[RING3-A1] self_test: create_user_address_space returned None");
            return false;
        }
    };
    unsafe {
        let new_pml4 = new_pml4_phys as *const MMPTE;
        let copied = (*new_pml4.add(0)).raw();
        // PML4[0] must be a private deep copy of the system's low
        // identity chain: present, and backed by a different frame
        // than the system root entry. Sharing the system frame would
        // re-introduce the cross-process user-mapping leak.
        if copied & PTE_P == 0 {
            return false;
        }
        if copied & PTE_FRAME_MASK == kernel_entry_0 & PTE_FRAME_MASK {
            return false;
        }
        // The user half of the copy must not carry user privileges
        // over from the system root.
        if (*new_pml4.add(255)).raw() & PTE_US != 0 {
            return false;
        }
    }
    // [DISABLED-KPRINTLN]     // // kprintln!("[RING3-A1] OK: user PML4 at 0x{:x}, system PML4 fully copied",
    // //     // [DISABLED-KPRINTLN]               new_pml4_phys);

    // A2 self-test: map a single user page and a user stack.
    if map_user_pages(
        new_pml4_phys,
        USER_STACK_BASE,
        USER_STACK_SIZE,
        PTE_RW | PTE_US,
    ) != MmStatus::Ok
    {
        // [DISABLED-KPRINTLN]         // // kprintln!("[RING3-A2] FAIL: map_user_pages for stack returned error");
        return false;
    }
    // [DISABLED-KPRINTLN]     // // kprintln!("[RING3-A2] OK: mapped user stack at 0x{:x} ({} bytes)",
    // //     // [DISABLED-KPRINTLN]               USER_STACK_BASE, USER_STACK_SIZE);

    // Map a single 4-KiB page for the user entry stub at USER_ENTRY_BASE.
    if map_user_pages(new_pml4_phys, USER_ENTRY_BASE, 0x1000, PTE_RW | PTE_US) != MmStatus::Ok {
        // [DISABLED-KPRINTLN]         // // kprintln!("[RING3-A2] FAIL: map_user_pages for entry returned error");
        return false;
    }
    // [DISABLED-KPRINTLN]     // // kprintln!("[RING3-A2] OK: mapped user entry at 0x{:x}", USER_ENTRY_BASE);

    // Free the address space (we have not attached it, so CR3 still
    // points to the system PML4).
    unmap_user_pages(new_pml4_phys, USER_STACK_BASE, USER_STACK_SIZE);
    unmap_user_pages(new_pml4_phys, USER_ENTRY_BASE, 0x1000);
    pfn::free_pfn(new_pml4_phys >> 12);
    // [DISABLED-KPRINTLN]     // // kprintln!("[RING3-A1/A2] self_test PASS");
    true
}

// ---------------------------------------------------------------------------
// Phase 0 user-mode layout constants
// ---------------------------------------------------------------------------

/// Default user-mode image base. The PE loader maps the loaded
/// executable starting at this address.
///
/// Note: Standard Windows 7 x64 uses 0x00400000, but this implementation
/// uses 0x00100000 for Phase 0 simplicity. The address should be page-aligned
/// and in the user-space range (below 0x0000_0001_0000_0000).
///
/// RISC-V note: QEMU virt wires the NS16550A UART as an identity map at
/// VA 0x1000_0000, and process roots share that mapping.  Loading user
/// images at 0x1000_0000 therefore overwrites the UART PTE and silently
/// kills kernel serial output (and any MMIO behind shared tables), so the
/// image base lives at 0x4000_0000, which is neither RAM nor device MMIO.
#[cfg(target_arch = "riscv64")]
pub const DEFAULT_USER_IMAGE_BASE: u64 = 0x0000_0000_4000_0000;

#[cfg(not(target_arch = "riscv64"))]
pub const DEFAULT_USER_IMAGE_BASE: u64 = 0x0000_1000_0000_0000;

/// Default user entry point (the first bytes of the mapped image).
pub const DEFAULT_USER_ENTRY_RIP: u64 = 0x0000_0000_0010_1000;

/// Top of the user-mode stack.
///
/// CRITICAL-006: moved down from `0x0000_7FFF_F000_0000` to
/// `0x0000_7FFF_DE00_0000` so there is 16 MiB of headroom below
/// the user-space limit for PEB (0x7FFE_D000), TEB, the loader
/// heap, and stack guard pages. With the previous value, the user
/// stack's top was less than 16 MiB from `0x0000_7FFF_FFFF_FFFF`
/// and too close to `PEB_VIRTUAL_ADDRESS` for any non-trivial
/// loader to fit safely.
#[cfg(target_arch = "riscv64")]
pub const USER_STACK_BASE: u64 = 0x0000_0000_7F_00_0000;

#[cfg(not(target_arch = "riscv64"))]
pub const USER_STACK_BASE: u64 = 0x0000_7FFF_DE00_0000;
pub const USER_STACK_SIZE: u64 = 0x0010_0000; // 1 MiB
pub const USER_STACK_TOP: u64 = USER_STACK_BASE + USER_STACK_SIZE;

/// Initial bytes reserved below the user stack top for the Ring 3
/// launcher frame and the compiler's stack-probing window.
pub const USER_STACK_INITIAL_HEAD: u64 = 0x2000;

/// User entry point where the minimal ring3 stub is mapped.
///
/// CRITICAL-005: the previous value `0xFFFF_8000_0000_1000` lived
/// in the kernel's canonical-high region. That made it impossible
/// to use the user-mode PML4 entry cleanly, and meant the entry
/// page was actually a kernel address masquerading as a user
/// entry. The user-mode stub now lives in the low half of the
/// address space at `0x0000_0000_0010_0000`, which is a true user
/// VA. This matches what NT 6.1 does for `csrss.exe` /
/// `smss.exe` minimal stubs.
#[cfg(target_arch = "riscv64")]
pub const USER_ENTRY_BASE: u64 = 0x0000_0000_0010_0000;

#[cfg(not(target_arch = "riscv64"))]
pub const USER_ENTRY_BASE: u64 = 0x0000_1000_0000_0000;

/// User entry RIP where the minimal ring3 stub starts executing.
pub const USER_ENTRY_RIP: u64 = USER_ENTRY_BASE + 0x1000;

/// Guard page one slot below the user stack.
pub const USER_STACK_GUARD_BASE: u64 = USER_STACK_BASE - 0x1000;

// Compile-time layout assertions: keep `USER_ENTRY_BASE`,
// `USER_STACK_BASE`, and `USER_STACK_TOP` from drifting back into
// the kernel half or overlapping PEB/TEB addresses. See CRITICAL-005
// and CRITICAL-006.
const _: () = {
    // 2 MiB below the user-space canonical limit
    #[cfg(target_arch = "riscv64")]
    const USER_LIMIT: u64 = 0x0000_0000_7F_E0_0000;
    #[cfg(not(target_arch = "riscv64"))]
    const USER_LIMIT: u64 = 0x0000_7FFF_FFFF_FFFF;
    assert!(
        USER_STACK_BASE < USER_LIMIT - 0x0040_0000,
        "USER_STACK_BASE must be at least 4 MiB below USER_LIMIT"
    );
    assert!(
        USER_STACK_TOP < USER_LIMIT,
        "USER_STACK_TOP must remain in user half of address space"
    );
    assert!(
        USER_STACK_TOP < 0x0000_7FFF_EF00_0000,
        "USER_STACK_TOP must leave 16 MiB for PEB/TEB/heap/guards"
    );
    assert!(
        USER_ENTRY_BASE < USER_STACK_BASE,
        "USER_ENTRY_BASE must be below USER_STACK_BASE (low half)"
    );
    assert!(
        USER_ENTRY_BASE >= 0x1000,
        "USER_ENTRY_BASE must be in low half, not page 0"
    );
    assert!(
        USER_ENTRY_BASE & 0xFFFF_8000_0000_0000 == 0,
        "USER_ENTRY_BASE must NOT live in the kernel canonical-high half"
    );
};

/// TEB (Thread environment Block) base address.
///
/// Windows 7 x64 places the first thread's TEB at 0x0000_7FFF_FFDF_0000
/// (canonical high address in the user half). Subsequent TEBs are spaced
/// at `TEB_SIZE * cpu_number` apart.
///
/// Reference: geoffchappell.com studies/windows/km/ntoskrnl/inc/ntos/
/// TEB_BASE and TEB_SIZE are imported from `crate::mm::constants`.
static CURRENT_ROOT: AtomicU64 = AtomicU64::new(0);

pub fn current_root() -> u64 {
    CURRENT_ROOT.load(Ordering::SeqCst)
}
pub fn set_current_root(root: u64) {
    CURRENT_ROOT.store(root, Ordering::SeqCst);
}

// =============================================================================
// Self-Map Status and Verification
// =============================================================================

/// Self-map status
#[derive(Debug, Clone, Copy)]
pub enum SelfMapStatus {
    /// Self-map is installed and verified
    Installed,
    /// Self-map installation was attempted but not verified
    Unverified,
    /// Self-map installation was skipped
    Skipped,
    /// Self-map installation failed
    Failed(&'static str),
}

/// Track the self-map status for debugging
static SELF_MAP_STATUS: AtomicU64 = AtomicU64::new(0);

impl SelfMapStatus {
    pub fn as_u64(&self) -> u64 {
        match self {
            SelfMapStatus::Installed => 1,
            SelfMapStatus::Unverified => 2,
            SelfMapStatus::Skipped => 3,
            SelfMapStatus::Failed(_) => 4,
        }
    }

    pub fn from_u64(val: u64) -> &'static str {
        match val {
            1 => "Installed",
            2 => "Unverified",
            3 => "Skipped",
            4 => "Failed",
            _ => "Unknown",
        }
    }
}

/// Self-map installation error types
#[derive(Debug, Clone, Copy)]
pub enum SelfMapError {
    /// Failed to allocate PFN for page table pages
    OutOfMemory,
    /// PML4 page is not writable (CR0.WP issue)
    Pml4NotWritable,
    /// Invalid PML4 PFN provided
    InvalidPfn,
    /// Self-map verification failed after installation
    VerificationFailed,
    /// Identity mapping failed
    IdentityMappingFailed,
}

impl SelfMapError {
    /// Get a human-readable description of the error
    pub fn as_str(&self) -> &'static str {
        match self {
            SelfMapError::OutOfMemory => "Out of memory: failed to allocate page table PFN",
            SelfMapError::Pml4NotWritable => "PML4 page is not writable",
            SelfMapError::InvalidPfn => "Invalid PML4 PFN",
            SelfMapError::VerificationFailed => "Self-map verification failed after installation",
            SelfMapError::IdentityMappingFailed => "Failed to create identity mapping for PML4",
        }
    }

    /// Check if this error indicates a fatal condition
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            SelfMapError::OutOfMemory
                | SelfMapError::Pml4NotWritable
                | SelfMapError::VerificationFailed
        )
    }
}

/// Try to enable self-map on the current PML4
/// Returns Ok if successful, Err with message if failed
/// CRITICAL-009: Try to enable the recursive PML4 self-map.
///
/// The recursive self-map is the kernel's only way to read or
/// modify arbitrary page-table entries from a known VA. Without
/// it, the kernel cannot walk the page tables of any process
/// (including its own kernel half) and cannot service page faults
/// from Ring 3.
///
/// Failure is therefore **fatal**. The previous behaviour — which
/// silently fell back to a single-level self-map and then to
/// `Ok(Failed(...))` if even that didn't work — left the kernel
/// running on a broken page-table infrastructure that would
/// triple-fault the moment any Ring 3 code touched a non-trivial
/// VA. We now print a structured diagnostic and halt.
///
/// Returns `Ok(SelfMapStatus::Installed)` only when
/// `verify_self_map_detailed()` confirms the layout.
pub fn try_enable_self_map() -> Result<SelfMapStatus, &'static str> {
    if !crate::arch::common::self_map::current_recursive_self_map_is_supported() {
        return Ok(SelfMapStatus::Installed);
    }

    // read current page root
    let page_root = crate::arch::read_current_page_root();
    let pml4_phys = page_root;

    // Check if self-map is already installed
    unsafe {
        let pml4 = pml4_phys as *const u64;
        let existing = *pml4.add(MI_SELF_MAP_INDEX);
        if existing != 0 && (existing & 0x01 != 0) {
            // Self-map already present
            return Ok(SelfMapStatus::Installed);
        }
    }

    // Get PML4 PFN
    let pml4_pfn = pml4_phys >> 12;

    // Try to install the full 4-level self-map. Any failure here
    // is fatal — we no longer fall back to a single-level self-map
    // because the kernel needs to walk the full 4-level chain
    // anyway (e.g. for process page-table debugging, VAD fill, MDL
    // mapping, etc.). A single-level self-map only supports
    // PML4-level access.
    if let Err(e) = install_self_map(pml4_pfn) {
        let msg = e.as_str();
        crate::hal::serial::write_string_always("[VAS] FATAL: self-map install failed: ");
        crate::hal::serial::write_string(msg);
        crate::hal::serial::write_string("\r\n");
        crate::arch::halt_loop();
    }

    // Verify the installation. Even though install_self_map()
    // returned Ok, the verification walk is the authoritative
    // check — if it fails we treat that as a fatal page-table
    // corruption event.
    if verify_self_map_detailed() {
        Ok(SelfMapStatus::Installed)
    } else {
        crate::hal::serial::write_string(
            "[VAS] FATAL: self-map verify failed after install_self_map\r\n",
        );
        crate::arch::halt_loop();
    }
}

/// Check if self-map is properly installed (returns bool)
/// This is a quick check without detailed error reporting.
///
/// Two legitimate self-map layouts are recognised:
/// 1. **Single-level**: `PML4[0x1ED]` points directly at the PML4 page
///    (so reading any PML4 entry via the recursive VA returns the
///    page-table entry itself). The PFN of `PML4[0x1ED]` equals the
///    PML4 base PFN.
/// 2. **4-level**: `PML4[0x1ED]` points at the first page of a
///    4-level chain (pdpt_self → pd_self → pt_self → self_page where
///    self_page mirrors the PML4). The PFN of `PML4[0x1ED]` is the
///    pdpt_self PFN, not the PML4 PFN. We additionally verify that
///    walking `PML4[0x1ED] → pdpt[0x1ED] → pd[0x1ED] → pt[0x1ED]`
///    yields a valid (non-zero) PTE that points at the PML4 page or
///    another mirror page.
pub fn check_self_map() -> bool {
    crate::arch::common::self_map::current_recursive_self_map_is_installed()
}

/// Verify that self-map is properly installed (detailed version)
/// Returns true if PML4[0x1ED] points back to the PML4 itself OR
/// to a valid 4-level self-map chain. See `check_self_map` for the
/// accepted layouts.
pub fn verify_self_map_detailed() -> bool {
    if !crate::arch::common::self_map::current_recursive_self_map_is_supported() {
        return true;
    }

    let pml4_phys = crate::arch::read_current_page_root();
    let pml4_pfn = pml4_phys >> 12;

    unsafe {
        let pml4 = pml4_phys as *const u64;
        let entry = *pml4.add(MI_SELF_MAP_INDEX);

        // Check if P bit (bit 0) is set
        if entry & 0x01 == 0 {
            // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: P bit not set at PML4[0x1ED]");
            return false;
        }

        let entry_pfn = (entry & 0x000F_FFFF_FFFF_F000) >> 12;
        if entry_pfn == pml4_pfn {
            // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: PML4[0x1ED]=0x{:016x} (single-level self-map) OK", entry);
            return true;
        }

        // Walk the 4-level chain and confirm each level is present
        // and the leaf closes the walk (either self-referential to
        // the PML4 page or back to the pdpt_self page).
        let pdpt_phys = entry_pfn << 12;
        let pdpt = pdpt_phys as *const u64;
        if (*pdpt.add(MI_SELF_MAP_INDEX) & 0x01) == 0 {
            // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: pdpt[0x1ED] not present");
            return false;
        }
        let pd_phys = ((*pdpt.add(MI_SELF_MAP_INDEX)) & 0x000F_FFFF_FFFF_F000) >> 12 << 12;
        let pd = pd_phys as *const u64;
        if (*pd.add(MI_SELF_MAP_INDEX) & 0x01) == 0 {
            // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: pd[0x1ED] not present");
            return false;
        }
        let pt_phys = ((*pd.add(MI_SELF_MAP_INDEX)) & 0x000F_FFFF_FFFF_F000) >> 12 << 12;
        let pt = pt_phys as *const u64;
        if (*pt.add(MI_SELF_MAP_INDEX) & 0x01) == 0 {
            // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: pt[0x1ED] not present");
            return false;
        }
        let leaf_pfn = ((*pt.add(MI_SELF_MAP_INDEX)) & 0x000F_FFFF_FFFF_F000) >> 12;
        if leaf_pfn != pml4_pfn && leaf_pfn != entry_pfn {
            // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: leaf PFN={:x} does not close loop", leaf_pfn);
            return false;
        }
        // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] verify_self_map: 4-level chain OK (pml4=0x{:x}, pdpt=0x{:x}, leaf=0x{:x})",
        // //     // [DISABLED-KPRINTLN]                   pml4_phys, pdpt_phys, leaf_pfn << 12);
        true
    }
}

/// Get current self-map status for debugging
pub fn get_self_map_status() -> &'static str {
    let status = SELF_MAP_STATUS.load(Ordering::SeqCst);
    SelfMapStatus::from_u64(status)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Reserve every intermediate page-table page reachable from the
/// system root. The PFN allocator is initialized after the bootstrap
/// identity map, so it cannot know which pages already hold PML4,
/// PDPT, PD, or PT structures. Without this walk it can later hand one
/// of those pages out and zero it, silently deleting kernel mappings.
#[cfg(target_arch = "x86_64")]
pub unsafe fn reserve_system_page_tables(pml4_phys: u64) {
    const PRESENT: u64 = 1;
    const LARGE_PAGE: u64 = 1 << 7;
    const FRAME_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    let mut reserved_count = 0u64;
    let mut reserve_failed = false;
    let mut reserve = |pfn| {
        if !crate::mm::pfn::reserve_pfn(pfn) {
            reserve_failed = true;
        } else {
            reserved_count += 1;
        }
    };

    let pml4 = pml4_phys as *const u64;
    for pml4_idx in 0..PT_ENTRIES {
        let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
        if pml4e & PRESENT == 0 {
            continue;
        }
        let pdpt_phys = pml4e & FRAME_MASK;
        reserve(pdpt_phys >> 12);

        let pdpt = pdpt_phys as *const u64;
        for pdpt_idx in 0..PT_ENTRIES {
            let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
            if pdpte & PRESENT == 0 {
                continue;
            }
            let pd_phys = pdpte & FRAME_MASK;
            reserve(pd_phys >> 12);
            if pdpte & LARGE_PAGE != 0 {
                continue;
            }

            let pd = pd_phys as *const u64;
            for pd_idx in 0..PT_ENTRIES {
                let pde = core::ptr::read_volatile(pd.add(pd_idx));
                if pde & PRESENT == 0 || pde & LARGE_PAGE != 0 {
                    continue;
                }
                reserve((pde & FRAME_MASK) >> 12);
            }
        }
    }

    crate::hal::serial::write_string_always("[VAS] SYSPT reserved=");
    crate::mm::write_decimal_u64(reserved_count);
    crate::hal::serial::write_string_always(" failed=");
    crate::hal::serial::write_string_always(if reserve_failed { "1" } else { "0" });
    crate::hal::serial::write_string_always("\r\n");
}

/// Initialise the system address space. Allocates a PML4 page and
/// installs the self-map.
pub fn init() {
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::paging::vector_page_check("vas_enter");
    // read the current page root
    let page_root = crate::arch::read_current_page_root();
    let pml4_phys = page_root;

    // CRITICAL: reserve the system PML4 PFN in the PFN database
    // so that no allocator (including the zero-page worker that
    // pops free pages and zeroes them) ever hands this page back
    // out. Without this reservation the zero-page worker would
    // eventually overwrite the system PML4 with zeros, and the
    // next `create_user_address_space` call would receive the
    // system PML4 as its "fresh" page, smashing the kernel half
    // of the address space and producing nested page-faults as
    // soon as the new process tries to execute in Ring 3.
    let pml4_pfn = pml4_phys >> 12;
    crate::boot_debug_println!("[VAS] RESERVING CR3");
    let reserved = crate::mm::pfn::reserve_pfn(pml4_pfn);
    let _ = reserved;
    crate::boot_debug_println!("[VAS] CR3 RESERVED pfn=0x{:x}", pml4_pfn);
    ensure_identity_or_log(pml4_phys & !0x1F_FFFF, 0x20_0000, "system PML4 page");
    {
        let (head, count) = crate::mm::pfn::get_free_list_stats();
        crate::hal::serial::write_string_always("[VASCHK] after pml4 identity head=");
        crate::mm::write_decimal_u64(head);
        crate::hal::serial::write_string_always(" count=");
        crate::mm::write_decimal_u64(count);
        crate::hal::serial::write_string_always("\r\n");
    }

    // The kernel uses VA == PA for bootstrap physical-memory access.
    // Install the complete x86 bootstrap window once, rather than
    // lazily installing 2 MiB slices whenever a fresh physical page is
    // touched. This removes both the page faults and the possibility of
    // a user VA below 4 GiB replacing part of the bootstrap map.
    if let Some(identity_limit) = crate::arch::identity_mapping_limit() {
        ensure_identity_or_log(0, identity_limit, "low RAM identity window");
    }
    {
        let (head, count) = crate::mm::pfn::get_free_list_stats();
        crate::hal::serial::write_string_always("[VASCHK] after low identity head=");
        crate::mm::write_decimal_u64(head);
        crate::hal::serial::write_string_always(" count=");
        crate::mm::write_decimal_u64(count);
        crate::hal::serial::write_string_always("\r\n");
    }

    // LoongArch64 MMIO (UART, EXTIOI, PCI ECAM).
    #[cfg(target_arch = "loongarch64")]
    {
        ensure_identity_or_log(0x1FE0_0000, 0x20_0000, "LoongArch64 MMIO (UART/EXTIOI)");
        ensure_identity_or_log(0x2000_0000, 0x1000_0000, "LoongArch64 MMIO (ECAM)");

        // CRMD switches from direct-address mode to mapped mode as one
        // instruction sequence inside load_page_root. The first mapped
        // instruction is the next instruction in the executing loader
        // image, and the active frame still uses the loader stack. The
        // low-RAM identity window above does not cover either range.
        // Map the current image and stack before flushing the TLB and
        // setting PG=1.
        let image_va = crate::kernel_main::kernel_main as *const () as u64;
        ensure_identity_or_log(
            image_va & !0x00FF_FFFF,
            0x0100_0000,
            "LoongArch64 loader image",
        );

        let stack_sp: u64;
        unsafe {
            core::arch::asm!("move {}, $sp", out(reg) stack_sp, options(nomem, nostack));
        }
        ensure_identity_or_log(
            stack_sp & !0x003F_FFFF,
            0x0040_0000,
            "LoongArch64 loader stack",
        );
    }

    // RISC-V: QEMU virt RAM starts at 0x8000_0000. Map the *entire*
    // tracked RAM range using 2 MiB superpages so the kernel retains
    // VA==PA access to every physical page once Sv39 replaces bare
    // mode. The previous partial windows (256 MiB each) left the UEFI
    // SystemTable, runtime-services code, and other high-RAM firmware
    // regions unmapped, causing page faults the moment a process root
    // was loaded.
    #[cfg(target_arch = "riscv64")]
    {
        // Use the PFN database's tracked range if available, otherwise
        // fall back to a conservative QEMU virt default (10 GiB).
        let (ram_base, ram_end) = {
            let db = crate::mm::pfn::PFN_DB.lock();
            if db.initialized && db.highest_pfn > db.lowest_pfn {
                (db.lowest_pfn << 12, db.highest_pfn << 12)
            } else {
                (0x8000_0000u64, 0x2800_0000u64)
            }
        };
        // Map in 2 MiB superpage chunks. `identity_map_region` handles
        // the superpage / sub-page split internally.
        ensure_identity_or_log(ram_base, ram_end - ram_base, "RISC-V tracked RAM range");

        // Map the UEFI SystemTable and firmware runtime region near the
        // top of RAM (above the PFN database's tracked range). This is
        // where EDK2 places its runtime data on QEMU virt.
        ensure_identity_or_log(0x27FF0000, 0x10_000, "RISC-V UEFI runtime region");

        // The kernel boots in Sv39 bare mode and the system root is
        // only enabled later. Preserve the current image and stack in
        // that root so a temporary switch back to system space cannot
        // fault on the instruction stream or the active stack.
        let image_va = crate::kernel_main::kernel_main as *const () as u64;
        ensure_identity_or_log(image_va & !0x00FF_FFFF, 0x0100_0000, "RISC-V kernel image");

        let stack_sp: u64;
        unsafe {
            core::arch::asm!("mv {}, sp", out(reg) stack_sp, options(nomem, nostack));
        }
        ensure_identity_or_log(stack_sp & !0x003F_FFFF, 0x0040_0000, "RISC-V kernel stack");
    }

    // Enable mapped-address mode (PG=1, DA=0).
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        crate::arch::loongarch64::paging::vector_page_check("vas_prepg");
        let root = crate::arch::read_current_page_root();
        if root != 0 {
            crate::arch::loongarch64::paging::load_page_root(root >> 12);
        }
        crate::arch::loongarch64::paging::vector_page_check("vas_pg_on");
    }

    // Initialize VAS state first
    {
        crate::boot_debug_println!("[VAS] LOCK ABOUT");
        let mut sys = match MM_SYSTEM_VAS.try_lock() {
            Some(guard) => {
                crate::boot_debug_println!("[VAS] TRY LOCK OK");
                guard
            }
            None => {
                crate::boot_debug_println!("[VAS] TRY LOCK BUSY");
                MM_SYSTEM_VAS.lock()
            }
        };
        crate::boot_debug_println!("[VAS] LOCK HELD");
        sys.pml4_phys = pml4_phys;
        sys.pml4_virt = pml4_phys;
        sys.initialized = true;
        set_current_root(sys.pml4_phys);
        crate::boot_debug_println!("[VAS] STATE WRITTEN");
    }
    crate::boot_debug_println!("[VAS] STATE READY");

    // Install the self-map. Without it, `pte_address_of()` returns
    // a virtual address in the `PTE_BASE` region that has no mapping,
    // so every page-table lookup (e.g. `syspte::map_io_space`, used
    // by NVMe and AHCI DMA, and every `mm::vm::virt_to_phys()` call)
    // page-faults. The historical "kprintln crash workaround" that
    // disabled this path is no longer needed: `kprintln!` now uses a
    // byte-copy writer that does not trigger `rep movsb` corruption.
    //
    // `try_enable_self_map` always returns `Ok` today (it falls back
    // to the single-level layout internally and reports failure via
    // `SelfMapStatus::Failed`), but we still cover the `Err` arm
    // because the signature promises a `Result`.
    let status = match try_enable_self_map() {
        Ok(SelfMapStatus::Installed) => {
            crate::boot_debug_println!("[VAS] init: self-map installed (verified)");
            SelfMapStatus::Installed
        }
        Ok(SelfMapStatus::Failed(reason)) => {
            crate::boot_println!("[VAS] init: self-map FAILED, falling back to single-level");
            install_single_level_self_map(pml4_phys);
            SelfMapStatus::Failed(reason)
        }
        Ok(other) => {
            crate::boot_println!("[VAS] init: self-map partial, installing single-level fallback");
            install_single_level_self_map(pml4_phys);
            other
        }
        Err(reason) => {
            crate::boot_println!("[VAS] init: try_enable_self_map returned Err, falling back");
            install_single_level_self_map(pml4_phys);
            SelfMapStatus::Failed(reason)
        }
    };
    SELF_MAP_STATUS.store(status.as_u64(), Ordering::SeqCst);

    if install_hyperspace_tables(pml4_pfn).is_err() {
        crate::hal::serial::write_string_always("[VAS] FATAL: hyperspace table install failed\r\n");
        crate::arch::halt_loop();
    }

    // Final verification
    if verify_self_map_detailed() {
        crate::boot_debug_println!("[VAS] init: self-map verification PASSED");
    } else {
        crate::hal::serial::write_string_always(
            "[VAS] init: self-map verification FAILED (fallback)\r\n",
        );
    }

    crate::boot_debug_println!("[VAS] init: done");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pte_address_calculation() {
        // PTE_BASE + ((VA & canonical_mask) >> 12) * 8
        let va = 0x1234_5678u64;
        let expected = PTE_BASE + (((va & VIRTUAL_ADDRESS_MASK) >> 12) * 8);
        assert_eq!(pte_address_of(va) as u64, expected);
    }

    #[test]
    fn self_map_constants() {
        // From docs/mem1.md
        assert_eq!(PTE_BASE, 0xFFFF_F680_0000_0000);
        // PXE_BASE is at PTE_BASE with 0x1ED in PML4 index + 0x1ED in
        // PDPT index + 0x1ED in PD index + 0x1ED in PT index:
        // = 0x1ED << 39 | 0x1ED << 30 | 0x1ED << 21 | 0x1ED << 12
        // The high 16 bits are the canonical-address sign-extension.
        let want = 0x1EDu64 << 39
            | 0x1EDu64 << 30
            | 0x1EDu64 << 21
            | 0x1EDu64 << 12
            | 0xFFFF_0000_0000_0000;
        assert_eq!(PXE_BASE, want);
    }

    #[test]
    fn pde_address_calculation() {
        // The PDE index is the full PT-page number: masking to 9
        // bits would alias every page table past the first 2 MiB.
        let va = 0x0000_7FFF_FFFF_FFFFu64;
        let expected = PDE_BASE + (((va & VIRTUAL_ADDRESS_MASK) >> 21) * 8);
        assert_eq!(pde_address_of(va) as u64, expected);
    }

    #[test]
    fn ppe_address_calculation() {
        // The PPE index is the full PD-page number.
        let va = 0x0000_7FFF_FFFF_FFFFu64;
        let expected = PPE_BASE + (((va & VIRTUAL_ADDRESS_MASK) >> 30) * 8);
        assert_eq!(ppe_address_of(va) as u64, expected);
    }

    #[test]
    fn pxe_address_calculation() {
        let va = 0x1234_5678u64;
        let expected = PXE_BASE + (((va >> 39) & 0x1FF) * 8);
        assert_eq!(pxe_address_of(va) as u64, expected);
    }

    #[test]
    fn self_map_index() {
        // MI_SELF_MAP_INDEX should be 0x1ED
        assert_eq!(MI_SELF_MAP_INDEX, 0x1ED);
    }

    #[test]
    fn user_address_constants() {
        assert!(USER_BASE < 0x0000_8000_0000_0000);
        assert!(USER_LIMIT <= 0x0000_7FFF_FFFF_FFFF);
        assert!(USER_STACK_BASE > USER_BASE);
        assert!(USER_STACK_TOP > USER_STACK_BASE);
    }

    #[test]
    fn kernel_address_constants() {
        assert!(KERNEL_BASE >= 0xFFFF_8000_0000_0000);
        assert!(KERNEL_LIMIT == 0xFFFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn pte_bits() {
        // Test PTE bit definitions
        assert_eq!(PTE_P, 0x1);
        assert_eq!(PTE_RW, 0x2);
        assert_eq!(PTE_US, 0x4);
        assert_eq!(PTE_A, 0x20);
        assert_eq!(PTE_D, 0x40);
        assert_eq!(PTE_NX, 1u64 << 63);
    }

    #[test]
    fn int_pte_bits() {
        // INT_PTE_BITS should include P + RW + US + A + D
        assert!(INT_PTE_BITS & PTE_P != 0);
        assert!(INT_PTE_BITS & PTE_RW != 0);
        assert!(INT_PTE_BITS & PTE_US != 0);
        assert!(INT_PTE_BITS & PTE_A != 0);
        assert!(INT_PTE_BITS & PTE_D != 0);
    }

    #[test]
    fn hyperspace_constants() {
        assert!(HYPERSPACE_BASE >= 0xFFFF_F700_0000_0000);
        assert!(HYPERSPACE_END > HYPERSPACE_BASE);
        assert_eq!(HYPERSPACE_ENTRIES, 512);
    }

    #[test]
    fn system_pte_constants() {
        // These constants should match syspte.rs definitions
        // System PTE pool should be in kernel space
        let expected_base = 0xFFFF_F900_0000_0000u64;
        let expected_end = 0xFFFF_F9A0_0000_0000u64;
        assert!(expected_end > expected_base);
    }

    #[test]
    fn page_size_constant() {
        assert_eq!(PAGE_SIZE, 4096);
        assert_eq!(PT_ENTRIES, 512);
    }

    #[test]
    fn self_map_error_types() {
        // Test SelfMapError can be created and inspected
        let err = SelfMapError::OutOfMemory;
        assert_eq!(
            err.as_str(),
            "Out of memory: failed to allocate page table PFN"
        );
        assert!(err.is_fatal());

        let err2 = SelfMapError::IdentityMappingFailed;
        assert!(!err2.is_fatal());
    }
}
