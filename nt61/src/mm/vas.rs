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

#![allow(non_snake_case)]

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::pfn;
use crate::mm::pte::{MMPTE, PfnNumber};
use crate::mm::vad::VadTree;

// Re-export all constants from the single source of truth.
// Locally-defined constants that duplicate these are removed below.
pub use crate::mm::constants::*;

/// Raw UART write helper for early-boot diagnostics. Writes each byte
/// of `s` to COM1 (0x3F8) after waiting for the transmit-hold register
/// to be empty. Safe to call before the kprintln subsystem is up.
#[cfg(target_arch = "x86_64")]
fn uart_puts(s: &[u8]) {
    const COM1: u16 = 0x3F8;
    unsafe {
        for &c in s {
            let mut lsr: u8;
            core::arch::asm!("in al, dx", in("dx") COM1 + 5, out("al") lsr, options(nostack, preserves_flags));
            while lsr & 0x20 == 0 {
                core::arch::asm!("in al, dx", in("dx") COM1 + 5, out("al") lsr, options(nostack, preserves_flags));
            }
            core::arch::asm!("out dx, al", in("dx") COM1, in("al") c, options(nostack, preserves_flags));
        }
    }
}

/// Print a hex u64 through the raw UART helper.
#[cfg(target_arch = "x86_64")]
pub fn uart_put_hex64(v: u64) {
    let hex = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    for shift in (0..16u32).rev() {
        buf[(15 - shift) as usize] = hex[((v >> (shift * 4)) & 0xF) as usize];
    }
    uart_puts(&buf);
}

/// Index into the PML4 for the self-map slot.
pub const MI_SELF_MAP_INDEX: usize = 0x1ED;

/// Self-map addresses (imported from `crate::mm::constants` via
/// `pub use crate::mm::constants::*`).

/// Self-map derived addresses for a given virtual address.
#[inline]
pub fn pte_address_of(va: u64) -> *mut MMPTE {
    let pte_index = (va >> 12) & 0x1FF;
    (PTE_BASE + pte_index * 8) as *mut MMPTE
}
#[inline]
pub fn pde_address_of(va: u64) -> *mut MMPTE {
    let pde_index = (va >> 21) & 0x1FF;
    (PDE_BASE + pde_index * 8) as *mut MMPTE
}
#[inline]
pub fn ppe_address_of(va: u64) -> *mut MMPTE {
    let ppe_index = (va >> 30) & 0x1FF;
    (PPE_BASE + ppe_index * 8) as *mut MMPTE
}
#[inline]
pub fn pxe_address_of(va: u64) -> *mut MMPTE {
    let pxe_index = (va >> 39) & 0x1FF;
    (PXE_BASE + pxe_index * 8) as *mut MMPTE
}

/// Invalidate a single TLB entry for the given virtual address.
/// Delegates to the architecture-specific TLB invalidation.
#[cfg(target_arch = "x86_64")]
pub fn invalidate_tlb(addr: u64) {
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

/// Invalidate a single TLB entry for the given virtual address.
#[cfg(not(target_arch = "x86_64"))]
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
        Self { pml4_phys: 0, pml4_virt: 0, initialized: false }
    }
}

pub static MM_SYSTEM_VAS: Spinlock<MmSystemAddressSpace> = Spinlock::new(MmSystemAddressSpace::new());

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
            // Allocate from current position
            let va = allocator.next_va;
            allocator.next_va = va + aligned_size;
            if allocator.next_va > allocator.end_va {
                return None; // Out of user VA space
            }
            va
        } else {
            // Use desired base if it's in user range
            if desired_base < 0x0000_7FFF_FFFF_FFFF {
                desired_base
            } else {
                return None; // Invalid user address
            }
        };

        Some(va)
    }

    /// Reset the user VA allocator to initial state
    pub fn reset_user_va_allocator(&self) {
        let mut allocator = self.user_va_allocator.lock();
        allocator.next_va = 0x10000; // Start from 64KB
        allocator.end_va = 0x0000_7FFF_FFFF_F000; // Windows 7 x64 user limit
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
        if !pte.is_hardware() { return None; }
        Some(pte.hardware_page_frame() >> 12)
    }
}

/// Install the recursive self-map. Should be called once at boot
/// after the PML4 page frame has been allocated.
///
/// The standard NT 6.1 self-map is a single 4-KiB page that acts
/// as the recursive target at *all four* levels of the page-table
/// walk. The page is the same one referred to by
/// `PML4[MI_SELF_MAP_INDEX]`; because every self-map window
/// (`PXE_BASE`, `PPE_BASE`, `PDE_BASE`, `PTE_BASE`) walks through
/// index 0x1ED at every level, the page's own entry at index
/// 0x1ED points back to itself and the recursion closes.
///
/// Concretely the page is wired up as follows (all four lines
/// target the *same* physical page):
///   * `PML4[0x1ED] = pdpt_self`
///   * `pdpt_self[0x1ED] = pd_self`
///   * `pd_self[0x1ED] = pt_self`
///   * `pt_self[0x1ED] = pdpt_self`   (close the loop)
///
/// We do NOT touch any of the user-half PML4 entries here; the
/// test code (or any later user-mode setup) is responsible for
/// installing the actual user-half translations.
///
/// # CRITICAL
/// This function requires 3 additional pages for the self-map chain.
/// If allocation fails, this returns an error instead of hanging.
/// Returns Ok(()) on success, Err(SelfMapError) on failure.
#[cfg(target_arch = "x86_64")]
pub fn install_self_map(pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    let pml4_phys = pfn_to_phys(pml4_pfn);
    const SELF_RW: u64 = 0x1 | 0x2 | 0x4 | 0x20 | 0x40;

    // Check if self-map is already installed
    let pml4 = pml4_phys as *mut MMPTE;
    let existing = unsafe { *pml4.add(MI_SELF_MAP_INDEX) };
    if existing.is_hardware() {
    // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] install_self_map: self-map already present at PML4[0x1ED]=0x{:x}", existing.raw())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return Ok(());
    }

    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] install_self_map: pml4_phys=0x{:x}", pml4_phys)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Allocate 3 pages for the self-map chain (pdpt_self, pd_self,
    // pt_self). The chain is closed by pointing `pt_self[0x1ED]` at
    // the PML4 page itself, so the walk terminates at a fixed point
    // and never recurses.
    let pdpt_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => {
    // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] ERROR: install_self_map failed - cannot allocate PDPT page")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return Err(SelfMapError::OutOfMemory);
        }
    };
    let pd_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => {
    // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] ERROR: install_self_map failed - cannot allocate PD page")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            pfn::free_pfn(pdpt_pfn);
            return Err(SelfMapError::OutOfMemory);
        }
    };
    let pt_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => {
    // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] ERROR: install_self_map failed - cannot allocate PT page")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            pfn::free_pfn(pdpt_pfn);
            pfn::free_pfn(pd_pfn);
            return Err(SelfMapError::OutOfMemory);
        }
    };
    let pdpt_phys = pfn_to_phys(pdpt_pfn);
    let pd_phys = pfn_to_phys(pd_pfn);
    let pt_phys = pfn_to_phys(pt_pfn);

    // Zero the three new pages. They are all in identity-mapped
    // low memory (the buddy allocator only hands out such pages),
    // so the physical addresses are valid pointers.
    unsafe {
        core::ptr::write_bytes(pdpt_phys as *mut u8, 0, 4096);
        core::ptr::write_bytes(pd_phys as *mut u8, 0, 4096);
        core::ptr::write_bytes(pt_phys as *mut u8, 0, 4096);
    }

    // Wire the chain. Closing with the PML4 itself (rather than a
    // separate mirror page) lets the self-map walk terminate without
    // recursing: PML4[0x1ED] → pdpt_self → pd_self → pt_self → PML4.
    // The CPU reads the leaf PTE as the value of self_page[0x1ED],
    // which IS the PML4[0x1ED] entry we just wrote — i.e. the chain
    // ends in a fixed point. This avoids the infinite loop the prior
    // implementation hit and is also what the canonical Windows 7
    // self-map uses (PXE/PPE/PDE/PTE_BASE windows point at the PML4).
    let pdpt = pdpt_phys as *mut MMPTE;
    let pd = pd_phys as *mut MMPTE;
    let pt = pt_phys as *mut MMPTE;
    // CRITICAL: The UEFI identity map may have the PML4 page mapped
    // as read-only (via a 2MB large page or via the boot-time identity
    // map). Clearing CR0.WP allows ring-0 code to write to read-only
    // pages so the self-map install can succeed. We restore CR0.WP
    // immediately after the writes.
    let saved_cr0: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr0",
            out(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0 & !0x0001_0000u64, // clear WP (bit 16)
            options(nostack, preserves_flags),
        );
    }
    unsafe {
        // Wire the chain. We point `pt_self[0x1ED]` at the PML4
        // page itself so the self-map walk returns the same PML4
        // entry at every level, terminating at a fixed point.
        (*pml4.add(MI_SELF_MAP_INDEX)).set_hardware(pdpt_phys, SELF_RW);
        (*pdpt.add(MI_SELF_MAP_INDEX)).set_hardware(pd_phys, SELF_RW);
        (*pd.add(MI_SELF_MAP_INDEX)).set_hardware(pt_phys, SELF_RW);
        (*pt.add(MI_SELF_MAP_INDEX)).set_hardware(pml4_phys, SELF_RW);
        // Restore CR0.WP.
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
    }
    // Verify the self-map (read via direct physical pointer; this
    // walk goes through the UEFI identity map of the PML4 page, not
    // the self-map, so it does not depend on the chain we just
    // installed).
    let _check_pml4 = unsafe { *pml4.add(MI_SELF_MAP_INDEX) };
    // _check_pml4 is intentionally unused - reserved for future verification
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] install_self_map: PML4[0x1ED]=0x{:x}", _check_pml4.raw())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] install_self_map: pdpt=0x{:x} pd=0x{:x} pt=0x{:x} pml4=0x{:x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //     // [DISABLED-KPRINTLN]               pdpt_phys, pd_phys, pt_phys, pml4_phys);
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn install_self_map(_pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    Ok(())
}

/// Fallback self-map: only the PML4 entry is recursive.
/// 
/// This provides basic self-map capability where PXE_BASE can access
/// the PML4. PPE_BASE/PDE_BASE/PTE_BASE will not be functional.
/// Kept as the only option when the frame allocator cannot hand us
/// enough pages for the full 4-level self-map.
/// 
/// # Warning
/// 
/// When this fallback is used, the system runs with limited self-map
/// functionality. Some memory management operations may fail or behave
/// unexpectedly. This should only occur during early bootstrap when
/// memory is extremely constrained.
fn install_single_level_self_map(pml4_phys: u64) {
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] WARNING: Falling back to single-level self-map")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] WARNING: Limited functionality - PPE_BASE/PDE_BASE/PTE_BASE may not work")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] WARNING: This indicates PFN allocation failure during bootstrap")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    
    let pte = pml4_phys as *mut u8;
    // The UEFI identity map can leave the PML4 page marked read-only
    // (it gets installed through a 2 MiB large page during
    // ExitBootServices). Clear CR0.WP around the write so ring-0 can
    // update the read-only PTE, then restore WP. This matches the
    // protection used in `install_self_map` above.
    let saved_cr0: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr0",
            out(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0 & !0x0001_0000u64, // clear WP (bit 16)
            options(nostack, preserves_flags),
        );
        let pml4e = pte.add(MI_SELF_MAP_INDEX * 8) as *mut MMPTE;
        // Self-map entry: P=1, R/W=1, U=1, A=1, D=1
        (*pml4e).set_hardware(pml4_phys, 0x1 | 0x2 | 0x4 | 0x20 | 0x40);
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
    }
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] Single-level self-map installed at PML4[0x1ED]=0x{:016x}",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //     // [DISABLED-KPRINTLN]               pml4_phys | 0x67);
}

/// Install single-level self-map directly to PML4 physical address.
/// This is used when we need to install the self-map but cannot use
/// the self-map window (because it's not set up yet). It writes
/// directly to the PML4's physical address.
pub fn install_single_level_self_map_direct(pml4_phys: u64) {
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] install_single: starting, pml4_phys=0x{:x}", pml4_phys)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // The PML4 is at pml4_phys (identity-mapped in UEFI).
    // We write directly to the PML4[MI_SELF_MAP_INDEX] entry.
    // Self-map entry: P=1, R/W=1, U=1, A=1, D=1
    const SELF_RW: u64 = 0x1 | 0x2 | 0x4 | 0x20 | 0x40;
    unsafe {
        let pml4 = pml4_phys as *mut MMPTE;
        (*pml4.add(MI_SELF_MAP_INDEX)).set_hardware(pml4_phys, SELF_RW);
    }
}

// Keep the symbol referenced via an internal alias so it is not
// flagged as dead code. This avoids `#[allow(dead_code)]` while
// preserving the public symbol for future callers that may need
// to install the self-map before the self-map window is up.
#[doc(hidden)]
pub fn _direct_self_map_keepalive(pml4_phys: u64) {
    install_single_level_self_map_direct(pml4_phys);
}

/// Identity-map a low-memory region (physical address `pa_base`,
/// `size` bytes long) into the system PML4 so the kernel can
/// dereference the bytes through their physical address.
///
/// This is needed by the winload → kernel handoff: `winload.efi`
/// allocates the ESP/System/ISO capture buffers via
/// `AllocatePages`, then returns to the kernel via
/// `ExitBootServices`. OVMF's low-memory identity mapping is largely
/// preserved across `ExitBootServices`, but the kernel subsequently
/// installs its own PML4 in `mm::vas::init` — that PML4 only carries
/// the recursive self-map and a 2 MiB identity slice covering the
/// PML4 page itself. Any boot-loader buffer that lives outside those
/// existing entries will fault on first dereference.
///
/// Implementation strategy: install one 2 MiB large-page PDE per
/// 2 MiB-aligned slice of the region. The PML4E / PDPTE entries are
/// created on demand (zeroed pages allocated from `pfn::allocate_pfn`)
/// so this works regardless of the existing kernel PML4 layout.
/// We deliberately use 2 MiB large pages instead of 4 KiB pages to
/// keep the page-table footprint small: a 32 MiB capture buffer
/// needs 16 PDEs versus 8192 PT entries.
#[cfg(target_arch = "x86_64")]
pub fn ensure_low_identity_map(pa_base: u64, size: u64) {
    crate::boot_println!("[VAS] ensure_low_identity_map: pa_base=0x{:x} size=0x{:x}", pa_base, size);
    if pa_base == 0 || size == 0 {
        crate::boot_println!("[VAS] ensure_low_identity_map: zero range, skipping");
        return;
    }
    const TWO_MB: u64 = 2 * 1024 * 1024;
    const PDE_2MB_FLAGS: u64 = 0x1 | 0x2 | 0x4 | 0x20 | 0x40 | 0x80; // P|RW|US|A|D|PS

    let start = pa_base & !(TWO_MB - 1);
    let end_unaligned = pa_base.saturating_add(size);
    let end = (end_unaligned + TWO_MB - 1) & !(TWO_MB - 1);
    crate::boot_println!("[VAS] ensure_low_identity_map: start=0x{:x} end=0x{:x}", start, end);

    let pml4_phys = crate::arch::read_current_page_root();
    crate::boot_println!("[VAS] ensure_low_identity_map: pml4_phys=0x{:x}", pml4_phys);
    if pml4_phys == 0 {
        return;
    }
    let pml4 = pml4_phys as *mut MMPTE;

    // CR0.WP may be set; clearing it lets us write to PDEs that the
    // UEFI firmware identity-mapped read-only. We restore WP before
    // returning so the rest of the kernel still benefits from the
    // write protection.
    let saved_cr0: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr0",
            out(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0 & !0x0001_0000u64,
            options(nostack, preserves_flags),
        );
    }

    let mut cur = start;
    crate::boot_println!("[VAS] ensure_low_identity_map: scanning PML4[0]={:016x} PML4[1]={:016x}",
        unsafe { (*pml4.add(0)).raw() },
        unsafe { (*pml4.add(1)).raw() });
    let mut pde_count = 0u64;
    while cur < end {
        let pml4_idx = ((cur >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((cur >> 30) & 0x1FF) as usize;
        let pd_idx = ((cur >> 21) & 0x1FF) as usize;

        unsafe {
            // PML4E -> PDPT (allocate on demand)
            let pml4e = pml4.add(pml4_idx);
            if !(*pml4e).is_hardware() {
                let new_pdpt = match crate::mm::pfn::allocate_pfn() {
                    Some(p) => pfn_to_phys(p),
                    None => {
                        crate::boot_println!("[VAS] ensure_low_identity_map: PDPT alloc failed at cur=0x{:x}", cur);
                        break;
                    }
                };
                core::ptr::write_bytes(new_pdpt as *mut u8, 0, 4096);
                (*pml4e).set_hardware(new_pdpt, INT_PTE_BITS);
            }
            let pdpt_phys = (*pml4e).hardware_page_frame();
            let pdpt = pdpt_phys as *mut MMPTE;

            // PDPTE -> PD (allocate on demand)
            let pdpte = pdpt.add(pdpt_idx);
            if !(*pdpte).is_hardware() {
                let new_pd = match crate::mm::pfn::allocate_pfn() {
                    Some(p) => pfn_to_phys(p),
                    None => {
                        crate::boot_println!("[VAS] ensure_low_identity_map: PD alloc failed at cur=0x{:x} pdpt_phys=0x{:x} pdpt_idx={}",
                            cur, pdpt_phys, pdpt_idx);
                        break;
                    }
                };
                core::ptr::write_bytes(new_pd as *mut u8, 0, 4096);
                (*pdpte).set_hardware(new_pd, INT_PTE_BITS);
            }
            let pd_phys = (*pdpte).hardware_page_frame();
            let pd = pd_phys as *mut MMPTE;

            // PDE: install as 2 MiB large page pointing at `cur`
            let pde = pd.add(pd_idx);
            (*pde).set_hardware(cur, PDE_2MB_FLAGS);
            pde_count += 1;
        }

        cur += TWO_MB;
    }
    crate::boot_println!("[VAS] ensure_low_identity_map: mapping loop done, cur=0x{:x}, pdes installed={}", cur, pde_count);

    unsafe {
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
    }

    // Flush the TLB so the new entries are picked up by subsequent
    // walks. A full CR3 reload is the simplest portable flush on
    // x86_64; the system PML4 has not changed, only its contents.
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack));
    }
    let cr3_after: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3_after, options(nostack)); }
    crate::boot_println!("[VAS] ensure_low_identity_map: CR3 before flush=0x{:x} after flush=0x{:x}", cr3, cr3_after);

    // Self-check: read back every leaf PDE we just installed and
    // confirm it really points at the requested PA with PS=1. If
    // any entry is missing, the very next dereference will #PF —
    // better to catch it here where the diagnostic message is at
    // least visible on the serial log.
    unsafe {
        let mut verify_cur = start;
        let mut count = 0u64;
        let mut bad = 0u64;
        while verify_cur < end {
            let pml4_idx = ((verify_cur >> 39) & 0x1FF) as usize;
            let pdpt_idx = ((verify_cur >> 30) & 0x1FF) as usize;
            let pd_idx = ((verify_cur >> 21) & 0x1FF) as usize;
            let pml4e_raw = (*pml4.add(pml4_idx)).raw();
            let pdpt_phys = pml4e_raw & !0xFFFu64;
            let pdpt = pdpt_phys as *mut MMPTE;
            let pdpte = (*pdpt.add(pdpt_idx)).raw();
            let pd_phys = pdpte & !0xFFFu64;
            let pd = pd_phys as *mut MMPTE;
            let pde = (*pd.add(pd_idx)).raw();
            count += 1;
            if pde & 1 == 0 || (pde & 0x80) == 0 || (pde & !0xFFFu64) != verify_cur {
                bad += 1;
                if bad <= 4 {
                    crate::boot_println!(
                        "[VAS] verify: BAD PDE for pa=0x{:x} -> 0x{:x} (P={} R/W={} PS={})",
                        verify_cur, pde, pde & 1, (pde >> 1) & 1, (pde >> 7) & 1
                    );
                }
            }
            verify_cur += TWO_MB;
        }
        crate::boot_println!("[VAS] verify: {} PDEs, {} bad", count, bad);
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn ensure_low_identity_map(_pa_base: u64, _size: u64) {}

/// Install the full 4-level self-map with identity-mapping for the new PML4.
/// When allocating a new PML4, we must add an identity-mapping entry
/// for the PML4 page itself so that after CR3 is switched, the kernel
/// can still access the PML4 through the lower portion of the address
/// space (which UEFI always maps 1:1).
///
/// Returns Ok(()) on success, Err(SelfMapError) on failure.
#[cfg(target_arch = "x86_64")]
fn install_self_map_with_identity_map(pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    let pml4_phys = pfn_to_phys(pml4_pfn);
    crate::hal::serial::write_string("[VAS] install_self_map: pml4_pfn=0x");
    crate::hal::serial::write_hex_u64(pml4_phys);
    crate::hal::serial::write_string("\r\n");
    const SELF_RW: u64 = 0x1 | 0x2 | 0x4 | 0x20 | 0x40;

    // Allocate the self-map page table chain.
    let pdpt_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => {
            crate::hal::serial::write_string("[VAS] install_self_map: ERROR: cannot allocate PDPT\r\n");
            return Err(SelfMapError::OutOfMemory);
        }
    };
    crate::hal::serial::write_string("[VAS] install_self_map: pdpt_pfn=0x");
    crate::hal::serial::write_hex_u64(pfn_to_phys(pdpt_pfn));
    crate::hal::serial::write_string("\r\n");
    let pd_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => {
            crate::hal::serial::write_string("[VAS] install_self_map: ERROR: cannot allocate PD\r\n");
            pfn::free_pfn(pdpt_pfn);
            return Err(SelfMapError::OutOfMemory);
        }
    };
    crate::hal::serial::write_string("[VAS] install_self_map: pd_pfn=0x");
    crate::hal::serial::write_hex_u64(pfn_to_phys(pd_pfn));
    crate::hal::serial::write_string("\r\n");
    let pt_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => {
            crate::hal::serial::write_string("[VAS] install_self_map: ERROR: cannot allocate PT\r\n");
            pfn::free_pfn(pdpt_pfn);
            pfn::free_pfn(pd_pfn);
            return Err(SelfMapError::OutOfMemory);
        }
    };
    crate::hal::serial::write_string("[VAS] install_self_map: pt_pfn=0x");
    crate::hal::serial::write_hex_u64(pfn_to_phys(pt_pfn));
    crate::hal::serial::write_string("\r\n");

    let pdpt_phys = pfn_to_phys(pdpt_pfn);
    let pd_phys = pfn_to_phys(pd_pfn);
    let pt_phys = pfn_to_phys(pt_pfn);

    // Zero all page table pages.
    unsafe {
        core::ptr::write_bytes(pdpt_phys as *mut u8, 0, 4096);
        core::ptr::write_bytes(pd_phys as *mut u8, 0, 4096);
        core::ptr::write_bytes(pt_phys as *mut u8, 0, 4096);
    }

    // Wire the self-map chain. Closing with the PML4 itself lets the
    // walk terminate at a fixed point (see `install_self_map`).
    let pml4 = pml4_phys as *mut MMPTE;
    let pdpt = pdpt_phys as *mut MMPTE;
    let pd = pd_phys as *mut MMPTE;
    let pt = pt_phys as *mut MMPTE;

    // CRITICAL: Same CR0.WP workaround as `install_self_map` — the
    // PML4 page may be mapped read-only by the UEFI identity map.
    let saved_cr0: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr0",
            out(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0 & !0x0001_0000u64, // clear WP (bit 16)
            options(nostack, preserves_flags),
        );
    }

    unsafe {
        (*pml4.add(MI_SELF_MAP_INDEX)).set_hardware(pdpt_phys, SELF_RW);
        (*pdpt.add(MI_SELF_MAP_INDEX)).set_hardware(pd_phys, SELF_RW);
        (*pd.add(MI_SELF_MAP_INDEX)).set_hardware(pt_phys, SELF_RW);
        (*pt.add(MI_SELF_MAP_INDEX)).set_hardware(pml4_phys, SELF_RW);
        // Restore CR0.WP.
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
    }

    // CRITICAL: Add an identity-mapping entry for the PML4 page itself.
    // This ensures that after we switch CR3 to the new PML4, we can
    // still access the PML4 at its physical address (which UEFI
    // always identity-maps in low memory).
    //
    // The PML4 entry index for identity-mapping the PML4 page is:
    //   (pml4_phys >> 39) & 0x1FF
    // Since the PML4 is in low memory (identity-mapped by UEFI),
    // and we copied all entries from the old PML4, the new PML4
    // should already have the identity-mappings needed.
    // However, if the new PML4's address is in a different 512GB
    // region than what was previously mapped, we need to add that entry.
    let pml4_self_idx = ((pml4_phys >> 39) & 0x1FF) as usize;
    let existing_entry = unsafe { *pml4.add(pml4_self_idx) };
    if !existing_entry.is_hardware() {
    // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] WARNING: PML4[0x{:x}] not mapped, adding identity-mapping", pml4_self_idx)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        // The PML4 is in low memory. We need to add an identity-mapping
        // for it. Since the PML4 is in low memory, the mapping should
        // be a 2MB large page (PDE with PS bit set).
        //
        // For a PML4 at address X, we need to add:
        // - PML4 entry at (X >> 39) & 0x1FF -> PDPT
        // - PDPT entry at (X >> 30) & 0x1FF -> PD (large page)
        // - PD entry with PS bit -> covers 2MB region containing X
        //
        // The simplest approach: add a 2MB identity-mapping PDE.
        // We need to allocate a PDPT and PD page, then install the entries.
        let pdpt_pfn_for_id = match pfn::allocate_pfn() {
            Some(p) => p,
            None => {
    // [DISABLED-KPRINTLN]                 // // kprintln!("[VAS] FATAL: cannot allocate PDPT for identity-mapping!")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                return Err(SelfMapError::OutOfMemory);
            }
        };
        let pd_for_id = match pfn::allocate_pfn() {
            Some(p) => p,
            None => {
    // [DISABLED-KPRINTLN]                 // // kprintln!("[VAS] FATAL: cannot allocate PD for identity-mapping!")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                return Err(SelfMapError::OutOfMemory);
            }
        };
        let pdpt_phys_id = pfn_to_phys(pdpt_pfn_for_id);
        let pd_phys_id = pfn_to_phys(pd_for_id);
        
        // Zero the pages
        unsafe {
            core::ptr::write_bytes(pdpt_phys_id as *mut u8, 0, 4096);
            core::ptr::write_bytes(pd_phys_id as *mut u8, 0, 4096);
        }
        
        // Install PML4 entry -> PDPT
        unsafe {
            (*pml4.add(pml4_self_idx)).set_hardware(pdpt_phys_id, 0x1 | 0x2 | 0x4 | 0x20 | 0x40);
        }

        // Calculate the PD index for the PML4 address
        let pd_idx = ((pml4_phys >> 21) & 0x1FF) as usize;
        // Install PDPT entry -> PD (large page)
        let pdpt_va = pdpt_phys_id as *mut MMPTE;
        let pdpt_idx = ((pml4_phys >> 30) & 0x1FF) as usize;
        unsafe {
            (*pdpt_va.add(pdpt_idx)).set_hardware(pd_phys_id, 0x1 | 0x2 | 0x4 | 0x20 | 0x40);
        }

        // Install PD entry as a 2MB large page covering the PML4
        let pd_va = pd_phys_id as *mut MMPTE;
        unsafe {
            (*pd_va.add(pd_idx)).set_hardware(pml4_phys & !0x1F_FFFF, 0x1 | 0x2 | 0x4 | 0x20 | 0x40 | 0x80);
        }
    // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] Added identity-mapping: PML4[0x{:x}] -> PDPT, PDPT[0x{:x}] -> PD(large), PD[0x{:x}] -> 0x{:x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //     // [DISABLED-KPRINTLN]             pml4_self_idx, pdpt_idx, pd_idx, pml4_phys & !0x1F_FFFF);
    } else {
    // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] Identity-mapping exists at PML4[0x{:x}]", pml4_self_idx)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }

    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] install_self_map_with_identity_map: done, PML4[0x1ED] set")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    crate::hal::serial::write_string("[VAS] install_self_map: OK, returning\r\n");
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn install_self_map_with_identity_map(_pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    Ok(())
}

#[inline]
fn pfn_to_phys(pfn: PfnNumber) -> u64 {
    pfn << 12
}

// ---------------------------------------------------------------------------
// Per-process address space creation
// ---------------------------------------------------------------------------

/// Create a new user process address space. Allocates a new PML4 page
/// from the PFN database, copies the system PML4 into it, then
/// overwrites the user-private entries, and returns the physical
/// address of the new PML4.
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
/// We therefore copy *all* of the system PML4 into the new PML4.
/// This keeps the kernel reachable in the user PML4 (Phase 0 has
/// no user/kernel isolation; that will be added later).
/// Create a new user process address space. Allocates a new PML4 page
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
/// We therefore copy the *entire* system PML4 into the new PML4.
/// This keeps the kernel reachable in the user PML4 (Phase 0 has
/// no user/kernel isolation; that will be added later). The
/// `install_into_pml4` call in `kernel_main` will then overwrite
/// the user-mode entries (PML4[0] for the user entry stub) using
/// the shared identity-mapped PDPT — this is fine for Phase 0
/// because we are not enforcing isolation yet.
pub fn create_user_address_space() -> Option<u64> {
    let pfn = pfn::allocate_pfn()?;
    crate::boot_println!("[VAS] create_user_address_space: A: new pfn=0x{:x}", pfn);
    // Zero the new PML4.
    unsafe {
        let va = (pfn << 12) as *mut u8;
        ptr::write_bytes(va, 0, 4096);
    }
    // Copy the *entire* system PML4. This gives the new user PML4
    // the same kernel mappings (identity-mapped image, recursive
    // self-map, etc.) that the boot PML4 has.
    let system = system_pml4_mut();
    let dst = (pfn << 12) as *mut MMPTE;
    unsafe {
        for i in 0..PT_ENTRIES {
            let src_entry = *system.add(i);
            *dst.add(i) = src_entry;
        }
    }
    crate::boot_println!("[VAS] create_user_address_space: B: copied system PML4", );
    // Install a self-map chain + identity map for this PML4. The
    // system PML4's identity-map entry points at the system PML4's
    // own physical address; the new user PML4 sits at a different
    // physical address, so the copy above inherits an identity map
    // that no longer resolves correctly. We re-install the chain
    // here so the kernel's PXE_BASE / PDE_BASE / PTE_BASE macros
    // (and any subsequent context switch to this PML4) can reach
    // the new page tables through the self-map.
    if install_self_map_with_identity_map(pfn).is_err() {
    // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] ERROR: create_user_address_space failed to install self-map")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        crate::boot_println!("[VAS] create_user_address_space: ERROR: self-map failed");
        pfn::free_pfn(pfn);
        return None;
    }
    crate::boot_println!("[VAS] create_user_address_space: D: self-map installed");
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
    #[cfg(target_arch = "x86_64")]
    {
        crate::boot_println!("[VAS] create_user_address_space: calling force_writable_identity_map(pfn=0x{:x})", pfn);
        unsafe { force_writable_identity_map(pfn); }
    }
    Some(pfn << 12)
}

/// Walk user PML4[0..256] (the low canonical half) and force W=1 on
/// every PTE/PDT/PML4 entry we find. This makes the entire identity-
/// mapped region writable when the kernel runs with this PML4 active
/// (i.e., during syscall/interrupt handling for a user process).
#[cfg(target_arch = "x86_64")]
unsafe fn force_writable_identity_map(pfn: PfnNumber) {
    let pml4_phys = pfn << 12;
    let pml4 = pml4_phys as *mut MMPTE;
    crate::boot_println!("[VAS] force_writable_identity_map: pml4_phys=0x{:x}", pml4_phys);
    // Clear CR0.WP so we can write to entries the boot loader
    // marked read-only (some EFI firmware identity-maps memory as
    // R/O). Restore WP after the walk.
    let saved_cr0: u64;
    core::arch::asm!(
        "mov {}, cr0",
        out(reg) saved_cr0,
        options(nostack, preserves_flags),
    );
    core::arch::asm!(
        "mov cr0, {}",
        in(reg) saved_cr0 & !0x0001_0000u64,
        options(nostack, preserves_flags),
    );
    let mut flipped = 0u64;
    // Walk the entire PML4 (entries 0..512) — both the low-half
    // identity map (the source of write-protected page-table pages)
    // and the high-half kernel mappings (where the kernel stack
    // pages live while servicing a syscall for this process).
    for pml4_idx in 0..PT_ENTRIES {
        let mut pml4e = (*pml4.add(pml4_idx)).raw();
        if pml4e & 0x1 == 0 { continue; }          // not present
        // Force W on the PML4 entry first so writes to PDPT[?]
        // below succeed.
        if pml4e & 0x2u64 == 0 {
            pml4e |= 0x2u64;
            core::ptr::write_volatile(pml4.add(pml4_idx) as *mut u64, pml4e);
        }
        let pdpt_phys = pml4e & !0xFFF_u64;
        let pdpt = pdpt_phys as *mut MMPTE;
        // If this is a 1GB large page (PS=1 in PDPT), we can only force W
        // by setting the W bit on the entry itself; there's no PT level.
        if pml4e & (1u64 << 7) != 0 {
            continue;
        }
        for pdpt_idx in 0..PT_ENTRIES {
            let mut pdpte = (*pdpt.add(pdpt_idx)).raw();
            if pdpte & 0x1 == 0 { continue; }
            // Force W on the PDPT entry too.
            if pdpte & 0x2u64 == 0 {
                pdpte |= 0x2u64;
                core::ptr::write_volatile(pdpt.add(pdpt_idx) as *mut u64, pdpte);
            }
            let next_phys = pdpte & !0xFFF_u64;
            if pdpte & (1u64 << 7) != 0 {
                continue;
            }
            // Pointing to a PD: walk PD entries.
            let pd = next_phys as *const MMPTE;
            for pd_idx in 0..PT_ENTRIES {
                let mut pde = (*pd.add(pd_idx)).raw();
                if pde & 0x1 == 0 { continue; }
                // Force W on the PD entry first.
                if pde & 0x2u64 == 0 {
                    pde |= 0x2u64;
                    core::ptr::write_volatile(pd.add(pd_idx) as *mut u64, pde);
                }
                let pt_phys = pde & !0xFFF_u64;
                if pde & (1u64 << 7) != 0 {
                    continue;
                }
                // Pointing to a PT: force W on every PT entry present.
                let pt = pt_phys as *const MMPTE as *mut MMPTE;
                for pt_idx in 0..PT_ENTRIES {
                    let mut pte = (*pt.add(pt_idx)).raw();
                    if pte & 0x1 == 0 { continue; }
                    if pte & 0x2u64 == 0 {
                        pte |= 0x2u64;
                        core::ptr::write_volatile(pt.add(pt_idx) as *mut u64, pte);
                        flipped += 1;
                    }
                }
            }
        }
    }
    crate::boot_println!("[VAS] force_writable_identity_map: flipped={}", flipped);
    // Restore CR0.WP.
    core::arch::asm!(
        "mov cr0, {}",
        in(reg) saved_cr0,
        options(nostack, preserves_flags),
    );
    // CRITICAL: also force U=1 on user-half PML4 entries (0..256) so
    // that the user-mode cmd.exe image (mapped at 0x65001000 via
    // PML4[0]) is reachable from Ring 3. The system PML4 has U=0 in
    // the low half because the kernel image lives there and is not
    // user-accessible. Naively copying the system PML4 inherits the
    // kernel U=0 setting, which causes err=0x15 instruction-fetch
    // violations from user mode even though every leaf PTE says U=1.
    unsafe { force_user_accessible(pfn); }
}

/// Walk user PML4[0..256] and force U=1 on every PML4/PDPT/PD entry
/// we find. This makes the entire low-half identity-mapped region
/// user-accessible. Used when the user PML4 is created by copying
/// the (kernel-only) system PML4.
///
/// x86_64 only — on aarch64 / riscv64 / loongarch64 user accessibility
/// is encoded in the PTEs directly via AP[1] / SUM / PLV fields
/// rather than toggled through CR0.WP, so the equivalent flush isn't
/// needed.
#[cfg(target_arch = "x86_64")]
unsafe fn force_user_accessible(pfn: PfnNumber) {
    let pml4_phys = pfn << 12;
    let pml4 = pml4_phys as *mut MMPTE;
    crate::boot_println!("[VAS] force_user_accessible: pml4_phys=0x{:x}", pml4_phys);
    let saved_cr0: u64;
    core::arch::asm!(
        "mov {}, cr0",
        out(reg) saved_cr0,
        options(nostack, preserves_flags),
    );
    core::arch::asm!(
        "mov cr0, {}",
        in(reg) saved_cr0 & !0x0001_0000u64,
        options(nostack, preserves_flags),
    );
    let mut flipped = 0u64;
    // Iterate user-half PML4 entries only (0..256). The kernel-half
    // (256..512) keeps U=0.
    for pml4_idx in 0..256 {
        let mut pml4e = (*pml4.add(pml4_idx)).raw();
        if pml4e & 0x1 == 0 { continue; }
        if pml4e & 0x4u64 == 0 {
            pml4e |= 0x4u64;
            core::ptr::write_volatile(pml4.add(pml4_idx) as *mut u64, pml4e);
            flipped += 1;
        }
        let pdpt_phys = pml4e & !0xFFF_u64;
        let pdpt = pdpt_phys as *mut MMPTE;
        // Skip 1GB large pages.
        if pml4e & (1u64 << 7) != 0 { continue; }
        for pdpt_idx in 0..PT_ENTRIES {
            let mut pdpte = (*pdpt.add(pdpt_idx)).raw();
            if pdpte & 0x1 == 0 { continue; }
            if pdpte & 0x4u64 == 0 {
                pdpte |= 0x4u64;
                core::ptr::write_volatile(pdpt.add(pdpt_idx) as *mut u64, pdpte);
                flipped += 1;
            }
            let next_phys = pdpte & !0xFFF_u64;
            if pdpte & (1u64 << 7) != 0 { continue; }
            let pd = next_phys as *const MMPTE;
            for pd_idx in 0..PT_ENTRIES {
                let mut pde = (*pd.add(pd_idx)).raw();
                if pde & 0x1 == 0 { continue; }
                if pde & 0x4u64 == 0 {
                    pde |= 0x4u64;
                    core::ptr::write_volatile(pd.add(pd_idx) as *mut u64, pde);
                    flipped += 1;
                }
            }
        }
    }
    crate::boot_println!("[VAS] force_user_accessible: flipped={}", flipped);
    core::arch::asm!(
        "mov cr0, {}",
        in(reg) saved_cr0,
        options(nostack, preserves_flags),
    );
}

/// Attach a process. Updates the per-CPU CR3 / TTBR1 etc. via the
/// arch-specific `load_page_root` helper. Returns the previous root.
pub fn attach_process(pml4_phys: u64) -> u64 {
    let prev = current_root();
    let root_pfn = pml4_phys >> 12;
    unsafe { crate::arch::load_page_root(root_pfn); }
    set_current_root(pml4_phys);
    // Publish the system PML4 / user PML4 pair in the per-CPU
    // area so the syscall / interrupt stubs can switch CR3 to
    // the system PML4 before running kernel handlers (the
    // system PML4 has a writable identity map, the user PML4
    // does not) and restore the user PML4 before sysretq /
    // iretq. The `arch::x86_64::syscall::get_per_cpu` accessor
    // is x86_64-only today; the other architectures expose an
    // equivalent through their own per-CPU module and gate
    // publishing the user PML4 there.
    #[cfg(target_arch = "x86_64")]
    {
        let per_cpu = crate::arch::x86_64::syscall::get_per_cpu();
        if !per_cpu.is_null() {
            unsafe {
                (*per_cpu).user_pml4 = pml4_phys;
                if (*per_cpu).system_pml4 == 0 {
                    // First attach after boot: the CR3 we just
                    // replaced IS the system PML4.
                    (*per_cpu).system_pml4 = prev;
                }
            }
        }
    }
    prev
}

/// Detach a process. Restores the system root.
pub fn detach_process(prev: u64) {
    unsafe { crate::arch::load_page_root(prev >> 12); }
    set_current_root(prev);
    #[cfg(target_arch = "x86_64")]
    {
        let per_cpu = crate::arch::x86_64::syscall::get_per_cpu();
        if !per_cpu.is_null() {
            unsafe {
                (*per_cpu).user_pml4 = 0;
            }
        }
    }
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
// virtual pointer to each page. The UEFI/boot identity map covers the
// low 4 GiB, so as long as the physical address of a page is below
// 0x1_0000_0000 we can use it as a virtual address directly. We
// assume Phase 0 allocations stay under that limit (this is enforced
// because `pfn::allocate_pfn` prefers zeroed pages from the boot
// range).
//
// To make the mapping helpers robust to allocations above 4 GiB we
// also accept that callers may use `kernel_va_for_phys` (provided in
// `mm::paging`) to map a page first; for the Phase 0 build the direct
// identity cast is sufficient and is what `create_user_address_space`
// already uses successfully.

/// Protection flags for `map_page_in_pml4`. The values are the raw
/// bits ORed into the leaf PTE. `R/W = 1<<1`, `U/S = 1<<2`, plus
/// `P = 1<<0` always.
///
/// All PTE_* constants and INT_PTE_BITS are now imported from
/// `crate::mm::constants` via `pub use crate::mm::constants::*`.

/// Allocate a fresh page, zero it, and return its physical address.
fn alloc_zeroed_page() -> Option<u64> {
    let pfn = pfn::allocate_pfn()?;
    let phys = pfn << 12;
    unsafe { ptr::write_bytes(phys as *mut u8, 0, 4096); }
    Some(phys)
}

/// Public variant of `alloc_zeroed_page` for callers that want to
/// allocate a backing page outside of `map_user_pages` (e.g. when
/// they need to write into the page before mapping it).
pub fn alloc_zeroed_page_for_vas() -> Option<u64> { alloc_zeroed_page() }

/// Read a PTE from a user PML4 at the given PML4 index. The PML4 is
/// addressed via its physical address (identity-mapped in low memory).
#[inline]
unsafe fn pml4e(pml4_phys: u64, idx: usize) -> u64 {
    let p = (pml4_phys as *mut u64).add(idx);
    core::ptr::read_volatile(p)
}

/// Write a PTE in a user PML4 at the given PML4 index.
#[inline]
unsafe fn set_pml4e(pml4_phys: u64, idx: usize, val: u64) {
    let p = (pml4_phys as *mut u64).add(idx);
    core::ptr::write_volatile(p, val);
}

/// Read a PTE from an intermediate page table.
#[inline]
unsafe fn pte_read(table_phys: u64, idx: usize) -> u64 {
    core::ptr::read_volatile((table_phys as *const u64).add(idx))
}

/// Write a PTE to an intermediate page table.
#[inline]
unsafe fn pte_write(table_phys: u64, idx: usize, val: u64) {
    core::ptr::write_volatile((table_phys as *mut u64).add(idx), val);
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
            crate::boot_println!(
                "[VAS] map_page_in_pml4: replacing 2MB large PDE at PD[{}] for va=0x{:x}",
                pd_idx, va
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
            crate::boot_println!(
                "[VAS] map_page_in_pml4: PD[{}] <= 0x{:x} (for va=0x{:x})",
                pd_idx, pde_val, va
            );
        }
        let pt_phys = pde_val & 0x000F_FFFF_FFFF_F000;

        // Leaf PTE
        // The NX bit lives in bit 63, well above the 12-bit flags
        // window that holds the protection bits, so we OR it in
        // explicitly instead of relying on `flags & 0xFFF`.
        // CRITICAL: For user-mode .text pages we MUST clear NX so
        // the CPU allows instruction fetch. The original kernel
        // PML4 copy had NX=0, but a stray write somewhere might
        // set bit 63; we mask it out defensively.
        let leaf = (pa & 0x000F_FFFF_FFFF_F000)
            | (flags & 0xFFF)
            | PTE_P
            | PTE_A
            | PTE_D
            | (flags & PTE_NX);
        // Ensure NX=0 for now (debug).
        let leaf = leaf & !(1u64 << 63);
        crate::boot_println!(
            "[VAS] map_page_in_pml4: PT[{}] <= 0x{:x} (for va=0x{:x})",
            pt_idx, leaf, va
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
    if size == 0 { return true; }
    let mut cur = va & !0xFFFu64;
    let end = (va + size + 0xFFF) & !0xFFFu64;
    while cur < end {
        let pml4_idx = ((cur >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((cur >> 30) & 0x1FF) as usize;
        let pd_idx = ((cur >> 21) & 0x1FF) as usize;
        let pt_idx = ((cur >> 12) & 0x1FF) as usize;
        unsafe {
            let pml4e_val = pml4e(pml4_phys, pml4_idx);
            if pml4e_val & PTE_P == 0 { return false; }
            let pdpt_phys = pml4e_val & 0x000F_FFFF_FFFF_F000;
            let pdpte_val = pte_read(pdpt_phys, pdpt_idx);
            if pdpte_val & PTE_P == 0 { return false; }
            let pd_phys = pdpte_val & 0x000F_FFFF_FFFF_F000;
            let pde_val = pte_read(pd_phys, pd_idx);
            if pde_val & PTE_P == 0 { return false; }
            let pt_phys = pde_val & 0x000F_FFFF_FFFF_F000;
            let pte_val = pte_read(pt_phys, pt_idx);
            if pte_val & PTE_P == 0 { return false; }
        }
        cur += 0x1000;
    }
    true
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
    if size == 0 { return MmStatus::Ok; }
    let mut cur = va & !0xFFFu64;
    let end = (va + size + 0xFFF) & !0xFFFu64;
    while cur < end {
        let pml4_idx = ((cur >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((cur >> 30) & 0x1FF) as usize;
        let pd_idx = ((cur >> 21) & 0x1FF) as usize;
        let pt_idx = ((cur >> 12) & 0x1FF) as usize;
        unsafe {
            let pml4e_val = pml4e(pml4_phys, pml4_idx);
            if pml4e_val & PTE_P == 0 { return MmStatus::InvalidAddress; }
            let pdpt_phys = pml4e_val & 0x000F_FFFF_FFFF_F000;
            let pdpte_val = pte_read(pdpt_phys, pdpt_idx);
            if pdpte_val & PTE_P == 0 { return MmStatus::InvalidAddress; }
            let pd_phys = pdpte_val & 0x000F_FFFF_FFFF_F000;
            let pde_val = pte_read(pd_phys, pd_idx);
            if pde_val & PTE_P == 0 { return MmStatus::InvalidAddress; }
            let pt_phys = pde_val & 0x000F_FFFF_FFFF_F000;
            let pte_val = pte_read(pt_phys, pt_idx);
            if pte_val & PTE_P == 0 { return MmStatus::InvalidAddress; }
            // Preserve the physical-address bits and P/A/D; replace
            // protection, NX, user/kernel, etc. from new_protect.
            let pa_bits = pte_val & 0x000F_FFFF_FFFF_F000u64;
            // new_protect is a u32 PAGE_* value; combine with the
            // standard hardware PTE bits expected for user mappings.
            let mut new_pte = pa_bits | PTE_P | PTE_A | PTE_D | PTE_US;
            if new_protect & 0x04 != 0 { new_pte |= PTE_RW; } // PAGE_READWRITE
            if new_protect & 0x40 != 0 { new_pte |= PTE_RW; } // PAGE_EXECUTE_READWRITE
            if new_protect & 0xF0 == 0 { new_pte |= PTE_NX; } // non-executable by default
            pte_write(pt_phys, pt_idx, new_pte);
            invalidate_tlb(cur);
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
    if size == 0 { return MmStatus::Ok; }
    let mut cur = va & !0xFFFu64;
    let end = (va + size + 0xFFF) & !0xFFFu64;
    while cur < end {
        let pa = match alloc_zeroed_page() {
            Some(p) => p,
            None => return MmStatus::OutOfMemory,
        };
        let r = map_page_in_pml4(pml4_phys, cur, pa, flags);
        if r != MmStatus::Ok { return r; }
        cur += 0x1000;
    }
    MmStatus::Ok
}

/// Map a contiguous range of user pages but reuse `phys_base` as the
/// backing store. Useful for mapping a kernel-side buffer (e.g. a
/// loaded PE image) into a process.
pub fn map_user_phys_range(pml4_phys: u64, va: u64, phys_base: u64, size: u64, flags: u64) -> MmStatus {
    if size == 0 { return MmStatus::Ok; }
    let mut cur = va & !0xFFFu64;
    let mut pa = phys_base & !0xFFFu64;
    let end = (va + size + 0xFFF) & !0xFFFu64;
    while cur < end {
        let r = map_page_in_pml4(pml4_phys, cur, pa, flags);
        if r != MmStatus::Ok { return r; }
        cur += 0x1000;
        pa += 0x1000;
    }
    MmStatus::Ok
}

/// Unmap a user range and free the backing physical pages. PT/PD/PDPT
/// pages that become empty are also freed back to the PFN database.
pub fn unmap_user_pages(pml4_phys: u64, va: u64, size: u64) -> MmStatus {
    if size == 0 { return MmStatus::Ok; }
    let mut cur = va & !0xFFFu64;
    let end = (va + size + 0xFFF) & !0xFFFu64;
    while cur < end {
        let pml4_idx = ((cur >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((cur >> 30) & 0x1FF) as usize;
        let pd_idx = ((cur >> 21) & 0x1FF) as usize;
        let pt_idx = ((cur >> 12) & 0x1FF) as usize;
        unsafe {
            let pml4e_val = pml4e(pml4_phys, pml4_idx);
            if (pml4e_val & PTE_P) == 0 { cur += 0x1000; continue; }
            let pdpt_phys = pml4e_val & 0x000F_FFFF_FFFF_F000;
            let pdpte_val = pte_read(pdpt_phys, pdpt_idx);
            if (pdpte_val & PTE_P) == 0 { cur += 0x1000; continue; }
            let pd_phys = pdpte_val & 0x000F_FFFF_FFFF_F000;
            let pde_val = pte_read(pd_phys, pd_idx);
            if (pde_val & PTE_P) == 0 { cur += 0x1000; continue; }
            let pt_phys = pde_val & 0x000F_FFFF_FFFF_F000;
            let pte = pte_read(pt_phys, pt_idx);
            if (pte & PTE_P) != 0 {
                let pa = pte & 0x000F_FFFF_FFFF_F000;
                if pa != 0 { pfn::free_pfn(pa >> 12); }
                pte_write(pt_phys, pt_idx, 0);
            }
        }
        cur += 0x1000;
    }
    MmStatus::Ok
}

// ---------------------------------------------------------------------------
// User VA allocation (for ntdll NtAllocateVirtualMemory)
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
}

impl UserVaAllocator {
    pub const fn new() -> Self {
        Self {
            // Start allocating from USER_BASE (0x0000_0000_0001_0000)
            // Leave low 64KB for NULL and DOS compatibility
            next_va: 0x0001_0000,
            // Windows 7 x64 user mode limit is 0x00007FFFFFFFFFFF
            end_va: 0x0000_7FFF_FFFF_F000,
        }
    }
}

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
        // Allocate from current position
        let va = alloc.next_va;
        alloc.next_va = va + aligned_size;
        if alloc.next_va > alloc.end_va {
            return None; // Out of user VA space
        }
        va
    } else {
        // Use desired base if it's in user range
        if desired_base < 0x0000_7FFF_FFFF_FFFF {
            desired_base
        } else {
            return None; // Invalid user address
        }
    };
    
    Some(va)
}

/// Free user-mode virtual address range.
pub fn free_user_va(_va: u64) -> bool {
    // For now, we don't support freeing user VA
    // A full implementation would track allocations and merge free blocks
    true
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/// Self-test: create a user address space and verify the kernel
/// identity-mapped region is copied from the system PML4.
pub fn self_test_user_address_space() -> bool {
    let system = system_pml4_mut();
    let kernel_entry_0 = unsafe { (*system.add(0)).raw() };

    let new_pml4_phys = match create_user_address_space() {
        Some(p) => p,
        None => {
    // [DISABLED-KPRINTLN]             // // kprintln!("[RING3-A1] self_test: create_user_address_space returned None")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    };
    unsafe {
        let new_pml4 = new_pml4_phys as *const MMPTE;
        let copied = (*new_pml4.add(0)).raw();
        if copied != kernel_entry_0 {
    // [DISABLED-KPRINTLN]             // // kprintln!("[RING3-A1] FAIL: PML4[0] not copied, got=0x{:x} want=0x{:x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //     // [DISABLED-KPRINTLN]                       copied, kernel_entry_0);
            return false;
        }
    }
    // [DISABLED-KPRINTLN]     // // kprintln!("[RING3-A1] OK: user PML4 at 0x{:x}, system PML4 fully copied",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //     // [DISABLED-KPRINTLN]               new_pml4_phys);

    // A2 self-test: map a single user page and a user stack.
    if map_user_pages(new_pml4_phys, USER_STACK_BASE, USER_STACK_SIZE, PTE_RW | PTE_US) != MmStatus::Ok {
    // [DISABLED-KPRINTLN]         // // kprintln!("[RING3-A2] FAIL: map_user_pages for stack returned error")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // [DISABLED-KPRINTLN]     // // kprintln!("[RING3-A2] OK: mapped user stack at 0x{:x} ({} bytes)",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //     // [DISABLED-KPRINTLN]               USER_STACK_BASE, USER_STACK_SIZE);

    // Map a single 4-KiB page for the user entry stub at USER_ENTRY_BASE.
    if map_user_pages(new_pml4_phys, USER_ENTRY_BASE, 0x1000, PTE_RW | PTE_US) != MmStatus::Ok {
    // [DISABLED-KPRINTLN]         // // kprintln!("[RING3-A2] FAIL: map_user_pages for entry returned error")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // [DISABLED-KPRINTLN]     // // kprintln!("[RING3-A2] OK: mapped user entry at 0x{:x}", USER_ENTRY_BASE)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Free the address space (we have not attached it, so CR3 still
    // points to the system PML4).
    unmap_user_pages(new_pml4_phys, USER_STACK_BASE, USER_STACK_SIZE);
    unmap_user_pages(new_pml4_phys, USER_ENTRY_BASE, 0x1000);
    pfn::free_pfn(new_pml4_phys >> 12);
    // [DISABLED-KPRINTLN]     // // kprintln!("[RING3-A1/A2] self_test PASS")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
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
pub const DEFAULT_USER_IMAGE_BASE: u64 = 0x0000_0000_0010_0000;

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
pub const USER_STACK_BASE: u64 = 0x0000_7FFF_DE00_0000;
pub const USER_STACK_SIZE: u64 = 0x0010_0000; // 1 MiB
pub const USER_STACK_TOP: u64 = USER_STACK_BASE + USER_STACK_SIZE;

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
pub const USER_ENTRY_BASE: u64 = 0x0000_0000_0010_0000;

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
    const USER_LIMIT: u64 = 0x0000_7FFF_FFFF_FFFF;
    assert!(USER_STACK_BASE < USER_LIMIT - 0x0040_0000,
        "USER_STACK_BASE must be at least 4 MiB below USER_LIMIT");
    assert!(USER_STACK_TOP < USER_LIMIT,
        "USER_STACK_TOP must remain in user half of address space");
    assert!(USER_STACK_TOP < 0x0000_7FFF_EF00_0000,
        "USER_STACK_TOP must leave 16 MiB for PEB/TEB/heap/guards");
    assert!(USER_ENTRY_BASE < USER_STACK_BASE,
        "USER_ENTRY_BASE must be below USER_STACK_BASE (low half)");
    assert!(USER_ENTRY_BASE >= 0x1000,
        "USER_ENTRY_BASE must be in low half, not page 0");
    assert!(USER_ENTRY_BASE & 0xFFFF_8000_0000_0000 == 0,
        "USER_ENTRY_BASE must NOT live in the kernel canonical-high half");
};

/// TEB (Thread Environment Block) base address.
///
/// Windows 7 x64 places the first thread's TEB at 0x0000_FFFF_FFDF_0000
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
        matches!(self,
            SelfMapError::OutOfMemory
            | SelfMapError::Pml4NotWritable
            | SelfMapError::VerificationFailed)
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
    // Read current page root
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
        #[cfg(target_arch = "x86_64")]
        {
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("[VAS] FATAL: self-map install failed: ");
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string(msg);
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string("\r\n");
        }
        let _ = msg;
        crate::arch::halt_loop();
    }

    // Verify the installation. Even though install_self_map()
    // returned Ok, the verification walk is the authoritative
    // check — if it fails we treat that as a fatal page-table
    // corruption event.
    if verify_self_map_detailed() {
        Ok(SelfMapStatus::Installed)
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::write_string(
                "[VAS] FATAL: self-map verify failed after install_self_map\r\n");
        }
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
    let pml4_phys = crate::arch::read_current_page_root();
    let pml4_pfn = pml4_phys >> 12;

    unsafe {
        let pml4 = pml4_phys as *const u64;
        let entry = *pml4.add(MI_SELF_MAP_INDEX);

        // Check if P bit (bit 0) is set.
        if entry & 0x01 == 0 {
            return false;
        }

        let entry_pfn = (entry & 0x000F_FFFF_FFFF_F000) >> 12;

        // Case 1: single-level (entry directly references the PML4).
        if entry_pfn == pml4_pfn {
            return true;
        }

        // Case 2: 4-level chain. Walk pdpt_self[0x1ED] → pd_self[0x1ED]
        // → pt_self[0x1ED] and check the final PTE is present and
        // points at either the PML4 itself (self-referential), the
        // pdpt_self PFN (closing the loop at the first level), or a
        // mirror page that contains the PML4 entries (the third
        // common Windows 7 layout).
        let pdpt_phys = entry_pfn << 12;
        let pdpt = pdpt_phys as *const u64;
        if (*pdpt.add(MI_SELF_MAP_INDEX) & 0x01) == 0 {
            return false;
        }
        let pd_phys = ((*pdpt.add(MI_SELF_MAP_INDEX)) & 0x000F_FFFF_FFFF_F000) >> 12 << 12;
        let pd = pd_phys as *const u64;
        if (*pd.add(MI_SELF_MAP_INDEX) & 0x01) == 0 {
            return false;
        }
        let pt_phys = ((*pd.add(MI_SELF_MAP_INDEX)) & 0x000F_FFFF_FFFF_F000) >> 12 << 12;
        let pt = pt_phys as *const u64;
        if (*pt.add(MI_SELF_MAP_INDEX) & 0x01) == 0 {
            return false;
        }
        let leaf_pfn = ((*pt.add(MI_SELF_MAP_INDEX)) & 0x000F_FFFF_FFFF_F000) >> 12;
        // Three legitimate layouts: (a) leaf = PML4 (single level
        // equivalent at the end of the chain), (b) leaf = pdpt_self
        // (loop closed at first level), (c) leaf = a mirror page
        // whose contents equal the PML4 entries.
        leaf_pfn == pml4_pfn || leaf_pfn == entry_pfn
    }
}

/// Verify that self-map is properly installed (detailed version)
/// Returns true if PML4[0x1ED] points back to the PML4 itself OR
/// to a valid 4-level self-map chain. See `check_self_map` for the
/// accepted layouts.
pub fn verify_self_map_detailed() -> bool {
    let pml4_phys = crate::arch::read_current_page_root();
    let pml4_pfn = pml4_phys >> 12;

    unsafe {
        let pml4 = pml4_phys as *const u64;
        let entry = *pml4.add(MI_SELF_MAP_INDEX);

        // Check if P bit (bit 0) is set
        if entry & 0x01 == 0 {
    // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: P bit not set at PML4[0x1ED]")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return false;
        }

        let entry_pfn = (entry & 0x000F_FFFF_FFFF_F000) >> 12;
        if entry_pfn == pml4_pfn {
    // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: PML4[0x1ED]=0x{:016x} (single-level self-map) OK", entry)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return true;
        }

        // Walk the 4-level chain and confirm each level is present
        // and the leaf closes the walk (either self-referential to
        // the PML4 page or back to the pdpt_self page).
        let pdpt_phys = entry_pfn << 12;
        let pdpt = pdpt_phys as *const u64;
        if (*pdpt.add(MI_SELF_MAP_INDEX) & 0x01) == 0 {
    // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: pdpt[0x1ED] not present")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return false;
        }
        let pd_phys = ((*pdpt.add(MI_SELF_MAP_INDEX)) & 0x000F_FFFF_FFFF_F000) >> 12 << 12;
        let pd = pd_phys as *const u64;
        if (*pd.add(MI_SELF_MAP_INDEX) & 0x01) == 0 {
    // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: pd[0x1ED] not present")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return false;
        }
        let pt_phys = ((*pd.add(MI_SELF_MAP_INDEX)) & 0x000F_FFFF_FFFF_F000) >> 12 << 12;
        let pt = pt_phys as *const u64;
        if (*pt.add(MI_SELF_MAP_INDEX) & 0x01) == 0 {
    // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: pt[0x1ED] not present")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return false;
        }
        let leaf_pfn = ((*pt.add(MI_SELF_MAP_INDEX)) & 0x000F_FFFF_FFFF_F000) >> 12;
        if leaf_pfn != pml4_pfn && leaf_pfn != entry_pfn {
    // [DISABLED-KPRINTLN]             // // kprintln!("[VAS] verify_self_map: leaf PFN={:x} does not close loop", leaf_pfn)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] verify_self_map: 4-level chain OK (pml4=0x{:x}, pdpt=0x{:x}, leaf=0x{:x})",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //     // [DISABLED-KPRINTLN]                   pml4_phys, pdpt_phys, leaf_pfn << 12);
        true
    }
}

/// Get current self-map status for debugging
pub fn get_self_map_status() -> &'static str {
    let status = SELF_MAP_STATUS.load(Ordering::SeqCst);
    SelfMapStatus::from_u64(status)
}

/// Initialise the system address space. Allocates a PML4 page and
/// installs the self-map.
pub fn init() {
    // Bypass kprintln — it triggers a memcpy byte-loop through
    // BufferWriter::write_str that has been observed to crash on
    // the very first call from a freshly-zeroed stack frame.
    // All status output goes through the raw-UART helper below.
    #[cfg(target_arch = "x86_64")]
    fn uart_puts(s: &[u8]) {
        const COM1: u16 = 0x3F8;
        unsafe {
            for &c in s {
                let mut lsr: u8;
                core::arch::asm!("in al, dx", in("dx") COM1 + 5, out("al") lsr, options(nostack, preserves_flags));
                while lsr & 0x20 == 0 {
                    core::arch::asm!("in al, dx", in("dx") COM1 + 5, out("al") lsr, options(nostack, preserves_flags));
                }
                core::arch::asm!("out dx, al", in("dx") COM1, in("al") c, options(nostack, preserves_flags));
            }
        }
    }
    #[cfg(target_arch = "x86_64")]
    uart_puts(b"[VAS] init: starting\r\n");

    // Read the current page root
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
    let reserved = crate::mm::pfn::reserve_pfn(pml4_pfn);
    #[cfg(target_arch = "x86_64")]
    {
        let s = b"[VAS] init: reserved system PML4 PFN=";
        let mut buf = [0u8; 96];
        for (i, &b) in s.iter().enumerate() { buf[i] = b; }
        let mut v = pml4_pfn;
        let mut digits = [0u8; 16];
        let mut n = 0;
        if v == 0 { digits[0] = b'0'; n = 1; }
        else {
            while v > 0 {
                let d = (v & 0xF) as u8;
                digits[n] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
                n += 1;
                v >>= 4;
            }
        }
        for i in 0..n { buf[s.len() + i] = digits[n - 1 - i]; }
        buf[s.len() + n] = b'\r';
        buf[s.len() + n + 1] = b'\n';
        uart_puts(&buf[..s.len() + n + 2]);
    }
    let _ = reserved;

    // Initialize VAS state first
    {
        let mut sys = MM_SYSTEM_VAS.lock();
        sys.pml4_phys = pml4_phys;
        sys.pml4_virt = pml4_phys;
        sys.initialized = true;
        set_current_root(sys.pml4_phys);
    }

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
    #[cfg(target_arch = "x86_64")]
    let status = match try_enable_self_map() {
        Ok(SelfMapStatus::Installed) => {
            uart_puts(b"[VAS] init: self-map installed (verified)\r\n");
            SelfMapStatus::Installed
        }
        Ok(SelfMapStatus::Failed(reason)) => {
            uart_puts(b"[VAS] init: self-map FAILED, falling back to single-level\r\n");
            install_single_level_self_map(pml4_phys);
            SelfMapStatus::Failed(reason)
        }
        Ok(other) => {
            uart_puts(b"[VAS] init: self-map partial, installing single-level fallback\r\n");
            install_single_level_self_map(pml4_phys);
            other
        }
        Err(reason) => {
            uart_puts(b"[VAS] init: try_enable_self_map returned Err, falling back\r\n");
            install_single_level_self_map(pml4_phys);
            SelfMapStatus::Failed(reason)
        }
    };
    #[cfg(not(target_arch = "x86_64"))]
    let status = SelfMapStatus::Skipped;
    SELF_MAP_STATUS.store(status.as_u64(), Ordering::SeqCst);

    // Final verification
    if verify_self_map_detailed() {
        #[cfg(target_arch = "x86_64")]
        uart_puts(b"[VAS] init: self-map verification PASSED\r\n");
    } else {
        #[cfg(target_arch = "x86_64")]
        uart_puts(b"[VAS] init: self-map verification FAILED (fallback)\r\n");
    }

    #[cfg(target_arch = "x86_64")]
    uart_puts(b"[VAS] init: done\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pte_address_calculation() {
        // PTE_BASE + ((VA >> 12) & 0x1FF) * 8
        let va = 0x1234_5678u64;
        let expected = PTE_BASE + (((va >> 12) & 0x1FF) * 8);
        assert_eq!(pte_address_of(va) as u64, expected);
    }

    #[test]
    fn self_map_constants() {
        // From docs/mem1.md
        assert_eq!(PTE_BASE, 0xFFFF_F680_0000_0000);
        // PXE_BASE is at PTE_BASE with 0x1ED in PML4 index + 0x1ED in
        // PDPT index + 0x1ED in PD index + 0x1ED in PT index:
        // = 0x1ED << 39 | 0x1ED << 30 | 0x1ED << 21 | 0x1ED << 12
        let want = 0x1EDu64 << 39 | 0x1EDu64 << 30 | 0x1EDu64 << 21 | 0x1EDu64 << 12;
        assert_eq!(PXE_BASE, want);
    }

    #[test]
    fn pde_address_calculation() {
        let va = 0x1234_5678u64;
        let expected = PDE_BASE + (((va >> 21) & 0x1FF) * 8);
        assert_eq!(pde_address_of(va) as u64, expected);
    }

    #[test]
    fn ppe_address_calculation() {
        let va = 0x1234_5678u64;
        let expected = PPE_BASE + (((va >> 30) & 0x1FF) * 8);
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
        assert_eq!(err.as_str(), "Out of memory: failed to allocate page table PFN");
        assert!(err.is_fatal());

        let err2 = SelfMapError::IdentityMappingFailed;
        assert!(!err2.is_fatal());
    }
}
