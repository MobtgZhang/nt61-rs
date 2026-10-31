//! x86_64 self-map implementation.
//!
//! This module owns the x86_64 page-table recursion mechanics so the
//! portable memory manager can call one architecture-neutral API.

use crate::mm::constants::*;
use crate::mm::pfn;
use crate::mm::pte::{PfnNumber, MMPTE};
use crate::mm::vas::SelfMapError;

#[inline]
fn pfn_to_phys(pfn: PfnNumber) -> u64 {
    pfn << 12
}

/// Install the canonical one-page recursive self-map used by Windows
/// NT x64. `PML4[0x1ED]` points back at the PML4 itself, so all four
/// self-map windows expose the appropriate page-table level.
pub fn install_recursive_self_map(pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    let pml4_phys = pfn_to_phys(pml4_pfn);
    const SELF_RW: u64 = 0x1 | 0x2 | 0x20 | 0x40;
    let pml4 = pml4_phys as *mut MMPTE;

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
        (*pml4.add(MI_SELF_MAP_INDEX)).set_hardware(pml4_phys, SELF_RW);
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
    }
    Ok(())
}

/// Install the page-table chain backing the NT x64 hyperspace window.
///
/// Windows places this window in its own PML4 entry, so the recursive
/// self-map entry alone cannot reach the temporary-mapping PTEs.
pub fn install_hyperspace_tables(pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    let pml4_phys = pfn_to_phys(pml4_pfn);
    const TABLE_RW: u64 = 0x1 | 0x2 | 0x20 | 0x40;

    let pdpt_pfn = pfn::allocate_pfn().ok_or(SelfMapError::OutOfMemory)?;
    let pd_pfn = pfn::allocate_pfn().ok_or(SelfMapError::OutOfMemory)?;
    let pt_pfn = pfn::allocate_pfn().ok_or(SelfMapError::OutOfMemory)?;

    let pdpt_phys = pfn_to_phys(pdpt_pfn);
    let pd_phys = pfn_to_phys(pd_pfn);
    let pt_phys = pfn_to_phys(pt_pfn);

    // Propagate mapping failures: without the identity map these fresh
    // table pages cannot be zeroed below and the first write would #PF.
    if !ensure_low_identity_map(pdpt_phys & !0x1F_FFFF, 0x20_0000)
        || !ensure_low_identity_map(pd_phys & !0x1F_FFFF, 0x20_0000)
        || !ensure_low_identity_map(pt_phys & !0x1F_FFFF, 0x20_0000)
    {
        return Err(SelfMapError::IdentityMappingFailed);
    }

    let pml4 = pml4_phys as *mut MMPTE;
    let pdpt = pdpt_phys as *mut MMPTE;
    let pd = pd_phys as *mut MMPTE;
    let pt = pt_phys as *mut MMPTE;

    unsafe {
        core::ptr::write_bytes(pdpt.cast::<u8>(), 0, PT_ENTRIES * 8);
        core::ptr::write_bytes(pd.cast::<u8>(), 0, PT_ENTRIES * 8);
        core::ptr::write_bytes(pt.cast::<u8>(), 0, PT_ENTRIES * 8);
        core::ptr::write_volatile(
            pml4.add(MI_HYPERSPACE_INDEX),
            MMPTE::from_raw(pdpt_phys | TABLE_RW),
        );
        core::ptr::write_volatile(pdpt.add(0), MMPTE::from_raw(pd_phys | TABLE_RW));
        core::ptr::write_volatile(pd.add(0), MMPTE::from_raw(pt_phys | TABLE_RW));
    }

    crate::mm::vas::invalidate_tlb(HYPERSPACE_BASE);
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
pub fn install_single_level(pml4_phys: u64) {
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] WARNING: Falling back to single-level self-map");
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] WARNING: Limited functionality - PPE_BASE/PDE_BASE/PTE_BASE may not work");
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] WARNING: This indicates PFN allocation failure during bootstrap");

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
        // Self-map entry: P=1, R/W=1, A=1, D=1
        (*pml4e).set_hardware(pml4_phys, 0x1 | 0x2 | 0x20 | 0x40);
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
    }
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] Single-level self-map installed at PML4[0x1ED]=0x{:016x}",
    // //     // [DISABLED-KPRINTLN]               pml4_phys | 0x67);
}

/// Install single-level self-map directly to PML4 physical address.
/// This is used when we need to install the self-map but cannot use
/// the self-map window (because it's not set up yet). It writes
/// directly to the PML4's physical address.
pub fn install_single_level_self_map_direct(pml4_phys: u64) {
    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] install_single: starting, pml4_phys=0x{:x}", pml4_phys);

    // The PML4 is at pml4_phys (identity-mapped in UEFI).
    // We write directly to the PML4[MI_SELF_MAP_INDEX] entry.
    // Self-map entry: P=1, R/W=1, U=1, A=1, D=1
    const SELF_RW: u64 = 0x1 | 0x2 | 0x20 | 0x40;
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
///
/// Returns `true` when every 2 MiB slice of `[pa_base, pa_base + size)`
/// is identity-mapped and verified. Returns `false` when a page-table
/// allocation failed mid-way (the remaining slices stay unmapped and the
/// partially built table pages are intentionally leaked: they cannot be
/// safely written or handed back), or when the read-back verification
/// finds a bad entry. Callers must treat the region as unreachable in
/// that case instead of assuming VA == PA works.
pub fn ensure_low_identity_map(pa_base: u64, size: u64) -> bool {
    crate::boot_debug_println!(
        "[VAS] ensure_low_identity_map: pa_base=0x{:x} size=0x{:x}",
        pa_base,
        size
    );
    if size == 0 {
        crate::boot_debug_println!("[VAS] ensure_low_identity_map: zero range, skipping");
        return true;
    }
    const TWO_MB: u64 = 2 * 1024 * 1024;
    // U (0x4) deliberately omitted: kernel identity mappings must not be
    // user-accessible (ring-3 pointers must not reach low physical pages).
    const PDE_2MB_FLAGS: u64 = 0x1 | 0x2 | 0x20 | 0x40 | 0x80; // P|RW|A|D|PS

    let start = pa_base & !(TWO_MB - 1);
    let end_unaligned = pa_base.saturating_add(size);
    let end = (end_unaligned + TWO_MB - 1) & !(TWO_MB - 1);
    crate::boot_debug_println!(
        "[VAS] ensure_low_identity_map: start=0x{:x} end=0x{:x}",
        start,
        end
    );

    let pml4_phys = crate::arch::read_current_page_root();
    crate::boot_debug_println!("[VAS] ensure_low_identity_map: pml4_phys=0x{:x}", pml4_phys);
    if pml4_phys == 0 {
        // No active page root to install entries into; the mapping
        // cannot be created, so fail closed instead of silently
        // returning with nothing mapped.
        return false;
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

    let mut ok = true;
    let mut cur = start;
    crate::boot_debug_println!(
        "[VAS] ensure_low_identity_map: scanning PML4[0]={:016x} PML4[1]={:016x}",
        unsafe { (*pml4.add(0)).raw() },
        unsafe { (*pml4.add(1)).raw() }
    );
    let mut _pde_count = 0u64;
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
                        crate::boot_println!(
                            "[VAS] ensure_low_identity_map: PDPT alloc failed at cur=0x{:x}",
                            cur
                        );
                        ok = false;
                        break;
                    }
                };
                // The new table page must itself be identity-mapped
                // before it can be zeroed. On failure fail closed: the
                // page is left allocated (leaked) rather than installed
                // with uninitialised contents.
                if !ensure_low_identity_map(new_pdpt & !(TWO_MB - 1), TWO_MB) {
                    ok = false;
                    break;
                }
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
                        ok = false;
                        break;
                    }
                };
                if !ensure_low_identity_map(new_pd & !(TWO_MB - 1), TWO_MB) {
                    ok = false;
                    break;
                }
                core::ptr::write_bytes(new_pd as *mut u8, 0, 4096);
                (*pdpte).set_hardware(new_pd, INT_PTE_BITS);
            }
            let pd_phys = (*pdpte).hardware_page_frame();
            let pd = pd_phys as *mut MMPTE;

            // PDE: install as 2 MiB large page pointing at `cur`
            let pde = pd.add(pd_idx);
            (*pde).set_hardware(cur, PDE_2MB_FLAGS);
            _pde_count += 1;
        }

        cur += TWO_MB;
    }
    crate::boot_debug_println!(
        "[VAS] ensure_low_identity_map: mapping loop done, cur=0x{:x}, pdes installed={}",
        cur,
        _pde_count
    );

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
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3_after, options(nostack));
    }
    crate::boot_debug_println!(
        "[VAS] ensure_low_identity_map: CR3 before flush=0x{:x} after flush=0x{:x}",
        cr3,
        cr3_after
    );

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
            if pml4e_raw & 1 == 0 {
                bad += 1;
                verify_cur += TWO_MB;
                continue;
            }
            let pdpt_phys = pml4e_raw & !0xFFFu64;
            let pdpt = pdpt_phys as *mut MMPTE;
            let pdpte = (*pdpt.add(pdpt_idx)).raw();
            if pdpte & 1 == 0 {
                bad += 1;
                verify_cur += TWO_MB;
                continue;
            }
            let pd_phys = pdpte & !0xFFFu64;
            let pd = pd_phys as *mut MMPTE;
            let pde = (*pd.add(pd_idx)).raw();
            count += 1;
            if pde & 1 == 0 || (pde & 0x80) == 0 || (pde & !0xFFFu64) != verify_cur {
                bad += 1;
                if bad <= 4 {
                    crate::boot_println!(
                        "[VAS] verify: BAD PDE for pa=0x{:x} -> 0x{:x} (P={} R/W={} PS={})",
                        verify_cur,
                        pde,
                        pde & 1,
                        (pde >> 1) & 1,
                        (pde >> 7) & 1
                    );
                }
            }
            verify_cur += TWO_MB;
        }
        crate::boot_debug_println!("[VAS] verify: {} PDEs, {} bad", count, bad);
        ok & (bad == 0)
    }
}

/// for the PML4 page itself so that after CR3 is switched, the kernel
/// can still access the PML4 through the lower portion of the address
/// space (which UEFI always maps 1:1).
///
/// Returns Ok(()) on success, Err(SelfMapError) on failure.
pub fn install_with_identity_map(pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    let pml4_phys = pfn_to_phys(pml4_pfn);
    crate::boot_debug_println!("[VAS] install_self_map: pml4_pfn=0x{:x}", pml4_phys);
    // U (0x4) omitted: this identity mapping is for kernel use only.
    const SELF_RW: u64 = 0x1 | 0x2 | 0x20 | 0x40;

    let pml4 = pml4_phys as *mut MMPTE;

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

    // Install the canonical one-page recursive self-map. The PML4's
    // own self-map index points back at the PML4, matching the NT 6.1
    // layout and giving every self-map window access to one page-table
    // level of the currently active address space.
    unsafe {
        (*pml4.add(MI_SELF_MAP_INDEX)).set_hardware(pml4_phys, SELF_RW);
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
        // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] WARNING: PML4[0x{:x}] not mapped, adding identity-mapping", pml4_self_idx);
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
                unsafe {
                    core::arch::asm!(
                        "mov cr0, {}",
                        in(reg) saved_cr0,
                        options(nostack, preserves_flags),
                    );
                }
                // [DISABLED-KPRINTLN]                 // // kprintln!("[VAS] FATAL: cannot allocate PDPT for identity-mapping!");
                return Err(SelfMapError::OutOfMemory);
            }
        };
        let pd_for_id = match pfn::allocate_pfn() {
            Some(p) => p,
            None => {
                unsafe {
                    core::arch::asm!(
                        "mov cr0, {}",
                        in(reg) saved_cr0,
                        options(nostack, preserves_flags),
                    );
                }
                pfn::free_pfn(pdpt_pfn_for_id);
                // [DISABLED-KPRINTLN]                 // // kprintln!("[VAS] FATAL: cannot allocate PD for identity-mapping!");
                return Err(SelfMapError::OutOfMemory);
            }
        };
        let pdpt_phys_id = pfn_to_phys(pdpt_pfn_for_id);
        let pd_phys_id = pfn_to_phys(pd_for_id);

        // Zero the pages
        unsafe {
            core::ptr::write_bytes(pdpt_phys_id as *mut u8, 0, 4096);
            core::ptr::write_bytes(pd_phys_id as *mut u8, 0, 4096);
            (*pml4.add(pml4_self_idx)).set_hardware(pdpt_phys_id, 0x1 | 0x2 | 0x20 | 0x40);
            let pdpt_va = pdpt_phys_id as *mut MMPTE;
            let pdpt_idx = ((pml4_phys >> 30) & 0x1FF) as usize;
            (*pdpt_va.add(pdpt_idx)).set_hardware(pd_phys_id, 0x1 | 0x2 | 0x20 | 0x40);
            let pd_idx = ((pml4_phys >> 21) & 0x1FF) as usize;
            let pd_va = pd_phys_id as *mut MMPTE;
            (*pd_va.add(pd_idx))
                .set_hardware(pml4_phys & !0x1F_FFFF, 0x1 | 0x2 | 0x20 | 0x40 | 0x80);
        }
    // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] Added identity-mapping: PML4[0x{:x}] -> PDPT, PDPT[0x{:x}] -> PD(large), PD[0x{:x}] -> 0x{:x}",
    // //     // [DISABLED-KPRINTLN]             pml4_self_idx, pdpt_idx, pd_idx, pml4_phys & !0x1F_FFFF);
    } else {
        // [DISABLED-KPRINTLN]         // // kprintln!("[VAS] Identity-mapping exists at PML4[0x{:x}]", pml4_self_idx);
    }

    unsafe {
        core::arch::asm!(
            "mov cr0, {}",
            in(reg) saved_cr0,
            options(nostack, preserves_flags),
        );
    }

    // [DISABLED-KPRINTLN]     // // kprintln!("[VAS] install_self_map_with_identity_map: done, PML4[0x1ED] set");
    crate::boot_debug_println!("[VAS] install_self_map: OK, returning");
    Ok(())
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Walk user PML4[0..256] and force U=1 on every PML4/PDPT/PD entry
/// we find. This makes the entire low-half identity-mapped region
/// user-accessible. Used when the user PML4 is created by copying
/// the (kernel-only) system PML4.
///
/// x86_64 only — on aarch64 / riscv64 / loongarch64 user accessibility
/// is encoded in the PTEs directly via AP[1] / SUM / PLV fields
/// rather than toggled through CR0.WP, so the equivalent flush isn't
/// needed.
/// Walk the page-table tree and force writable entries. This is required
/// when a user PML4 is copied from the boot-loader-owned system PML4.
pub unsafe fn force_writable_identity_map(pfn: PfnNumber) {
    let pml4_phys = pfn << 12;
    let pml4 = pml4_phys as *mut MMPTE;
    crate::boot_println!(
        "[VAS] force_writable_identity_map: pml4_phys=0x{:x}",
        pml4_phys
    );
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
    for pml4_idx in 0..PT_ENTRIES {
        let mut pml4e = (*pml4.add(pml4_idx)).raw();
        if pml4e & 0x1 == 0 {
            continue;
        }
        if pml4e & 0x2u64 == 0 {
            pml4e |= 0x2u64;
            core::ptr::write_volatile(pml4.add(pml4_idx) as *mut u64, pml4e);
        }
        let pdpt_phys = pml4e & !0xFFF_u64;
        let pdpt = pdpt_phys as *mut MMPTE;
        if pml4e & (1u64 << 7) != 0 {
            continue;
        }
        for pdpt_idx in 0..PT_ENTRIES {
            let mut pdpte = (*pdpt.add(pdpt_idx)).raw();
            if pdpte & 0x1 == 0 {
                continue;
            }
            if pdpte & 0x2u64 == 0 {
                pdpte |= 0x2u64;
                core::ptr::write_volatile(pdpt.add(pdpt_idx) as *mut u64, pdpte);
            }
            let next_phys = pdpte & !0xFFF_u64;
            if pdpte & (1u64 << 7) != 0 {
                continue;
            }
            let pd = next_phys as *const MMPTE;
            for pd_idx in 0..PT_ENTRIES {
                let mut pde = (*pd.add(pd_idx)).raw();
                if pde & 0x1 == 0 {
                    continue;
                }
                if pde & 0x2u64 == 0 {
                    pde |= 0x2u64;
                    core::ptr::write_volatile(pd.add(pd_idx) as *mut u64, pde);
                }
                let pt_phys = pde & !0xFFF_u64;
                if pde & (1u64 << 7) != 0 {
                    continue;
                }
                let pt = pt_phys as *const MMPTE as *mut MMPTE;
                for pt_idx in 0..PT_ENTRIES {
                    let mut pte = (*pt.add(pt_idx)).raw();
                    if pte & 0x1 == 0 {
                        continue;
                    }
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
    core::arch::asm!(
        "mov cr0, {}",
        in(reg) saved_cr0,
        options(nostack, preserves_flags),
    );
    unsafe {
        force_user_accessible(pfn);
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Walk user PML4 entries and force user-accessible bits.
pub unsafe fn force_user_accessible(pfn: PfnNumber) {
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
        if pml4e & 0x1 == 0 {
            continue;
        }
        if pml4e & 0x4u64 == 0 {
            pml4e |= 0x4u64;
            core::ptr::write_volatile(pml4.add(pml4_idx) as *mut u64, pml4e);
            flipped += 1;
        }
        let pdpt_phys = pml4e & !0xFFF_u64;
        let pdpt = pdpt_phys as *mut MMPTE;
        // Skip 1GB large pages.
        if pml4e & (1u64 << 7) != 0 {
            continue;
        }
        for pdpt_idx in 0..PT_ENTRIES {
            let mut pdpte = (*pdpt.add(pdpt_idx)).raw();
            if pdpte & 0x1 == 0 {
                continue;
            }
            if pdpte & 0x4u64 == 0 {
                pdpte |= 0x4u64;
                core::ptr::write_volatile(pdpt.add(pdpt_idx) as *mut u64, pdpte);
                flipped += 1;
            }
            let next_phys = pdpte & !0xFFF_u64;
            if pdpte & (1u64 << 7) != 0 {
                continue;
            }
            let pd = next_phys as *const MMPTE;
            for pd_idx in 0..PT_ENTRIES {
                let mut pde = (*pd.add(pd_idx)).raw();
                if pde & 0x1 == 0 {
                    continue;
                }
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
