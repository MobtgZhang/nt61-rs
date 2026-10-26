//! Architecture-neutral self-map facade.
//!
//! The portable memory manager calls these functions without knowing
//! whether the hardware uses x86 page-table recursion or another paging
//! model. Each architecture owns the actual implementation.

use crate::mm::pte::PfnNumber;

#[cfg(target_arch = "x86_64")]
pub use crate::mm::vas::SelfMapError;

#[cfg(not(target_arch = "x86_64"))]
use crate::mm::vas::SelfMapError;

#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::self_map::*;

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn install_full(_pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn install_single_level(_pml4_phys: u64) {}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn install_single_level_direct(_pml4_phys: u64) {}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn install_single_level_direct(pml4_phys: u64) {
    crate::arch::x86_64::self_map::install_single_level_self_map_direct(pml4_phys);
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn install_recursive(pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    crate::arch::x86_64::self_map::install_recursive_self_map(pml4_pfn)
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn install_hyperspace(pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    crate::arch::x86_64::self_map::install_hyperspace_tables(pml4_pfn)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn install_with_identity_map(_pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn install_recursive(_pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn install_hyperspace(_pml4_pfn: PfnNumber) -> Result<(), SelfMapError> {
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn ensure_low_identity_map(pa_base: u64, size: u64) -> bool {
    // NOTE: pa_base == 0 is a valid call. The LoongArch64
    // bootstrap depends on ensure_low_identity_map(0, limit)
    // mapping the entire low-RAM window so the kernel heap
    // (allocated pre-flush under identity mapping) remains
    // reachable once CRMD.PG is enabled. Only a zero-size
    // range is a no-op.
    if size == 0 {
        return;
    }
    let mapped = crate::arch::identity_map_region(pa_base, size);
    crate::boot_debug_println!(
        "[VAS] ensure_low_identity_map: base=0x{:x} size=0x{:x} mapped={}",
        pa_base,
        size,
        mapped
    );
    mapped
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn force_writable_identity_map(_pfn: PfnNumber) {}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn arm_write_watchpoint(_pfn: PfnNumber) {}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn current_recursive_self_map_is_installed() -> bool {
    true
}

#[inline]
pub fn current_recursive_self_map_is_supported() -> bool {
    cfg!(target_arch = "x86_64")
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn arm_write_watchpoint(pfn: PfnNumber) {
    if pfn == 0x20f2a {
        core::arch::asm!("mov dr0, {}", in(reg) pfn << 12, options(nomem, nostack));
        core::arch::asm!("mov dr7, {}", in(reg) 0xD0001u64, options(nomem, nostack));
        crate::boot_println!("[DB] armed DR0=0x{:x}", pfn << 12);
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn current_recursive_self_map_is_installed() -> bool {
    const RECURSIVE_INDEX: usize = 0x1ED;
    let root: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) root, options(nostack, preserves_flags));
    }
    let root = root & !0xFFF;
    let root = root as *const u64;
    let entry = unsafe { *root.add(RECURSIVE_INDEX) };
    if entry & 1 == 0 {
        return false;
    }

    let root_pfn = root as u64 >> 12;
    let entry_pfn = (entry & 0x000F_FFFF_FFFF_F000) >> 12;
    if entry_pfn == root_pfn {
        return true;
    }

    let pdpt = (entry_pfn << 12) as *const u64;
    let pdpt_entry = unsafe { *pdpt.add(RECURSIVE_INDEX) };
    if pdpt_entry & 1 == 0 {
        return false;
    }
    let pd = (pdpt_entry & 0x000F_FFFF_FFFF_F000) as *const u64;
    let pd_entry = unsafe { *pd.add(RECURSIVE_INDEX) };
    if pd_entry & 1 == 0 {
        return false;
    }
    let pt = (pd_entry & 0x000F_FFFF_FFFF_F000) as *const u64;
    let pt_entry = unsafe { *pt.add(RECURSIVE_INDEX) };
    if pt_entry & 1 == 0 {
        return false;
    }

    let leaf_pfn = (pt_entry & 0x000F_FFFF_FFFF_F000) >> 12;
    leaf_pfn == root_pfn || leaf_pfn == entry_pfn
}
