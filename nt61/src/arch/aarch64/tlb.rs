//! AArch64 TLB (Translation Lookaside Buffer) Management
//!
//! Provides comprehensive TLB invalidation operations for:
//! - Single page invalidation
//! - Range invalidation
//! - Full TLB flush (kernel/user/both)
//! - ASID-based invalidation
//! - Broadcast operations for SMP

use core::arch::asm;

/// Address Space ID type
pub type Asid = u16;

/// Invalidate entire TLB for all ASIDs (kernel and user)
#[inline]
pub fn flush_all() {
    unsafe {
        // TLBI VMALLE1IS - invalidate all stage 1 translations for EL1
        // Inner Shareable variant (broadcasts to all cores)
        asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}

/// Invalidate entire TLB for current ASID only
#[inline]
pub fn flush_current_asid() {
    unsafe {
        // TLBI ASIDE1IS - invalidate by ASID, Inner Shareable
        let asid = read_current_asid();
        asm!(
            "tlbi aside1is, {asid}",
            "dsb ish",
            "isb",
            asid = in(reg) (asid as u64) << 48,
            options(nostack)
        );
    }
}

/// Invalidate TLB for specific ASID
#[inline]
pub fn flush_asid(asid: Asid) {
    unsafe {
        asm!(
            "tlbi aside1is, {asid}",
            "dsb ish",
            "isb",
            asid = in(reg) (asid as u64) << 48,
            options(nostack)
        );
    }
}

/// Invalidate single page at virtual address
#[inline]
pub fn flush_page(vaddr: u64) {
    unsafe {
        // TLBI VAE1IS - invalidate by VA, EL1, Inner Shareable
        // Bits [55:12] contain the VA, bits [63:56] unused
        let va = (vaddr >> 12) & 0xFFFF_FFFF_FFFF;
        asm!(
            "tlbi vae1is, {va}",
            "dsb ish",
            "isb",
            va = in(reg) va,
            options(nostack)
        );
    }
}

/// Invalidate single page with specific ASID
#[inline]
pub fn flush_page_asid(vaddr: u64, asid: Asid) {
    unsafe {
        // Combine ASID in upper bits with VA in lower bits
        let va_asid = ((asid as u64) << 48) | ((vaddr >> 12) & 0xFFFF_FFFF_FFFF);
        asm!(
            "tlbi vae1is, {va}",
            "dsb ish",
            "isb",
            va = in(reg) va_asid,
            options(nostack)
        );
    }
}

/// Invalidate TLB for a range of pages
#[inline]
pub fn flush_range(start_vaddr: u64, end_vaddr: u64) {
    const PAGE_SIZE: u64 = 4096;
    let mut addr = start_vaddr & !(PAGE_SIZE - 1);
    let end = (end_vaddr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    unsafe {
        while addr < end {
            let va = (addr >> 12) & 0xFFFF_FFFF_FFFF;
            asm!(
                "tlbi vae1is, {va}",
                va = in(reg) va,
                options(nostack)
            );
            addr += PAGE_SIZE;
        }
        asm!("dsb ish", "isb", options(nostack));
    }
}

/// Invalidate TLB for range with specific ASID
#[inline]
pub fn flush_range_asid(start_vaddr: u64, end_vaddr: u64, asid: Asid) {
    const PAGE_SIZE: u64 = 4096;
    let mut addr = start_vaddr & !(PAGE_SIZE - 1);
    let end = (end_vaddr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    unsafe {
        while addr < end {
            let va_asid = ((asid as u64) << 48) | ((addr >> 12) & 0xFFFF_FFFF_FFFF);
            asm!(
                "tlbi vae1is, {va}",
                va = in(reg) va_asid,
                options(nostack)
            );
            addr += PAGE_SIZE;
        }
        asm!("dsb ish", "isb", options(nostack));
    }
}

/// Invalidate instruction TLB for a page
#[inline]
pub fn flush_instruction_page(vaddr: u64) {
    unsafe {
        let va = (vaddr >> 12) & 0xFFFF_FFFF_FFFF;
        asm!(
            "tlbi vaae1is, {va}",
            "dsb ish",
            "isb",
            va = in(reg) va,
            options(nostack)
        );
    }
}

/// Read current ASID from TTBR0_EL1
#[inline]
fn read_current_asid() -> Asid {
    let ttbr0: u64;
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack));
    }
    ((ttbr0 >> 48) & 0xFFFF) as Asid
}

/// Set ASID in TTBR0_EL1
#[inline]
pub fn set_asid(asid: Asid) {
    unsafe {
        let mut ttbr0: u64;
        asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack));

        // Clear old ASID and set new
        ttbr0 &= 0x0000_FFFF_FFFF_FFFF;
        ttbr0 |= (asid as u64) << 48;

        asm!(
            "msr ttbr0_el1, {}",
            "isb",
            in(reg) ttbr0,
            options(nostack)
        );
    }
}

/// Flush TLB for kernel mappings only (TTBR1_EL1)
#[inline]
pub fn flush_kernel() {
    unsafe {
        // Invalidate all EL1 translations
        asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}

/// Flush TLB for user mappings only (TTBR0_EL1)
#[inline]
pub fn flush_user() {
    flush_current_asid();
}

/// Flush both kernel and user TLBs
#[inline]
pub fn flush_all_both() {
    unsafe {
        asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}
