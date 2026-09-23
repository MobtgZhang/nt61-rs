//! RISC-V64 TLB (Translation Lookaside Buffer) Management
//!
//! Comprehensive TLB operations using sfence.vma:
//! - Single page invalidation
//! - Range invalidation
//! - ASID-based invalidation
//! - Global TLB flush

use core::arch::asm;

/// Address Space ID type
pub type Asid = u16;

/// Invalidate entire TLB
#[inline]
pub fn flush_all() {
    unsafe {
        asm!("sfence.vma zero, zero", options(nostack));
    }
}

/// Invalidate TLB for specific ASID
#[inline]
pub fn flush_asid(asid: Asid) {
    unsafe {
        asm!("sfence.vma zero, {asid}", asid = in(reg) asid as usize, options(nostack));
    }
}

/// Invalidate single page at virtual address
#[inline]
pub fn flush_page(vaddr: u64) {
    unsafe {
        asm!("sfence.vma {addr}, zero", addr = in(reg) vaddr, options(nostack));
    }
}

/// Invalidate single page with specific ASID
#[inline]
pub fn flush_page_asid(vaddr: u64, asid: Asid) {
    unsafe {
        asm!(
            "sfence.vma {addr}, {asid}",
            addr = in(reg) vaddr,
            asid = in(reg) asid as usize,
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

    // For small ranges, invalidate individual pages
    // For large ranges, flush everything
    let num_pages = (end - addr) / PAGE_SIZE;

    if num_pages > 64 {
        flush_all();
    } else {
        unsafe {
            while addr < end {
                asm!("sfence.vma {addr}, zero", addr = in(reg) addr, options(nostack));
                addr += PAGE_SIZE;
            }
        }
    }
}

/// Invalidate TLB for range with specific ASID
#[inline]
pub fn flush_range_asid(start_vaddr: u64, end_vaddr: u64, asid: Asid) {
    const PAGE_SIZE: u64 = 4096;
    let mut addr = start_vaddr & !(PAGE_SIZE - 1);
    let end = (end_vaddr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let num_pages = (end - addr) / PAGE_SIZE;

    if num_pages > 64 {
        flush_asid(asid);
    } else {
        unsafe {
            while addr < end {
                asm!(
                    "sfence.vma {addr}, {asid}",
                    addr = in(reg) addr,
                    asid = in(reg) asid as usize,
                    options(nostack)
                );
                addr += PAGE_SIZE;
            }
        }
    }
}

/// Read current ASID from satp
#[inline]
pub fn read_current_asid() -> Asid {
    let satp: u64;
    unsafe {
        asm!("csrr {}, satp", out(reg) satp, options(nostack));
    }
    ((satp >> 44) & 0xFFFF) as Asid
}

/// Set ASID in satp
#[inline]
pub fn set_asid(asid: Asid) {
    unsafe {
        let mut satp: u64;
        asm!("csrr {}, satp", out(reg) satp, options(nostack));

        // Clear old ASID (bits 59:44)
        satp &= !(0xFFFF_u64 << 44);
        // Set new ASID
        satp |= (asid as u64) << 44;

        asm!("csrw satp, {}", in(reg) satp, options(nostack));
        // Fence to ensure TLB sees new ASID
        asm!("sfence.vma zero, zero", options(nostack));
    }
}

/// Invalidate TLB for all global mappings
#[inline]
pub fn flush_global() {
    flush_all();
}

/// Remote TLB shootdown (for SMP)
/// Send IPI to other harts to flush their TLBs
#[inline]
pub fn flush_remote(hart_mask: u64) {
    // Use SBI or direct IPI mechanism
    // This would call into clint or SBI HSM
    let _ = hart_mask;
    // Placeholder - full implementation would send IPIs
}
