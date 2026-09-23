//! LoongArch64 TLB (Translation Lookaside Buffer) Management
//!
//! Comprehensive TLB operations using LoongArch-specific instructions:
//! - Single page invalidation
//! - Range invalidation
//! - ASID-based invalidation
//! - TLB refill handling

use core::arch::asm;

/// Address Space ID type
pub type Asid = u16;

/// CSR register numbers for LoongArch64
mod csr {
    pub const ASID: u16 = 0x18;
    pub const PGDL: u16 = 0x19;
    pub const PGDH: u16 = 0x1A;
    pub const TLBRENTRY: u16 = 0x88;
    pub const TLBIDX: u16 = 0x10;
    pub const TLBEHI: u16 = 0x11;
    pub const TLBELO0: u16 = 0x12;
    pub const TLBELO1: u16 = 0x13;
}

/// Invalidate entire TLB
#[inline]
pub fn flush_all() {
    unsafe {
        // Use invtlb instruction with op=0 (invalidate all)
        asm!("invtlb $zero, $zero, 0", options(nostack));
    }
}

/// Invalidate TLB for specific ASID
#[inline]
pub fn flush_asid(asid: Asid) {
    unsafe {
        // invtlb op=4: invalidate by ASID
        asm!(
            "invtlb {asid}, $zero, 4",
            asid = in(reg) asid as u64,
            options(nostack)
        );
    }
}

/// Invalidate single page at virtual address
#[inline]
pub fn flush_page(vaddr: u64) {
    unsafe {
        // invtlb op=5: invalidate by VA (all ASIDs)
        asm!(
            "invtlb $zero, {addr}, 5",
            addr = in(reg) vaddr,
            options(nostack)
        );
    }
}

/// Invalidate single page with specific ASID
#[inline]
pub fn flush_page_asid(vaddr: u64, asid: Asid) {
    unsafe {
        // invtlb op=6: invalidate by VA and ASID
        asm!(
            "invtlb {asid}, {addr}, 6",
            asid = in(reg) asid as u64,
            addr = in(reg) vaddr,
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

    let num_pages = (end - addr) / PAGE_SIZE;

    if num_pages > 64 {
        flush_all();
    } else {
        unsafe {
            while addr < end {
                asm!(
                    "invtlb $zero, {addr}, 5",
                    addr = in(reg) addr,
                    options(nostack)
                );
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
                    "invtlb {asid}, {addr}, 6",
                    asid = in(reg) asid as u64,
                    addr = in(reg) addr,
                    options(nostack)
                );
                addr += PAGE_SIZE;
            }
        }
    }
}

/// Read current ASID
#[inline]
pub fn read_current_asid() -> Asid {
    let asid: u64;
    unsafe {
        asm!("csrrd {}, 0x18", out(reg) asid, options(nostack));
    }
    (asid & 0x3FF) as Asid
}

/// Set ASID
#[inline]
pub fn set_asid(asid: Asid) {
    unsafe {
        let val = asid as u64;
        asm!("csrwr {}, 0x18", in(reg) val, options(nostack));
    }
}

/// TLB probe - check if VA is in TLB
#[inline]
pub fn probe(vaddr: u64) -> Option<usize> {
    unsafe {
        // Write VA to TLBEHI
        asm!("csrwr {}, 0x11", in(reg) vaddr, options(nostack));

        // Execute tlbsrch (TLB search)
        asm!("tlbsrch", options(nostack));

        // Read TLBIDX to check if found
        let idx: u64;
        asm!("csrrd {}, 0x10", out(reg) idx, options(nostack));

        // Bit 31 indicates not found
        if (idx & (1 << 31)) == 0 {
            Some((idx & 0x1F) as usize)
        } else {
            None
        }
    }
}

/// TLB read - read entry at index
#[inline]
pub fn read_entry(index: usize) -> (u64, u64, u64) {
    unsafe {
        // Write index to TLBIDX
        asm!("csrwr {}, 0x10", in(reg) index as u64, options(nostack));

        // Execute tlbrd (TLB read)
        asm!("tlbrd", options(nostack));

        // Read TLBEHI, TLBELO0, TLBELO1
        let ehi: u64;
        let elo0: u64;
        let elo1: u64;
        asm!("csrrd {}, 0x11", out(reg) ehi, options(nostack));
        asm!("csrrd {}, 0x12", out(reg) elo0, options(nostack));
        asm!("csrrd {}, 0x13", out(reg) elo1, options(nostack));

        (ehi, elo0, elo1)
    }
}

/// TLB write - write entry at index
#[inline]
pub fn write_entry(index: usize, ehi: u64, elo0: u64, elo1: u64) {
    unsafe {
        // Write values to CSRs
        asm!("csrwr {}, 0x10", in(reg) index as u64, options(nostack));
        asm!("csrwr {}, 0x11", in(reg) ehi, options(nostack));
        asm!("csrwr {}, 0x12", in(reg) elo0, options(nostack));
        asm!("csrwr {}, 0x13", in(reg) elo1, options(nostack));

        // Execute tlbwr (TLB write)
        asm!("tlbwr", options(nostack));
    }
}

/// TLB fill - automatic TLB refill from page table
#[inline]
pub fn tlb_fill(vaddr: u64) {
    unsafe {
        asm!("csrwr {}, 0x11", in(reg) vaddr, options(nostack));
        asm!("tlbfill", options(nostack));
    }
}

/// Invalidate all guest TLB entries
#[inline]
pub fn flush_guest() {
    unsafe {
        // invtlb op=3: invalidate all guest entries
        asm!("invtlb $zero, $zero, 3", options(nostack));
    }
}

/// Set page table base address (low)
#[inline]
pub fn set_pgd_low(paddr: u64) {
    unsafe {
        asm!("csrwr {}, 0x19", in(reg) paddr, options(nostack));
    }
}

/// Set page table base address (high)
#[inline]
pub fn set_pgd_high(paddr: u64) {
    unsafe {
        asm!("csrwr {}, 0x1A", in(reg) paddr, options(nostack));
    }
}

/// Read page table base address (low)
#[inline]
pub fn read_pgd_low() -> u64 {
    let val: u64;
    unsafe {
        asm!("csrrd {}, 0x19", out(reg) val, options(nostack));
    }
    val
}

/// Read page table base address (high)
#[inline]
pub fn read_pgd_high() -> u64 {
    let val: u64;
    unsafe {
        asm!("csrrd {}, 0x1A", out(reg) val, options(nostack));
    }
    val
}
